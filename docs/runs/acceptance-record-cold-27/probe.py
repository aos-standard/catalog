#!/usr/bin/env python3
"""Probes OUTSIDE the published vectors, for rules the text states loosely.

Builds a fresh verified case with its own throwaway keys (so payloads can be
re-signed), then changes one thing per probe. Each probe is run through this
reader and, as black boxes by their command line only, the reference checker
and actaseal's checker. No checker source is read.

Usage: python3 -I probe.py <pgc-repo-root> <actaseal-repo-root>
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from acceptance_cold_reader import evaluate, jcs  # noqa: E402

pgc, acold = Path(sys.argv[1]), Path(sys.argv[2])
REF = pgc / "tools/acceptance_record_check.py"
ALT = acold / "checker.py"
# optional third black box: robertolocatelli81-dev/x402-acceptance-check-omega (acceptance_check.py CASE.json)
OMEGA = Path(sys.argv[3]) / "acceptance_check.py" if len(sys.argv) > 3 else None


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def key(seed: int):
    sk = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, b64u(pub)


cp_sk, cp_x = key(0x51)
iss_sk, iss_x = key(0x52)
RECORD = {"issuer": "did:probe:issuer", "issuer_kid": "iss-p", "record_id": "receipt-p1",
          "terms_sha256": hashlib.sha256(b"terms").hexdigest(),
          "outcome_sha256": hashlib.sha256(b"outcome").hexdigest(),
          "outcome_at": "2026-10-04T18:00:00.000Z"}


def payload_for(record, **over):
    p = {"acceptance_version": "acceptance-record-v0", "accepted_at": "2026-10-04T18:05:00.000Z",
         "accepted_record_sha256": hashlib.sha256(jcs(record)).hexdigest(),
         "confirming_party": "did:probe:cp", "disposition": "accepted",
         "outcome_sha256": record["outcome_sha256"], "terms_sha256": record["terms_sha256"]}
    for k, v in over.items():
        if v is ...:
            p.pop(k, None)
        else:
            p[k] = v
    return p


def sign(payload: dict, sk=cp_sk, kid="cp-p", protected_over=None, payload_bytes=None):
    prot = {"alg": "EdDSA", "kid": kid}
    if protected_over:
        prot.update(protected_over)
    pb = payload_bytes if payload_bytes is not None else jcs(payload)
    ps, hs = b64u(pb), b64u(jcs(prot))
    sig = sk.sign(f"{hs}.{ps}".encode())
    return {"protected": hs, "payload": ps, "signature": b64u(sig)}


def case(record=RECORD, acceptance=None, trust=None, delegation=None, complete=False, **extra):
    c = {"accepted_record": record,
         "acceptance": acceptance if acceptance is not None else sign(payload_for(record)),
         "trust_material": trust or {"keys": [
             {"kty": "OKP", "crv": "Ed25519", "kid": "iss-p", "x": iss_x},
             {"kty": "OKP", "crv": "Ed25519", "kid": "cp-p", "x": cp_x}]},
         "delegation": delegation or {"did:probe:cp": ["cp-p"], "did:probe:issuer": ["iss-p"]},
         "trust_material_complete": complete}
    c.update(extra)
    return c


rec5 = {k: v for k, v in RECORD.items() if k != "record_id"}
probes = {
    "q00-control-verified": case(),
    "q01-accepted_at-no-fraction": case(acceptance=sign(payload_for(RECORD, accepted_at="2026-10-04T18:05:00Z"))),
    "q02-accepted_at-offset-plus09-same-instant": case(acceptance=sign(payload_for(RECORD, accepted_at="2026-10-05T03:05:00.000+09:00"))),
    "q03-accepted_at-offset-plus09-earlier-instant": case(acceptance=sign(payload_for(RECORD, accepted_at="2026-10-04T18:05:00.000+09:00"))),
    "q04-digest-uppercase-hex": case(acceptance=sign(payload_for(RECORD, terms_sha256=RECORD["terms_sha256"].upper()))),
    "q05-record-digest-over-5-fields-no-record_id": case(acceptance=sign(payload_for(RECORD, accepted_record_sha256=hashlib.sha256(jcs(rec5)).hexdigest()))),
    "q06-record-without-record_id-digest-matches": case(record=rec5),
    "q07-complete-omitted": {k: v for k, v in case().items() if k != "trust_material_complete"},
    "q08-complete-as-string-true": case(complete="true"),
    "q09-duplicate-kid-second-key-is-signer": case(trust={"keys": [
        {"kty": "OKP", "crv": "Ed25519", "kid": "iss-p", "x": iss_x},
        {"kty": "OKP", "crv": "Ed25519", "kid": "cp-p", "x": key(0x77)[1]},
        {"kty": "OKP", "crv": "Ed25519", "kid": "cp-p", "x": cp_x}]}),
    "q10-kid-delegated-to-both-parties": case(delegation={"did:probe:cp": ["cp-p"], "did:probe:issuer": ["iss-p", "cp-p"]}),
    "q11-confirming_party-whitespace": case(acceptance=sign(payload_for(RECORD, confirming_party="   "))),
    "q12-disposition-capitalised": case(acceptance=sign(payload_for(RECORD, disposition="Accepted"))),
    "q13-alg-ES256-in-header": case(acceptance=sign(payload_for(RECORD), protected_over={"alg": "ES256"})),
    "q14-header-without-kid": case(acceptance=sign(payload_for(RECORD), protected_over={"kid": None}) | {}),
    "q15-unknown-extra-member": case(acceptance=sign(payload_for(RECORD, note="hello"))),
    "q16-version-v1": case(acceptance=sign(payload_for(RECORD, acceptance_version="acceptance-record-v1"))),
    "q17-payload-non-canonical-json-spaces": case(acceptance=sign(payload_for(RECORD), payload_bytes=json.dumps(payload_for(RECORD), indent=1).encode())),
    "q18-key-unresolved-and-digest-mismatch-together": case(acceptance=sign(payload_for(RECORD, terms_sha256="0" * 64), kid="ghost")),
    "q19-outcome_at-no-fraction-same-instant": case(record=RECORD | {"outcome_at": "2026-10-04T18:05:00Z"}),
    "q20-key-unresolved-complete-as-string-true": case(acceptance=sign(payload_for(RECORD), kid="ghost"), complete="true"),
    "q21-key-unresolved-complete-as-int-1": case(acceptance=sign(payload_for(RECORD), kid="ghost"), complete=1),
    "q22-key-unresolved-complete-true-bool": case(acceptance=sign(payload_for(RECORD), kid="ghost"), complete=True),
}
# q14: drop kid entirely
p14 = probes["q14-header-without-kid"]
prot = json.loads(base64.urlsafe_b64decode(p14["acceptance"]["protected"] + "=="))
prot.pop("kid", None)
hs = b64u(jcs(prot)); ps = p14["acceptance"]["payload"]
p14["acceptance"] = {"protected": hs, "payload": ps, "signature": b64u(cp_sk.sign(f"{hs}.{ps}".encode()))}
# q19: payload must reference the modified record
r19 = probes["q19-outcome_at-no-fraction-same-instant"]["accepted_record"]
probes["q19-outcome_at-no-fraction-same-instant"]["acceptance"] = sign(payload_for(r19, accepted_at="2026-10-04T18:05:00.000Z"))


def run_black_box(script: Path, c: dict) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(c, f)
    # -s -E: no user site, no env; the script's own directory stays importable
    p = subprocess.run([sys.executable, "-s", "-E", str(script), f.name], capture_output=True, text=True,
                       cwd=str(script.parent))
    d = {}
    for text in (p.stdout.strip(), p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""):
        try:
            d = json.loads(text)
            break
        except Exception:
            continue
    keep = {k: d.get(k) for k in ("result", "conditions", "disposition") if k in d}
    keep["exit"] = p.returncode
    if not keep.get("result") and p.stderr.strip():
        keep["stderr"] = p.stderr.strip().splitlines()[-1][:120]
    return keep


out = {}
for name, c in probes.items():
    mine = evaluate(c)
    out[name] = {"mine": {k: mine.get(k) for k in ("result", "conditions", "disposition", "exit")},
                 "reference": run_black_box(REF, c),
                 # actaseal's checker.py is a library without a command line; its runner
                 # fetches vectors.json over the network. Not run on these probes.
                 "actaseal": None,
                 "omega": run_black_box(OMEGA, c) if OMEGA and OMEGA.exists() else None}
(HERE / "probe_cases.json").write_text(json.dumps(probes, indent=1, sort_keys=True))
print(json.dumps(out, indent=1, sort_keys=True))
