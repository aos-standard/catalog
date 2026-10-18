#!/usr/bin/env python3
"""Build proposed vectors 12-21 for checks the eleven vectors do not exercise (lax_battery survivors).

Starts from vector 01 at f7d8984, changes one thing per vector, re-signs with a fresh Ed25519 TEST
key (published in TEST_KEY.json, private half included so anyone can regenerate; never trust it),
and rebuilds RFC 3161 tokens by substituting the 32-byte imprint and the 15-byte GeneralizedTime in
vector 01's token bytes (same DER lengths, so the structure is unchanged).

`expected` objects are this verifier's reading of the README; they are proposals.
Usage: python3 -I build_proposed.py <repo clone> <out dir>
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
from war_cold_verifier import jcs, parse_tsr, verify  # noqa: E402

repo, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
base = json.loads((repo / "vectors/01-valid.json").read_text(encoding="utf-8"))

# --- deterministic test key (seed from a fixed string; published, never trust)
seed = hashlib.sha256(b"work-acceptance-record cold proposed vectors test key 2026-10-18").digest()
priv = Ed25519PrivateKey.from_private_bytes(seed)
pub_b64 = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
KEY_ID = "hori-cold-test-1"
seed2 = hashlib.sha256(b"work-acceptance-record cold proposed vectors second test key 2026-10-18").digest()
priv2 = Ed25519PrivateKey.from_private_bytes(seed2)
pub2_b64 = base64.b64encode(priv2.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
KEY_ID2 = "hori-cold-test-2"
(out.parent / "TEST_KEY.json").write_text(json.dumps({
    "warning": "TEST keys. Private halves are published so the vectors can be regenerated. Never trust a record signed by them.",
    "keys": [
        {"key_id": KEY_ID, "alg": "Ed25519", "public_key_base64": pub_b64, "private_seed_hex": seed.hex()},
        {"key_id": KEY_ID2, "alg": "Ed25519", "public_key_base64": pub2_b64, "private_seed_hex": seed2.hex()},
    ],
}, indent=1) + "\n", encoding="utf-8")

# --- token template from vector 01 (criteria token); substitute imprint and genTime
TEMPLATE = base64.b64decode(base["inputs"]["criteria_tsr_base64"])
t01 = parse_tsr(TEMPLATE)
IMPRINT_01 = bytes.fromhex(t01["imprint_hex"])
GEN_01 = t01["gen_time"].encode("ascii")
assert TEMPLATE.count(IMPRINT_01) == 1 and TEMPLATE.count(GEN_01) == 1


def token(imprint_hex: str, gen_time: str) -> str:
    b = TEMPLATE.replace(IMPRINT_01, bytes.fromhex(imprint_hex)).replace(GEN_01, gen_time.encode("ascii"))
    chk = parse_tsr(b)
    assert chk["imprint_hex"] == imprint_hex and chk["gen_time"] == gen_time
    return base64.b64encode(b).decode()


def sign(receipt: dict, key=priv, key_id=KEY_ID) -> dict:
    return {"alg": "Ed25519", "key_id": key_id, "value": base64.b64encode(key.sign(jcs(receipt))).decode()}


def keys_block(*ids_pubs):
    return {"issuer": "Hori cold verifier (proposed test vectors)", "keys": [{"alg": "Ed25519", "key_id": k, "public_key_base64": p, "status": "test"} for k, p in ids_pubs]}


def make(name: str, title: str, description: str, pins: str, mutate):
    vec = copy.deepcopy(base)
    inp = vec["inputs"]
    r = inp["receipt"]["receipt"]
    r["key_id"] = KEY_ID
    r["parties"]["checker"]["key_id"] = KEY_ID
    inp["keys"] = keys_block((KEY_ID, pub_b64))
    inp["receipt_tsr_base64"] = None
    inp["receipt"]["timestamp"] = None
    mutate(vec, inp, r)
    if "signature" not in inp["receipt"] or inp["receipt"]["signature"] is None:
        inp["receipt"]["signature"] = sign(r)
    if inp.get("receipt_tsr_base64") is None:
        inp["receipt_tsr_base64"] = None
    vec.update({
        "vector": name, "title": title, "description": description, "pins": pins,
        "contributed_by": "proposed by the maintainer of aos-standard/catalog from the cold verifier in docs/runs/work-acceptance-record-cold (CC0); expectations are that verifier's reading of README f7d8984",
        "license": "CC0-1.0",
    })
    got = verify(vec)
    vec["expected"] = {k: got[k] for k in ("criteria_committed_before_check", "criteria_hash", "independence", "problem_codes", "receipt_timestamp", "signature_valid", "verdict_recomputed", "verdict_stated", "warning_codes") if k in got}
    if "refused" in got:
        vec["expected"] = {"refused": True, "reason": got["refused"]}
    (out / f"{name}.json").write_text(json.dumps(vec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return name, vec["expected"]


def m12(vec, inp, r):  # signer is not the declared checker
    inp["keys"] = keys_block((KEY_ID, pub_b64), (KEY_ID2, pub2_b64))
    inp["receipt"]["signature"] = sign(r, priv2, KEY_ID2)


def m13(vec, inp, r):  # stated independent, but producer name equals checker name
    r["parties"]["producer"]["name"] = r["parties"]["checker"]["name"]
    r["independence"] = "independent"
    inp["receipt"]["signature"] = None


def m14(vec, inp, r):  # criteria document matches its hash, but results name a criterion it does not have
    r["results"].append({"id": "c9", "required": False, "result": "pass", "title": "Not in the criteria document", "finding": "Met."})
    inp["receipt"]["signature"] = None


def m15(vec, inp, r):  # criteria token over other bytes
    inp["criteria_tsr_base64"] = token("ab" * 32, "20260301000000Z")
    inp["receipt"]["signature"] = None


def m16(vec, inp, r):  # no criteria token at all
    inp["criteria_tsr_base64"] = None
    inp["receipt"]["signature"] = None


def m17(vec, inp, r):  # commitment time equal to the reference time (not strictly earlier)
    r["criteria"]["committed_at"] = r["issued_utc"]
    inp["criteria_tsr_base64"] = token(r["criteria"]["sha256"], "20260601120000Z")
    inp["receipt"]["signature"] = None


def m18(vec, inp, r):  # mismatching receipt token whose genTime would rescue the commitment
    r["criteria"]["committed_at"] = "2026-06-01T12:30:00Z"
    inp["criteria_tsr_base64"] = token(r["criteria"]["sha256"], "20260601123000Z")
    inp["receipt"]["signature"] = sign(r)
    inp["receipt_tsr_base64"] = token("cd" * 32, "20260601130000Z")  # over other bytes, later time
    inp["receipt"]["timestamp"] = {"covers": "sha256 of the canonical receipt object", "digest_sha256": "cd" * 32, "gen_time": "20260601130000Z", "status": "granted", "tsa": "test-tsa.invalid", "tsr_file": "receipt.tsr"}


def m19(vec, inp, r):  # result outside the vocabulary
    r["results"][0]["result"] = "passed"
    inp["receipt"]["signature"] = None


def m20(vec, inp, r):  # producer undeclared
    r["parties"]["producer"] = {"key_id": None, "name": None}
    inp["receipt"]["signature"] = None


def m21(vec, inp, r):  # unknown schema identifier
    r["schema"] = "trilatic.acceptance-receipt/9.9"
    inp["receipt"]["signature"] = None


rows = [
    make("12-signer-is-not-the-checker", "Signer is not the declared checker", "Valid signature by a second published test key; parties.checker.key_id names the first. Step 2 passes, step 8 must raise CHECKER_NOT_SIGNER.", "CHECKER_NOT_SIGNER", m12),
    make("13-independent-but-same-party", "Stated independent, producer is the checker", "independence: independent while parties.producer.name equals parties.checker.name.", "INDEPENDENCE_INCONSISTENT", m13),
    make("14-results-not-in-criteria", "Results name a criterion the committed document lacks", "Criteria document matches criteria.sha256; results add c9 which is not in it.", "CRITERIA_RESULTS_MISMATCH", m14),
    make("15-criteria-token-over-other-bytes", "Criteria token imprint is not criteria.sha256", "A structurally valid token whose imprint is other bytes.", "CRITERIA_TIMESTAMP_MISMATCH (+ fallback reading)", m15),
    make("16-no-criteria-token", "No criteria token supplied", "Only criteria.committed_at; step 5 fallback.", "CRITERIA_COMMITMENT_UNVERIFIED", m16),
    make("17-committed-at-equals-reference", "Commitment time equals the reference time", "Criteria token genTime == issued_utc, no record token. 'Strictly earlier' decides.", "strict < in step 5", m17),
    make("18-mismatching-record-token-later-time", "Mismatching record token with a later genTime", "Criteria committed 12:30 after issued_utc 12:00; the record's token is over other bytes and says 13:00. A verifier that uses the mismatching token's time says 'yes'.", "step 6: a mismatching token is never evidence of time", m18),
    make("19-result-outside-vocabulary", "A result token outside pass|fail|not-evaluated|error", "c1 result 'passed'.", "RESULT_VOCABULARY", m19),
    make("20-producer-undeclared", "No producer declared", "parties.producer has no name or key.", "PRODUCER_UNDECLARED", m20),
    make("21-unknown-schema", "Unknown schema identifier", "schema trilatic.acceptance-receipt/9.9; step 1 refuses.", "step 1 refusal", m21),
]
for name, exp in rows:
    print(name, json.dumps(exp))
