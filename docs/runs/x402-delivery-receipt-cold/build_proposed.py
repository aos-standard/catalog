#!/usr/bin/env python3
"""Build proposed negative vectors for delivery-receipt v0.2.1, derived from `endToEnd` and re-signed with the
PUBLISHED test seeds (endToEnd.seeds: governance 0101…, receipt keys 0202…). Never trust these keys.

Output: proposed/delivery-receipt.proposed-vectors.json — self-contained (shared inputs copied under /base),
expectedVerdicts in the Appendix A.7 convention. Usage: python3 build_proposed.py <vectors.json> <out.json>
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dr_cold_verifier as V  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def sign_ed(seed_hex: str, msg: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)).sign(msg)


def sign_ml(seed_hex: str, msg: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as td:
        pem = subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-pkeyopt", "hexseed:" + seed_hex],
                             capture_output=True, check=True).stdout
        kp, mp, sp = (os.path.join(td, n) for n in ("k.pem", "m", "s"))
        open(kp, "wb").write(pem); open(mp, "wb").write(msg)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", kp, "-in", mp, "-out", sp], check=True, capture_output=True)
        return open(sp, "rb").read()


def main() -> int:
    doc = V.parse_strict(Path(sys.argv[1]).read_bytes())
    e = doc["endToEnd"]
    seeds = e["seeds"]["receiptKeys"]
    kid = {s["alg"]: s["kid"] for s in e["receipt"]["signatures"]}

    def resign(payload: dict, *, break_mldsa: bool = False, drop_mldsa: bool = False) -> dict:
        rid = V.receipt_id(payload)
        msg = V.signed_message(rid)
        sigs = [{"alg": "ed25519", "kid": kid["ed25519"], "signature": b64(sign_ed(seeds["ed25519"], msg))}]
        if not drop_mldsa:
            raw = bytearray(sign_ml(seeds["ml-dsa-65"], msg))
            if break_mldsa:
                raw[5] ^= 0x01
            sigs.append({"alg": "ml-dsa-65", "kid": kid["ml-dsa-65"], "signature": b64(bytes(raw))})
        return {"payload": payload, "signatures": sigs}

    base_payload = e["receipt"]["payload"]
    out: dict = {
        "spec": "x402 delivery-receipt, draft v0.2.1 — PROPOSED negative vectors (not part of the specification)",
        "derivedFrom": "delivery-receipt.vectors.json at x402-foundation/x402#3783 head 737243dc (endToEnd)",
        "signedWith": "the published test seeds endToEnd.seeds.receiptKeys (0202…×32) for both algorithms; ML-DSA-65 signatures are hedged (openssl 3.6), so verify, do not re-sign",
        "generator": "aos-standard/catalog docs/runs/x402-delivery-receipt-cold/build_proposed.py (clean-room verifier, not the reference)",
        "readingNote": "Levels after the first failing level are reported as not-evaluated by the generator's verifier. A verifier that evaluates every level independently may report pass on a later level; valid, reason.level and longTermEvidence are the same either way (§8.1).",
        "refNote": "Shared inputs are $ref pointers into delivery-receipt.vectors.json (/endToEnd/…), as they would be if these fixtures were merged into that file; the runner overlays this file onto it.",
        "fixtures": {},
        "expectedVerdicts": [],
    }
    common = {"directory": {"$ref": "/endToEnd/directory"}, "pinnedGovernanceKeys": {"$ref": "/endToEnd/governanceKeys"},
              "now": {"$ref": "/endToEnd/now"}, "settle": {"$ref": "/endToEnd/settle"}, "requirements": {"$ref": "/endToEnd/requirements"},
              "resourceUrl": {"$ref": "/endToEnd/resourceUrl"}, "method": "GET", "responseBody": {"$ref": "/endToEnd/body"}}

    def run(id_, fixture, path, levels, valid, lte, reason, extra_inputs=None, inputs_override=None, note=None):
        inp = dict(common)
        if inputs_override is not None:
            inp = inputs_override
        else:
            inp["receipt"] = {"$ref": f"/fixtures/{fixture}/receipt"}
        if extra_inputs:
            inp.update(extra_inputs)
        ev = {"id": id_, "vector": f"/fixtures/{fixture}", "path": path, "offline": False, "inputs": inp,
              "levels": dict(zip(V.LEVELS, levels)), "valid": valid, "longTermEvidence": lte, "reason": reason}
        if note:
            ev["note"] = note
        out["expectedVerdicts"].append(ev)

    P, F, N = "pass", "fail", "not-evaluated"

    # P1 — KEY_DIRECTORY_DIGEST_MISMATCH: the code A.7 compares, with no run that produces it
    p = copy.deepcopy(base_payload); p["keyDirectoryDigest"] = hashlib.sha256(b"not the root of epoch 1").hexdigest()
    out["fixtures"]["keyDirectoryDigestMismatch"] = {"description": "endToEnd payload with keyDirectoryDigest replaced by another 64-hex value and re-signed with the published receipt seeds. The epoch resolves and the signatures verify; §7.5 step 2 fails: the receipt is not trusted.", "receipt": resign(p)}
    for path, lte in (("session", False), ("archival", False)):
        run(f"keyDirectoryDigestMismatch/{path}", "keyDirectoryDigestMismatch", path, (P, P, F, N, N), False, False,
            {"level": "trusted", "code": "KEY_DIRECTORY_DIGEST_MISMATCH"}, note="longTermEvidence is false because trusted fails (§8.1)")

    # P2 — amount inflated and re-signed (the question raised in #3758 about inflated amounts)
    p = copy.deepcopy(base_payload); p["amount"] = "10000000"
    out["fixtures"]["amountInflatedResigned"] = {"description": "endToEnd payload with amount 10000 → 10000000, re-signed with the published receipt seeds. Everything a third party can check passes (integrity, authentic, trusted); only the client's own observation (SettleResponse / accepted requirements, §8.3) catches it. This is the §12 boundary: a receipt is the issuer's admission, not an independent witness of the amount.", "receipt": resign(p)}
    run("amountInflatedResigned/session", "amountInflatedResigned", "session", (P, P, P, F, N), False, False, {"level": "settlement", "code": "SETTLEMENT_MISMATCH"})
    run("amountInflatedResigned/archival", "amountInflatedResigned", "archival", (P, P, P, F, N), False, True, {"level": "settlement", "code": "SETTLEMENT_MISMATCH"}, note="longTermEvidence is true: authentic and trusted pass on the archival path; the receipt is genuine evidence of what the issuer signed, and it does not match this settlement")

    # P3 — ml-dsa-65 stripped: malformed on every path (§6.1)
    out["fixtures"]["mlDsa65Stripped"] = {"description": "endToEnd receipt with the ml-dsa-65 entry removed. §6.1: a receipt that lacks either baseline signature is malformed (integrity fails) on every path, including the session path that would not have checked it.", "receipt": resign(copy.deepcopy(base_payload), drop_mldsa=True)}
    for path in ("session", "archival"):
        run(f"mlDsa65Stripped/{path}", "mlDsa65Stripped", path, (F, N, N, N, N), False, False, {"level": "integrity", "code": "SIGNATURES_SHAPE"},
            note="one entry left: the 2–4 entry count of §5.3 fails before the baseline-pair check; a verifier that checks the pair first reports the missing ml-dsa-65 instead — same level")

    # P4 — no split verdict: valid ed25519 next to a broken ml-dsa-65
    out["fixtures"]["splitVerdict"] = {"description": "endToEnd payload re-signed; the ml-dsa-65 signature has one byte flipped, the ed25519 signature is valid. §6.1: the archival path verifies every entry and fails; the session path passes and MUST report ml-dsa-65 as not checked. A result from the session path is not long-term evidence.", "receipt": resign(copy.deepcopy(base_payload), break_mldsa=True)}
    run("splitVerdict/session", "splitVerdict", "session", (P, P, P, P, P), True, False, None, note="the verifier's report MUST list ml-dsa-65 among the algorithms it did not check (§6.1)")
    run("splitVerdict/archival", "splitVerdict", "archival", (P, F, N, N, N), False, False, {"level": "authentic", "code": "SIGNATURE_INVALID"})

    # P5 — issuedAt beyond the clock-skew allowance
    p = copy.deepcopy(base_payload); p["issuedAt"] = e["now"] + 3600
    out["fixtures"]["issuedInFuture"] = {"description": "endToEnd payload with issuedAt = now + 3600 (beyond the default 300 s allowance of §7.4), re-signed. Integrity and the signatures pass; trusted fails.", "receipt": resign(p)}
    run("issuedInFuture/session", "issuedInFuture", "session", (P, P, F, N, N), False, False, {"level": "trusted", "code": "ISSUED_IN_FUTURE"})

    # P7 — unregistered framing on a stream receipt (§5.6: integrity)
    sp = copy.deepcopy(V.parse_strict(json.dumps(e["receipt"]["payload"])))
    st = doc["stream"]
    sp.update({"resourceUrl": e["stream"]["resourceUrl"], "responseStatus": 200, "responseContentType": "text/event-stream",
               "delivery": {"mode": "stream", "framing": "ndjson", "frameCount": st["frameCount"], "digest": st["digest"]}})
    rec = resign(sp)
    term = json.dumps({"frameCount": st["frameCount"], "digest": st["digest"], "receipt": rec}, separators=(",", ":"))
    frames_text = "".join(f"data: {f.replace(chr(10), chr(10) + 'data: ')}\n\n" for f in st["frames"])
    out["fixtures"]["framingUnregistered"] = {"description": "endToEnd/stream with delivery.framing = \"ndjson\" (not registered by v0.2.1), receipt inline in the terminal event, re-signed. §5.6: a verifier MUST reject (integrity) a stream receipt whose framing is not registered, before any digest is compared.",
                                               "resourceUrl": e["stream"]["resourceUrl"], "eventStream": frames_text + f"event: {V.TERMINAL_EVENT}\ndata: {term}\n\n"}
    run("framingUnregistered/session", "framingUnregistered", "session", (F, N, N, N, N), False, False, {"level": "integrity", "code": "DELIVERY_FRAMING"},
        inputs_override={"eventStream": {"$ref": "/fixtures/framingUnregistered/eventStream"}, "directory": {"$ref": "/endToEnd/directory"}, "pinnedGovernanceKeys": {"$ref": "/endToEnd/governanceKeys"},
                         "now": {"$ref": "/endToEnd/now"}, "settle": {"$ref": "/endToEnd/settle"}, "requirements": {"$ref": "/endToEnd/requirements"}, "resourceUrl": {"$ref": "/fixtures/framingUnregistered/resourceUrl"}, "method": "GET", "responseStatus": 200})

    # P8 — an event after the terminal event (§5.6: delivery failure), receipt unchanged
    out["fixtures"]["eventAfterTerminal"] = {"description": "endToEnd/stream event stream with one more data event appended after the terminal event. The receipt is the original; the digest over the first three frames still matches. §5.6: events after the terminal event are not covered and their presence is a delivery failure.",
                                             "resourceUrl": e["stream"]["resourceUrl"], "eventStream": e["stream"]["eventStream"] + 'data: {"seq":3,"price":"64003"}\n\n'}
    run("eventAfterTerminal/session", "eventAfterTerminal", "session", (P, P, P, P, F), False, False, {"level": "delivery", "code": "EVENTS_AFTER_TERMINAL"},
        inputs_override={"eventStream": {"$ref": "/fixtures/eventAfterTerminal/eventStream"}, "directory": {"$ref": "/endToEnd/directory"}, "pinnedGovernanceKeys": {"$ref": "/endToEnd/governanceKeys"},
                         "now": {"$ref": "/endToEnd/now"}, "settle": {"$ref": "/endToEnd/settle"}, "requirements": {"$ref": "/endToEnd/requirements"}, "resourceUrl": {"$ref": "/fixtures/eventAfterTerminal/resourceUrl"}, "method": "GET"})

    Path(sys.argv[2]).parent.mkdir(parents=True, exist_ok=True)
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("fixtures:", len(out["fixtures"]), "runs:", len(out["expectedVerdicts"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
