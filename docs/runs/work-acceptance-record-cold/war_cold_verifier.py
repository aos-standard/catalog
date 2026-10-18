#!/usr/bin/env python3
"""war_cold_verifier — a clean-room verifier for the work-acceptance record (draft profile 1.2.1).

Written from README.md of maximusrufus/work-acceptance-record at f7d8984 and the vectors'
`inputs` shape only. Not opened: any other verifier (babyblueviper1's checker, Trilatic's
Python/Node/browser verifiers). Answer-exposed: the vectors' `expected` objects were on screen
while the input shape was being inspected, before this file was written, so this is not a blind
run; it is a second implementation of the README's procedure, frozen (FROZEN.txt) before the first
scored run.

Standard library, plus `cryptography` for the Ed25519 signature check. JCS (RFC 8785) and the
RFC 3161 TimeStampResp parsing are this file's own.

Usage: python3 -I war_cold_verifier.py <vector.json>   → prints the verifier's outcome object
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "trilatic.acceptance-receipt/1.2"
CANON = "JCS-RFC8785"
SUITE = {"digest": "sha-256", "signature": "Ed25519"}
RESULT_VOCAB = {"pass", "fail", "not-evaluated", "error"}

# ------------------------------------------------------------------ JCS (RFC 8785)


def jcs(value) -> bytes:
    """RFC 8785 canonical JSON. Vectors carry only objects, arrays, strings, ints, bools, null."""

    def ser(v) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            raise ValueError("float not expected in these records")  # fail closed
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)  # RFC 8785 §3.2.2.2 escaping matches json.dumps
        if isinstance(v, list):
            return "[" + ",".join(ser(x) for x in v) + "]"
        if isinstance(v, dict):
            # §3.2.3: sort by UTF-16 code units; identical to code-point order for BMP keys
            items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + ser(x) for k, x in items) + "}"
        raise TypeError(type(v).__name__)

    return ser(value).encode("utf-8")


# ------------------------------------------------------------------ DER / RFC 3161


def _tlv(b: bytes, i: int):
    """Return (tag, value_bytes, next_index) for the DER element at b[i:]."""
    tag = b[i]
    ln = b[i + 1]
    j = i + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[j : j + n], "big")
        j += n
    return tag, b[j : j + ln], j + ln


def _children(b: bytes):
    out, i = [], 0
    while i < len(b):
        tag, val, i = _tlv(b, i)
        out.append((tag, val))
    return out


def parse_tsr(der: bytes) -> dict:
    """TimeStampResp → {status, imprint_alg_oid, imprint_hex, gen_time}. Fails closed on shape."""
    tag, resp, _ = _tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a SEQUENCE")
    parts = _children(resp)
    status_seq = parts[0][1]
    status = _children(status_seq)[0][1]  # INTEGER
    status_int = int.from_bytes(status, "big") if status else -1
    if len(parts) < 2:
        raise ValueError("no timeStampToken")
    content_info = _children(parts[1][1])  # [OID id-signedData, [0] EXPLICIT SignedData]
    signed_data = _children(content_info[1][1])[0][1]  # SEQUENCE SignedData
    sd = _children(signed_data)  # version, digestAlgorithms, encapContentInfo, ...
    eci = _children(sd[2][1])  # [OID id-ct-TSTInfo, [0] EXPLICIT OCTET STRING]
    tst_octets = _children(eci[1][1])[0][1]  # OCTET STRING → TSTInfo DER
    tst_tag, tst, _ = _tlv(tst_octets, 0)
    if tst_tag != 0x30:
        raise ValueError("TSTInfo not a SEQUENCE")
    t = _children(tst)  # version, policy, messageImprint, serialNumber, genTime, ...
    imprint = _children(t[2][1])  # [AlgorithmIdentifier, OCTET STRING]
    alg_oid = _children(imprint[0][1])[0][1]
    digest = imprint[1][1]
    gen_time = None
    for tg, val in t[4:]:
        if tg == 0x18:  # GeneralizedTime
            gen_time = val.decode("ascii")
            break
    if gen_time is None:
        raise ValueError("no genTime")
    return {"status": status_int, "imprint_alg_oid": alg_oid.hex(), "imprint_hex": digest.hex(), "gen_time": gen_time}


SHA256_OID_HEX = "608648016503040201"


def gen_time_to_dt(s: str) -> datetime:
    # GeneralizedTime YYYYMMDDHHMMSS[.f]Z
    main = s.rstrip("Z").split(".")[0]
    return datetime.strptime(main, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def iso_to_dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


# ------------------------------------------------------------------ verification


def recompute_verdict(results: list) -> tuple[str, bool]:
    """Property 4. Returns (verdict, vocabulary_ok)."""
    vocab_ok = all(r.get("result") in RESULT_VOCAB for r in results)
    required = [r for r in results if r.get("required") is True]
    if any(r.get("result") == "fail" for r in required):
        return "fail", vocab_ok
    if any(r.get("result") in ("not-evaluated", "error") for r in required):
        return "incomplete", vocab_ok
    if all(r.get("result") == "pass" for r in required):
        return "pass", vocab_ok
    return "incomplete", vocab_ok  # unknown token among required → never pass


def verify(vector: dict) -> dict:
    inp = vector["inputs"]
    rec_env = inp["receipt"]
    receipt = rec_env["receipt"]
    sig = rec_env.get("signature") or {}
    problems: set[str] = set()
    warnings: set[str] = set()
    out: dict = {}

    # 1. schema / suites — refuse unknown
    if receipt.get("schema") != SCHEMA or receipt.get("canonicalization") != CANON or receipt.get("suite") != SUITE:
        return {"refused": "unknown schema, canonicalization or suite"}

    # 2. signature over canonical receipt
    canonical = jcs(receipt)
    canonical_sha = hashlib.sha256(canonical).hexdigest()
    keys = {k["key_id"]: k for k in inp["keys"]["keys"]}
    key = keys.get(sig.get("key_id"))
    sig_ok = False
    if key is not None and key.get("alg") == "Ed25519" and sig.get("alg") == "Ed25519":
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key["public_key_base64"])).verify(
                base64.b64decode(sig["value"]), canonical
            )
            sig_ok = True
        except (InvalidSignature, ValueError):
            sig_ok = False
    if not sig_ok:
        problems.add("SIGNATURE_INVALID")
    out["signature_valid"] = sig_ok

    # parties / independence
    checker = (receipt.get("parties") or {}).get("checker") or {}
    producer = (receipt.get("parties") or {}).get("producer") or {}
    if sig.get("key_id") != checker.get("key_id"):
        problems.add("CHECKER_NOT_SIGNER")
    if not producer or not producer.get("name"):
        warnings.add("PRODUCER_UNDECLARED")
    if producer.get("key_id") is not None and producer.get("key_id") == checker.get("key_id"):
        problems.add("KEY_COLLISION")
    stated_indep = receipt.get("independence")
    looks_self = (producer.get("key_id") is not None and producer.get("key_id") == checker.get("key_id")) or (
        producer.get("name") is not None and producer.get("name") == checker.get("name")
    )
    if stated_indep == "self-checked":
        warnings.add("SELF_CHECKED")
    elif stated_indep == "independent":
        if looks_self:
            problems.add("INDEPENDENCE_INCONSISTENT")
    else:
        problems.add("INDEPENDENCE_INCONSISTENT")
    out["independence"] = stated_indep

    # 3. delivered file (optional)
    if inp.get("delivered_file_base64"):
        delivered = base64.b64decode(inp["delivered_file_base64"])
        out["file_hash"] = "match" if hashlib.sha256(delivered).hexdigest() == receipt["files"]["remediated"]["sha256"] else "mismatch"
        if out["file_hash"] == "mismatch":
            problems.add("FILE_HASH_MISMATCH")

    # 4. criteria document
    criteria = receipt.get("criteria") or {}
    if inp.get("criteria_file_base64"):
        cbytes = base64.b64decode(inp["criteria_file_base64"])
        if hashlib.sha256(cbytes).hexdigest() == criteria.get("sha256"):
            out["criteria_hash"] = "match"
            try:
                cdoc = json.loads(cbytes.decode("utf-8"))
                want = {(c["id"], bool(c.get("required"))) for c in cdoc.get("criteria", [])}
                have = {(r["id"], bool(r.get("required"))) for r in receipt.get("results", [])}
                if want != have:
                    problems.add("CRITERIA_RESULTS_MISMATCH")
            except (ValueError, KeyError, TypeError):
                problems.add("CRITERIA_RESULTS_MISMATCH")
        else:
            out["criteria_hash"] = "mismatch"
            problems.add("CRITERIA_HASH_MISMATCH")

    # 6. (needed by 5) record's own token
    receipt_time = None  # reference time candidate from the record's token
    if inp.get("receipt_tsr_base64"):
        try:
            rt = parse_tsr(base64.b64decode(inp["receipt_tsr_base64"]))
            if rt["imprint_alg_oid"] == SHA256_OID_HEX and rt["imprint_hex"] == canonical_sha:
                out["receipt_timestamp"] = "imprint_match"
                receipt_time = gen_time_to_dt(rt["gen_time"])
            else:
                out["receipt_timestamp"] = "imprint_mismatch"  # never used as evidence of time
        except (ValueError, IndexError):
            out["receipt_timestamp"] = "imprint_mismatch"
    else:
        out["receipt_timestamp"] = "none"

    # 5. criteria commitment
    reference = receipt_time if receipt_time is not None else iso_to_dt(receipt["issued_utc"])
    committed_at = iso_to_dt(criteria["committed_at"]) if criteria.get("committed_at") else None
    commitment_time = None
    if inp.get("criteria_tsr_base64"):
        try:
            ct = parse_tsr(base64.b64decode(inp["criteria_tsr_base64"]))
            if ct["imprint_alg_oid"] == SHA256_OID_HEX and ct["imprint_hex"] == criteria.get("sha256"):
                commitment_time = gen_time_to_dt(ct["gen_time"])
                if committed_at is None or committed_at != commitment_time:
                    problems.add("CRITERIA_TIME_MISMATCH")
            else:
                problems.add("CRITERIA_TIMESTAMP_MISMATCH")
        except (ValueError, IndexError):
            problems.add("CRITERIA_TIMESTAMP_MISMATCH")
    if commitment_time is None:
        commitment_time = committed_at
        warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")
    if commitment_time is not None and commitment_time < reference:
        out["criteria_committed_before_check"] = "yes"
    else:
        out["criteria_committed_before_check"] = "no"
        problems.add("CRITERIA_COMMITTED_AFTER_CHECK")

    # 7. verdict
    recomputed, vocab_ok = recompute_verdict(receipt.get("results", []))
    if not vocab_ok:
        problems.add("RESULT_VOCABULARY")
    out["verdict_recomputed"] = recomputed
    out["verdict_stated"] = receipt.get("verdict")
    if recomputed != receipt.get("verdict"):
        problems.add("VERDICT_MISMATCH")

    # 8.
    out["problem_codes"] = sorted(problems)
    out["warning_codes"] = sorted(warnings)
    out["accepted_as_stated"] = sig_ok and not problems
    out["canonical_receipt_sha256"] = canonical_sha
    return out


def main() -> int:
    vec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps(verify(vec), indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
