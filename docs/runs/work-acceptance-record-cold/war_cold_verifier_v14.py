#!/usr/bin/env python3
"""war_cold_verifier_v14 — v13 plus the profile 1.4 outcome `tsa_signature` (step 9, in tsa_check.py); nothing else changed.

v13 docstring follows.
war_cold_verifier_v13 — the clean-room verifier of war_cold_verifier.py, moved to draft profile 1.3.

Written 2026-10-19 from README.md of maximusrufus/work-acceptance-record at 270e9fe (profile 1.3, 28 vectors) and
the v1 file (f7d8984, profile 1.2.1). Still not opened: any other verifier. Answer-exposed as v1 was; additionally,
v1 had already been scored 24/28 against these vectors (20, 22, 26, 27 disagreed) before this file was written.

What changed from v1, each tied to a 1.3 ruling:
  step 2  the key is the one named by the SIGNED receipt.key_id; an envelope signature.key_id that differs is
          SIGNATURE_INVALID with no verification. Key rule: canonical encoding (y < p) of a prime-order point, else
          KEY_REJECTED and no signature check (signature_valid false, SIGNATURE_INVALID not added). Applies to the
          named key only; other key-file entries are reported in `key_file_notes`, never in the outcome codes (vector 28).
  step 5  reference time = the EARLIER of issued_utc and the covering record token's genTime; a token's `accuracy`
          widens its time (criteria token: later bound; record token: earlier bound); `ordering` ignored.
  step 8  derived independence: "undeclared" (no producer name and no producer key), "self-checked" (producer key ==
          checker key or producer name == checker name), else "independent"; a stated value that differs from the
          derived one is INDEPENDENCE_INCONSISTENT (vector 20 was the case v1 read as warning-only).
Standard library plus `cryptography` for the Ed25519 equation; JCS, DER/RFC 3161 and the Ed25519 point checks are own.

Usage: python3 -I war_cold_verifier_v13.py <vector.json>
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsa_check import tsa_signature  # noqa: E402

SCHEMA = "trilatic.acceptance-receipt/1.2"
CANON = "JCS-RFC8785"
SUITE = {"digest": "sha-256", "signature": "Ed25519"}
RESULT_VOCAB = {"pass", "fail", "not-evaluated", "error"}
SHA256_OID_HEX = "608648016503040201"

# ------------------------------------------------------------------ JCS (RFC 8785)


def jcs(value) -> bytes:
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
            raise ValueError("float not expected in these records")
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False)
        if isinstance(v, list):
            return "[" + ",".join(ser(x) for x in v) + "]"
        if isinstance(v, dict):
            items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + ser(x) for k, x in items) + "}"
        raise TypeError(type(v).__name__)

    return ser(value).encode("utf-8")


# ------------------------------------------------------------------ DER / RFC 3161


def _tlv(b: bytes, i: int):
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


def _accuracy_seconds(val: bytes) -> float:
    """Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] OPTIONAL, micros [1] OPTIONAL }."""
    total = 0.0
    for tg, v in _children(val):
        n = int.from_bytes(v, "big") if v else 0
        if tg == 0x02:
            total += n
        elif tg == 0x80:
            total += n / 1000.0
        elif tg == 0x81:
            total += n / 1_000_000.0
    return total


def parse_tsr(der: bytes) -> dict:
    """TimeStampResp → {status, imprint_alg_oid, imprint_hex, gen_time, accuracy_s}. Fails closed on shape."""
    tag, resp, _ = _tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a SEQUENCE")
    parts = _children(resp)
    status = _children(parts[0][1])[0][1]
    status_int = int.from_bytes(status, "big") if status else -1
    if len(parts) < 2:
        raise ValueError("no timeStampToken")
    content_info = _children(parts[1][1])
    signed_data = _children(content_info[1][1])[0][1]
    sd = _children(signed_data)
    eci = _children(sd[2][1])
    tst_octets = _children(eci[1][1])[0][1]
    tst_tag, tst, _ = _tlv(tst_octets, 0)
    if tst_tag != 0x30:
        raise ValueError("TSTInfo not a SEQUENCE")
    t = _children(tst)
    imprint = _children(t[2][1])
    alg_oid = _children(imprint[0][1])[0][1]
    digest = imprint[1][1]
    gen_time = None
    accuracy_s = 0.0
    seen_gen = False
    for tg, val in t[4:]:
        if tg == 0x18 and gen_time is None:
            gen_time = val.decode("ascii")
            seen_gen = True
            continue
        if seen_gen and tg == 0x30:  # accuracy follows genTime when present
            accuracy_s = _accuracy_seconds(val)
            break
        if seen_gen and tg in (0x01, 0x02, 0xA0):  # ordering / nonce / tsa — no accuracy
            break
    if gen_time is None:
        raise ValueError("no genTime")
    return {"status": status_int, "imprint_alg_oid": alg_oid.hex(), "imprint_hex": digest.hex(), "gen_time": gen_time,
            "accuracy_s": accuracy_s}


def gen_time_to_dt(s: str) -> datetime:
    main = s.rstrip("Z").split(".")[0]
    return datetime.strptime(main, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)


def iso_to_dt(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


# ------------------------------------------------------------------ Ed25519 key rule (RFC 8032 decoding + order)

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_ID = (0, 1, 1, 0)


def _decode_point(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None  # non-canonical (y >= p)
    y2 = y * y % _P
    u, v = (y2 - 1) % _P, (_D * y2 + 1) % _P
    x2 = u * pow(v, -1, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
        if (x * x - x2) % _P != 0:
            return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(pt, n):
    acc = _ID
    while n:
        if n & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        n >>= 1
    return acc


def _is_identity(pt) -> bool:
    x, y, z, _ = pt
    return x % _P == 0 and (y - z) % _P == 0


def key_rule(pub: bytes) -> tuple[bool, str]:
    """Profile 1.3 step 2: canonical encoding of a prime-order point."""
    pt = _decode_point(pub)
    if pt is None:
        return False, "non-canonical encoding or not on the curve"
    if _is_identity(_mul(pt, 8)):
        return False, "small-order point"
    if not _is_identity(_mul(pt, _L)):
        return False, "mixed-order point"
    return True, ""


# ------------------------------------------------------------------ verification


def recompute_verdict(results: list) -> tuple[str, bool]:
    vocab_ok = all(r.get("result") in RESULT_VOCAB for r in results)
    required = [r for r in results if r.get("required") is True]
    if any(r.get("result") == "fail" for r in required):
        return "fail", vocab_ok
    if any(r.get("result") in ("not-evaluated", "error") for r in required):
        return "incomplete", vocab_ok
    if all(r.get("result") == "pass" for r in required):
        return "pass", vocab_ok
    return "incomplete", vocab_ok


def verify(vector: dict) -> dict:
    inp = vector["inputs"]
    rec_env = inp["receipt"]
    receipt = rec_env["receipt"]
    sig = rec_env.get("signature") or {}
    problems: set[str] = set()
    warnings: set[str] = set()
    out: dict = {}

    # 1. schema / suites
    if receipt.get("schema") != SCHEMA or receipt.get("canonicalization") != CANON or receipt.get("suite") != SUITE:
        return {"refused": True, "reason": "unknown schema, canonicalization or suite"}

    # 2. signature with the key named by the SIGNED receipt.key_id; key rule first
    canonical = jcs(receipt)
    canonical_sha = hashlib.sha256(canonical).hexdigest()
    keys: dict = {}
    notes: list[str] = []
    for k in inp["keys"]["keys"]:
        kid = k.get("key_id")
        if kid in keys:
            notes.append(f"duplicate key_id {kid}")
        keys[kid] = k
    signed_kid = receipt.get("key_id")
    key = keys.get(signed_kid)
    sig_ok = False
    key_rejected = False
    if sig.get("key_id") != signed_kid:
        problems.add("SIGNATURE_INVALID")  # the unsigned envelope cannot choose the key
    elif key is None or key.get("alg") != "Ed25519" or sig.get("alg") != "Ed25519":
        problems.add("SIGNATURE_INVALID")
    else:
        try:
            pub = base64.b64decode(key["public_key_base64"])
        except (ValueError, TypeError):
            pub = b""
        ok, why = key_rule(pub)
        if not ok:
            key_rejected = True
            problems.add("KEY_REJECTED")
            out["key_rejected_reason"] = why
        else:
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(sig["value"]), canonical)
                sig_ok = True
            except (InvalidSignature, ValueError, TypeError):
                sig_ok = False
            if not sig_ok:
                problems.add("SIGNATURE_INVALID")
    out["signature_valid"] = sig_ok
    # other entries of the key file: reported, never an outcome code (vector 28)
    for kid, k in keys.items():
        if kid == signed_kid:
            continue
        try:
            ok, why = key_rule(base64.b64decode(k.get("public_key_base64") or ""))
        except (ValueError, TypeError):
            ok, why = False, "undecodable"
        if not ok:
            notes.append(f"key_id {kid}: {why} (not the signing key; outcome unaffected)")
    if notes:
        out["key_file_notes"] = notes

    # parties / independence (step 8)
    checker = (receipt.get("parties") or {}).get("checker") or {}
    producer = (receipt.get("parties") or {}).get("producer") or {}
    if signed_kid != checker.get("key_id"):
        problems.add("CHECKER_NOT_SIGNER")
    producer_named = bool(producer.get("name")) or producer.get("key_id") is not None
    if not producer_named:
        warnings.add("PRODUCER_UNDECLARED")
    if producer.get("key_id") is not None and producer.get("key_id") == checker.get("key_id"):
        problems.add("KEY_COLLISION")
    looks_self = (producer.get("key_id") is not None and producer.get("key_id") == checker.get("key_id")) or (
        producer.get("name") is not None and producer.get("name") == checker.get("name")
    )
    derived = "undeclared" if not producer_named else ("self-checked" if looks_self else "independent")
    stated_indep = receipt.get("independence")
    if stated_indep == "self-checked":
        warnings.add("SELF_CHECKED")
    if stated_indep != derived:
        problems.add("INDEPENDENCE_INCONSISTENT")
    out["independence"] = stated_indep
    out["independence_derived"] = derived

    # 3. delivered file
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

    # 6. record's own token (needed by 5)
    receipt_time = None
    receipt_acc = 0.0
    if inp.get("receipt_tsr_base64"):
        try:
            rt = parse_tsr(base64.b64decode(inp["receipt_tsr_base64"]))
            if rt["imprint_alg_oid"] == SHA256_OID_HEX and rt["imprint_hex"] == canonical_sha:
                out["receipt_timestamp"] = "imprint_match"
                receipt_time = gen_time_to_dt(rt["gen_time"])
                receipt_acc = rt["accuracy_s"]
            else:
                out["receipt_timestamp"] = "imprint_mismatch"
        except (ValueError, IndexError):
            out["receipt_timestamp"] = "imprint_mismatch"
    else:
        out["receipt_timestamp"] = "none"

    # 5. criteria commitment — reference = earlier of issued_utc and the covering token's genTime (minus its accuracy)
    issued = iso_to_dt(receipt["issued_utc"])
    reference = issued
    if receipt_time is not None:
        reference = min(issued, receipt_time - timedelta(seconds=receipt_acc))
    committed_at = iso_to_dt(criteria["committed_at"]) if criteria.get("committed_at") else None
    commitment_time = None
    commitment_acc = 0.0
    if inp.get("criteria_tsr_base64"):
        try:
            ct = parse_tsr(base64.b64decode(inp["criteria_tsr_base64"]))
            if ct["imprint_alg_oid"] == SHA256_OID_HEX and ct["imprint_hex"] == criteria.get("sha256"):
                commitment_time = gen_time_to_dt(ct["gen_time"])
                commitment_acc = ct["accuracy_s"]
                if committed_at is None or committed_at != commitment_time:
                    problems.add("CRITERIA_TIME_MISMATCH")
            else:
                problems.add("CRITERIA_TIMESTAMP_MISMATCH")
        except (ValueError, IndexError):
            problems.add("CRITERIA_TIMESTAMP_MISMATCH")
    if commitment_time is None:
        commitment_time = committed_at
        warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")
    if commitment_time is not None and commitment_time + timedelta(seconds=commitment_acc) < reference:
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

    # 9. (profile 1.4) time-stamp authority signature, one key per token present; never changes another member
    tsa = {}
    anchors = inp.get("tsa_roots_base64")
    for name, key in (("criteria", "criteria_tsr_base64"), ("receipt", "receipt_tsr_base64")):
        if not inp.get(key):
            continue
        if not anchors:
            tsa[name] = "not_evaluated"
        else:
            tsa[name] = tsa_signature(base64.b64decode(inp[key]), [base64.b64decode(a) for a in anchors])
    if tsa:
        out["tsa_signature"] = tsa

    # 8.
    out["problem_codes"] = sorted(problems)
    out["warning_codes"] = sorted(warnings)
    out["accepted_as_stated"] = sig_ok and not problems
    out["canonical_receipt_sha256"] = canonical_sha
    out["key_rejected"] = key_rejected
    return out


def main() -> int:
    vec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps(verify(vec), indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
