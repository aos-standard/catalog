#!/usr/bin/env python3
"""acceptance_cold_reader v2 — v1 plus README sentences 1–8 (2026-10-12).

v1 (acceptance_cold_reader.py, hash frozen) was written from the text as it
stood at d750291. This file is v1 with the eight sentences the README adopted
on 2026-10-12 applied, each marked `# S<n>`. Nothing else changed. The
reference checker, actaseal's and omega's code were still not opened; the
small-order test is this file's own Ed25519 point arithmetic.

Usage: python3 -I acceptance_cold_reader_v2.py <case.json>
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone

HEX64 = re.compile(r"^[0-9a-f]{64}$")
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")          # S5
B64U = re.compile(r"^[A-Za-z0-9_-]+$")                                       # S2 (no padding, url alphabet)
VERSION = "acceptance-record-v0"                                             # S3
DISPOSITIONS_SIGNED = ("accepted", "rejected", "disputed")
REQUIRED = ("acceptance_version", "accepted_at", "accepted_record_sha256",
            "confirming_party", "disposition", "outcome_sha256", "terms_sha256")

# ---------------------------------------------------------------- Ed25519 points (S4)
_P = 2**255 - 19
_D = (-121665 * pow(121666, -1, _P)) % _P
_ID = (0, 1)   # neutral element (x=0, y=1)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _decode_point(b: bytes):
    """RFC 8032 §5.1.3. Returns (x, y) or None when not a point."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    y2 = y * y % _P
    u, v = (y2 - 1) % _P, (_D * y2 + 1) % _P
    x2 = u * _inv(v) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if (x * x - x2) % _P:
        return None
    if x == 0 and sign:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x, y


def _add(p, q):
    x1, y1 = p
    x2, y2 = q
    k = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k) % _P
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k) % _P
    return x3, y3


def is_small_order(b: bytes) -> bool:
    """True when the encoding is not a point, or 8*P is the neutral element."""
    pt = _decode_point(b)
    if pt is None:
        return True
    for _ in range(3):           # 8 = 2^3
        pt = _add(pt, pt)
    return pt == _ID


# ---------------------------------------------------------------- helpers
def b64u_strict(s) -> bytes | None:                                          # S2
    if not isinstance(s, str) or not B64U.match(s):
        return None
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        return None


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s[:-1] + "+00:00")


def ed25519_ok(x_raw: bytes, msg: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(x_raw).verify(sig, msg)
        return True
    except Exception:
        return False


def keys_by_kid(trust: dict | None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for k in (trust or {}).get("keys", []) or []:
        if isinstance(k, dict) and isinstance(k.get("kid"), str) and k.get("kty") == "OKP" and k.get("crv") == "Ed25519":
            out.setdefault(k["kid"], k)                                       # S8: first Ed25519 entry wins
    return out


def evaluate(case: dict) -> dict:
    record = case.get("accepted_record") or {}
    acc = case.get("acceptance")
    complete = case.get("trust_material_complete") is True                   # S8: only JSON true
    out = {"result": None, "conditions": [], "disposition": None, "key_step": None, "exit": None}

    if not acc:
        out.update(result="no_record", disposition="not_responded", exit=2)
        return out

    def malformed(code: str, step=None):
        out.update(result="malformed", conditions=[code], exit=1)
        if step:
            out["key_step"] = step
        return out

    # --- envelope and header, before the key step (S2, S6) --------------
    if not isinstance(acc, dict):
        return malformed("acceptance_member_invalid")
    prot_b, pay_b, sig = (b64u_strict(acc.get(k)) for k in ("protected", "payload", "signature"))
    if prot_b is None or pay_b is None or sig is None:
        return malformed("acceptance_member_invalid")
    try:
        protected = json.loads(prot_b)
    except Exception:
        return malformed("acceptance_member_invalid")
    if not isinstance(protected, dict) or protected.get("alg") != "EdDSA" or not isinstance(protected.get("kid"), str):
        return malformed("acceptance_member_invalid")                        # S6
    kid = protected["kid"]
    signing_input = (acc["protected"] + "." + acc["payload"]).encode("ascii")

    # --- key step (§5.4.2, S4) ------------------------------------------
    keys = keys_by_kid(case.get("trust_material"))
    key = keys.get(kid)
    key_raw = b64u_strict(key.get("x")) if key else None
    if key is None or key_raw is None or is_small_order(key_raw):            # S4: small-order key is no key
        out.update(result="key_unresolved", key_step="key_unresolved", exit=2)
        if complete:
            out["policy_refusal"] = True
        return out
    if len(sig) != 64 or is_small_order(sig[:32]) or not ed25519_ok(key_raw, signing_input, sig):   # S4: small-order R
        return malformed("signature_invalid", "signature_invalid")
    out["key_step"] = "key_resolved"

    # --- payload, after the key step (S2) --------------------------------
    try:
        payload = json.loads(pay_b)
    except Exception:
        payload = None
    if not isinstance(payload, dict):
        return malformed("acceptance_member_invalid")

    conds: set[str] = set()
    well_typed: dict[str, bool] = {}
    for m in REQUIRED:
        v = payload.get(m)
        ok = isinstance(v, str) and v != ""
        if ok and m.endswith("_sha256"):
            ok = bool(HEX64.match(v))
        if ok and m == "disposition":
            ok = v in DISPOSITIONS_SIGNED
        if ok and m == "acceptance_version":
            ok = v == VERSION                                                 # S3
        if ok and m == "accepted_at":
            ok = bool(TS.match(v))                                           # S5
        well_typed[m] = ok
    # S1: members beyond the seven are ignored (nothing to do)
    confirming = payload.get("confirming_party")
    if confirming is None or confirming == "":                               # S7: byte-exact, not trimmed
        conds.add("confirming_party_absent")
        well_typed["confirming_party"] = True
    if any(not ok for ok in well_typed.values()):
        conds.add("acceptance_member_invalid")

    issuer = record.get("issuer")
    issuer_kid = record.get("issuer_kid")
    issuer_key = keys.get(issuer_kid) if isinstance(issuer_kid, str) else None
    delegation = case.get("delegation") or {}
    if (kid == issuer_kid
            or (issuer_key is not None and issuer_key.get("x") == key.get("x"))
            or (isinstance(confirming, str) and confirming == issuer)
            or (isinstance(issuer, str) and kid in (delegation.get(issuer) or []))):
        conds.add("acceptance_signer_is_issuer")
    if well_typed["terms_sha256"] and payload["terms_sha256"] != record.get("terms_sha256"):
        conds.add("acceptance_terms_digest_mismatch")
    if well_typed["outcome_sha256"] and payload["outcome_sha256"] != record.get("outcome_sha256"):
        conds.add("acceptance_outcome_digest_mismatch")
    if well_typed["accepted_record_sha256"] and payload["accepted_record_sha256"] != hashlib.sha256(jcs(record)).hexdigest():
        conds.add("acceptance_record_digest_mismatch")
    outcome_at = record.get("outcome_at")
    if not (isinstance(outcome_at, str) and TS.match(outcome_at)):          # S5 applies to the record too
        conds.add("acceptance_member_invalid")
    elif well_typed["accepted_at"] and parse_ts(payload["accepted_at"]) < parse_ts(outcome_at):
        conds.add("acceptance_precedes_outcome")

    if conds:
        out.update(result="malformed", conditions=sorted(conds), exit=1)
        return out
    if kid not in (delegation.get(confirming) or []):
        out.update(result="unknown", conditions=["acceptance_authority_unresolved"],
                   disposition=payload["disposition"], exit=2)
        return out
    out.update(result="verified", disposition=payload["disposition"], exit=0)
    return out


if __name__ == "__main__":
    print(json.dumps(evaluate(json.load(open(sys.argv[1], encoding="utf-8"))), indent=1, sort_keys=True))
