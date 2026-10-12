#!/usr/bin/env python3
"""Third, independent reader for the acceptance-record conditions.

Written from: Shodai's condition table (x402-foundation/tsc#4, 2026-10-04),
draft-krausz-verification-state-03 §5.3.2 / §5.4.1(h) / §5.4.2, and the prose
of examples/acceptance-record-cold/README.md (result tokens, evaluation order,
readings A1–A8). The reference checker, its Ed25519 module, build_vectors.py,
run_vectors.py and actaseal's checker.py were not opened (NOT_OPENED.txt).

Ed25519 verification uses `cryptography` (not re-derived from RFC 8032).
Everything else is the standard library.

Usage: python3 -I acceptance_cold_reader.py <case.json>   (one case object)
       or import and call evaluate(case) -> dict
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone

HEX64 = re.compile(r"^[0-9a-f]{64}$")
DISPOSITIONS_SIGNED = ("accepted", "rejected", "disputed")
REQUIRED = ("acceptance_version", "accepted_at", "accepted_record_sha256",
            "confirming_party", "disposition", "outcome_sha256", "terms_sha256")


def b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jcs(obj) -> bytes:
    # RFC 8785 for the value shapes that appear here (strings, objects, arrays).
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_ts(s: str) -> datetime:
    t = s[:-1] + "+00:00" if s.endswith("Z") else s
    d = datetime.fromisoformat(t)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def ed25519_ok(x_b64u: str, msg: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(b64u(x_b64u)).verify(sig, msg)
        return True
    except Exception:
        return False


def keys_by_kid(trust: dict | None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for k in (trust or {}).get("keys", []) or []:
        if isinstance(k, dict) and isinstance(k.get("kid"), str):
            out.setdefault(k["kid"], k)   # first wins; duplicates are a probe, not a rule
    return out


def evaluate(case: dict) -> dict:
    record = case.get("accepted_record") or {}
    acc = case.get("acceptance")
    complete = case.get("trust_material_complete") is True   # omitted = not complete (§5.4.2)
    out = {"result": None, "conditions": [], "disposition": None, "key_step": None, "exit": None}

    # --- no record ------------------------------------------------------
    if not acc:
        out.update(result="no_record", disposition="not_responded", exit=2)
        return out

    # --- key step (§5.4.2) runs first and stops on its own outcomes ------
    try:
        protected = json.loads(b64u(acc["protected"]))
        kid = protected.get("kid")
        sig = b64u(acc["signature"])
        signing_input = (acc["protected"] + "." + acc["payload"]).encode("ascii")
    except Exception:
        out.update(result="malformed", conditions=["acceptance_member_invalid"], exit=1)
        return out
    keys = keys_by_kid(case.get("trust_material"))
    key = keys.get(kid) if isinstance(kid, str) else None
    if key is None:
        out.update(result="key_unresolved", key_step="key_unresolved", exit=2)
        if complete:
            out["policy_refusal"] = True
        return out
    if not ed25519_ok(key.get("x", ""), signing_input, sig):
        out.update(result="malformed", conditions=["signature_invalid"], key_step="signature_invalid", exit=1)
        return out
    out["key_step"] = "key_resolved"

    # --- payload and member typing ---------------------------------------
    try:
        payload = json.loads(b64u(acc["payload"]))
        assert isinstance(payload, dict)
    except Exception:
        out.update(result="malformed", conditions=["acceptance_member_invalid"], exit=1)
        return out
    conds: set[str] = set()
    well_typed: dict[str, bool] = {}
    for m in REQUIRED:
        v = payload.get(m)
        ok = isinstance(v, str) and v != ""
        if ok and m.endswith("_sha256"):
            ok = bool(HEX64.match(v))          # -03 §5.3.2 rule applied to *_sha256 (README)
        if ok and m == "disposition":
            ok = v in DISPOSITIONS_SIGNED      # A2: a signed not_responded contradicts itself
        well_typed[m] = ok
    confirming = payload.get("confirming_party")
    if confirming is None or (isinstance(confirming, str) and confirming == ""):
        conds.add("confirming_party_absent")
        well_typed["confirming_party"] = True   # its own condition, not member_invalid
    if any(not ok for m, ok in well_typed.items()):
        conds.add("acceptance_member_invalid")

    # --- the six conditions (report-all, dependent mismatches suppressed) --
    issuer = record.get("issuer")
    issuer_kid = record.get("issuer_kid")
    issuer_key = keys.get(issuer_kid) if isinstance(issuer_kid, str) else None
    delegation = case.get("delegation") or {}
    signer_is_issuer = (
        kid == issuer_kid
        or (issuer_key is not None and issuer_key.get("x") == key.get("x"))
        or (isinstance(confirming, str) and confirming == issuer)
        or (isinstance(issuer, str) and kid in (delegation.get(issuer) or []))
    )
    if signer_is_issuer:
        conds.add("acceptance_signer_is_issuer")
    if well_typed["terms_sha256"] and payload["terms_sha256"] != record.get("terms_sha256"):
        conds.add("acceptance_terms_digest_mismatch")
    if well_typed["outcome_sha256"] and payload["outcome_sha256"] != record.get("outcome_sha256"):
        conds.add("acceptance_outcome_digest_mismatch")
    if well_typed["accepted_record_sha256"]:
        if payload["accepted_record_sha256"] != hashlib.sha256(jcs(record)).hexdigest():
            conds.add("acceptance_record_digest_mismatch")
    if well_typed["accepted_at"]:
        try:
            if parse_ts(payload["accepted_at"]) < parse_ts(record["outcome_at"]):   # strict (A7)
                conds.add("acceptance_precedes_outcome")
        except Exception:
            conds.add("acceptance_member_invalid")

    if conds:
        out.update(result="malformed", conditions=sorted(conds), exit=1)
        return out

    # --- authority, only when nothing is malformed ------------------------
    if kid not in (delegation.get(confirming) or []):
        out.update(result="unknown", conditions=["acceptance_authority_unresolved"],
                   disposition=payload["disposition"], exit=2)
        return out
    out.update(result="verified", disposition=payload["disposition"], exit=0)
    return out


if __name__ == "__main__":
    case = json.load(open(sys.argv[1], encoding="utf-8"))
    print(json.dumps(evaluate(case), indent=1, sort_keys=True))
