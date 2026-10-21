#!/usr/bin/env python3
"""Build a probe for the claim (tsc#4, 2026-10-21T10:29Z) that an imprint can be matched outside the signed TSTInfo.

Start from vector 31 (live FreeTSA tokens). The criteria token is replaced by the record's token — a genuine FreeTSA
token, but over the canonical receipt, not over the criteria — and its unsigned PKIStatusInfo gets a statusString whose
bytes are `AlgorithmIdentifier(sha-256) || OCTET STRING(criteria.sha256) || GeneralizedTime(criteria.committed_at)`.
The signed TSTInfo still states the receipt's imprint. Nothing signed is changed.

Expected by the 1.4 text (steps 5, 9): the criteria token's imprint is not criteria.sha256 ⇒ CRITERIA_TIMESTAMP_MISMATCH,
fallback to committed_at with CRITERIA_COMMITMENT_UNVERIFIED; tsa_signature.criteria is `verified` (the authority's
signature over its own TSTInfo is genuine), which is exactly why the imprint must be read from that TSTInfo.

Usage: python3 build_vector_status_imprint.py <vectors dir> <out.json>
"""
from __future__ import annotations

import base64
import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def hdr(b: bytes, i: int):
    ln = b[i + 1]
    j = i + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[j:j + n], "big")
        j += n
    return j, j + ln


def main() -> int:
    vdir, out = Path(sys.argv[1]), Path(sys.argv[2])
    v = json.loads((vdir / "31-tsa-freetsa-verified.json").read_text())
    rec = v["inputs"]["receipt"]["receipt"]
    crit_sha = bytes.fromhex(rec["criteria"]["sha256"])
    t = datetime.fromisoformat(rec["criteria"]["committed_at"].replace("Z", "+00:00")).astimezone(timezone.utc)
    gentime = t.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    tsr = base64.b64decode(v["inputs"]["receipt_tsr_base64"])
    cs, ce = hdr(tsr, 0)
    body = tsr[cs:ce]
    ss, se = hdr(body, 0)                      # PKIStatusInfo
    status_seq_content = body[ss:se]
    token = body[se:]
    alg = tlv(0x30, tlv(0x06, bytes.fromhex("608648016503040201")) + b"\x05\x00")
    pattern = alg + tlv(0x04, crit_sha) + tlv(0x18, gentime)
    free_text = tlv(0x30, tlv(0x0C, pattern))  # PKIFreeText ::= SEQUENCE OF UTF8String
    new_status = tlv(0x30, status_seq_content + free_text)
    forged = tlv(0x30, new_status + token)
    p = copy.deepcopy(v)
    p["vector"] = "probe-status-string-imprint"
    p["title"] = "Imprint pattern in the unsigned PKIStatusInfo; the signed TSTInfo covers other bytes"
    p["description"] = (__doc__.split("\n\n")[1]).replace("\n", " ")
    p["contributed_by"] = "aos-standard/catalog (CC0), probe for the claim at x402-foundation/tsc#4 comment 6313776392"
    p["inputs"]["criteria_tsr_base64"] = base64.b64encode(forged).decode()
    p["expected"] = dict(v["expected"])
    p["expected"]["problem_codes"] = ["CRITERIA_TIMESTAMP_MISMATCH"]
    p["expected"]["warning_codes"] = ["CRITERIA_COMMITMENT_UNVERIFIED"]
    p["expected"]["tsa_signature"] = {"criteria": "verified", "receipt": "verified"}
    out.write_text(json.dumps(p, indent=1, sort_keys=True) + "\n")
    print("forged criteria token", len(forged), "bytes; pattern found at", forged.find(crit_sha), "; token starts at", forged.find(token))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
