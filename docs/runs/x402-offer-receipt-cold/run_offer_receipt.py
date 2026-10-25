#!/usr/bin/env python3
"""Score x402_offer_receipt.py on the JWS vectors (PR #3207) and the EIP-712 vectors (issue #3533).

The keys come from each file's `signing` block (an input: the verifier is told which key is authorized).
Agreement is the files' own rule: accept every `valid` entry, reject every `invalid` one. The stage that
rejected is reported beside `reject_at` and is not scored (both files say an earlier or different layer is
conformant). Also compared, not scored: the decoded JWS payload against the vector's `payload`, the EIP-712
struct hash against `structHash`, and the domain separators and type hashes against `constants`.

Usage: python3 -I -B run_offer_receipt.py <jws.json> <eip712.json> <now unix seconds> <out.json>
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import x402_offer_receipt as v  # noqa: E402


def main() -> int:
    jws_raw, eip_raw = Path(sys.argv[1]).read_bytes(), Path(sys.argv[2]).read_bytes()
    now = int(sys.argv[3])
    jws, eip = json.loads(jws_raw), json.loads(eip_raw)
    rows = []

    sg = jws["signing"]
    keys = {sg["kid"]: {"alg": "EdDSA", "public_key": bytes.fromhex(sg["public_key_hex"]), "authorized": True}}
    for group in ("valid", "invalid"):
        for vec in jws[group]:
            kind = "receipt" if vec["name"].startswith("receipt") else "offer"
            got = v.verify_jws(kind, vec["jws"], keys, now)
            row = {"set": "jws", "id": vec["name"], "kind": kind, "expect": vec["expect"],
                   "reject_at": vec.get("reject_at"), "got_accept": got["accept"], "got_stage": got["stage"],
                   "detail": got["detail"], "expired": got.get("expired")}
            row["agree"] = got["accept"] == (vec["expect"] == "accept")
            if got["accept"] and "payload" in vec:
                row["payload_matches_vector"] = got["payload"] == vec["payload"]
            rows.append(row)

    authorized = {eip["signing"]["address"].lower()}
    for group in ("valid", "invalid"):
        for vec in eip[group]:
            got = v.verify_eip712(vec["kind"], vec["artifact"], authorized, now)
            row = {"set": "eip712", "id": vec["name"], "kind": vec["kind"], "expect": vec["expect"],
                   "reject_at": vec.get("reject_at"), "got_accept": got["accept"], "got_stage": got["stage"],
                   "detail": got["detail"], "expired": got.get("expired")}
            row["agree"] = got["accept"] == (vec["expect"] == "accept")
            if "structHash" in vec and "struct_hash" in got:
                row["struct_hash_matches_vector"] = got["struct_hash"] == vec["structHash"].lower()
            rows.append(row)

    c = eip.get("constants", {})
    constants = {}
    for kind in ("offer", "receipt"):
        constants[f"domainSeparator.{kind}"] = ("0x" + v.domain_separator(kind).hex()) == c.get("domainSeparator", {}).get(kind, "").lower()
        th = c.get("typeHash", {}).get(kind) or c.get("typeHash", {}).get(v.PRIMARY[kind])
        constants[f"typeHash.{kind}"] = ("0x" + v.type_hash(kind).hex()) == (th or "").lower()

    for r in rows:
        extra = {k: r[k] for k in ("payload_matches_vector", "struct_hash_matches_vector", "expired") if r.get(k) is not None}
        print(f"{'agree' if r['agree'] else 'DIFFER':6} {r['set']:6} {r['id']:44} expect={r['expect']:6} "
              f"reject_at={str(r['reject_at']):13} got={'accept' if r['got_accept'] else 'reject'}"
              f"@{r['got_stage']} {r['detail']} {extra if extra else ''}")
    for k, ok in constants.items():
        print(f"constant {k}: {'match' if ok else 'DIFFER'}")
    agree = sum(r["agree"] for r in rows)
    print(f"{agree}/{len(rows)} agree on accept/reject "
          f"(jws {sum(r['agree'] for r in rows if r['set']=='jws')}/{sum(r['set']=='jws' for r in rows)}, "
          f"eip712 {sum(r['agree'] for r in rows if r['set']=='eip712')}/{sum(r['set']=='eip712' for r in rows)})")
    out = {"jws_sha256": hashlib.sha256(jws_raw).hexdigest(), "eip712_sha256": hashlib.sha256(eip_raw).hexdigest(),
           "now": now, "agree": agree, "total": len(rows), "constants": constants, "rows": rows}
    Path(sys.argv[4]).write_text(json.dumps(out, indent=1) + "\n")
    return 0 if agree == len(rows) and all(constants.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
