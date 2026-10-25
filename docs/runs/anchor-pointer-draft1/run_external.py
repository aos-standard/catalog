#!/usr/bin/env python3
"""Run the draft 1 reader on other projects' published vectors, without copying them here.

  nenrin   ogasurfproject-jpg/horizon-shield ea658bd, workers/hs-ledger/nenrin/anchor-pointer-draft0/vectors.json
           (draft 0 pointers). Reports earliest_height, which is the point of entry 120.
  evm      giskard09/argentum-core 63711d8, examples/conformance/anchor-pointer-evm-log-v1/vectors.json. Each
           `input` is rewritten as a draft 1 evm-log pointer (the digest without 0x, lowercased); live RPC.

Usage: python3 -I -B run_external.py nenrin|evm <vectors.json> <out.json>
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anchor_pointer_check_d1 import check  # noqa: E402


def evm_pointer(inp: dict) -> dict:
    p = {"anchor_pointer": "1", "mechanism": "evm-log",
         "anchored_digest": {"alg": "sha-256", "hex": str(inp.get("anchored_digest", "")).lower().removeprefix("0x")},
         "claimed": {k: inp[k] for k in ("chain", "contract", "tx", "log_index", "height") if k in inp}}
    if "proof" in inp:
        p["proof"] = inp["proof"]
    return p


def main() -> int:
    kind, src, dst = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    raw = src.read_bytes()
    d = json.loads(raw)
    rows = []
    if kind == "nenrin":
        blobs = {k: base64.b64decode(v) for k, v in d["blobs"].items()}
        for v in d["vectors"]:
            got = check(v["pointer"], blobs[v["anchored_bytes"]], blobs[v["proof_bytes"]], v["headers"])
            ok = got["result"] == v["expected"]
            rows.append({"id": v["id"], "expected": v["expected"], "got": got, "agree": ok})
    else:
        for v in d["vectors"]:
            got = check(evm_pointer(v["input"]))
            ok = (got["result"] == "anchored") == (v["expected"] == "PASS")
            rows.append({"id": v["id"], "expected": v["expected"], "their_mode": v.get("failure_mode"), "got": got, "agree": ok})
    for r in rows:
        print(f"{'agree' if r['agree'] else 'DIFFER':6} {r['id']:56} expected={r['expected']} got={json.dumps(r['got'], sort_keys=True)}")
    agree = sum(r["agree"] for r in rows)
    print(f"{agree}/{len(rows)}  (source sha256 {hashlib.sha256(raw).hexdigest()})")
    dst.write_text(json.dumps({"source_sha256": hashlib.sha256(raw).hexdigest(), "agree": agree, "total": len(rows), "rows": rows}, indent=1) + "\n")
    return 0 if agree == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
