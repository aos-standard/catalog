#!/usr/bin/env python3
"""Each lax variant drops one check of anchor_pointer_check.check; the vectors must catch every one.

A variant that drops check X is modelled as answering `anchored` wherever the real checker stops at X. That is the
answer a lax reader gives when everything after X passes, which holds for every vector here, since each changes one
thing from AP-01.
Usage: python3 -I lax_battery.py <vectors.json>
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anchor_pointer_check import check  # noqa: E402

DROPS = {
    "no-shape-check": {"malformed"},
    "accept-any-mechanism": {"unsupported_mechanism"},
    "skip-set-digest": {"set_digest_mismatch"},
    "skip-proof-sha": {"proof_sha_mismatch"},
    "ignore-proof-file-digest": {"proof_for_other_digest"},
    "pending-counts-as-anchored": {"pending"},
    "ignore-claimed-height": {"height_not_in_proof"},
    "no-root-compare": {"header_unavailable", "root_mismatch"},
}


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    blobs = {k: base64.b64decode(v) for k, v in d["blobs"].items()}
    real = {v["id"]: check(v["pointer"], blobs[v["anchored_bytes"]], blobs[v["proof_bytes"]], v["headers"])
            for v in d["vectors"]}
    caught = 0
    for name, dropped in DROPS.items():
        fails = [v["id"] for v in d["vectors"]
                 if ("anchored" if real[v["id"]] in dropped else real[v["id"]]) != v["expected"]]
        caught += bool(fails)
        print(f"{'caught' if fails else 'MISSED':6} {name:28} by {fails}")
    print(f"{caught}/{len(DROPS)} lax variants caught")
    return 0 if caught == len(DROPS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
