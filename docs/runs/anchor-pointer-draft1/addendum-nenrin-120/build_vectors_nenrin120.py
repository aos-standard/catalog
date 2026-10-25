#!/usr/bin/env python3
"""Build AP-23 and AP-24 for anchor-pointer draft 1 from NENRIN's JIDEC ledger entry 120, carried under CC0 with
the owner's permission (aeoess/agent-governance-vocabulary#217, 2026-10-25). The proof reaches blocks 972141 and
972145; a pointer may claim either, and the reader must report 972141 as `earliest_height` both times.
Usage: python3 -I -B build_vectors_nenrin120.py <record120.raw> <record120.ots> <out vectors.json>
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

# Merkle roots read from blockstream.info and mempool.space on 2026-10-25; the two agree for both blocks.
ROOTS = {972141: "a2669dac9d1dcda64d589cf47a01dabda7b7795947ade803a80bf14225fd6550",
         972145: "48f80cfdacc9e97b2798e4988111b1a478ad7c8439bfbf6cc426f4827ada81f0"}
LOC = "https://ledger.horizonshield.dev/ledger/120"


def main() -> int:
    raw, ots = Path(sys.argv[1]).read_bytes(), Path(sys.argv[2]).read_bytes()
    sha = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731

    def vec(id_, height):
        return {"id": id_, "note": f"NENRIN JIDEC entry 120, claimed at {height}; the proof also reaches the other block",
                "pointer": {"anchor_pointer": "1", "anchored_digest": {"alg": "sha-256", "hex": sha(raw)},
                            "anchored_set": {"locator": LOC + "?format=raw"}, "mechanism": "opentimestamps",
                            "proof": {"locator": LOC + "/ots", "sha256": sha(ots)},
                            "claimed": {"chain": "bitcoin", "height": height}},
                "anchored_bytes": "nenrin_120", "proof_bytes": "nenrin_120_ots", "headers": {str(height): ROOTS[height]},
                "expected": {"result": "anchored", "earliest_height": 972141, "set_checked": True}}

    out = {"anchor_pointer_vectors": "draft 1, addendum", "license": "CC0-1.0",
           "sources": {"AP-23..AP-24": "NENRIN (ogasurfproject-jpg) JIDEC ledger entry 120, CC0 by its owner on aeoess/agent-governance-vocabulary#217"},
           "blobs": {"nenrin_120": base64.b64encode(raw).decode(), "nenrin_120_ots": base64.b64encode(ots).decode()},
           "blob_sha256": {"nenrin_120": sha(raw), "nenrin_120_ots": sha(ots)},
           "vectors": [vec("AP-23", 972141), vec("AP-24", 972145)]}
    Path(sys.argv[3]).write_text(json.dumps(out, indent=1) + "\n")
    print("2 vectors", sha(raw)[:12], sha(ots)[:12])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
