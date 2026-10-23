#!/usr/bin/env python3
"""Build anchor-pointer draft 0 vectors from one real anchor (aos-standard/catalog, 2026-10 manifest).

Every negative vector changes one thing from AP-01, and its `expected` is the result that change is built to give,
fixed here by construction (not by running the checker).
Usage: python3 -I build_vectors.py <MANIFEST.txt> <MANIFEST.txt.ots> <MANIFEST.txt.upgraded.ots> <out vectors.json>
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

HEIGHT = 972227
# Block 972227's merkle root as explorers print it; checked against blockstream.info and mempool.space on 2026-10-24.
ROOT = "14bc2bbfd1477465e98c985b305b7de97fc31a1dcb183ec162bb1288733cfc7b"
BASE = "https://github.com/aos-standard/catalog/raw/64b52df/docs/runs/ledger-timestamps/2026-10/"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    manifest, pending, upgraded = (Path(p).read_bytes() for p in sys.argv[1:4])
    changed = bytearray(manifest)
    i = changed.index(b"0")
    changed[i] = ord("1")  # one hex digit of one line, so the text stays a well-formed manifest
    changed = bytes(changed)
    other = b"some other bytes\n"
    # Flip one byte inside the first append argument after the file digest: still parses, path no longer ends at ROOT.
    flipped = bytearray(upgraded)
    j = upgraded.index(b"\xf0", 31 + 1 + 1 + 32) + 2
    flipped[j] ^= 0x01
    flipped = bytes(flipped)
    truncated = upgraded[:-5]

    blobs = {"manifest": manifest, "manifest_changed": changed, "other": other, "proof_pending": pending,
             "proof": upgraded, "proof_flipped": flipped, "proof_truncated": truncated}
    p0 = {"anchor_pointer": "0", "anchored_digest": {"alg": "sha-256", "hex": sha(manifest)},
          "anchored_set": {"locator": BASE + "MANIFEST.txt"}, "mechanism": "opentimestamps",
          "proof": {"locator": BASE + "MANIFEST.txt.upgraded.ots", "sha256": sha(upgraded)},
          "claimed": {"chain": "bitcoin", "height": HEIGHT}}
    hdr = {str(HEIGHT): ROOT}

    def v(id_, note, expected, set_="manifest", proof="proof", headers=hdr, edit=None):
        p = copy.deepcopy(p0)
        if edit:
            edit(p)
        return {"id": id_, "note": note, "pointer": p, "anchored_bytes": set_, "proof_bytes": proof,
                "headers": headers, "expected": expected}

    def setp(path, val):
        def f(p):
            o = p
            for k in path[:-1]:
                o = o[k]
            o[path[-1]] = val
        return f

    def drop(k):
        return lambda p: p.pop(k)

    vectors = [
        v("AP-01", "the real 2026-10 anchor", "anchored"),
        v("AP-02", "anchored_digest in uppercase hex", "malformed",
          edit=setp(["anchored_digest", "hex"], sha(manifest).upper())),
        v("AP-03", "claimed missing", "malformed", edit=drop("claimed")),
        v("AP-04", "height as a string", "malformed", edit=setp(["claimed", "height"], str(HEIGHT))),
        v("AP-05", "a mechanism this reader does not implement", "unsupported_mechanism",
          edit=setp(["mechanism"], "evm-log")),
        v("AP-06", "anchored bytes with one hex digit changed", "set_digest_mismatch", set_="manifest_changed"),
        v("AP-07", "pointer names the pending proof's sha but the upgraded proof is supplied", "proof_sha_mismatch",
          edit=setp(["proof", "sha256"], sha(pending))),
        v("AP-08", "proof truncated by five bytes", "proof_unparseable", proof="proof_truncated",
          edit=setp(["proof", "sha256"], sha(truncated))),
        v("AP-09", "a valid proof of the manifest, offered for other bytes", "proof_for_other_digest", set_="other",
          edit=setp(["anchored_digest", "hex"], sha(other))),
        v("AP-10", "the proof before upgrade: calendar commitments only", "pending", proof="proof_pending",
          edit=setp(["proof", "sha256"], sha(pending))),
        v("AP-11", "claimed one block later than the attestation", "height_not_in_proof",
          headers={str(HEIGHT + 1): ROOT}, edit=setp(["claimed", "height"], HEIGHT + 1)),
        v("AP-12", "no header supplied for the claimed height", "header_unavailable", headers={}),
        v("AP-13", "the header supplied is another block's root", "root_mismatch",
          headers={str(HEIGHT): "00" * 32}),
        v("AP-14", "one byte flipped inside an append argument of the proof", "root_mismatch",
          proof="proof_flipped", edit=setp(["proof", "sha256"], sha(flipped))),
    ]
    out = {"anchor_pointer_vectors": "draft 0", "license": "CC0-1.0",
           "blobs": {k: base64.b64encode(b).decode() for k, b in blobs.items()},
           "blob_sha256": {k: sha(b) for k, b in blobs.items()}, "vectors": vectors}
    Path(sys.argv[4]).write_text(json.dumps(out, indent=1) + "\n")
    print(len(vectors), "vectors;", {k: sha(b)[:12] for k, b in blobs.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
