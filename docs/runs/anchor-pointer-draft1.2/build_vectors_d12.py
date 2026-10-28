#!/usr/bin/env python3
"""Build the draft 1.2 vectors: draft 1.1's AP-01..AP-28 unchanged, AP-29..AP-31 new.

Written 2026-10-28 after aeoess published a second reader (aeoess/ots-anchor-reader 2d721cb, 28/28 on draft 1.1 at
5294818) with four questions the draft text did not answer. Draft 1.2 answers them; three get a vector.
Every `expected` here is fixed by construction.
Usage: python3 -I -B build_vectors_d12.py <draft1.1 vectors.json> <out vectors.json>
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anchor_pointer_check_d12 import BITCOIN_TAG, parse_ots  # noqa: E402


def varuint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    blobs = dict(d["blobs"])
    raw = {k: base64.b64decode(v) for k, v in blobs.items()}
    vectors = copy.deepcopy(d["vectors"])
    V = {v["id"]: v for v in vectors}
    assert [v["id"] for v in vectors] == [f"AP-{i:02d}" for i in range(1, 29)]

    # AP-29 (I1): two attestations at one height. In NENRIN entry 120's proof the 972145 attestation's height is
    # rewritten to 972141, so the proof names 972141 twice with two different roots. With 972141's real header
    # supplied, one attestation matches and the other does not: the height is not verified.
    ots = raw["nenrin_120_ots"]
    needle = BITCOIN_TAG + bytes([len(varuint(972145))]) + varuint(972145)
    assert ots.count(needle) == 1, ots.count(needle)
    dup = ots.replace(needle, BITCOIN_TAG + bytes([len(varuint(972141))]) + varuint(972141))
    _, atts = parse_ots(dup)
    heights = sorted(h for k, h, _ in atts if k == "bitcoin")
    assert heights == [972141, 972141], heights
    blobs["nenrin_120_ots_dup_972141"] = base64.b64encode(dup).decode()
    raw["nenrin_120_ots_dup_972141"] = dup
    v29 = copy.deepcopy(V["AP-25"]); v29["id"] = "AP-29"
    v29["pointer"]["claimed"]["height"] = 972141
    v29["pointer"]["proof"]["sha256"] = sha(dup)
    v29["proof_bytes"] = "nenrin_120_ots_dup_972141"
    v29["headers"] = {"972141": V["AP-25"]["headers"]["972141"]}
    v29["note"] = ("two attestations at one height (972145's attestation rewritten to 972141, proof.sha256 updated): "
                   "one matches 972141's header and one does not, so the height is not verified and the pointer fails")
    v29["expected"] = {"result": "root_mismatch", "failed_height": 972141, "proof_heights": [972141], "set_checked": True}
    vectors.append(v29)

    # AP-30 (I3): the real 2026-10 anchor with no proof bytes supplied.
    v30 = copy.deepcopy(V["AP-01"]); v30["id"] = "AP-30"
    del v30["proof_bytes"]
    v30["note"] = "as AP-01 but the proof bytes are not supplied: proof_unavailable after the digest comparison ran"
    v30["expected"] = {"result": "proof_unavailable", "set_checked": True}
    vectors.append(v30)

    # AP-31 (I5): a select of a kind the reader does not implement, with a member that would be malformed for `line`.
    v31 = copy.deepcopy(V["AP-15"]); v31["id"] = "AP-31"
    v31["pointer"]["anchored_set"]["select"] = {"kind": "byte-range", "index": "x"}
    v31["note"] = ("as AP-15 with a select of kind byte-range whose other member is not an integer: only `kind` is "
                   "shape-checked for a kind the reader does not implement, so unsupported_select, not malformed")
    v31["expected"] = {"result": "unsupported_select", "set_checked": False}
    vectors.append(v31)

    out = {"anchor_pointer_vectors": "draft 1.2", "license": "CC0-1.0",
           "sources": dict(d["sources"], **{"AP-29": "NENRIN entry 120's proof with one attestation height rewritten (CC0 as AP-23..AP-27)",
                                            "AP-30": "the catalog's own 2026-10 anchor as AP-01, proof not supplied",
                                            "AP-31": "babyblueviper1's slot log as AP-15, with a select of another kind"}),
           "blobs": blobs, "blob_sha256": {k: sha(b) for k, b in raw.items()}, "vectors": vectors}
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1) + "\n")
    print(len(vectors), "vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
