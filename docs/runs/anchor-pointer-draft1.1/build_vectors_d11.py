#!/usr/bin/env python3
"""Build the draft 1.1 vectors: draft 1's AP-01..AP-23 unchanged, AP-24 corrected, AP-25..AP-28 new.

Written 2026-10-28 after aeoess's second reader (aeoess/agent-governance-vocabulary#217, 6448170085) showed that
draft 1's `earliest_height` took the minimum over every height the proof names, verified or not, and that AP-24
supplied only the header of its claimed block. Draft 1.1 makes `earliest_height` the smallest height among the
attestations the reader verified. Every `expected` here is fixed by construction.
Usage: python3 -I -B build_vectors_d11.py <draft1 vectors.json> <addendum vectors-nenrin-120.json> <out vectors.json>
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anchor_pointer_check_d11 import BITCOIN_TAG, parse_ots  # noqa: E402

ROOTS = {972141: "a2669dac9d1dcda64d589cf47a01dabda7b7795947ade803a80bf14225fd6550",
         972145: "48f80cfdacc9e97b2798e4988111b1a478ad7c8439bfbf6cc426f4827ada81f0"}


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
    d1 = json.loads(Path(sys.argv[1]).read_text())
    nen = json.loads(Path(sys.argv[2]).read_text())
    blobs = dict(d1["blobs"]); blobs.update(nen["blobs"])
    vectors = copy.deepcopy(d1["vectors"])
    ap23, ap24 = (copy.deepcopy(v) for v in nen["vectors"])
    assert ap23["id"] == "AP-23" and ap24["id"] == "AP-24"
    vectors.append(ap23)
    ap24["note"] = "NENRIN JIDEC entry 120, claimed at 972145 with only that block's header: the earlier attestation (972141) is not verified, so it does not lower earliest_height (draft 1 expected 972141 here; corrected in 1.1)"
    ap24["expected"] = {"result": "anchored", "earliest_height": 972145, "set_checked": True}
    vectors.append(ap24)

    base = copy.deepcopy(ap24)
    def nen_vec(id_, note, headers, expected, pointer=None, proof="nenrin_120_ots"):
        v = copy.deepcopy(base); v["id"] = id_; v["note"] = note; v["headers"] = headers; v["expected"] = expected
        v["proof_bytes"] = proof
        if pointer is not None:
            v["pointer"] = pointer
        return v

    vectors.append(nen_vec("AP-25", "as AP-24 with both blocks' headers supplied: both attestations verified, earliest is 972141",
                           {str(h): r for h, r in ROOTS.items()},
                           {"result": "anchored", "earliest_height": 972141, "set_checked": True}))
    vectors.append(nen_vec("AP-26", "as AP-25 but the header supplied for 972141 is another block's root: a supplied header that does not match its attestation fails the pointer",
                           {"972145": ROOTS[972145], "972141": "00" * 32},
                           {"result": "root_mismatch", "failed_height": 972141}))
    # AP-27: aeoess's probe. The 972141 attestation's height is changed to 972140 inside the proof.
    ots = base64.b64decode(blobs["nenrin_120_ots"])
    needle = BITCOIN_TAG + bytes([len(varuint(972141))]) + varuint(972141)
    assert ots.count(needle) == 1, ots.count(needle)
    tampered = ots.replace(needle, BITCOIN_TAG + bytes([len(varuint(972140))]) + varuint(972140))
    _, atts = parse_ots(tampered)
    assert sorted(h for k, h, _ in atts if k == "bitcoin") == [972140, 972145]
    blobs["nenrin_120_ots_tampered_972140"] = base64.b64encode(tampered).decode()
    p27 = copy.deepcopy(ap24["pointer"]); p27["proof"]["sha256"] = sha(tampered)
    vectors.append(nen_vec("AP-27", "aeoess's probe: the unverified earlier attestation is rewritten to name 972140 and proof.sha256 updated; with only 972145's header the pointer is still anchored at 972145, and 972140 does not become the earliest",
                           {"972145": ROOTS[972145]},
                           {"result": "anchored", "earliest_height": 972145, "proof_heights": [972140, 972145], "set_checked": True},
                           pointer=p27, proof="nenrin_120_ots_tampered_972140"))
    # AP-28: two failures at once; the selector check comes before the proof checks.
    ap15 = next(v for v in d1["vectors"] if v["id"] == "AP-15")
    v28 = copy.deepcopy(ap15); v28["id"] = "AP-28"
    v28["note"] = "two failures at once: select index 2 is past the last line and proof.sha256 is wrong; the selector check runs first"
    v28["pointer"]["anchored_set"]["select"] = {"kind": "line", "index": 2}
    v28["pointer"]["proof"]["sha256"] = "0" * 64
    v28["expected"] = {"result": "select_out_of_range", "set_checked": False}
    vectors.append(v28)

    raw = {k: base64.b64decode(v) for k, v in blobs.items()}
    out = {"anchor_pointer_vectors": "draft 1.1", "license": "CC0-1.0",
           "sources": dict(d1["sources"], **{"AP-23..AP-27": "NENRIN (ogasurfproject-jpg) JIDEC ledger entry 120, CC0 by its owner on aeoess/agent-governance-vocabulary#217; AP-27 rewrites one attestation height inside the proof",
                                             "AP-28": "babyblueviper1's slot log as AP-15, with two faults"}),
           "blobs": blobs, "blob_sha256": {k: sha(b) for k, b in raw.items()}, "vectors": vectors}
    Path(sys.argv[3]).write_text(json.dumps(out, indent=1) + "\n")
    print(len(vectors), "vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
