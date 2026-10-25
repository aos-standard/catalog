#!/usr/bin/env python3
"""Build anchor-pointer draft 1 vectors (offline ones: opentimestamps, plus evm-log shape checks).

AP-01..AP-14 are draft 0's, moved to version "1" (AP-05 now names a mechanism no reader implements, since `evm-log`
is defined in draft 1). AP-15..AP-19 come from babyblueviper1's decision-receipt slot log of 2026-10-22, carried
under CC0 with the owner's permission (aeoess/agent-governance-vocabulary#217). AP-20..AP-22 check the `evm-log`
shape without a network. Every `expected` is fixed by construction, not by running the reader.

Usage: python3 -I -B build_vectors_d1.py <draft0 vectors.json> <slot log> <slot log .ots> <out vectors.json>
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

BBV_HEIGHT = 972677
# Block 972677's merkle root; read from blockstream.info and mempool.space on 2026-10-24, the two agree.
BBV_ROOT = "018f62bea2b90fe50ea0e6fd75fdd0656631fd0e95be98adf665f2f066b164ef"
BBV_LOG = "https://api.babyblueviper.com/decision-receipt/slots/log/2026-10-22"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    d0 = json.loads(Path(sys.argv[1]).read_text())
    log, ots = Path(sys.argv[2]).read_bytes(), Path(sys.argv[3]).read_bytes()
    blobs = dict(d0["blobs"])
    blobs["bbv_slot_log"] = base64.b64encode(log).decode()
    blobs["bbv_slot_log_ots"] = base64.b64encode(ots).decode()

    vectors = []
    for v in d0["vectors"]:
        v = copy.deepcopy(v)
        if isinstance(v["pointer"], dict) and "anchor_pointer" in v["pointer"]:
            v["pointer"]["anchor_pointer"] = "1"
        if v["id"] == "AP-05":
            v["pointer"]["mechanism"] = "registry-x"
            v["note"] = "a mechanism this reader does not implement (draft 0 used evm-log here)"
        if v["expected"] == "anchored":
            v["expected"] = {"result": "anchored", "earliest_height": 972227, "set_checked": True}
        vectors.append(v)

    first = log.split(b"\n")[0]
    base = {"anchor_pointer": "1", "anchored_digest": {"alg": "sha-256", "hex": sha(first)},
            "anchored_set": {"locator": BBV_LOG, "select": {"kind": "line", "index": 0}},
            "mechanism": "opentimestamps", "proof": {"locator": BBV_LOG + ".ots", "sha256": sha(ots)},
            "claimed": {"chain": "bitcoin", "height": BBV_HEIGHT}}
    hdr = {str(BBV_HEIGHT): BBV_ROOT}

    def bbv(id_, note, expected, edit=None):
        p = copy.deepcopy(base)
        if edit:
            edit(p)
        return {"id": id_, "note": note, "pointer": p, "anchored_bytes": "bbv_slot_log",
                "proof_bytes": "bbv_slot_log_ots", "headers": hdr, "expected": expected}

    def sel(val):
        def f(p):
            p["anchored_set"]["select"] = val
        return f

    vectors += [
        bbv("AP-15", "babyblueviper1's slot log: the anchored bytes are line 0 of the resource",
            {"result": "anchored", "earliest_height": BBV_HEIGHT, "set_checked": True}),
        bbv("AP-16", "the same pointer without `select`: the whole resource is not what was anchored",
            {"result": "set_digest_mismatch"}, edit=lambda p: p["anchored_set"].pop("select")),
        bbv("AP-17", "`select` line 1 (the resource has two lines)", {"result": "set_digest_mismatch"},
            edit=sel({"kind": "line", "index": 1})),
        bbv("AP-18", "`select` line 2: past the last line (a final LF does not start a line)",
            {"result": "select_out_of_range"}, edit=sel({"kind": "line", "index": 2})),
        bbv("AP-19", "a `select` kind this reader does not implement", {"result": "unsupported_select"},
            edit=sel({"kind": "json-pointer", "path": "/merkle_root"})),
    ]

    evm = {"anchor_pointer": "1",
           "anchored_digest": {"alg": "sha-256", "hex": "d8b6a69f57ba2209561fb551443c096c47fcb0cb6db37005fd0713690de88299"},
           "mechanism": "evm-log",
           "claimed": {"chain": "eip155:8453", "contract": "0x49fEcA52bC634a9Ab773226D16619deC547794aa",
                       "tx": "0x4d4b45f7ddb970bf37a640d651f24bc0e26a4acdb2e14285c19a9f3f95c720f7",
                       "log_index": 59, "height": 52987624}}

    def ev(id_, note, edit):
        p = copy.deepcopy(evm)
        edit(p)
        return {"id": id_, "note": note, "pointer": p, "expected": {"result": "malformed"}}

    vectors += [
        ev("AP-20", "evm-log with a proof file: this mechanism has none",
           lambda p: p.__setitem__("proof", {"locator": "https://example.invalid/p", "sha256": "0" * 64})),
        ev("AP-21", "evm-log chain not in CAIP-2 form", lambda p: p["claimed"].__setitem__("chain", "base")),
        ev("AP-22", "evm-log `log_index` missing", lambda p: p["claimed"].pop("log_index")),
    ]
    raw = {k: base64.b64decode(v) for k, v in blobs.items()}
    out = {"anchor_pointer_vectors": "draft 1", "license": "CC0-1.0",
           "sources": {"AP-01..AP-14": "aos-standard/catalog anchor-pointer-draft0 (a348d35)",
                       "AP-15..AP-19": "babyblueviper1 decision-receipt slot log 2026-10-22, CC0 by its owner on aeoess/agent-governance-vocabulary#217"},
           "blobs": blobs, "blob_sha256": {k: sha(b) for k, b in raw.items()}, "vectors": vectors}
    Path(sys.argv[4]).write_text(json.dumps(out, indent=1) + "\n")
    print(len(vectors), "vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
