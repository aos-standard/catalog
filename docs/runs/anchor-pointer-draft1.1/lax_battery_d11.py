#!/usr/bin/env python3
"""Lax readers against the draft 1.1 vectors. A reader that drops check X answers `anchored` where the real reader
stops at X. Four variants are run instead of modelled: `ignore-select` drops `select`; `earliest-from-unverified`
reports the smallest height the proof names (draft 1's behaviour); `ignore-other-headers` verifies only the claimed
block; `set-checked-means-supplied` reports whether bytes were given rather than whether the comparison ran.
Usage: python3 -I -B lax_battery_d11.py <vectors.json>
"""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anchor_pointer_check_d11 import check  # noqa: E402

DROPS = {"no-shape-check": {"malformed"}, "accept-any-mechanism": {"unsupported_mechanism"},
         "accept-any-select": {"unsupported_select"}, "no-select-range-check": {"select_out_of_range"},
         "skip-set-digest": {"set_digest_mismatch"}, "skip-proof-sha": {"proof_sha_mismatch"},
         "ignore-proof-file-digest": {"proof_for_other_digest"}, "pending-counts-as-anchored": {"pending"},
         "ignore-claimed-height": {"height_not_in_proof"}, "no-root-compare": {"header_unavailable", "root_mismatch"}}


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    blobs = {k: base64.b64decode(v) for k, v in d["blobs"].items()}
    vecs = d["vectors"]

    def run(v, pointer=None, headers=None):
        return check(pointer or v["pointer"], blobs.get(v.get("anchored_bytes")), blobs.get(v.get("proof_bytes")),
                     v.get("headers") if headers is None else headers)

    real = {v["id"]: run(v) for v in vecs}
    names = list(DROPS) + ["ignore-select", "earliest-from-unverified", "ignore-other-headers", "set-checked-means-supplied"]
    caught = 0
    for name in names:
        fails = []
        for v in vecs:
            got = dict(real[v["id"]])
            if name in DROPS and got["result"] in DROPS[name]:
                got["result"] = "anchored"
            elif name == "ignore-select" and isinstance(v["pointer"], dict) and (v["pointer"].get("anchored_set") or {}).get("select"):
                p = copy.deepcopy(v["pointer"]); p["anchored_set"].pop("select"); got = run(v, p)
            elif name == "earliest-from-unverified" and "proof_heights" in got and got["result"] == "anchored":
                got["earliest_height"] = min(got["proof_heights"])
            elif name == "ignore-other-headers" and isinstance(v["pointer"], dict) and isinstance(v.get("headers"), dict):
                h = str(v["pointer"].get("claimed", {}).get("height")); got = run(v, headers={k: x for k, x in v["headers"].items() if k == h})
            elif name == "set-checked-means-supplied":
                got["set_checked"] = v.get("anchored_bytes") is not None and isinstance(v["pointer"], dict) and v["pointer"].get("anchored_set") is not None
            exp = v["expected"] if isinstance(v["expected"], dict) else {"result": v["expected"]}
            if any(got.get(k) != val for k, val in exp.items()):
                fails.append(v["id"])
        caught += bool(fails)
        print(f"{'caught' if fails else 'MISSED':6} {name:28} by {fails}")
    print(f"{caught}/{len(names)} lax readers caught")
    return 0 if caught == len(names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
