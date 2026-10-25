#!/usr/bin/env python3
"""Lax readers against the draft 1 offline vectors (and NENRIN's, for the earliest-height check).

A reader that drops check X is modelled as answering `anchored` where the real reader stops at X, as in draft 0.
Two variants are rerun instead: `ignore-select` drops `select` and hashes the whole resource, and
`earliest-is-claimed` reports the claimed height as `earliest_height`.
Usage: python3 -I -B lax_battery_d1.py <vectors.json> <nenrin vectors.json>
"""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from anchor_pointer_check_d1 import check  # noqa: E402

DROPS = {"no-shape-check": {"malformed"}, "accept-any-mechanism": {"unsupported_mechanism"},
         "accept-any-select": {"unsupported_select"}, "no-select-range-check": {"select_out_of_range"},
         "skip-set-digest": {"set_digest_mismatch"}, "skip-proof-sha": {"proof_sha_mismatch"},
         "ignore-proof-file-digest": {"proof_for_other_digest"}, "pending-counts-as-anchored": {"pending"},
         "ignore-claimed-height": {"height_not_in_proof"}, "no-root-compare": {"header_unavailable", "root_mismatch"}}


def load(p):
    d = json.loads(Path(p).read_text())
    return d, {k: base64.b64decode(v) for k, v in d.get("blobs", {}).items()}


def want(v):
    return v["expected"] if isinstance(v["expected"], dict) else {"result": v["expected"]}


def run(v, blobs, pointer=None):
    return check(pointer or v["pointer"], blobs.get(v.get("anchored_bytes")), blobs.get(v.get("proof_bytes")), v.get("headers"))


def main() -> int:
    sets = [load(sys.argv[1]), load(sys.argv[2])]
    real = {(i, v["id"]): run(v, b) for i, (d, b) in enumerate(sets) for v in d["vectors"]}
    caught = 0
    names = list(DROPS) + ["ignore-select", "earliest-is-claimed"]
    for name in names:
        fails = []
        for i, (d, b) in enumerate(sets):
            for v in d["vectors"]:
                got = dict(real[(i, v["id"])])
                if name in DROPS and got["result"] in DROPS[name]:
                    got["result"] = "anchored"
                elif name == "ignore-select" and isinstance(v["pointer"], dict) and (v["pointer"].get("anchored_set") or {}).get("select"):
                    p = copy.deepcopy(v["pointer"]); p["anchored_set"].pop("select")
                    got = run(v, b, p)
                elif name == "earliest-is-claimed" and "earliest_height" in got:
                    got["earliest_height"] = v["pointer"]["claimed"]["height"]
                exp = want(v) if i == 0 else dict(want(v), **({"earliest_height": 972141} if v["id"].startswith("HS-120") else {}))
                if any(got.get(k) != val for k, val in exp.items()):
                    fails.append(v["id"])
        caught += bool(fails)
        print(f"{'caught' if fails else 'MISSED':6} {name:28} by {fails}")
    print(f"{caught}/{len(names)} lax readers caught")
    return 0 if caught == len(names) else 1


if __name__ == "__main__":
    raise SystemExit(main())
