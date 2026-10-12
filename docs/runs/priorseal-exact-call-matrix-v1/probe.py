#!/usr/bin/env python3
"""Build mutated observed envelopes from case-00 and run all three readers.

These mutations are NOT part of the fixture. Each changes one thing in the
positive-control envelope to exercise a rule INPUT-CONTRACT.md states loosely.
Usage: python3 -I probe.py <repo-root>
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import oel_exact_call_reader as mine  # noqa: E402

repo = Path(sys.argv[1])
d = repo / "examples/open-evidence-lab-exact-call-matrix-v1"
base = json.loads((d / "fixture/observed/case-00-exact-call-observed-match.json").read_text())
intent = json.loads((d / "fixture/signed-authorization.json").read_text())["authorization"]["intent"]


def mut(**changes):
    o = copy.deepcopy(base)
    for k, v in changes.items():
        if v is ...:
            o.pop(k, None)
        else:
            o[k] = v
    return o


mutations = {
    "p1-unavailable-and-target-mismatch": mut(executionDataAvailable=False, target="0x9999999999999999999999999999999999999999"),
    "p2-nativeValue-as-json-number": mut(nativeValue=1000000000000000),
    "p3-nonce-as-json-number": mut(nonce=7),
    "p4-observed-nonce-absent": mut(nonce=...),
    "p5-target-uppercase-hex": mut(target="0x" + "3" * 40, calldataHash="0x" + "5A" * 32),
    "p6-chainId-as-string": mut(chainId=str(base["chainId"])),
    "p7-executedAt-absent-observedAt-late": mut(executedAt=..., observedAt=2001),
    "p8-executedAt-equals-validUntil": mut(executedAt=2000),
    "p9-executedAt-null-observedAt-late": mut(executedAt=None, observedAt=2001),
}
mpath = HERE / "mutations.json"
mpath.write_text(json.dumps(mutations, indent=1))
theirs = json.loads(subprocess.check_output(["node", str(HERE / "probe.mjs"), str(repo), str(mpath)], text=True))
rows = {}
for name, obs in mutations.items():
    try:
        codes = mine.compare(intent, obs)
        m = {"bound": not codes, "reasonCodes": codes,
             "availabilityCode": "EXECUTION_UNAVAILABLE" if obs.get("executionDataAvailable") is False else None}
    except Exception as e:  # noqa: BLE001
        m = {"error": f"{type(e).__name__}: {e}"}
    rows[name] = {"independent": m, **theirs[name]}
print(json.dumps(rows, indent=1))
