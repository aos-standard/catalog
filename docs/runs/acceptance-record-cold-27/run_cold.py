#!/usr/bin/env python3
"""Run acceptance_cold_reader over vectors.json and compare against `expect`.

Usage: python3 -I run_cold.py <vectors.json>
Compares result, conditions (as sets) and disposition when the vector pins it.
Prints one JSON report; exits 0 only when every vector agrees.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from acceptance_cold_reader import evaluate  # noqa: E402

path = Path(sys.argv[1])
raw = path.read_bytes()
doc = json.loads(raw)
rows, agree = [], 0
for v in doc["vectors"]:
    got = evaluate(v["case"])
    exp = v["expect"]
    ok = got["result"] == exp.get("result") and set(got["conditions"]) == set(exp.get("conditions", []))
    if "disposition" in exp:
        ok = ok and got["disposition"] == exp["disposition"]
    agree += ok
    rows.append({"id": v["id"], "agree": ok,
                 "expected": {k: exp.get(k) for k in ("result", "conditions", "disposition") if k in exp},
                 "got": {k: got.get(k) for k in ("result", "conditions", "disposition", "key_step", "policy_refusal") if k in got}})
report = {"vectors_sha256": hashlib.sha256(raw).hexdigest(), "n": len(rows), "agree": agree,
          "disagree": [r for r in rows if not r["agree"]], "rows": rows}
print(json.dumps(report, indent=1, sort_keys=True))
sys.exit(0 if agree == len(rows) else 1)
