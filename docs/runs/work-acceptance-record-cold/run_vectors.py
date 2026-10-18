#!/usr/bin/env python3
"""Run war_cold_verifier over every vector and compare with `expected`.

Usage: python3 -I run_vectors.py <repo clone> <out.json>
Compared keys: signature_valid, independence, criteria_hash, criteria_committed_before_check,
receipt_timestamp, verdict_recomputed, verdict_stated, problem_codes (set), warning_codes (set).
Exit 0 only when every vector agrees on every compared key.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from war_cold_verifier import verify  # noqa: E402

KEYS = (
    "signature_valid", "independence", "criteria_hash", "criteria_committed_before_check",
    "receipt_timestamp", "verdict_recomputed", "verdict_stated",
)
SET_KEYS = ("problem_codes", "warning_codes")

repo, out_path = Path(sys.argv[1]), Path(sys.argv[2])
rows, agree = [], 0
for path in sorted((repo / "vectors").glob("*.json")):
    raw = path.read_bytes()
    vec = json.loads(raw)
    got = verify(vec)
    exp = vec["expected"]
    diffs = {}
    for k in KEYS:
        if k in exp and got.get(k) != exp.get(k):
            diffs[k] = {"expected": exp.get(k), "got": got.get(k)}
    for k in SET_KEYS:
        if set(got.get(k, [])) != set(exp.get(k, [])):
            diffs[k] = {"expected": sorted(exp.get(k, [])), "got": sorted(got.get(k, []))}
    ok = not diffs
    agree += ok
    rows.append({"vector": path.name, "input_sha256": hashlib.sha256(raw).hexdigest(), "agree": ok, "diffs": diffs, "got": got})
report = {"readme_pin": "f7d898425be6e9a45968019a1b27ffdf36ff4f92", "n": len(rows), "agree": agree, "rows": rows}
out_path.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
print(f"{agree}/{len(rows)} agree")
for r in rows:
    if not r["agree"]:
        print(r["vector"], json.dumps(r["diffs"]))
sys.exit(0 if agree == len(rows) else 1)
