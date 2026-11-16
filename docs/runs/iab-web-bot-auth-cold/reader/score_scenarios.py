#!/usr/bin/env python3
"""Compare runs/scenarios_v1.json (scenario_harness.py output) with answers/scenarios_answers.json.
target_uris carry no expected member: a pass with computed_wire equal to the scenario's wire agrees."""
import json, os, sys
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
got = json.load(open(sys.argv[1] if len(sys.argv) > 1 else os.path.join(W, "runs", "scenarios_v1.json")))
ans = json.load(open(os.path.join(W, "answers", "scenarios_answers.json")))
S = json.load(open(os.path.join(W, "inputs", "scenarios_inputs.json")))
wire = {u["id"]: u["wire"] for u in S["target_uris"]}
out = {"groups": {}, "rows": []}
for grp, items in ans.items():
    n = 0
    for it in items:
        g = got[it["id"]]; a = it.get("expected", {"ok": True})
        if a["ok"]: same = g.get("ok") is True and (a.get("identity") is None or g.get("identity") == a.get("identity"))
        else: same = g.get("ok") is False and g.get("status") == a["status"] and g.get("rule") == a["rule"]
        if grp == "target_uris": same = same and g.get("computed_wire") == wire[it["id"]]
        n += same; out["rows"].append({"id": it["id"], "tier": it.get("tier"), "agree": same, "got": g, "expected": a})
    out["groups"][grp] = [n, len(items)]
out["agree"] = sum(v[0] for v in out["groups"].values()); out["cases"] = sum(v[1] for v in out["groups"].values())
json.dump(out, sys.stdout, indent=1, sort_keys=True)
