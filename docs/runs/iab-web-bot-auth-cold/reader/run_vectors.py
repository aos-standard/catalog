#!/usr/bin/env python3
"""Run the frozen verifier on the 20 committed vectors (inputs/) and, with --score, compare with answers/."""
import glob, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); W = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import wba_cold_verifier as V  # noqa: E402
got = {os.path.basename(f)[:-5]: V.run(json.load(open(f))["operation"]) for f in sorted(glob.glob(os.path.join(W, "inputs", "[pn][oe][sg]-*.json")))}
if "--score" not in sys.argv:
    json.dump(got, sys.stdout, indent=1, sort_keys=True); sys.exit(0)
rows, n = [], 0
for c, g in got.items():
    a = json.load(open(os.path.join(W, "answers", c + ".json")))["expected"]
    same = (g.get("ok") is True and g.get("identity") == a.get("identity")) if a["ok"] else (g.get("ok") is False and g.get("status") == a["status"] and g.get("rule") == a["rule"])
    n += same
    rows.append({"case": c, "agree": same, "got": g, "expected": {k: a[k] for k in ("ok", "identity", "status", "rule") if k in a}})
json.dump({"agree": n, "cases": len(rows), "rows": rows}, sys.stdout, indent=1, sort_keys=True)
