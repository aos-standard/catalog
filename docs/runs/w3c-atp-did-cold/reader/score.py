#!/usr/bin/env python3
"""Compare runs/run_v1.json with answers/answers.json, member by member. An invalid identifier agrees when the reader
refuses it."""
import json, os, sys
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
got = json.load(open(sys.argv[1] if len(sys.argv) > 1 else os.path.join(W, "runs", "run_v1.json")))
ans = json.load(open(os.path.join(W, "answers", "answers.json")))
rows, n, tot = [], 0, 0
for grp, items in ans.items():
    for a in items:
        g = next(x for x in got[grp] if x["i"] == a["i"])
        if grp == "invalidIdentifiers":
            checks = {"refused": g["valid"] is False}
        else:
            checks = {k: g.get(k) == v for k, v in a.items() if k not in ("i", "description")}
        ok = all(checks.values()); n += ok; tot += 1
        rows.append({"group": grp, "i": a["i"], "agree": ok, "checks": checks})
json.dump({"agree": n, "cases": tot, "rows": rows}, sys.stdout, indent=1, sort_keys=True)
