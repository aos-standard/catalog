#!/usr/bin/env python3
"""Usage: score.py <run.json> <expected_SEALED.json>. Values compared as parsed JSON; reasons are not compared."""
import json, sys
run, exp = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
rows = []
for key, got in sorted(run.items()):
    cid = key.split("|")[0]; e = exp[cid]["expect"]
    g = {"json": got["json"]} if "json" in got else {"reject": True}
    rows.append({"run": key, "expected": e, "got": g, "agree": g == e})
cases = {}
for r in rows:
    cases.setdefault(r["run"].split("|")[0], []).append(r["agree"])
summary = {"case_header_runs": "%d/%d" % (sum(r["agree"] for r in rows), len(rows)),
           "cases": "%d/%d" % (sum(all(v) for v in cases.values()), len(cases))}
json.dump({"summary": summary, "mismatches": [r for r in rows if not r["agree"]], "rows": rows}, sys.stdout, indent=1, ensure_ascii=False)
