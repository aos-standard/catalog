#!/usr/bin/env python3
"""Score a run_v3 output against the sealed #306 expected values. usage: score_v3.py run.json http_expected_SEALED.json"""
import json, sys
run, hexp = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
E = {e["n"]: e for e in hexp}; rows = []
for x in run["http"]:
    e = E[x["n"]]
    if "steps" in e:
        exp = [[s["expected"], s.get("reason")] for s in e["steps"]]
        rows.append({"n": x["n"], "id": e["id"], "verdict_agree": [a[0] for a in x["steps"]] == [b[0] for b in exp],
                     "reason_agree": x["steps"] == exp, "expected": exp, "got": x["steps"]})
    elif "expectedSequence" in e:
        rows.append({"n": x["n"], "id": e["id"], "verdict_agree": x["sequence"] == e["expectedSequence"],
                     "reason_agree": x["reasons"] == e.get("expectedReasons"), "expected": [e["expectedSequence"], e.get("expectedReasons")], "got": [x["sequence"], x["reasons"]]})
    else:
        rows.append({"n": x["n"], "id": e["id"], "verdict_agree": x["ok"] == e["expected"],
                     "reason_agree": (x["reason"] == e.get("reason")) if not e["expected"] else x["reason"] is None,
                     "expected": [e["expected"], e.get("reason")], "got": [x["ok"], x["reason"]]})
print(json.dumps({"summary": {"verdict": "%d/%d" % (sum(r["verdict_agree"] for r in rows), len(rows)),
                              "reason": "%d/%d" % (sum(r["reason_agree"] for r in rows), len(rows))},
                  "verdict_mismatch": [r for r in rows if not r["verdict_agree"]],
                  "reason_mismatch": [r for r in rows if r["verdict_agree"] and not r["reason_agree"]], "rows": rows}, indent=1, ensure_ascii=False))
