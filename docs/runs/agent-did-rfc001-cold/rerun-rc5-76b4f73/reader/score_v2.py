#!/usr/bin/env python3
"""Score a v2 run against the sealed expected values. usage: score_v2.py run.json http_expected_SEALED.json v1_expected_SEALED.json"""
import json, sys
run, hexp, v1exp = (json.load(open(p)) for p in sys.argv[1:4])
E = {e["n"]: e for e in hexp}
rows = []
for x in run["http"]:
    e = E[x["n"]]
    if "expectedSequence" in e:
        rows.append({"n": x["n"], "id": e["id"], "verdict_agree": x["sequence"] == e["expectedSequence"],
                     "reason_agree": x["reasons"] == e.get("expectedReasons"), "expected": [e["expectedSequence"], e.get("expectedReasons")],
                     "got": [x["sequence"], x["reasons"]], "base_agree": x["base"] == e["signatureBase"] if x["base"] is not None else None})
    else:
        rows.append({"n": x["n"], "id": e["id"], "verdict_agree": x["ok"] == e["expected"],
                     "reason_agree": (x["reason"] == e.get("reason")) if not e["expected"] else (x["reason"] is None),
                     "expected": [e["expected"], e.get("reason")], "got": [x["ok"], x["reason"]],
                     "base_agree": x["base"] == e["signatureBase"] if x["base"] is not None else None})
inter = []
for name, x in run["interop"].items():
    e = v1exp["interop"][name]
    inter.append({"case": name, "base_agree": x["base"] == e["signatureBase"], "digest_agree": x["content_digest"] == e["contentDigest"],
                  "http_ok": x["http_ok"], "message_ok": x["message_ok"]})
s = {"verdict": "%d/%d" % (sum(r["verdict_agree"] for r in rows), len(rows)),
     "reason": "%d/%d" % (sum(r["reason_agree"] for r in rows), len(rows)),
     "base_built_and_equal": "%d/%d built" % (sum(1 for r in rows if r["base_agree"]), sum(1 for r in rows if r["base_agree"] is not None)),
     "interop": inter}
print(json.dumps({"summary": s, "verdict_mismatch": [r for r in rows if not r["verdict_agree"]],
                  "reason_mismatch": [r for r in rows if r["verdict_agree"] and not r["reason_agree"]], "rows": rows}, indent=1, ensure_ascii=False))
