#!/usr/bin/env python3
"""Scores a blind run against the sealed expected values. Usage: score.py <run.json> <expected_SEALED.json>"""
import json, sys
run, exp = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
rows = []
def row(group, name, expected, got):
    rows.append({"group": group, "case": name, "expected": expected, "got": got, "agree": expected == got})
for i, e in enumerate(exp["jcs_documents"]):
    row("jcs_documents", i, e, run["jcs_documents"][i])
for i, e in enumerate(exp["jcs_numbers"]):
    g = run["jcs_numbers"][i]
    if isinstance(e, dict):
        row("jcs_numbers", i, "reject", "reject" if isinstance(g, dict) and "error" in g else g)
    else:
        row("jcs_numbers", i, e, g)
row("document_ref", 0, exp["document_ref"], run["document_ref"])
for i, e in enumerate(exp["hmac"]): row("hmac", i, e, run["hmac"][i])
for i, e in enumerate(exp["legacy"]): row("legacy", i, e, run["legacy"][i])
for name, e in exp["interop"].items():
    g = run["interop"][name]
    row("http_signature_base", name, e["signatureBase"], (g["http"] or {}).get("base"))
    row("content_digest", name, e["contentDigest"], g["content_digest"])
    row("http_verdict", name, True, g["http"].get("valid"))      # the vectors are published as valid signatures
    row("message_verdict", name, True, g["message_valid"])
from collections import OrderedDict
summ = OrderedDict()
for r in rows:
    s = summ.setdefault(r["group"], [0, 0]); s[1] += 1; s[0] += r["agree"]
json.dump({"summary": {k: "%d/%d" % tuple(v) for k, v in summ.items()}, "mismatches": [r for r in rows if not r["agree"]], "rows": rows},
          sys.stdout, indent=1, ensure_ascii=False)
