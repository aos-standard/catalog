#!/usr/bin/env python3
"""Split http_headers.json into inputs (id, headers, value) and sealed expectations (note, expect)."""
import json, sys, os
d = json.load(open(sys.argv[1])); out = sys.argv[2]
inp = {"fixture_version": d["fixture_version"], "spec": d["spec"], "decode": [{"id": c["id"], "headers": c["headers"], "value": c["value"]} for c in d["decode"]]}
exp = {c["id"]: {"note": c["note"], "expect": c["expect"]} for c in d["decode"]}
json.dump(inp, open(os.path.join(out, "inputs.json"), "w"), indent=1, ensure_ascii=False)
json.dump(exp, open(os.path.join(out, "expected_SEALED.json"), "w"), indent=1, ensure_ascii=False)
print("ok", len(inp["decode"]))
