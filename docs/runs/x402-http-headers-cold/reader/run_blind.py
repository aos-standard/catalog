#!/usr/bin/env python3
"""Runs a reader on blind/inputs.json. Usage: run_blind.py <reader.py> <inputs.json> <out.json>
Each case runs once per listed header (the same decoder serves all three headers)."""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("reader", sys.argv[1]); R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
inp = json.load(open(sys.argv[2])); out = {}
for c in inp["decode"]:
    for h in c["headers"]:
        try:
            got = {"json": R.decode_header(c["value"])}
        except R.Reject as e:
            got = {"reject": True, "why": str(e)}
        out[c["id"] + "|" + h] = got
json.dump(out, open(sys.argv[3], "w"), indent=1, ensure_ascii=False, sort_keys=True)
print("runs:", len(out))
