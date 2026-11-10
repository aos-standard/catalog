"""Make the inputs-only copy the readers ran on: drop expect, note, notes and open_questions everywhere.
Usage: python3 -I -B reader/split_inputs.py exact_lnbtc.json inputs.json  (gives the sha256 in FROZEN.txt)"""
import json, sys
SKIP = {"expect", "note", "open_questions", "notes"}
def strip(x):
    if isinstance(x, dict):
        return {k: strip(v) for k, v in x.items() if k not in SKIP}
    if isinstance(x, list):
        return [strip(v) for v in x]
    return x
json.dump(strip(json.load(open(sys.argv[1]))), open(sys.argv[2], "w"), indent=1, ensure_ascii=False)
