#!/usr/bin/env python3
"""Rerun both batteries of the rc.5 rerun (mutants_v2.py rule toggles and mutants_v2_src.py source mutants) on the #306
vectors with the steps-aware runner. The mutant definitions are read from those two files unchanged.
usage: mutants_v3.py READER_DIR http_inputs.json http_expected_SEALED.json out.json"""
import json, sys, re, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_v3
rd, hin, hexp, out = sys.argv[1:5]
H = json.load(open(hin)); E = {e["n"]: e for e in json.load(open(hexp))}
SRC = open(os.path.join(rd, "agent_did_http_v2.py")).read()
def exp(n):
    e = E[n]
    if "steps" in e: return [s["expected"] for s in e["steps"]]
    return e["expectedSequence"] if "expectedSequence" in e else e["expected"]
def verdicts(rows):
    out = {}
    for x in rows:
        out[x["n"]] = [s[0] for s in x["steps"]] if "steps" in x else x["sequence"] if "sequence" in x else x["ok"]
    return out
def caught_by(rows):
    g = verdicts(rows); return [E[n]["id"] for n in g if g[n] != exp(n)]
base = caught_by(run_v3.run(run_v3.load("v2", SRC), H))
results = [{"mutant": "(baseline: frozen reader)", "differs_on": base}]
rules_src = open(os.path.join(rd, "mutants_v2.py")).read()
RULES = eval(re.search(r"RULES = (\[.*?\])", rules_src, re.S).group(1))
for k in RULES:
    c = [i for i in caught_by(run_v3.run(run_v3.load("v2", SRC), H, {k: False})) if i not in base]
    results.append({"mutant": "rule off: " + k, "caught_by": c, "caught": bool(c)})
msrc = open(os.path.join(rd, "mutants_v2_src.py")).read()
M = eval(re.search(r"^M = (\[.*?^\])", msrc, re.S | re.M).group(1))
for name, a, b in M:
    src = SRC.replace(a, b, 1)
    if name.startswith("@signature-params"):
        src = "RAW_PARAMS = {}\n" + src.replace("    labels = [(l, m)", "    import re as _re\n    _m = _re.search(r'=(\\(.*)$', sig_in)\n    RAW_PARAMS['v'] = _m.group(1) if _m else None\n    labels = [(l, m)", 1)
    c = [i for i in caught_by(run_v3.run(run_v3.load("m", src), H)) if i not in base]
    results.append({"mutant": name, "caught_by": c, "caught": bool(c)})
json.dump(results, open(out, "w"), indent=1, ensure_ascii=False)
print("baseline differs on:", base)
for x in results[1:]: print("CAUGHT " if x["caught"] else "SURVIVE", x["mutant"], ("<- " + ", ".join(x["caught_by"][:3])) if x["caught"] else "")
print(sum(x["caught"] for x in results[1:]), "of", len(results) - 1, "caught")
