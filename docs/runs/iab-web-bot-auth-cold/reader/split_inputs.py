#!/usr/bin/env python3
"""Split each committed vector into the input a verifier sees (operation, reference_now) and the answer members, and
strip expected, basis, tier, name and $comment from scenarios.json. Run once before the verifier was written."""
import glob, json, os, sys
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V = sys.argv[1] if len(sys.argv) > 1 else os.path.join(W, "upstream/src/iab_agentic_primitives/web_bot_auth/vectors")
os.makedirs(os.path.join(W, "inputs"), exist_ok=True); os.makedirs(os.path.join(W, "answers"), exist_ok=True)
for f in sorted(glob.glob(V + "/positive/*.json") + glob.glob(V + "/negative/*.json")):
    d = json.load(open(f)); cid = os.path.basename(os.path.dirname(f))[:3] + "-" + os.path.basename(f)[:3]
    inp = {"case": cid, "operation": d["operation"], "reference_now": d["reference_now"]}
    ans = {k: d[k] for k in d if k not in ("operation", "reference_now")}; ans["case"] = cid; ans["file"] = os.path.relpath(f, V)
    json.dump(inp, open(os.path.join(W, "inputs", cid + ".json"), "w"), indent=1)
    json.dump(ans, open(os.path.join(W, "answers", cid + ".json"), "w"), indent=1)
d = json.load(open(os.path.join(V, "scenarios.json")))
HIDE = {"expected", "basis", "tier", "$comment", "name", "rationale"}
def strip(x):
    if isinstance(x, dict): return {k: strip(v) for k, v in x.items() if k not in HIDE}
    if isinstance(x, list): return [strip(v) for v in x]
    return x
json.dump(strip(d), open(os.path.join(W, "inputs", "scenarios_inputs.json"), "w"), indent=1)
ans = {k: [{kk: vv for kk, vv in it.items() if kk in HIDE | {"id"}} for it in d[k]] for k in ("request_scenarios", "directory_scenarios", "response_scenarios", "target_uris")}
json.dump(ans, open(os.path.join(W, "answers", "scenarios_answers.json"), "w"), indent=1)
