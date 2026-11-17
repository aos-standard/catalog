#!/usr/bin/env python3
"""Check johnInarti's statement in x402#3758 (comment 6937265029) about d9027a5 against the two source files:
the 14 earlier runs and everything else in the base file are unchanged; the seven fixtures equal ours (catalog 036e9ab,
e376c64b) apart from $ref paths; each of our runs only lost levels after its first non-passing level."""
import json, sys
new = json.load(open(sys.argv[1])); base = json.load(open(sys.argv[2])); ours = json.load(open(sys.argv[3]))
LV = ["integrity", "authentic", "trusted", "settlement", "delivery"]
out = {}
out["base_members_unchanged"] = {k: new.get(k) == v for k, v in base.items() if k != "expectedVerdicts"}
bids = [r["id"] for r in base["expectedVerdicts"]]
out["earlier_runs_unchanged"] = all(next(r for r in new["expectedVerdicts"] if r["id"] == i) == next(r for r in base["expectedVerdicts"] if r["id"] == i) for i in bids)
out["new_top_level_members"] = sorted(set(new) - set(base))
fx_new = new["negative"]["fixtures"] if "fixtures" in new.get("negative", {}) else new["negative"]
fx_ours = ours.get("fixtures", ours)
def norm(x):
    s = json.dumps(x, sort_keys=True)
    return s.replace('"/negative/fixtures/', '"/fixtures/').replace('"#/negative/fixtures/', '"#/fixtures/')
out["fixtures_equal_modulo_ref"] = {k: (k in fx_new and norm(fx_new[k]) == norm(v)) for k, v in fx_ours.items()} if isinstance(fx_ours, dict) else "shape?"
runs_ours = ours.get("expectedVerdicts", [])
res = []
for r in runs_ours:
    n = next((x for x in new["expectedVerdicts"] if x["id"] == r["id"]), None)
    if n is None: res.append({"id": r["id"], "present": False}); continue
    first = next((lv for lv in LV if r["levels"][lv] != "pass"), None)
    keep = LV if first is None else LV[:LV.index(first) + 1]
    same_rest = {k: (norm(n.get(k)) == norm(r.get(k))) for k in r if k not in ("levels",)}
    res.append({"id": r["id"], "levels_kept_equal": {lv: n["levels"].get(lv) == r["levels"][lv] for lv in keep},
                "levels_dropped": sorted(set(r["levels"]) - set(n["levels"])), "dropped_only_after_first": set(n["levels"]) == set(keep),
                "other_members_equal": same_rest})
out["our_runs"] = res
print(json.dumps(out, indent=1, sort_keys=True))
