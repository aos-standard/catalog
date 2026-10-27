#!/usr/bin/env python3
"""Mutation battery over the frozen reader (corpus_adequacy, applied to this second implementation).
Each mutation is one textual edit of otc_effect_evidence_cold.py that drops or bends one check; the mutant
is run over every case of a fixture set and compared with the manifest. A mutant that still agrees with
the manifest on every case is a SURVIVOR: a fault the sealed set does not exercise. Usage: lax_battery.py <fixtures_dir>"""
import json, os, sys, types

SRC = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "otc_effect_evidence_cold.py"), encoding="utf-8").read()
MUTATIONS = [
 ("M01 ignore decision.approved",               "if not d[\"approved\"]:", "if False:"),
 ("M02 ignore reviewer.approved on verify/escalate", "elif dec in NEEDS_REVIEWER and not (isinstance(rev, dict) and rev.get(\"approved\") is True):", "elif False:"),
 ("M03 ignore envelope/evidence binding to the proposal", "if env_rid is not None and env_rid != pid:", "if False:"),
 ("M03b ignore evidence proposal_id binding",   "elif ev_pid is not None and ev_pid != pid:", "elif False:"),
 ("M04 executed=false with APPLIED twin is only NOT_ESTABLISHED", "if twin_applied or obs is not None:\n            out[CLAIMS[0]] = (\"CONTRADICTED\"", "if twin_applied or obs is not None:\n            out[CLAIMS[0]] = (\"NOT_ESTABLISHED\""),
 ("M05 assume executions=1 when absent",        "if \"executions\" not in e:\n        out[CLAIMS[1]] = (\"NOT_ESTABLISHED\"", "if False:\n        out[CLAIMS[1]] = (\"NOT_ESTABLISHED\""),
 ("M06 accept any executions count",            "elif e[\"executions\"] == 1:", "elif True:"),
 ("M07 ignore twin operation_id (call_binding)", "elif twin.get(\"operation_id\") != pid:", "elif False:"),
 ("M08 ignore twin status APPLIED",             "elif not twin_applied:\n        out[CLAIMS[3]]", "elif False:\n        out[CLAIMS[3]]"),
 ("M09 ignore twin zone_id",                    "elif twin.get(\"zone_id\") != cl[\"zone_id\"]:", "elif False:"),
 ("M10 ignore twin new_setpoint_c (observation only)", "elif not (is_num(twin.get(\"new_setpoint_c\")) and twin[\"new_setpoint_c\"] == cl[\"setpoint_c\"]):", "elif False:"),
 ("M11 ignore observed_setpoint_c (twin only)", "elif obs[\"observed_setpoint_c\"] != cl[\"setpoint_c\"]:", "elif False:"),
 ("M12 null observation counts as observed",    "elif obs is None:\n        out[CLAIMS[3]] = (\"NOT_ESTABLISHED\", \"effect not observed\")", "elif False:\n        pass"),
 ("M13 assume dispatch time = twin sim_time_s when absent", "disp = e.get(\"dispatched_at_sim_s\")", "disp = e.get(\"dispatched_at_sim_s\")\n    if disp is None and isinstance(twin, dict): disp = twin.get(\"sim_time_s\")"),
 ("M14 assume observation time = dispatch time when absent", "elif obs is None or \"observed_at_sim_s\" not in obs or not is_int(obs[\"observed_at_sim_s\"]):", "elif obs is not None and \"observed_at_sim_s\" not in obs and (obs.__setitem__(\"observed_at_sim_s\", disp) or False):"),
 ("M15 observed == dispatched is a contradiction (strict after)", "elif obs[\"observed_at_sim_s\"] < disp:", "elif obs[\"observed_at_sim_s\"] <= disp:"),
 ("M16 ignore evidence digest",                 "elif canonical_sha256(c[\"remora_evidence\"]) != want:", "elif False:"),
 ("M17 digest with ensure_ascii=True",          "ensure_ascii=False", "ensure_ascii=True"),
 ("M18 digest without sort_keys",               "sort_keys=True, separators", "sort_keys=False, separators"),
 ("M19 digest with default separators",         "separators=(\",\", \":\"),\n                                     ensure_ascii", "separators=(\", \", \": \"),\n                                     ensure_ascii"),
 ("M20 malformed case answered ESTABLISHED",    "return {\"verdict\": \"NOT_ESTABLISHED\", \"reason\": \"malformed: not an ot-federation-case/v1 of the schema's shape\"}", "return {\"verdict\": \"ESTABLISHED\", \"reason\": \"malformed but accepted\"}"),
]

def load_mutant(name, old, new):
    assert SRC.count(old) == 1, f"{name}: anchor not unique ({SRC.count(old)})"
    mod = types.ModuleType("mutant"); exec(compile(SRC.replace(old, new), name, "exec"), mod.__dict__); return mod

def main(fixtures):
    manifest = json.load(open(os.path.join(fixtures, "manifest.json")))
    cases = []
    for f in manifest["files"]:
        cases.append(json.load(open(os.path.join(fixtures, f["path"]), encoding="utf-8")))
    exp = {c["case_id"]: ("ESTABLISHED" if c["kind"] == "positive" else c["expected_verdict"]) for c in manifest["cases"]}
    base = types.ModuleType("base"); exec(compile(SRC, "base", "exec"), base.__dict__)
    assert all(base.verdict_for(c)["verdict"] == exp[c["case_id"]] for c in cases), "frozen reader must agree first"
    survivors = []
    print(f"{'mutation':64} {'disagrees on':>12}  caught by")
    for name, old, new in MUTATIONS:
        mod = load_mutant(name, old, new)
        diff = [c["case_id"] for c in cases if mod.verdict_for(c)["verdict"] != exp[c["case_id"]]]
        tag = ", ".join(sorted({d.split("-", 1)[0] if d.startswith("pos") else d.rsplit("-", 5)[0] for d in diff}))
        print(f"{name:64} {len(diff):>12}  {tag if diff else 'SURVIVOR'}")
        if not diff: survivors.append(name)
    print(f"\n{len(MUTATIONS)} mutants, {len(MUTATIONS)-len(survivors)} caught, {len(survivors)} survivors: {survivors}")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
