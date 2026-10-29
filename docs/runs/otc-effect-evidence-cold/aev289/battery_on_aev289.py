#!/usr/bin/env python3
"""The 21 mutants of the frozen reader (otc_effect_evidence_cold.py, sha256 90031452...) over the 42 cases of
agent-evidence-vectors ot_federation/corpus/cases.json at 38ed52b (PR #289 merge head).
The reader is not changed; the mutation list is imported from lax_battery.py (v4) unchanged. Only the loader differs:
the corpus is one JSON file (schema aev-ot-federation-cases/v1) with the trail under "case" and the frozen answer
under "expected" {verdict, claims}, instead of an ot-federation-fixtures/v1 directory.
Usage: battery_on_aev289.py <cases.json> <reader_dir> [out.json]"""
import copy, hashlib, json, os, sys, types

READER_SHA = "90031452020ad9ae1c4a6b0f6c7ec7b7fd8471f6201bb1039f95d1350afc0cd6"
BATTERY_SHA = "f4193f428cd9b5a9893dbd661090583e69739fa7156c7f6332303e30889170e4"
CASES_SHA = "7f942b889b8cabf1460576e8923d86704f0e1b86e6f61207fb17c53f5263403b"

def sha(p): return hashlib.sha256(open(p, "rb").read()).hexdigest()

def main(cases_path, reader_dir, out_path=None):
    assert sha(os.path.join(reader_dir, "otc_effect_evidence_cold.py")) == READER_SHA, "reader is not the frozen one"
    assert sha(os.path.join(reader_dir, "lax_battery.py")) == BATTERY_SHA, "battery is not v4"
    cases_sha = sha(cases_path); assert cases_sha == CASES_SHA, f"cases.json differs: {cases_sha}"
    sys.path.insert(0, reader_dir)
    import lax_battery as LB  # MUTATIONS, load_mutant, SRC
    corpus = json.load(open(cases_path, encoding="utf-8"))
    assert corpus["schema"] == "aev-ot-federation-cases/v1", corpus["schema"]
    rows = corpus["cases"]; assert len(rows) == 42, len(rows)
    base = types.ModuleType("base"); exec(compile(LB.SRC, "base", "exec"), base.__dict__)

    # 1. frozen reader vs frozen answers (verdict, and the six claims where the corpus gives them)
    first = []; agree_v = 0; agree_c = 0; have_c = 0
    for r in rows:
        got = base.verdict_for(copy.deepcopy(r["case"]))
        exp = r["expected"]
        ok_v = got["verdict"] == exp["verdict"]; agree_v += ok_v
        got_claims = {k: v[0] for k, v in got.get("_claims", {}).items()} if got.get("_claims") else None
        ok_c = None
        if exp["claims"] is not None:
            have_c += 1; ok_c = got_claims == exp["claims"]; agree_c += bool(ok_c)
        first.append({"id": r["id"], "fault_shape": r["fault_shape"], "expected_verdict": exp["verdict"],
                      "got_verdict": got["verdict"], "verdict_agrees": ok_v, "expected_claims": exp["claims"],
                      "got_claims": got_claims, "claims_agree": ok_c, "got_reason": got["reason"]})
    print(f"frozen reader over 42 cases: verdict agrees on {agree_v}/42; six claims agree on {agree_c}/{have_c} (claims given)")
    for f in first:
        if not f["verdict_agrees"] or f["claims_agree"] is False:
            print("  DISAGREE", f["id"], f["fault_shape"], "expected", f["expected_verdict"], f["expected_claims"], "got", f["got_verdict"], f["got_claims"], "|", f["got_reason"])

    # 2. the 21 mutants
    print(f"\n{'mutation':64} {'disagrees on':>12}  caught by (case ids)")
    results = []; survivors = []; misbuilt = []
    for name, old, new in LB.MUTATIONS:
        mod = LB.load_mutant(name, old, new)
        got = {r["id"]: mod.verdict_for(copy.deepcopy(r["case"])) for r in rows}
        crashed = [k for k, v in got.items() if v["reason"].startswith("malformed: reader could not read")]
        diff = [r["id"] for r in rows if got[r["id"]]["verdict"] != r["expected"]["verdict"]]
        label = f"MISBUILT (raises on {len(crashed)})" if crashed else (", ".join(diff) if diff else "SURVIVOR")
        print(f"{name:64} {len(diff):>12}  {label}")
        results.append({"mutation": name, "disagrees_on": diff, "raises_on": crashed,
                        "status": "MISBUILT" if crashed else ("CAUGHT" if diff else "SURVIVOR")})
        if crashed: misbuilt.append(name)
        elif not diff: survivors.append(name)
    print(f"\n{len(LB.MUTATIONS)} mutants, {len(LB.MUTATIONS)-len(survivors)-len(misbuilt)} caught, {len(survivors)} survivors: {survivors}, {len(misbuilt)} misbuilt: {misbuilt}")
    if out_path:
        json.dump({"corpus": {"path": "packaging/agent_evidence_vectors/ot_federation/corpus/cases.json", "sha256": cases_sha,
                              "repo": "probityai/agent-evidence-vectors", "commit": "38ed52b00cfc9628f7a4775d7b1cb8ff9c5a9301", "schema": corpus["schema"]},
                   "reader_sha256": READER_SHA, "battery_sha256": BATTERY_SHA,
                   "frozen_reader": {"verdict_agrees": agree_v, "claims_agree": agree_c, "claims_given": have_c, "cases": first},
                   "mutants": results, "survivors": survivors, "misbuilt": misbuilt}, open(out_path, "w"), indent=1, ensure_ascii=False)
    return 0

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
