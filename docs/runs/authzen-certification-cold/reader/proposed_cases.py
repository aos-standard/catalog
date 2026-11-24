#!/usr/bin/env python3
"""Proposed scenario cases for gaps the certification scenario leaves open, and a check that each one passes the frozen
PDP and fails the mutant that drops the rule. usage: proposed_cases.py PDP.py out.json"""
import json, sys, types, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scenario_cases as S
SRC = open(sys.argv[1]).read()
def mod(src):
    m = types.ModuleType("p"); exec(compile(src, "pdp", "exec"), m.__dict__); return m
A, R1, R2ARCH = S.A, S.R1, S.R2ARCH
P = [
 {"id": "proposed-basic-props-status-not-id", "level": "Basic Properties", "rule": "fixture rule 5",
  "request": {"path": S.EV, "body": {"subject": A, "action": {"name": "write"},
                                     "resource": {"type": "record", "id": "record-1", "properties": {"status": "archived"}}}},
  "expect": {"status": 200, "decision": False},
  "why": "c-2-2-4 says the deny is based on properties.status, not on the identifier, but it sends record-2, whose fixture status is already archived. Here the identifier is the active record-1 and only the request property says archived.",
  "mutants": ["request properties of subject and resource ignored (stored fixture values only)", "stored fixture properties win over request properties",
              "resource status taken from the resource id, not from properties (record-2 = archived)"]},
 {"id": "proposed-batch-whole-object-override", "level": "Batch Properties", "rule": "c-3-2-7 (whole-object replacement), fixture rules 2 and 5",
  "request": {"path": S.EVS, "body": {"subject": A, "action": {"name": "write"}, "resource": R2ARCH,
                                      "evaluations": [{"resource": {"type": "record", "id": "record-1"}}]}},
  "expect": {"status": 200, "decisions": [True]},
  "why": "In c-3-2-7 the overriding resource carries type, id and properties, so a PDP that merges sub-fields gets the same result. Here the override has no properties: whole replacement gives record-1 as identified (rule 2, permit), while sub-field merging keeps the top-level properties.status archived (rule 5, deny).",
  "mutants": ["batch defaults merged by sub-field instead of replaced whole"]},
 {"id": "proposed-invalid-type-subject-type-number", "level": "Basic Core", "rule": "c-2-4-6",
  "request": {"path": S.EV, "body": {"subject": {"type": 7, "id": "alice"}, "action": {"name": "read"}, "resource": R1}},
  "expect": {"status": 400}, "why": "c-2-4-6 checks an entity given as a string and action.name as a number; nothing checks the type of `type` or `id`.",
  "mutants": ["non-string type or id accepted (only presence checked)"]},
 {"id": "proposed-invalid-type-properties-string", "level": "Basic Core", "rule": "c-2-4-6",
  "request": {"path": S.EV, "body": {"subject": A, "action": {"name": "read"}, "resource": {"type": "record", "id": "record-1", "properties": "active"}}},
  "expect": {"status": 400}, "why": "properties is an object in the information model; no case sends another type.",
  "mutants": ["properties of a non-object type accepted"]},
 {"id": "proposed-invalid-type-context-string", "level": "Basic Core", "rule": "c-2-4-6",
  "request": {"path": S.EV, "body": {"subject": A, "action": {"name": "read"}, "resource": R1, "context": "2025-06-27"}},
  "expect": {"status": 400}, "why": "context is an object; no case sends another type.",
  "mutants": ["context of a non-object type accepted"]},
]
MUT = {}
src_m = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants.py")).read()
M = eval(src_m[src_m.index("M = [") + 4: src_m.index("\nrows = []")])
for name, a, b in M: MUT[name] = (a, b)
def check(p, c):
    try:
        st, h, j = S.call(p, c["request"]["path"], c["request"]["body"])
    except Exception:
        return False  # an uncaught error would be a 500 from a server
    e = c["expect"]
    if st != e["status"]: return False
    if "decision" in e: return isinstance(j, dict) and j.get("decision") is e["decision"]
    if "decisions" in e: return isinstance(j, dict) and [x.get("decision") for x in j.get("evaluations", [])] == e["decisions"]
    return True
rows = []
for c in P:
    frozen = check(mod(SRC), c)
    caught = {m: not check(mod(SRC.replace(*MUT[m], 1)), c) for m in c["mutants"]}
    rows.append({"id": c["id"], "frozen_passes": frozen, "mutants_fail": caught, "isolates": frozen and all(caught.values())})
json.dump({"cases": P, "check": rows}, open(sys.argv[2], "w"), indent=1, ensure_ascii=False)
for r in rows: print("OK " if r["isolates"] else "BAD", r["id"], r["mutants_fail"])
print(sum(r["isolates"] for r in rows), "of", len(rows), "isolate")
