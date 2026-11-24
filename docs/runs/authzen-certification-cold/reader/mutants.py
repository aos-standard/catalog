#!/usr/bin/env python3
"""One rule of the frozen PDP changed at a time (source replacement); rerun the transcribed scenario.
A mutant survives when no scenario check changes from the frozen PDP's result. usage: mutants.py PDP.py out.json"""
import json, sys, types, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scenario_cases as S
SRC = open(sys.argv[1]).read()
def mod(src):
    m = types.ModuleType("p"); exec(compile(src, "pdp", "exec"), m.__dict__); return m
base = {r["id"]: r["ok"] for r in S.run(mod(SRC))}
M = [
 ("request properties of subject and resource ignored (stored fixture values only)",
  "    sp = _props(SUBJECTS[skey], subject.get(\"properties\"))\n    rp = _props(RESOURCES[rkey], resource.get(\"properties\"))",
  "    sp = dict(SUBJECTS[skey])\n    rp = dict(RESOURCES[rkey])"),
 ("stored fixture properties win over request properties",
  "    out = dict(stored or {})\n    out.update(given or {})", "    out = dict(given or {})\n    out.update(stored or {})"),
 ("resource status taken from the resource id, not from properties (record-2 = archived)",
  "        if rp.get(\"status\") == \"archived\":", "        if rkey == (\"record\", \"record-2\"):"),
 ("rule 5 wins for alice even with role admin in the request",
  "            return sp.get(\"role\") == \"admin\"           # rules 5, 6", "            return sp.get(\"role\") == \"admin\" and skey != (\"user\", \"alice\")"),
 ("soft compared loosely (any truthy value)", "        return ap.get(\"soft\") is True", "        return bool(ap.get(\"soft\"))"),
 ("batch defaults merged by sub-field instead of replaced whole",
  "            if k in ev:\n                m[k] = ev[k]", "            if k in ev:\n                m[k] = dict(req.get(k) or {}, **ev[k]) if isinstance(ev[k], dict) and isinstance(req.get(k), dict) else ev[k]"),
 ("per-evaluation context replaces nothing (top-level context always used)",
  "        for k in (\"subject\", \"action\", \"resource\", \"context\"):\n            # R7", "        for k in (\"subject\", \"action\", \"resource\"):\n            # R7"),
 ("short-circuit semantics ignored (always execute_all)",
  "        if sem == \"deny_on_first_deny\" and not d:\n            break", "        if False:\n            break"),
 ("unknown evaluations_semantic accepted",
  "        raise BadRequest(\"unknown evaluations_semantic\")", "        sem = \"execute_all\""),
 ("properties of a non-object type accepted",
  "    if \"properties\" in e and not isinstance(e[\"properties\"], dict):\n        raise BadRequest", "    if False:\n        raise BadRequest"),
 ("non-string type or id accepted (only presence checked)",
  "        if not _is_str(e.get(\"type\")):", "        if e.get(\"type\") is None:"),
 ("context of a non-object type accepted",
  "    if \"context\" in req and not isinstance(req[\"context\"], dict):\n        raise BadRequest(\"context must be an object\")", "    pass"),
 ("a non-object top-level JSON value accepted as an empty request",
  "    if not isinstance(req, dict):\n        return reply(400, \"the top-level element must be a JSON object\")", "    if not isinstance(req, dict):\n        req = {}"),
 ("page token not bound to the request (a changed request is accepted)",
  "        if d != digest:\n            raise BadRequest(\"request changed mid-pagination\")", "        pass"),
 ("negative or non-integer page.limit accepted",
  "        raise BadRequest(\"page.limit must be a non-negative integer\")", "        limit = None"),
 ("X-Request-ID not echoed", "        out_h[\"X-Request-ID\"] = rid", "        pass"),
 ("Content-Type not checked", "    if ct is None or ct.split(\";\")[0].strip().lower() != \"application/json\":", "    if False:"),
 ("subject search filters to the given subject.id",
  "            if st != t:\n                continue\n            s =", "            if st != t or (req[\"subject\"].get(\"id\") not in (None, sid)):\n                continue\n            s ="),
 ("unknown search type is a bad request",
  "    results = []\n    if kind == \"subject\":", "    results = []\n    if kind == \"subject\" and req[\"subject\"][\"type\"] not in {t for t, _ in SUBJECTS}:\n        raise BadRequest(\"unknown type\")\n    if kind == \"subject\":"),
 ("decision returned as a string", "    return {\"decision\": decide(req[\"subject\"], req[\"action\"], req[\"resource\"], req.get(\"context\"))}",
  "    return {\"decision\": str(decide(req[\"subject\"], req[\"action\"], req[\"resource\"], req.get(\"context\"))).lower()}"),
 ("metadata endpoint missing", "    if path == WELL_KNOWN:", "    if False:"),
]
rows = []
for name, a, b in M:
    assert SRC.count(a) == 1, name
    got = {r["id"]: r["ok"] for r in S.run(mod(SRC.replace(a, b, 1)))}
    caught = [k for k in got if got[k] != base[k]]
    rows.append({"mutant": name, "caught_by": caught, "caught": bool(caught)})
json.dump({"baseline_fail": [k for k, v in base.items() if not v], "mutants": rows}, open(sys.argv[2], "w"), indent=1)
for r in rows: print("CAUGHT " if r["caught"] else "SURVIVE", r["mutant"], ("<- " + ", ".join(r["caught_by"][:3])) if r["caught"] else "")
print(sum(r["caught"] for r in rows), "of", len(rows), "caught")
