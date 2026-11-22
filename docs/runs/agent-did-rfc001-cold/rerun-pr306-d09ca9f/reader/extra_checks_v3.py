#!/usr/bin/env python3
"""Code mutants of mutants_v2.py that are not rule toggles, rerun on #306; and the proposed IPv6 vector against
the frozen reader and against the same reader with brackets kept in @authority.
usage: extra_checks_v3.py READER_DIR http_inputs.json http_expected_SEALED.json proposed.json out.json"""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))); import run_v3
rd, hin, hexp, pv, out = sys.argv[1:6]
H = json.load(open(hin)); E = {e["n"]: e for e in json.load(open(hexp))}
SRC = open(os.path.join(rd, "agent_did_http_v2.py")).read()
BRACKETS = ('        host = u.hostname or ""', '        host = ("[" + u.hostname + "]") if (u.hostname and ":" in u.hostname) else (u.hostname or "")')
def caught(src):
    o = []
    for x in run_v3.run(run_v3.load("m", src), H):
        e = E[x["n"]]; ex = [s["expected"] for s in e["steps"]] if "steps" in e else e.get("expectedSequence", e.get("expected"))
        g = [s[0] for s in x["steps"]] if "steps" in x else x.get("sequence", x.get("ok"))
        if g != ex and e["id"] != "reject-url-non-canonical-ipv4-literal": o.append(e["id"])  # baseline difference excluded
    return o
M = {"percent-encoded dot segments allowed": [('        if dec in (".", ".."):\n            return False', '        if seg in (".", ".."):\n            return False')],
     "@query empty string when the URL has no query": [('        return "?" + u.query', '        return ("?" + u.query) if u.query else ""')],
     "explicit default port kept in @authority": [('port is not None and port != default', 'port is not None')],
     "IPv6 RFC 5952 check off (reader as frozen, brackets dropped)": [('        if a.compressed != host[1:-1]:\n            return False', '        if False:\n            return False')],
     "IPv6 RFC 5952 check off, with brackets kept in @authority": [('        if a.compressed != host[1:-1]:\n            return False', '        if False:\n            return False'), BRACKETS]}
res = {"mutants": [], "proposed": []}
for k, reps in M.items():
    s = SRC
    for a, b in reps: assert a in s, k; s = s.replace(a, b, 1)
    c = caught(s); res["mutants"].append({"mutant": k, "caught_by": c, "caught": bool(c)})
for v in json.load(open(pv))["vectors"]:
    H2 = dict(H, vectors=[{"n": 0, "request": v["request"], "headers": v["headers"]}])
    for name, s in (("frozen v2", SRC), ("v2 with brackets kept", SRC.replace(*BRACKETS, 1))):
        x = run_v3.run(run_v3.load("p", s), H2)[0]; res["proposed"].append({"id": v["id"], "reader": name, "ok": x["ok"], "reason": x["reason"], "expected": v["expected"]})
json.dump(res, open(out, "w"), indent=1, ensure_ascii=False)
for m in res["mutants"]: print("CAUGHT " if m["caught"] else "SURVIVE", m["mutant"], m["caught_by"][:2])
for p in res["proposed"]: print(p)
