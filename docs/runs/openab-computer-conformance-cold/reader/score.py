#!/usr/bin/env python3
"""Score openab_check.py on the three vector files. Two grades per case where the vector has a free-text value:
'kind' (allow vs deny, stop vs redial) and 'exact' (the full expected value). Usage: score.py <reader.py> <conformance dir> <out.json>"""
import hashlib, importlib.util, json, sys
from pathlib import Path
rp = Path(sys.argv[1]).resolve(); C = Path(sys.argv[2])
sp = importlib.util.spec_from_file_location("r", rp); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
rows = []
def add(set_, name, exp, got, kind_ok, exact_ok):
    rows.append({"set": set_, "name": name, "expected": exp, "got": got, "kind": kind_ok, "exact": exact_ok})
a = json.loads((C / "auth_vectors.json").read_text())
for c in a["cases"]:
    if "validate" in c:
        got = m.validate(c["config"]); add("auth", c["name"], c["validate"], got, got == c["validate"], got == c["validate"]); continue
    got = m.decide(c["config"], c.get("headers", {}), c.get("remoteIsLoopback", False)); e = c["expect"]
    add("auth", c["name"], e, got, set(got) == set(e), got == e)
r = json.loads((C / "reverse_attach_vectors.json").read_text())
for c in r["close_code"]:
    got = m.close_disposition(c["code"]); e = c["expect"]; add("close_code", str(c["code"]), e, got, set(got) == set(e), got == e)
for c in r["handshake_status"]:
    got = m.handshake_disposition(c["status"]); e = c["expect"]; add("handshake", str(c["status"]), e, got, set(got) == set(e), got == e)
for c in r["attach_url"]:
    got = m.attach_url(c["runtime"], c["session"]); add("attach_url", c["runtime"] + " " + c["session"], c["expect"], got, got == c["expect"], got == c["expect"])
w = json.loads((C / "mcp_wire_vectors.json").read_text())
for c in w["cases"]:
    got = m.answer(c["request"], c.get("profile")); e = c["expect"]; ok = True
    if e.get("response") != (got is not None): ok = False
    if "error" in e and (got or {}).get("error") != e["error"]: ok = False
    if "result_subset" in e:
        res = (got or {}).get("result")
        if not isinstance(res, dict) or any(res.get(k) != v for k, v in e["result_subset"].items()): ok = False
    if "result_tools_shape" in e:
        t = ((got or {}).get("result") or {}).get("tools")
        shape = isinstance(t, list) and len(t) > 0 and all(isinstance(x, dict) and {"name", "description", "inputSchema"} <= set(x) for x in t)
        if shape != e["result_tools_shape"]: ok = False
    add("wire", c["name"], e, got, ok, ok)
tally = {}
for x in rows:
    t = tally.setdefault(x["set"], [0, 0, 0]); t[0] += x["kind"]; t[1] += x["exact"]; t[2] += 1
out = {"reader_sha256": hashlib.sha256(rp.read_bytes()).hexdigest(), "by_set": {k: {"kind": "%d/%d" % (v[0], v[2]), "exact": "%d/%d" % (v[1], v[2])} for k, v in tally.items()}, "rows": rows}
Path(sys.argv[3]).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print(json.dumps(out["by_set"]))
for x in rows:
    if not x["exact"]:
        print(("KIND " if not x["kind"] else "name ") + x["set"], x["name"], "| exp", json.dumps(x["expected"]), "| got", json.dumps(x["got"]))
