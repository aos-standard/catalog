#!/usr/bin/env python3
"""(Mutants that change more than one rule are in mutants_v2_src.py.) One rule of frozen reader v2 changed at a time; rerun the 84 HTTP vectors + interop; count verdict changes.
usage: mutants_v2.py READER_DIR http_inputs.json http_expected_SEALED.json v1_inputs.json out.json"""
import json, sys, importlib.util, copy, base64, hashlib
rd, hin, hexp, v1in, out = sys.argv[1:6]
H = json.load(open(hin)); E = {e["n"]: e for e in json.load(open(hexp))}
def load():
    spec = importlib.util.spec_from_file_location("r", rd + "/agent_did_http_v2.py"); r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r); return r
def run(r, rules):
    docs = {H["did"]: {"vms": {k["id"]: (k["publicKeyMultibase"], k["relationships"]) for k in H["keys"].values()}}}
    res = r.Resolver(docs); got = {}
    for v in H["vectors"]:
        now = v.get("now", H["clock"]); skew = v.get("maxCreatedSkewSeconds", 300); q = v["request"]; store = {}
        def one():
            try: return r.verify_request(q["method"], q["url"], q["body"], v["headers"], res, now, skew, 300, store, rules)["ok"]
            except Exception: return False
        got[v["n"]] = [one() for _ in range(v["repeat"])] if "repeat" in v else one()
    return got
def exp(n):
    e = E[n]; return e["expectedSequence"] if "expectedSequence" in e else e["expected"]
RULES = ["tag", "alg", "nonce_required", "nonce_grammar", "keyid_bound", "required", "order", "skew", "expires_ge_created",
         "lifetime", "now_le_expires", "url_normalized", "keyid_in_doc", "assertion_method", "replay", "digest"]
results = []
base = run(load(), {})
assert all(base[n] == exp(n) for n in base), "baseline must agree"
def record(name, got):
    caught = [E[n]["id"] for n in got if got[n] != exp(n)]
    results.append({"mutant": name, "caught_by": caught, "caught": bool(caught)})
for k in RULES:
    record("rule off: " + k, run(load(), {k: False}))
# code mutants
r = load(); od = r.derived
def d1(name, method, url):
    v = od(name, method, url); return "" if name == "@query" and v == "?" else v
r.derived = d1; record("@query empty string when the URL has no query", run(r, {}))
r = load(); od2 = r.derived
def d2(name, method, url):
    if name == "@authority":
        u = r.urlsplit(url); return (u.hostname or "") + (":%d" % u.port if u.port is not None else "")
    return od2(name, method, url)
r.derived = d2; record("explicit default port kept in @authority", run(r, {}))
r = load(); of4 = r._field
def f4(headers, name):
    vals = [v for k, v in headers.items() if k == name.title() or k == "Signature-Input" and name == "signature-input" or k == "Agent-DID" and name == "agent-did" or k == "Content-Digest" and name == "content-digest"]
    return ", ".join(v.strip() for v in vals) if vals else None
r._field = f4; record("field names matched case-sensitively (canonical capitalisation only)", run(r, {}))
r = load(); ou = r.url_normalized
r.url_normalized = lambda u: ou(u) or "%2e" in u.lower(); record("percent-encoded dot segments allowed", run(r, {}))
r = load(); ou2 = r.url_normalized
r.url_normalized = lambda u: ou2(u.lower()); record("URL normalization ignores case", run(r, {}))
json.dump(results, open(out, "w"), indent=1, ensure_ascii=False)
for x in results: print("CAUGHT " if x["caught"] else "SURVIVE", x["mutant"], ("<- " + ", ".join(x["caught_by"][:4])) if x["caught"] else "")
print(sum(x["caught"] for x in results), "of", len(results), "caught")
