#!/usr/bin/env python3
"""Each proposed vector: frozen reader v2 gives the expected result, and the reader with the named rule off does not."""
import json, sys, types
rd, pv, hin = sys.argv[1:4]
SRC = open(rd + "/agent_did_http_v2.py").read(); H = json.load(open(hin))
def mod(src): m = types.ModuleType("r"); exec(compile(src, "m", "exec"), m.__dict__); return m
MUT = {"proposed-forged-does-not-consume-nonce": ("src", "    if mb is None or not _verify(ed25519_from_multibase(mb), sig_value, base.encode(\"utf-8\")):\n        return False, \"signature_invalid\", base\n    if rules.get(\"replay\", True) and \"nonce\" in p:\n        k = keyid + \" \" + p[\"nonce\"]\n        if k in store and store[k] >= now:\n            return False, \"nonce_replayed\", base\n        store[k] = p[\"expires\"]",
         "    if rules.get(\"replay\", True) and \"nonce\" in p:\n        k = keyid + \" \" + p[\"nonce\"]\n        if k in store and store[k] >= now:\n            return False, \"nonce_replayed\", base\n        store[k] = p[\"expires\"]\n    if mb is None or not _verify(ed25519_from_multibase(mb), sig_value, base.encode(\"utf-8\")):\n        return False, \"signature_invalid\", base"),
       "proposed-replay-in-last-second": ("src", "if k in store and store[k] >= now:", "if k in store and store[k] > now:")}
def run(r, v, rules):
    res = r.Resolver({H["did"]: {"vms": {k["id"]: (k["publicKeyMultibase"], k["relationships"]) for k in H["keys"].values()}}})
    now = v.get("now", H["clock"]); store = {}
    def one(q, hd):
        x = r.verify_request(q["method"], q["url"], q["body"], hd, res, now, 300, 300, store, rules); return x["ok"], (None if x["ok"] else x["reason"])
    if "steps" in v: return [one(s["request"], s["headers"]) for s in v["steps"]]
    if "expectedSequence" in v: return [one(v["request"], v["headers"]) for _ in v["expectedSequence"]]
    return one(v["request"], v["headers"])
ok = 0; P = json.load(open(pv))["vectors"]
for v in P:
    exp = list(zip(v["expectedSequence"], v["expectedReasons"])) if "expectedSequence" in v else (v["expected"], v["reason"])
    got = run(mod(SRC), v, {})
    if v["id"] in MUT: _, a, b = MUT[v["id"]]; mg = run(mod(SRC.replace(a, b, 1)), v, {})
    else: mg = run(mod(SRC), v, {"url_normalized": False})
    gv = [g[0] for g in got] if isinstance(got, list) else got[0]; ev = [e[0] for e in exp] if isinstance(exp, list) else exp[0]
    mv = [g[0] for g in mg] if isinstance(mg, list) else mg[0]
    good = got == exp and mv != ev; ok += good
    print("OK " if good else "BAD", v["id"], "frozen:", got, "| rule off:", mg)
print(ok, "of", len(P), "isolate")
