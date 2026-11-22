#!/usr/bin/env python3
"""Run a reader module (frozen v2 unchanged, or a mutant of it) on the #306 inputs, including steps[].
usage: run_v3.py READER_FILE http_inputs.json out.json [rules-json]"""
import json, sys, types

def load(path, src=None):
    m = types.ModuleType("r"); exec(compile(src if src is not None else open(path).read(), path, "exec"), m.__dict__); return m

def run(r, H, rules=None):
    rules = rules or {}
    res = r.Resolver({H["did"]: {"vms": {k["id"]: (k["publicKeyMultibase"], k["relationships"]) for k in H["keys"].values()}}})
    rows = []
    for v in H["vectors"]:
        skew = v.get("maxCreatedSkewSeconds", 300); q = v["request"]; store = {}
        def one(headers, now):
            try:
                x = r.verify_request(q["method"], q["url"], q["body"], headers, res, now, skew, 300, store, rules)
            except Exception as e:
                x = {"ok": False, "reason": "exception:" + type(e).__name__, "base": None}
            return x
        vnow = v.get("now", H["clock"])
        if "steps" in v:
            xs = [one(s.get("headers", v["headers"]), s.get("now", vnow)) for s in v["steps"]]
            rows.append({"n": v["n"], "steps": [[x["ok"], None if x["ok"] else x["reason"]] for x in xs]})
        elif "repeat" in v:
            xs = [one(v["headers"], vnow) for _ in range(v["repeat"])]
            rows.append({"n": v["n"], "sequence": [x["ok"] for x in xs], "reasons": [None if x["ok"] else x["reason"] for x in xs]})
        else:
            x = one(v["headers"], vnow); rows.append({"n": v["n"], "ok": x["ok"], "reason": None if x["ok"] else x["reason"], "base": x["base"]})
    return rows

if __name__ == "__main__":
    rf, hin, out = sys.argv[1:4]; rules = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
    rows = run(load(rf), json.load(open(hin)), rules)
    json.dump({"rules": rules, "http": rows}, open(out, "w"), indent=1, ensure_ascii=False); print(len(rows), "rows")
