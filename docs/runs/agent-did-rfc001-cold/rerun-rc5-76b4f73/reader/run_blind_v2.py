#!/usr/bin/env python3
"""Run reader v2 on the sealed-input files only. usage: run_blind_v2.py READER_DIR http_inputs.json v1_inputs.json out.json"""
import json, sys, importlib.util
rd, hin, v1in, out = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("r", rd + "/agent_did_http_v2.py"); r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
RULES = json.loads(sys.argv[5]) if len(sys.argv) > 5 else {}
H = json.load(open(hin))
docs = {H["did"]: {"vms": {k["id"]: (k["publicKeyMultibase"], k["relationships"]) for k in H["keys"].values()}}}
res = r.Resolver(docs)  # R2: one agent document holding every key, registered under the agent DID only
rows = []
for v in H["vectors"]:
    now = v.get("now", H["clock"]); skew = v.get("maxCreatedSkewSeconds", 300)
    q = v["request"]; store = {}
    def one():
        try:
            return r.verify_request(q["method"], q["url"], q["body"], v["headers"], res, now, skew, 300, store, RULES)
        except Exception as e:
            return {"ok": False, "reason": "exception:" + type(e).__name__, "base": None, "label": None}
    if "repeat" in v:
        seq = [one() for _ in range(v["repeat"])]
        rows.append({"n": v["n"], "sequence": [s["ok"] for s in seq], "reasons": [None if s["ok"] else s["reason"] for s in seq], "base": seq[0]["base"]})
    else:
        x = one(); rows.append({"n": v["n"], "ok": x["ok"], "reason": None if x["ok"] else x["reason"], "base": x["base"]})
I = json.load(open(v1in))["interop"]
inter = {}
for name, v in I.items():
    vm = v["verificationMethod"]; hv = v["httpVector"]
    rr = r.Resolver({v["did"]: {"vms": {vm["id"]: (vm["publicKeyMultibase"], ["assertionMethod"])}}})  # R7
    try: mv = r.verify_message(vm["publicKeyMultibase"], v["messageVector"]["payload"], v["messageVector"]["signatureHex"])
    except Exception as e: mv = "exception:" + type(e).__name__
    try:
        x = r.verify_request(hv["method"], hv["url"], hv["body"], hv["headers"], rr, H["clock"],
                             hv.get("maxCreatedSkewSeconds", 300), hv.get("maxSignatureLifetimeSeconds", 300), {}, RULES)
    except Exception as e:
        x = {"ok": False, "reason": "exception:" + type(e).__name__, "base": None}
    inter[name] = {"message_ok": mv, "http_ok": x["ok"], "http_reason": x["reason"], "base": x["base"], "content_digest": r.content_digest(hv["body"])}
json.dump({"now_default": H["clock"], "rules": RULES, "http": rows, "interop": inter}, open(out, "w"), indent=1, ensure_ascii=False)
print("http", len(rows), "interop", len(inter))
