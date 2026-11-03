#!/usr/bin/env python3
"""Runs a reader on blind/inputs.json only. Usage: run_blind.py <reader.py> <inputs.json> <out.json> <now>"""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("reader", sys.argv[1]); R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
inp = json.load(open(sys.argv[2])); now = int(sys.argv[4])
def safe(f, *a):
    try: return f(*a)
    except Exception as e: return {"error": type(e).__name__ + ": " + str(e)}
out = {"now": now}
out["jcs_documents"] = [safe(lambda r: R.jcs_text(r).decode("utf-8"), d["input"]) for d in inp["jcs_documents"]]
out["jcs_numbers"] = [safe(R.jcs_number_from_hex, d["ieee754"]) for d in inp["jcs_numbers"]]
out["document_ref"] = safe(R.document_ref, inp["document_ref"]["document"])
out["hmac"] = [safe(R.hmac_commitment, d["value"], d["salt"]) for d in inp["hmac"]]
out["legacy"] = [safe(R.legacy_commitment, d["value"]) for d in inp["legacy"]]
out["interop"] = {}
for name, v in inp["interop"].items():
    h = v["httpVector"]
    out["interop"][name] = {
        "message_valid": safe(R.verify_message, v["verificationMethod"], v["messageVector"]["payload"], v["messageVector"]["signatureHex"]),
        "content_digest": safe(R.content_digest, h["body"]),
        "http": safe(R.verify_http, h["method"], h["url"], h["body"], h["headers"], v["verificationMethod"], now, h["maxCreatedSkewSeconds"], set()),
    }
json.dump(out, open(sys.argv[3], "w"), indent=1, ensure_ascii=False)
errs = json.dumps(out).count('"error"')
print("written; error entries:", errs)
