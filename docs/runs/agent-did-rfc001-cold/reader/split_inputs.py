#!/usr/bin/env python3
"""Split the RFC-001 fixture files into inputs (seen before freeze) and expected values (not seen until scoring)."""
import json, sys, os
src, out = sys.argv[1], sys.argv[2]
def L(n): return json.load(open(os.path.join(src, n)))
inp, exp = {}, {}
j = L("jcs-vectors.json")
inp["jcs_documents"] = [{"name": d["name"], "input": d["input"]} for d in j["documents"]]
exp["jcs_documents"] = [d["expected"] for d in j["documents"]]
inp["jcs_numbers"] = [{"ieee754": d["ieee754"]} for d in j["numbers"]]
exp["jcs_numbers"] = [{"error": d["error"]} if "error" in d else d["expected"] for d in j["numbers"]]
c = L("canonical-document-reference.json")
inp["document_ref"] = {"canonicalization": c["canonicalization"], "document": c["document"]}
exp["document_ref"] = c["expectedDocumentRef"]
m = L("metadata-commitment-vectors.json")
inp["hmac"] = [{k: v for k, v in d.items() if k != "expected"} for d in m["hmacSha256"]]
exp["hmac"] = [d["expected"] for d in m["hmacSha256"]]
inp["legacy"] = [{k: v for k, v in d.items() if k != "expected"} for d in m["legacySha256"]]
exp["legacy"] = [d["expected"] for d in m["legacySha256"]]
iv = L("interop-vectors.json")
inp["interop"], exp["interop"] = {}, {}
for name, v in iv["vectors"].items():
    h = dict(v["httpVector"])
    e = {"signatureBase": h.pop("signatureBase"), "contentDigest": h.pop("contentDigest")}
    inp["interop"][name] = {"did": v["did"], "controller": v["controller"], "verificationMethod": v["verificationMethod"],
                            "messageVector": v["messageVector"], "httpVector": h}
    exp["interop"][name] = e
json.dump(inp, open(os.path.join(out, "inputs.json"), "w"), indent=1, ensure_ascii=False)
json.dump(exp, open(os.path.join(out, "expected_SEALED.json"), "w"), indent=1, ensure_ascii=False)
print("ok")
