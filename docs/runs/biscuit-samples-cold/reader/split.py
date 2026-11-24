"""Split samples.json: inputs = root public key, per validation the token filename and authorizer_code.
Sealed = titles, decoded token blocks, world, result, revocation_ids, validation names."""
import json, sys, os
src, out = sys.argv[1], sys.argv[2]; os.makedirs(out, exist_ok=True)
d = json.load(open(src))
inp = {"root_public_key": d["root_public_key"], "cases": []}; exp = {"cases": []}
n = 0
for ti, t in enumerate(d["testcases"]):
    for vname, v in t["validations"].items():
        inp["cases"].append({"n": n, "test": ti, "filename": t["filename"], "authorizer_code": v["authorizer_code"]})
        exp["cases"].append({"n": n, "test": ti, "title": t["title"], "validation": vname, "token": t["token"],
                             "world": v["world"], "result": v["result"], "revocation_ids": v["revocation_ids"]})
        n += 1
json.dump(inp, open(out + "/inputs.json", "w"), indent=1); json.dump(exp, open(out + "/expected_SEALED.json", "w"), indent=1)
print(n, "cases")
