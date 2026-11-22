"""Split http-verification-vectors.json (format with steps[]) into inputs and sealed expected values.
Inputs: request, headers, now, maxCreatedSkewSeconds, repeat count, and per step: headers, now.
Sealed: id, rule, description, signatureBase, expected, reason, expectedSequence, expectedReasons, step expected/reason."""
import json, sys, os
src, out = sys.argv[1], sys.argv[2]
o = json.load(open(src, encoding="utf-8")); os.makedirs(out, exist_ok=True)
INPUT = ("request", "headers", "now", "maxCreatedSkewSeconds")
inp = {"clock": o["clock"], "did": o["did"], "otherDid": o["otherDid"], "controller": o["controller"],
       "keys": {k: {"id": v["id"], "publicKeyMultibase": v["publicKeyMultibase"], "relationships": v["relationships"]} for k, v in o["keys"].items()},
       "vectors": []}
sealed = []
for i, v in enumerate(o["vectors"]):
    x = {"n": i, **{k: v[k] for k in INPUT if k in v}}
    if "expectedSequence" in v: x["repeat"] = len(v["expectedSequence"])
    if "steps" in v: x["steps"] = [{k: s[k] for k in ("headers", "now") if k in s} for s in v["steps"]]
    inp["vectors"].append(x)
    e = {"n": i, **{k: v[k] for k in v if k not in INPUT and k != "steps"}}
    if "steps" in v: e["steps"] = [{k: s[k] for k in ("expected", "reason") if k in s} for s in v["steps"]]
    sealed.append(e)
json.dump(inp, open(f"{out}/http_inputs.json", "w"), indent=1, ensure_ascii=False)
json.dump(sealed, open(f"{out}/http_expected_SEALED.json", "w"), indent=1, ensure_ascii=False)
print(len(inp["vectors"]), "vectors split")
