"""Split http-verification-vectors.json into inputs and sealed expected values.
Inputs: request, headers, now, maxCreatedSkewSeconds, repeat count; top-level clock, dids, public keys.
Sealed: id, rule, description, signatureBase, expected, reason, expectedSequence, expectedReasons, seeds."""
import json, sys, os
src, out = sys.argv[1], sys.argv[2]
o = json.load(open(src, encoding="utf-8"))
os.makedirs(out, exist_ok=True)
INPUT = ("request", "headers", "now", "maxCreatedSkewSeconds")
inp = {"clock": o["clock"], "did": o["did"], "otherDid": o["otherDid"], "controller": o["controller"],
       "keys": {k: {"id": v["id"], "publicKeyMultibase": v["publicKeyMultibase"],
                    "relationships": v["relationships"]} for k, v in o["keys"].items()},
       "vectors": []}
sealed = []
for i, v in enumerate(o["vectors"]):
    x = {"n": i}
    for k in INPUT:
        if k in v: x[k] = v[k]
    if "expectedSequence" in v: x["repeat"] = len(v["expectedSequence"])
    inp["vectors"].append(x)
    sealed.append({"n": i, **{k: v[k] for k in v if k not in INPUT}})
json.dump(inp, open(f"{out}/http_inputs.json", "w"), indent=1, ensure_ascii=False)
json.dump(sealed, open(f"{out}/http_expected_SEALED.json", "w"), indent=1, ensure_ascii=False)
print(len(inp["vectors"]), "vectors split")
