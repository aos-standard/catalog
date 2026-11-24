"""Run the reader on the inputs only. usage: run_blind.py READER inputs.json samples_dir out.json"""
import json, sys, importlib.util, traceback
s = importlib.util.spec_from_file_location("r", sys.argv[1]); r = importlib.util.module_from_spec(s); s.loader.exec_module(r)
I = json.load(open(sys.argv[2])); out = []
for c in I["cases"]:
    raw = open(sys.argv[3] + "/" + c["filename"], "rb").read()
    try:
        res = r.authorize(raw, I["root_public_key"], c["authorizer_code"])
        res["result"] = list(res["result"])
    except Exception as e:
        res = {"result": ["crash", type(e).__name__, str(e)[:200], traceback.format_exc().splitlines()[-3]], "revocation_ids": []}
    out.append({"n": c["n"], "filename": c["filename"], **res})
json.dump(out, open(sys.argv[4], "w"), indent=1, default=str)
for o in out: print(o["n"], o["filename"][:34], json.dumps(o["result"], default=str)[:150])
