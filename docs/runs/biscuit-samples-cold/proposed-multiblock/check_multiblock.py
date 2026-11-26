"""Each multi-block proposal: the frozen reader gives the expected result; the reader without the named rule does not."""
import json, sys, os, types
here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reader")
SRC = open(here + "/biscuit_reader_v1.py").read()
msrc = open(here + "/mutants.py").read(); M = {n: (a, b) for n, a, b in eval(msrc[msrc.index("M = [") + 4: msrc.index("\nrows = []")])}
def mod(src): m = types.ModuleType("r"); exec(compile(src, "r", "exec"), m.__dict__); return m
pd = sys.argv[1]; P = json.load(open(pd + "/proposed_multiblock.json"))
def agree(res, e):
    r = res["result"]
    if e[0] == "ok": return r[0] == "ok" and r[1] == e[1]
    if e[1] == "format": return r[0] == "err" and r[1] == "format"
    return r[0] == "err" and r[1] == "failed_logic" and sorted(map(list, r[2]["checks"])) == sorted(e[2])
ok = 0
for c in P["cases"]:
    raw = open(pd + "/" + c["token_file"], "rb").read()
    f = mod(SRC).authorize(raw, P["root_public_key"], c["authorizer_code"])
    m = mod(SRC.replace(*M[c["mutant"]], 1)).authorize(raw, P["root_public_key"], c["authorizer_code"])
    g = agree(f, c["expect"]) and not agree(m, c["expect"]); ok += g
    print("OK " if g else "BAD", c["id"], "| frozen:", str(f["result"])[:90], "| mutant:", str(m["result"])[:70])
print(ok, "of", len(P["cases"]), "isolate")
