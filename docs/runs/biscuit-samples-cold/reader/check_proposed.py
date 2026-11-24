"""Each proposal: the frozen reader gives the expected class; the reader with the named rule removed does not."""
import json, sys, os, types
here = os.path.dirname(os.path.abspath(__file__))
SRC = open(here + "/biscuit_reader_v1.py").read()
msrc = open(here + "/mutants.py").read(); M = {n: (a, b) for n, a, b in eval(msrc[msrc.index("M = [") + 4: msrc.index("\nrows = []")])}
def mod(src): m = types.ModuleType("r"); exec(compile(src, "r", "exec"), m.__dict__); return m
pd, sd = sys.argv[1], sys.argv[2]; P = json.load(open(pd + "/proposed.json"))
def cls(res, exp):
    r = res["result"]
    if exp[0] == "ok": return tuple(r[:2]) == tuple(exp)
    if exp[1] == "deny": return r[0] == "err" and r[1] == "deny" and r[2] == exp[2]
    return r[0] == "err" and r[1] == exp[1]
ok = 0
for c in P["cases"]:
    path = (pd if c["token_file"].startswith("proposed_") else sd) + "/" + c["token_file"]
    raw = open(path, "rb").read()
    f = mod(SRC).authorize(raw, P["root_public_key"], c["authorizer_code"])
    m = mod(SRC.replace(*M[c["mutant"]], 1)).authorize(raw, P["root_public_key"], c["authorizer_code"])
    good = cls(f, c["expect"]) and not cls(m, c["expect"]); ok += good
    print("OK " if good else "BAD", c["id"], "| frozen:", f["result"][:2], "| mutant:", m["result"][:2])
print(ok, "of", len(P["cases"]), "isolate")
