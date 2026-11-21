"""Frozen reader must reject every proposed vector; the mutant that removes the named rule must accept it."""
import os as _os_, tempfile as _tf_
_HERE = _os_.path.dirname(_os_.path.abspath(__file__))
_SCR = _os_.environ.get("WIMSE_TMP", _tf_.gettempdir())
import sys, json, importlib.util, tempfile
sys.path.insert(0, _HERE)
import mutation_battery as MB
SCR = _SCR
V = json.load(open((_HERE + "/proposed/proposed_vectors.json")))
ISSUER = {"alg":"Ed25519","crv":"Ed25519","kid":"issuer-key","kty":"OKP","x":"QH_Zu0pnwyO8xdFQm9upOUFAbpb4nhMrGc29L3uJXDA"}
AUD = {"https://svcb.example.com/gimme-ice-cream","https://svcb.example.com/inventory/cones","https://svcb.example.com/status","https://svcb.example.com"}
def load(src, name):
    d = tempfile.mkdtemp(dir=SCR); open(f"{d}/{name}.py", "w").write(src)
    spec = importlib.util.spec_from_file_location(name, f"{d}/{name}.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
SRC = open(MB.SRC).read()
frozen = load(SRC, "frozen_reader")
def run(R, v):
    if v["kind"] == "request":
        return R.verify_request(v["message"], now=v["verification_time"], trusted_aud=AUD, issuer_jwk=ISSUER)[:2]
    return R.verify_response(v["message"], request=v["request"], now=v["verification_time"], issuer_jwk=ISSUER)[:2]
out = {}
for vid, v in V.items():
    mname = [k for k in MB.M if k.startswith(v["isolates"] + " ")][0]
    src = SRC
    for a, b in MB.M[mname]:
        src = src.replace(a, b)
    mut = load(src, "mut_" + vid)
    f, m = run(frozen, v), run(mut, v)
    out[vid] = {"frozen": f, "mutant": mname, "mutant_outcome": m, "isolates": f[0] == "reject" and m[0] == "accept"}
    print(f"{vid} frozen={f[0]}:{f[1]:34s} {mname[:50]:50s} -> {m[0]}")
json.dump(out, open((_HERE + "/runs/check_proposed.json"), "w"), indent=1)
print("isolating:", sum(o["isolates"] for o in out.values()), "/", len(out))
