#!/usr/bin/env python3
"""The frozen v2 reader refuses each proposed value or input; the mutant that loosens exactly that rule accepts it."""
import json, os, types
HERE = os.path.dirname(os.path.abspath(__file__)); W = os.path.dirname(HERE)
SRC = open(os.path.join(HERE, "atp_did_reader.py"), encoding="utf-8").read()
mb = open(os.path.join(HERE, "mutation_battery.py"), encoding="utf-8").read(); ns = {}
exec(mb[mb.index("MUTANTS = {"):mb.index("def load")], ns)
def load(src):
    m = types.ModuleType("r"); exec(compile(src, "r", "exec"), m.__dict__); return m
def patched(name):
    ps = ns["MUTANTS"][name]; ps = [ps] if isinstance(ps, tuple) else ps; s = SRC
    for o, n in ps: s = s.replace(o, n)
    return load(s)
add = json.load(open(os.path.join(W, "proposed", "test-vectors-additions.json")))
pairs = ["N2 method name compared case-insensitively", "N4 fingerprint alphabet not checked", "N5 path-type DID with no path segment accepted"]
frozen = load(SRC)
def verdict(mod, value):
    try: mod.parse(value); return "accepted"
    except ValueError as e: return "refused: " + str(e)
for v, m in zip(add["invalidIdentifiers"], pairs):
    print(v["description"], "| frozen:", verdict(frozen, v["value"]), "|", m + ":", verdict(patched(m), v["value"]))
for v in add["invalidPairwiseInputs"]:
    def pw(mod):
        try: mod.pairwise(v["domain"], bytes.fromhex(v["masterSecretHex"]), v["peerId"]); return "accepted"
        except ValueError as e: return "refused: " + str(e)
    print(v["description"], "| frozen:", pw(frozen), "| N7:", pw(patched("N7 master secret shorter than 32 bytes accepted")))
