#!/usr/bin/env python3
"""Each proposed vector is refused by the frozen verifier with its rule, and accepted by the mutant that drops
exactly that rule's check, so no other check refuses it."""
import json, os, types
HERE = os.path.dirname(os.path.abspath(__file__)); W = os.path.dirname(HERE)
SRC = open(os.path.join(HERE, "wba_cold_verifier.py"), encoding="utf-8").read()
mb = open(os.path.join(HERE, "mutation_battery.py"), encoding="utf-8").read()
ns = {}
exec(mb[mb.index("MUTANTS = {"):mb.index("def load")], ns)
def load(src):
    m = types.ModuleType("v"); exec(compile(src, "v", "exec"), m.__dict__); return m
PAIR = {"x01-response-other-origin.json": "M15 response signer origin not checked",
        "x02-directory-kid-not-thumbprint.json": "M24 directory kid not checked against thumbprint",
        "x03-directory-signature-wrong-tag.json": "M28 directory signature tag not checked"}
frozen = load(SRC)
for fn, mname in PAIR.items():
    v = json.load(open(os.path.join(W, "proposed", fn)))
    patches = ns["MUTANTS"][mname]; patches = [patches] if isinstance(patches, tuple) else patches
    src = SRC
    for old, new in patches:
        assert src.count(old) == 1; src = src.replace(old, new)
    print(fn, "| frozen:", json.dumps(frozen.run(v["operation"])), "| expected:", v["expected"]["rule"], "|", mname + ":", json.dumps(load(src).run(v["operation"])))
