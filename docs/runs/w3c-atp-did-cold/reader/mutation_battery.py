#!/usr/bin/env python3
"""Loosen one rule of the frozen v2 reader at a time and see which of the 11 vectors notice."""
import json, os, sys, types
HERE = os.path.dirname(os.path.abspath(__file__)); W = os.path.dirname(HERE)
SRC = open(os.path.join(HERE, "atp_did_reader.py"), encoding="utf-8").read()
GIVEN = json.load(open(os.path.join(W, "inputs", "given.json")))
sys.path.insert(0, HERE)
ANS = json.load(open(os.path.join(W, "answers", "answers.json")))
MUTANTS = {
 "N1 uppercase domain accepted": ('LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"', 'LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"'),
 "N2 method name compared case-insensitively": [('ROOT_RE = re.compile(rf"did:atp:({DOMAIN})")', 'ROOT_RE = re.compile(rf"(?i:did:atp):({DOMAIN})")'), ('PATH_RE = re.compile(rf"did:atp:({DOMAIN})((?::{SEG})+):e1_({B64}):pq1_({B64})")', 'PATH_RE = re.compile(rf"(?i:did:atp):({DOMAIN})((?::{SEG})+):e1_({B64}):pq1_({B64})")')],
 "N3 fingerprint length not checked": ('B64 = r"[A-Za-z0-9_-]{43}"', 'B64 = r"[A-Za-z0-9_-]+"'),
 "N4 fingerprint alphabet not checked": ('B64 = r"[A-Za-z0-9_-]{43}"', 'B64 = r"[^:]{43}"'),
 "N5 path-type DID with no path segment accepted": ('PATH_RE = re.compile(rf"did:atp:({DOMAIN})((?::{SEG})+):e1_({B64}):pq1_({B64})")', 'PATH_RE = re.compile(rf"did:atp:({DOMAIN})((?::{SEG})*):e1_({B64}):pq1_({B64})")'),
 "N6 pq1_ segment optional": [('PATH_RE = re.compile(rf"did:atp:({DOMAIN})((?::{SEG})+):e1_({B64}):pq1_({B64})")', 'PATH_RE = re.compile(rf"did:atp:({DOMAIN})((?::{SEG})+):e1_({B64})(?::pq1_({B64}))?")'), ('"pq1_" + m.group(4)', '"pq1_" + (m.group(4) or "")')],
 "N7 master secret shorter than 32 bytes accepted": ('    if len(master) < 32:\n        raise ValueError("master secret shorter than 32 bytes")', '    pass'),
 "N8 salt ignored": ('    ed_seed = hkdf(master, info("ed25519", peer), 32, salt)', '    salt = b""\n    ed_seed = hkdf(master, info("ed25519", peer), 32, salt)'),
 "N9 domain port form not checked": ('DOMAIN = rf"{LABEL}(?:\\.{LABEL})*(?:%3A[0-9]+)?"', 'DOMAIN = rf"{LABEL}(?:\\.{LABEL})*(?:%3A[^:]*)?"'),
}
def load(src):
    m = types.ModuleType("r"); exec(compile(src, "r", "exec"), m.__dict__); return m
def grade(mod):
    got = mod.run(GIVEN); res = {}
    for grp, items in ANS.items():
        for a in items:
            g = next(x for x in got[grp] if x["i"] == a["i"])
            ok = (g["valid"] is False) if grp == "invalidIdentifiers" else all(g.get(k) == v for k, v in a.items() if k not in ("i", "description"))
            res[f"{grp}[{a['i']}]"] = ok
    return res
assert all(grade(load(SRC)).values())
out = []
for name, patches in MUTANTS.items():
    patches = [patches] if isinstance(patches, tuple) else patches
    src = SRC
    for old, new in patches:
        assert src.count(old) == 1, name; src = src.replace(old, new)
    r = grade(load(src)); killers = sorted(k for k, ok in r.items() if not ok)
    out.append({"mutant": name, "killed": bool(killers), "killed_by": killers})
json.dump({"reader_sha256": __import__("hashlib").sha256(SRC.encode()).hexdigest(), "mutants": out}, sys.stdout, indent=1)
