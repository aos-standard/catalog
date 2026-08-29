#!/usr/bin/env python3
"""Method-comparison harness for the 2026-08-16 census (catalog#2).

Carries the locality-pattern patch as text (REMOVED/ADDED below), applied at
runtime to a deep copy of METHOD_VERSIONS["2026-08-16.1"] — the shipped census
spec is never mutated, and no new method version is declared (that decision is
the maintainers', separately). Publishing the patch closes the VCL-0017 gap:
102 becomes re-derivable from text, not just checkable against a row list.

Default run: prints both readings' counts and regenerates
moved_out.jsonl / moved_in.jsonl next to this file.

--check: CI mode. Recomputes everything from the frozen snapshot and exits
nonzero unless counts are exactly (372 scannable; v1 132/240/27; v2 102/270/27;
35 out / 5 in) AND the regenerated rows byte-match the committed fixtures.
An unexecuted harness is fake coverage; this mode is what the workflow runs.
"""
import copy
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("census", HERE / "registry_capability_census.py")
census = importlib.util.module_from_spec(spec)
spec.loader.exec_module(census)

CUR = census.CURRENT_METHOD_VERSION

REMOVED = [
    r"\blocal(?:ly|-only|-first)?\b",
    r"\bfiles?\b",
    r"\bsandbox",
]
ADDED = [
    r"\bsandboxed\b",
    r"\bsandbox(?:es)? (?:its|itself)\b",
    r"\b(?:in|inside|within) an? (?:[a-zA-Z-]+,? ){0,3}sandbox\b",
    r"\bsandbox (?:mcp|server|filesystem|shell|exec|execution|workspace|browser|session|python|repl|proxy)\b",
    r"\bfile (?:ops|operations|system)\b",
    r"\blocal(?:ly|[-\s]only|[-\s]first)\b",
    r"\b(?:fully|100%|completely|entirely) local\b",
    r"\bruns? local\b",
    r"\blocal\b(?! (?:business(?:es)?|services?|marketplace|news|events|jobs|listings|shops|stores|restaurants|government)\b)(?! or remote\b)(?! by flywheel\b)",
    r"\bno api keys?\b",
]

base_spec = census.METHOD_VERSIONS[CUR]
patched_spec = copy.deepcopy(base_spec)
lp = patched_spec["locality_patterns"]
for pat in REMOVED:
    if pat not in lp:
        sys.exit(f"pattern to remove not found verbatim: {pat!r}")
    lp.remove(pat)
lp.extend(ADDED)

v1 = census._compile_method_spec(base_spec)
v2 = census._compile_method_spec(patched_spec)

records = census._load_records(HERE / "registry_2026-08-16.jsonl.gz")

# Row walk mirrors _aggregate_counts but keeps the server name per claim.
seen = {}
for row in records:
    meta = (row.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
    if meta.get("status") != "active":
        continue
    srv = row.get("server") or {}
    name = srv.get("name")
    if not name:
        continue
    seen[name] = srv

scannable = []
for name, srv in seen.items():
    text = " ".join(filter(None, [srv.get("title"), srv.get("description")]))
    if not census._match_axes(text, v1["axes"]):
        continue
    pkgs = srv.get("packages") or []
    repo = ((srv.get("repository") or {}).get("url")) or ""
    if bool(pkgs) and "github.com" in repo:
        scannable.append({"name": name, "claim": text[:300]})

def is_process(claim, compiled):
    return any(p.search(claim) for p in compiled["locality"])

def offline(claim, compiled):
    return any(p.search(claim) for p in compiled["network_offline"])

p1 = [r for r in scannable if is_process(r["claim"], v1)]
p2 = [r for r in scannable if is_process(r["claim"], v2)]
n1 = {r["name"] for r in p1}
n2 = {r["name"] for r in p2}

removed_c = [re.compile(p, re.I) for p in REMOVED]
def cause_out(claim):
    hits = []
    if removed_c[2].search(claim):
        hits.append("sandbox")
    if removed_c[1].search(claim):
        hits.append("files")
    if removed_c[0].search(claim):
        hits.append("local")
    return "+".join(hits) or "?"

added_c = [(p, re.compile(p, re.I)) for p in ADDED]
def cause_in(claim):
    return ";".join(p for p, c in added_c if c.search(claim)) or "?"

moved_out = sorted((r for r in scannable if r["name"] in n1 - n2), key=lambda r: r["name"])
moved_in = sorted((r for r in scannable if r["name"] in n2 - n1), key=lambda r: r["name"])

off1 = sum(1 for r in p1 if offline(r["claim"], v1))
off2 = sum(1 for r in p2 if offline(r["claim"], v2))

CHECK = "--check" in sys.argv

def fail(msg):
    sys.exit(f"census-diff CHECK FAILED: {msg}")

if CHECK:
    if len(scannable) != 372:
        fail(f"scannable={len(scannable)} != 372")
    if (len(p1), len(scannable) - len(p1), off1) != (132, 240, 27):
        fail(f"v1 counts {(len(p1), len(scannable)-len(p1), off1)} != (132, 240, 27)")
    if (len(p2), len(scannable) - len(p2), off2) != (102, 270, 27):
        fail(f"v2 counts {(len(p2), len(scannable)-len(p2), off2)} != (102, 270, 27)")
    if (len(moved_out), len(moved_in)) != (35, 5):
        fail(f"moved counts {(len(moved_out), len(moved_in))} != (35, 5)")
    key = lambda r: (r["name"], r["cause"], r["claim"])
    for fname, rows, causefn in (("moved_out.jsonl", moved_out, cause_out), ("moved_in.jsonl", moved_in, cause_in)):
        committed = [json.loads(l) for l in open(HERE / fname, encoding="utf-8")]
        regenerated = [{"name": r["name"], "cause": causefn(r["claim"]), "claim": r["claim"]} for r in rows]
        if [key(r) for r in committed] != [key(r) for r in regenerated]:
            fail(f"{fname} rows diverge from recomputation")
    print("census-diff CHECK OK: 372; v1 132/240/27; v2 102/270/27; 35 out / 5 in; rows byte-match")
    sys.exit(0)

print(f"scannable={len(scannable)} v1: process={len(p1)} data={len(scannable)-len(p1)} offline={off1}")
print(f"           v2: process={len(p2)} data={len(scannable)-len(p2)} offline={off2}")
print(f"moved_out={len(moved_out)} moved_in={len(moved_in)}")

from collections import Counter
print("out causes:", dict(Counter(cause_out(r["claim"]) for r in moved_out)))

with open(HERE / "moved_out.jsonl", "w") as f:
    for r in moved_out:
        f.write(json.dumps({"name": r["name"], "cause": cause_out(r["claim"]), "claim": r["claim"]}, ensure_ascii=False) + "\n")
with open(HERE / "moved_in.jsonl", "w") as f:
    for r in moved_in:
        f.write(json.dumps({"name": r["name"], "cause": cause_in(r["claim"]), "claim": r["claim"]}, ensure_ascii=False) + "\n")
print("wrote moved_out.jsonl / moved_in.jsonl")
