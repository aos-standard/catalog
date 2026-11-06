#!/usr/bin/env python3
"""Build conformance_cases.json for the ACP dispute_resolution extension (SEP #303, PR #316) from the cold-run case
set at ddc2871 (aos-standard/catalog docs/runs/acp-dispute-cold/ddc2871/). Inputs and expectations are copied as
they are; only the selection, the layout and the notes change:

- U1 and U2 are left out: they are the example pairs as published at db04871 and 089d8f9, superseded by the
  example at ddc2871 (U3, kept). What they test is covered by E4 (line_amount_missing) and E6 (opened_at).
- Parentheticals in notes that compare with older readers or older text are removed.
- The case-set field spec_open is dropped. At the RFC commit named in the output, each reading it listed is stated in
  the text (readings_stated below); that is this author's reading, for the RFC author to confirm.

Usage: make_conformance_cases.py <ddc2871 dir> <rfc sha> <out.json>
"""
import json
import re
import sys
from pathlib import Path

src, rfc_sha, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
meta = json.loads((src / "cases.json").read_text(encoding="utf-8"))
DROP = {"U1", "U2"}
PAREN = re.compile(r"\s*\((?:db04871 reader|now stated|R4 not restated|both readers|whole UTC days, now stated)[^)]*\)")

cases = []
for c in meta["cases"]:
    if c["id"] in DROP:
        continue
    inp = json.loads((src / "cases" / f"{c['id']}.json").read_text(encoding="utf-8"))
    note = PAREN.sub("", c["note"]).strip()
    cases.append({"id": c["id"], "input": inp, "expect": c["expect"], "note": note})

doc = {
    "description": (
        "Conformance cases for the dispute_resolution extension. Each case gives a DisputeRecord (input.record) and, "
        "for the determination checks, a DisputeDetermination (input.determination). expect states what a provider "
        "following the RFC decides. See README.md in this directory for the fields."
    ),
    "rfc": "rfcs/rfc.dispute_resolution.md at " + rfc_sha,
    "readings_stated": {
        "approval binding (D8, D8b, D8c, D8d)": "Section 4.4a: recompute approval_digest from items and approved_at, and check it equals the digest the merchant received",
        "intent conflict (D8)": "Section 7.4 rule 4: a finding against the agent platform; the charge stands",
        "allocation and unfulfilled share (D4d, E7)": "Section 7.4 rules 1 and 3",
        "adjustment types for rule 3 (E1, E2, E7)": "Section 7.4 rule 3: a completed adjustment of a type counted in rule 1",
    },
    "source": {
        "repository": "https://github.com/aos-standard/catalog",
        "record": "docs/runs/acp-dispute-cold/ddc2871/",
        "license": "CC0-1.0",
    },
    "cases": cases,
}
out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(len(cases), "cases")
