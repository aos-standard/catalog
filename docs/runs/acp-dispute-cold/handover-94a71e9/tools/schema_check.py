#!/usr/bin/env python3
"""Validate each case's record (DisputeRecord) and determination (DisputeDetermination) against the
ACP dispute_resolution schema, the way validate-consistency.js validates named examples (draft 2020-12,
$ref inside the schema, formats not asserted). Usage: schema_check.py <schema.json> <cases_dir> <out.json>
"""
import json
import sys
from pathlib import Path

import jsonschema

schema_path, cases_dir, out_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
schema = json.loads(schema_path.read_text(encoding="utf-8"))
cls = jsonschema.validators.validator_for(schema)


def validator_for(defname):
    sub = {"$ref": "#/$defs/" + defname, "$defs": schema["$defs"]}
    return cls(sub)


V = {"record": validator_for("DisputeRecord"), "determination": validator_for("DisputeDetermination")}
result = {}
for p in sorted(cases_dir.glob("*.json")):
    case = json.loads(p.read_text(encoding="utf-8"))
    row = {}
    for part, v in V.items():
        if part in case:
            errs = sorted(v.iter_errors(case[part]), key=lambda e: list(e.absolute_path))
            row[part] = [("/".join(map(str, e.absolute_path)) or "(root)") + ": " + e.message[:160] for e in errs]
    result[p.stem] = row
out_path.write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
bad = {k: v for k, v in result.items() if any(v.values())}
print("cases", len(result), "with schema errors", len(bad))
for k, v in bad.items():
    for part, errs in v.items():
        for e in errs:
            print(" ", k, part, e)
