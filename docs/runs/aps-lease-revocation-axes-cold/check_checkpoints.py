#!/usr/bin/env python3
"""Compare lra_cold_model.py with revision-2/oracle-checkpoints.json (the twelve hand-reasoned checkpoints of ORACLE.md).

The model fixes the default path (no diagnostic read, readings R4/R5), so a checkpoint marked `diagnostic: true` is
reported as outside the model, not as agreement or disagreement.
Usage: python3 -I check_checkpoints.py <vectors.json> <oracle-checkpoints.json> <out.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lra_cold_model import run_case  # noqa: E402


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    cps = json.loads(Path(sys.argv[2]).read_text())
    cases = {c["id"]: c for c in d["cases"]}
    rows = []
    for i, cp in enumerate(cps):
        got = run_case(d["profile"], cases[cp["case"]], cp["mode"], cp["boundary"])[cp["call"]]
        want = dict(cp["answer"], downstream_reached=cp["downstream_reached"])
        diffs = {k: {"checkpoint": v, "model": got.get(k)} for k, v in want.items() if got.get(k) != v}
        status = "outside_model" if cp.get("diagnostic") else ("agree" if not diffs else "differ")
        rows.append({"index": i, "call": cp["call"], "mode": cp["mode"], "boundary": cp["boundary"],
                     "diagnostic": cp.get("diagnostic"), "status": status, "diffs": diffs})
        print(i, cp["call"], cp["mode"], cp["boundary"], status, json.dumps(diffs) if diffs else "")
    scored = [r for r in rows if r["status"] != "outside_model"]
    out = {"agree": sum(r["status"] == "agree" for r in scored), "scored": len(scored), "total": len(rows), "rows": rows}
    Path(sys.argv[3]).write_text(json.dumps(out, indent=1) + "\n")
    print(f"{out['agree']}/{out['scored']} non-diagnostic checkpoints agree; {len(rows) - len(scored)} diagnostic outside the model")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
