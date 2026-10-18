#!/usr/bin/env python3
"""Run dr_cold_verifier over a self-contained expectedVerdicts file (the proposed vectors, or any A.7-style file).

Usage: python3 run_proposed.py <proposed.json> <out.json> [<upstream vectors.json>]. When the upstream file is given, the
proposed file is overlaid onto it (its `fixtures` and `expectedVerdicts` are added; `$ref` pointers such as /endToEnd/…
resolve into the upstream file). Compares path, five levels, valid, longTermEvidence, reason.level; reason.code is
informative (all codes here are the generator's own).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dr_cold_verifier as V  # noqa: E402
from run_vectors import deref, jptr  # noqa: E402


def main() -> int:
    raw = Path(sys.argv[1]).read_bytes()
    prop = V.parse_strict(raw)
    res = {"source_sha256": hashlib.sha256(raw).hexdigest(), "runs": []}
    if len(sys.argv) > 3:
        up_raw = Path(sys.argv[3]).read_bytes()
        doc = V.parse_strict(up_raw)
        res["upstream_sha256"] = hashlib.sha256(up_raw).hexdigest()
        doc["fixtures"] = prop["fixtures"]
        doc["expectedVerdicts"] = prop["expectedVerdicts"]
    else:
        doc = prop
    agree = 0
    for ev in doc["expectedVerdicts"]:
        inputs = {k: deref(doc, v) for k, v in ev["inputs"].items()}
        vec = jptr(doc, ev["vector"])
        got = V.verify(inputs, path=ev["path"], offline=ev.get("offline", False), vector=vec if isinstance(vec, dict) else None)
        diffs = {}
        for lv in V.LEVELS:
            if got["levels"][lv] != ev["levels"][lv]:
                diffs[f"levels.{lv}"] = {"expected": ev["levels"][lv], "got": got["levels"][lv]}
        for k in ("valid", "longTermEvidence"):
            if got[k] != ev[k]:
                diffs[k] = {"expected": ev[k], "got": got[k]}
        er, gr = ev.get("reason"), got.get("reason")
        if (er is None) != (gr is None) or (er and er["level"] != gr["level"]):
            diffs["reason"] = {"expected": er, "got": gr}
        info = {}
        if er and gr and er.get("code") != gr.get("code"):
            info["reason.code"] = {"expected": er.get("code"), "got": gr.get("code")}
        status = "AGREE" if not diffs else "DISAGREE"
        agree += status == "AGREE"
        res["runs"].append({"id": ev["id"], "status": status, "diffs": diffs, "informative": info,
                            "got": {"levels": got["levels"], "valid": got["valid"], "longTermEvidence": got["longTermEvidence"],
                                    "reason": got["reason"], "unchecked_algs": got["report"]["unchecked_algs"]}})
    res["agree"], res["n"] = agree, len(doc["expectedVerdicts"])
    Path(sys.argv[2]).write_text(json.dumps(res, indent=1, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"{agree}/{len(doc['expectedVerdicts'])} agree")
    for r in res["runs"]:
        if r["status"] != "AGREE" or r["informative"]:
            print(" ", r["id"], r["status"], json.dumps(r["diffs"])[:240], json.dumps(r["informative"])[:160], "unchecked:", r["got"]["unchecked_algs"])
    return 0 if agree == len(doc["expectedVerdicts"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
