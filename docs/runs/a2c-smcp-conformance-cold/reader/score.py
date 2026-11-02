#!/usr/bin/env python3
"""Score a2c_check.py on the bundle_id, env_segment and canonical_path vector files.
Usage: score.py <reader.py> <fixtures dir> <out.json>"""
import hashlib, importlib.util, json, sys
from pathlib import Path
rp = Path(sys.argv[1]).resolve(); F = Path(sys.argv[2])
sp = importlib.util.spec_from_file_location("r", rp); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
rows = []
for v in json.loads((F / "bundle_id_conformance_vectors.json").read_text())["vectors"]:
    try: got = m.resolve_bundle_id(v["name"], v["config"])
    except Exception as e: got = "EXC %s" % type(e).__name__
    rows.append({"set": "bundle_id", "id": v["name"], "expected": v["expected_bundle_id"], "got": got})
for v in json.loads((F / "env_segment_conformance_vectors.json").read_text())["vectors"]:
    got = m.env_var_name(v["input_id"], v.get("bundle_id"), v.get("tool_name"))
    rows.append({"set": "env_segment", "id": v["id"], "expected": v["expected_env_var_name"], "got": got})
for v in json.loads((F / "canonical_path_conformance_vectors.json").read_text())["vectors"]:
    exp = v["expected"] if "expected" in v else {"error": v["error"]}
    try: got = m.normalize_path(v["input"], v["platform"])
    except m.InvalidPath: got = {"error": "invalid_path"}
    rows.append({"set": "canonical_path", "id": v["id"], "expected": exp, "got": got})
for r in rows: r["agree"] = r["expected"] == r["got"]
tally = {}
for r in rows:
    t = tally.setdefault(r["set"], [0, 0]); t[0] += r["agree"]; t[1] += 1
out = {"reader_sha256": hashlib.sha256(rp.read_bytes()).hexdigest(), "by_set": {k: "%d/%d" % tuple(v) for k, v in tally.items()}, "rows": rows}
Path(sys.argv[3]).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print(json.dumps(out["by_set"]))
for r in rows:
    if not r["agree"]: print("MISMATCH", r["set"], r["id"], "| exp", json.dumps(r["expected"], ensure_ascii=False), "| got", json.dumps(r["got"], ensure_ascii=False))
