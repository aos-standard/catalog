#!/usr/bin/env python3
"""Score aep_check.py on manifest.json#conformance_target. A layer is scored only where the manifest gives a
record outcome; 'not-checked' (an evaluation state, verifier-result-contract.md section 1) is reported, not scored.
Usage: python3 -I -B run_corpus.py <reader.py> <corpus dir> <out.json>"""
import hashlib, importlib.util, json, sys
from pathlib import Path
rp = Path(sys.argv[1]).resolve(); C = Path(sys.argv[2]).resolve()
spec = importlib.util.spec_from_file_location("reader", rp); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
man = json.loads((C / "manifest.json").read_text())
schema = json.loads((C.parent.parent / man["canonical_schema"]).read_text())
keys = {kid: m.load_key((C / p).read_text()) for kid, p in man["verifying_keys"]["by_keyid"].items()}
rows = []; tally = {}
for e in man["conformance_target"]:
    try:
        got = m.check_file(C / e["path"], schema, keys); err = None
    except Exception as ex:
        got = {}; err = "%s: %s" % (type(ex).__name__, ex)
    row = {"path": e["path"], "layers": {}, "error": err, "detail": got.get("detail")}
    for layer in ("structural", "semantic", "authenticity", "chain"):
        if layer not in e:
            continue
        exp = e[layer]
        if exp == "not-checked":
            row["layers"][layer] = {"expected": exp, "got": got.get(layer), "scored": False}
            continue
        ok = got.get(layer) == exp
        row["layers"][layer] = {"expected": exp, "got": got.get(layer), "scored": True, "agree": ok}
        t = tally.setdefault(layer, [0, 0]); t[0] += ok; t[1] += 1
    row["all_scored_agree"] = err is None and all(v["agree"] for v in row["layers"].values() if v["scored"])
    rows.append(row)
out = {"reader": rp.name, "reader_sha256": hashlib.sha256(rp.read_bytes()).hexdigest(),
       "manifest_sha256": hashlib.sha256((C / "manifest.json").read_bytes()).hexdigest(),
       "fixtures": len(rows), "fixtures_all_agree": sum(r["all_scored_agree"] for r in rows),
       "by_layer": {k: "%d/%d" % tuple(v) for k, v in tally.items()},
       "errors": sum(1 for r in rows if r["error"]), "rows": rows}
Path(sys.argv[3]).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print(json.dumps({k: out[k] for k in ("reader_sha256", "fixtures", "fixtures_all_agree", "by_layer", "errors")}))
for r in rows:
    if not r["all_scored_agree"]:
        print("MISMATCH", r["path"], r["error"] or {k: (v["expected"], v["got"]) for k, v in r["layers"].items() if v["scored"] and not v["agree"]},
              {k: v for k, v in (r["detail"] or {}).items() if any(v) if isinstance(v, list)})
