#!/usr/bin/env python3
"""Each mutant removes one check from the frozen v1 reader by an exact source edit, then runs the corpus.
A mutant 'survives' if the corpus still gives full agreement: that rule is not pinned by any fixture.
Usage: python3 -I -B mutants.py <aep_check_v1.py> <corpus dir> <out.json>"""
import hashlib, importlib.util, json, sys, tempfile
from pathlib import Path
src = Path(sys.argv[1]).read_text(); C = Path(sys.argv[2]).resolve()
MUT = [
 ("A1 payloadType not checked", 'if env["payloadType"] != INTOTO_PAYLOAD_TYPE:', 'if False:'),
 ("A2 signature count not checked", 'if not isinstance(sigs, list) or len(sigs) != 1:', 'if not isinstance(sigs, list) or len(sigs) < 1:'),
 ("A3 Ed25519 not verified", 'key.verify(sig, pae(env["payloadType"], raw))', 'pass'),
 ("A4 PAE over base64 text instead of decoded body", 'key.verify(sig, pae(env["payloadType"], raw))', 'key.verify(sig, pae(env["payloadType"], env["payload"].encode()))'),
 ("A5 unknown keyid falls back to any key", 'key = keys.get(s.get("keyid"))', 'key = keys.get(s.get("keyid")) or next(iter(keys.values()))'),
 ("A6 statement _type not checked", 'st.get("_type") != STATEMENT_TYPE:', 'False:'),
 ("A7 predicateType not checked", 'st.get("predicateType") != PREDICATE_TYPE:', 'False:'),
 ("A8 predicate not compared with inline record", 'if pred != b:', 'if False:'),
 ("A9 subject count not checked", 'len(subj) != 1 or', 'len(subj) < 1 or'),
 ("A10 subject name absent accepted", 'if name is None:\n            why.append("subject:name-missing")\n        elif', 'if'),
 ("A11 subject name not compared with run_id", 'elif name != "urn:wasmagent:run:" + str(r.get("run_id")):', 'elif False:'),
 ("A12 subject digest not checked", 'if d != hashlib.sha256(canonical(b)).hexdigest():', 'if False:'),
 ("A13 legacy signature field not compared", "if isinstance(legacy, dict) and (", "if False and ("),
 ("C1 broken links not detected", 'if broken:\n        return "broken"', 'if False:\n        return "broken"'),
 ("C2 first record with predecessor read as intact", 'if first_prev is not None:\n        return "orphaned", {}', 'if False:\n        return "orphaned", {}'),
 ("C3 missing links read as intact", 'if missing:\n        return "partial"', 'if False:\n        return "partial"'),
 ("C4 all-missing read as partial", 'if n > 1 and len(missing) == n - 1:', 'if False:'),
 ("C5 chain hash over the whole record incl. signature carriers", 'return hashlib.sha256(canonical(body(record))).hexdigest()', 'return hashlib.sha256(canonical(record)).hexdigest()'),
 ("S1 schema enum not checked", 'if "enum" in s and not', 'if False and not'),
 ("S2 schema uniqueItems not checked", 'if s.get("uniqueItems"):', 'if False:'),
 ("S3 schema minimum not checked", 'and "minimum" in s and v < s["minimum"]:', 'and False:'),
 ("S4 schema required not checked", 'for r in s.get("required", []):', 'for r in []:'),
 ("S5 schema type not checked", 'if "type" in s and not _type_ok(v, s["type"]):', 'if False:'),
 ("M1 vocabulary not checked in semantic", 'if bad:\n            out.append("vocabulary:observed")', 'if False:\n            out.append("vocabulary:observed")'),
 ("M2 duplicate observed not checked in semantic", 'if len(set(map(str, obs))) != len(obs):', 'if False:'),
 ("M3 floor without observed accepted", 'if has_floor and (not has_obs or not obs):', 'if False:'),
 ("M4 observed without floor accepted", 'if has_obs and not has_floor:', 'if False:'),
 ("M5 floor not in observed accepted", 'if floor not in obs:\n            out.append("floor:not-observed")\n        elif', 'if'),
 ("M6 floor rounded up accepted", 'elif known and floor != min(known, key=GRADE_ORDER.index):', 'elif False:'),
 ("M7 negative count accepted in semantic", 'or c < 0:', 'or False:'),
 ("M8 count below observed grades accepted", 'elif has_obs and isinstance(obs, list) and len(set(map(str, obs))) > c:', 'elif False:'),
 ("M9 empty observed with no floor accepted", 'if has_obs and not has_floor:', 'if has_obs and obs and not has_floor:'),
]
rows = []
runner = Path(__file__).with_name("run_corpus.py")
for name, old, new in MUT:
    assert src.count(old) == 1, name
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "aep_check_mut.py"; p.write_text(src.replace(old, new))
        spec = importlib.util.spec_from_file_location("rc", runner)
        out = Path(td) / "o.json"
        import subprocess
        res = subprocess.run([sys.executable, "-I", "-B", str(runner), str(p), str(C), str(out)], capture_output=True, text=True)
        o = json.loads(out.read_text())
        caught = [r["path"] for r in o["rows"] if not r["all_scored_agree"]]
        rows.append({"mutant": name, "caught_by": caught, "survives": not caught})
        print(("SURVIVES " if not caught else "caught   ") + name, caught[:4])
Path(sys.argv[3]).write_text(json.dumps({"reader_sha256": hashlib.sha256(src.encode()).hexdigest(), "mutants": rows}, indent=1) + "\n")
print(sum(r["survives"] for r in rows), "of", len(rows), "survive")
