"""Run the frozen 2026-10-11 reader (unchanged) over one-field variants of case-00 at PriorSeal 2ff89d8.

Usage: python3 -I run_variants.py <PriorSeal clone at 2ff89d8> <reader.py> <out.json>
Each variant: copy the example dir to a scratch dir, change one field of case-00, run the reader as a subprocess.
"""
import hashlib, json, shutil, subprocess, sys, tempfile
from pathlib import Path

clone, reader, out_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
ex = clone / "examples/open-evidence-lab-exact-call-matrix-v1"
case00 = "case-00-exact-call-observed-match"

def drop_times(o):
    o.pop("executedAt", None); o.pop("observedAt", None)
def late(o):
    o["executedAt"] = "late"
def chain_str(o):
    o["chainId"] = str(o["chainId"])  # same number, as a JSON string

VARIANTS = [("baseline", None), ("no executedAt, no observedAt", drop_times),
            ('executedAt: "late"', late), ('chainId as a JSON string of the same number', chain_str)]
results = []
for name, fn in VARIANTS:
    with tempfile.TemporaryDirectory() as td:
        dst = Path(td) / "ex"
        shutil.copytree(ex, dst)
        p = dst / "fixture/observed" / f"{case00}.json"
        obs = json.loads(p.read_text(encoding="utf-8"))
        if fn:
            fn(obs)
            p.write_text(json.dumps(obs, indent=2) + "\n", encoding="utf-8")
        proc = subprocess.run([sys.executable, "-I", str(reader), str(dst)], capture_output=True, text=True)
        row = {"variant": name, "exit": proc.returncode, "case00_input_sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        if proc.returncode == 0:
            o = json.loads(proc.stdout)
            row["case00"] = o["cases"][case00]
            row["other_cases"] = {k: v["bound"] for k, v in o["cases"].items() if k != case00}
            row["eip712_signerMatches"] = o["eip712"]["signerMatches"]
        else:
            row["stderr_tail"] = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
        results.append(row)
doc = {"subject": "imokokok/PriorSeal@2ff89d86611257b4440232e5c2793926b3d52043 examples/open-evidence-lab-exact-call-matrix-v1",
       "reader_sha256": hashlib.sha256(reader.read_bytes()).hexdigest(), "results": results}
out_path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(doc, indent=1, sort_keys=True))
