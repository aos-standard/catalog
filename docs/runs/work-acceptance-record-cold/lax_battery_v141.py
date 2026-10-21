#!/usr/bin/env python3
"""Mutations of the live tokens of vectors 31/32: each must move tsa_signature off `verified`."""
import base64, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tsa_check_141 import tsa_signature, _items  # noqa: E402

D = Path(sys.argv[1]) / "vectors"
rows = []
for vec in ("31-tsa-freetsa-verified", "32-tsa-digicert-verified"):
    d = json.loads((D / f"{vec}.json").read_text())
    tsr = base64.b64decode(d["inputs"]["criteria_tsr_base64"]); anchors = [base64.b64decode(a) for a in d["inputs"]["tsa_roots_base64"]]
    base = tsa_signature(tsr, anchors)
    i_tst = tsr.find(bytes.fromhex("060b2a864886f70d0109100104")) + 20   # a byte inside the TSTInfo eContent
    def flip(b, i): b = bytearray(b); b[i] ^= 0x01; return bytes(b)
    certs_at = tsr.find(b"\xa0\x82", i_tst)
    muts = {
        "M1 one bit inside TSTInfo (messageDigest no longer matches)": flip(tsr, i_tst + 30),
        "M2 one bit inside the first embedded certificate's TBS": flip(tsr, certs_at + 40),
        "M3 one bit in the last byte (inside the signature)": flip(tsr, len(tsr) - 1),
    }
    rows.append({"vector": vec, "mutation": "M0 unchanged", "got": base, "ok": base == "verified"})
    for name, m in muts.items():
        g = tsa_signature(m, anchors)
        rows.append({"vector": vec, "mutation": name, "got": g, "ok": g != "verified"})
    g = tsa_signature(tsr, [])
    rows.append({"vector": vec, "mutation": "M4 empty anchor list passed to step 9", "got": g, "ok": g != "verified"})
    # the token's own certificates offered as anchors must not make a foreign anchor set verify:
    other = "32-tsa-digicert-verified" if vec.startswith("31") else "31-tsa-freetsa-verified"
    oa = [base64.b64decode(a) for a in json.loads((D / f"{other}.json").read_text())["inputs"]["tsa_roots_base64"]]
    g = tsa_signature(tsr, oa)
    rows.append({"vector": vec, "mutation": "M5 the other authority's root as the only anchor", "got": g, "ok": g == "untrusted"})
out = {"n": len(rows), "ok": sum(r["ok"] for r in rows), "rows": rows}
Path(sys.argv[2]).write_text(json.dumps(out, indent=1) + "\n")
for r in rows: print(("ok  " if r["ok"] else "LAX ") + r["vector"][:2], r["mutation"], "->", r["got"])
sys.exit(0 if out["ok"] == out["n"] else 1)
