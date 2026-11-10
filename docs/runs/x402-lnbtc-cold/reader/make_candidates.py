"""Candidate mcp_binding cases for three JSON rules no case reaches, in the vectors' own layout.
Expectations come from the frozen lnbtc_binding_v1. Usage: python3 -I -B reader/make_candidates.py out.json"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lnbtc_binding_v1 as B
SERVER = "https://api.example.com/mcp"
cases = [
    ("arguments-duplicate-member", '{"name":"get_article","arguments":{"x":1,"x":2}}',
     "A repeated member name in arguments. Description Hash Encoding: implementations MUST reject inputs outside the JCS data model, including duplicate object member names."),
    ("arguments-nan", '{"name":"get_article","arguments":{"x":NaN}}',
     "NaN is not JSON (RFC 8259 section 6), but several parsers accept it by default. JCS cannot serialize it."),
    ("arguments-utf16-key-order", '{"name":"get_article","arguments":{"\\ue000":1,"\\ud83d\\ude00":2}}',
     "Keys U+E000 and U+1F600. JCS sorts by UTF-16 code units (RFC 8785 section 3.2.3), so U+1F600 (0xD83D...) comes first; code-point order would put U+E000 first."),
]
out = []
for cid, pj, note in cases:
    r = B.run_case("mcp_binding", {"input": {"server": SERVER, "bound_metadata": [], "params_json": pj}})
    exp = {"error": r["error"]} if "error" in r else {"request_hash": r["request_hash"], "canonical_description": r["canonical_description"]}
    out.append({"id": cid, "note": note, "input": {"server": SERVER, "bound_metadata": [], "params_json": pj}, "expect": exp})
json.dump({"candidate_for": "specs/schemes/exact/vectors/exact_lnbtc.json mcp_binding (x402 PR #3727 at 63d5640)", "mcp_binding": out},
          open(sys.argv[1], "w"), indent=1, ensure_ascii=False)
for c in out: print(c["id"], json.dumps(c["expect"], ensure_ascii=False)[:200])
