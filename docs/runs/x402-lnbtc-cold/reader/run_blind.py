"""Run the frozen readers on the inputs-only copy. Usage: python3 -I -B reader/run_blind.py blind/inputs.json out.json"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lnbtc_binding_v1 as B
import lnbtc_payment_v1 as P
inp = json.load(open(sys.argv[1]))
out = {}
for s in ("http_binding", "http_server_adapter", "mcp_binding"):
    out[s] = {c["id"]: B.run_case(s, c) for c in inp[s]}
out["client"] = {c["id"]: P.run_client(inp["client"]["base"], c) for c in inp["client"]["cases"]}
out["facilitator_settle"] = {c["id"]: P.run_settle(inp["facilitator_settle"]["base"], c) for c in inp["facilitator_settle"]["cases"]}
json.dump(out, open(sys.argv[2], "w"), indent=1, ensure_ascii=False, sort_keys=True)
print("cases", sum(len(v) for v in out.values()))
