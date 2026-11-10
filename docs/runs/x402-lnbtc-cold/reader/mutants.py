"""One-rule-changed battery over the frozen readers. Each mutant replaces one exact source fragment in an in-memory
copy, runs all 199 cases and rescores (outcome level). A mutant is caught when the outcome count drops below the
frozen readers' own. The frozen files are not modified. Usage: python3 -I -B reader/mutants.py sealed/exact_lnbtc.json out.json"""
import json, sys, types, importlib.util
from pathlib import Path
HERE = Path(__file__).resolve().parent
vec = json.load(open(sys.argv[1])); OUT = sys.argv[2]
inp = json.load(open(HERE.parent / "blind" / "inputs.json"))
SRC_B = (HERE / "lnbtc_binding_v1.py").read_text()
SRC_P = (HERE / "lnbtc_payment_v1.py").read_text()
spec = importlib.util.spec_from_file_location("score_v2", HERE / "score_v2.py")

def load(src_b, src_p):
    mb = types.ModuleType("lnbtc_binding_v1"); exec(compile(src_b, "B", "exec"), mb.__dict__)
    sys.modules["lnbtc_binding_v1"] = mb
    mp = types.ModuleType("lnbtc_payment_v1"); exec(compile(src_p, "P", "exec"), mp.__dict__)
    return mb, mp

def outcomes(mb, mp):
    run = {}
    for s in ("http_binding", "http_server_adapter", "mcp_binding"):
        run[s] = {c["id"]: mb.run_case(s, c) for c in inp[s]}
    run["client"] = {c["id"]: mp.run_client(inp["client"]["base"], c) for c in inp["client"]["cases"]}
    run["facilitator_settle"] = {c["id"]: mp.run_settle(inp["facilitator_settle"]["base"], c) for c in inp["facilitator_settle"]["cases"]}
    tmp = HERE.parent / "runs" / "_mutant_run.json"
    json.dump(run, open(tmp, "w"))
    g = {"__name__": "x"}
    sys.argv[1:4] = [str(tmp), str(HERE.parent / "sealed" / "exact_lnbtc.json"), str(HERE.parent / "runs" / "_mutant_score.json")]
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        exec(compile((HERE / "score_v2.py").read_text(), "S", "exec"), g)
    rows = json.load(open(HERE.parent / "runs" / "_mutant_score.json"))["rows"]
    tmp.unlink(); (HERE.parent / "runs" / "_mutant_score.json").unlink()
    return {(r["section"], r["id"]) for r in rows if r["outcome"]}

M = [
 ("B", "field value: lines not trimmed", 'v = v.strip(" \\t")', 'v = v'),
 ("B", "field value: control and non-ASCII characters accepted", 'raise Reject("unsupported field value")', 'pass'),
 ("B", "bound header names: order not checked", 'raise Reject("header names not strictly ascending")', 'pass'),
 ("B", "bound header names: payment-signature allowed", 'raise Reject("payment-signature bound")', 'pass'),
 ("B", "absent header hashed as present-and-empty", 'h = sha(b"\\x00") if v is None', 'h = sha(b"\\x01") if v is None'),
 ("B", "JCS numbers as Python repr", 'return _num(v)', 'return json.dumps(v)'),
 ("B", "JCS keys sorted by code point, not UTF-16", 'sorted(v, key=_utf16_key)', 'sorted(v)'),
 ("B", "duplicate member names accepted", 'raise Reject("duplicate member name")', 'pass'),
 ("B", "lone surrogates accepted", 'raise Reject("lone surrogate")', 'pass'),
 ("B", "NaN/Infinity literals accepted by the parser", 'raise Reject("non-finite literal")', 'return float("nan")'),
 ("B", "excluded metadata names allowed", 'raise Reject("excluded metadata name bound")', 'pass'),
 ("B", "null or non-object arguments treated as {}", 'raise Reject("arguments null or not an object")', 'args = {}'),
 ("B", "non-object _meta treated as {}", 'raise Reject("_meta not an object")', 'meta = {}'),
 ("B", "URL fragment allowed", 'raise Reject("fragment")', 'pass'),
 ("B", "authority userinfo / path / backslash allowed", 'raise Reject("authority has path, query, fragment, backslash, userinfo or a control/non-ASCII char")', 'pass'),
 ("B", "port range not checked", 'or int(port) > 65535', 'or False'),
 ("B", "method token not checked", 'raise Reject("method not a token")', 'pass'),
 ("B", "adapter: request authority not compared with the configured origin", 'raise Reject("request authority is not the configured origin")', 'pass'),
 ("P", "created_in_future without the skew", 'if inv["timestamp"] > now + skew:\n        raise Fail("invalid_exact_lnbtc_invoice_created_in_future", 5)', 'if inv["timestamp"] > now:\n        raise Fail("invalid_exact_lnbtc_invoice_created_in_future", 5)'),
 ("P", "settle expiry boundary exclusive", 'if now > end + skew:', 'if now >= end + skew:'),
 ("P", "settle expiry without the skew grace", 'if now > end + skew:', 'if now > end:'),
 ("P", "replay key without the network", 'key = req["network"] + ":" + inv["payment_hash"]', 'key = inv["payment_hash"]'),
 ("P", "replay retention without the skew", '"retain_until_at_least": end + skew + 3600', '"retain_until_at_least": end + 3600'),
 ("P", "preimage: uppercase hex accepted", 'if not isinstance(pre, str) or not re.match(r"^[0-9a-f]*$", pre):', 'if not isinstance(pre, str) or not re.match(r"^[0-9a-fA-F]*$", pre):'),
 ("P", "invoice signer not compared with payTo (settle)", 'if inv["signer"] != req["payTo"]:\n        raise Fail("invalid_exact_lnbtc_invoice_payee_mismatch", 5)', 'pass'),
 ("P", "inline description accepted beside the hash", 'if len(inv["description_hashes"]) != 1 or inv["descriptions"]:\n        raise Fail("invalid_exact_lnbtc_invoice_description", 5)', 'if len(inv["description_hashes"]) != 1:\n        raise Fail("invalid_exact_lnbtc_invoice_description", 5)'),
 ("P", "other extra fields not compared", 'raise Fail("invalid_exact_lnbtc_extra_mismatch", 3)', 'pass'),
 ("P", "params compared without JCS (raw equality)", 'if B.jcs(rx["requestBindingParams"]) != B.jcs(ax["requestBindingParams"]):', 'if rx["requestBindingParams"] != ax["requestBindingParams"]:'),
 ("P", "client: resource URL not checked", 'raise Fail("invalid_exact_lnbtc_request_mismatch")  # P9', 'pass'),
 ("P", "client: MCP server identity not checked", 'raise Fail("invalid_exact_lnbtc_request_mismatch")  # P10: server identity', 'pass'),
 ("P", "client: expiry with the skew grace", 'if now > inv["timestamp"] + inv["expiry"]:', 'if now > inv["timestamp"] + inv["expiry"] + skew:'),
 ("P", "client: payer amount not checked", 'raise Fail("invalid_exact_lnbtc_payer_amount_mismatch")', 'pass'),
 ("P", "BOLT11: bech32 checksum not checked", 'if _polymod(_hrp_expand(hrp) + groups) != 1:', 'if False:'),
 ("P", "BOLT11: mixed case accepted", 'if inv != inv.lower() and inv != inv.upper():\n        raise bad', 'pass'),
 ("P", "BOLT11: p multiplier last digit not checked", 'if n % 10:\n                raise bad', 'pass'),
 ("P", "BOLT11: second payment hash ignored", 'raise bad  # P3: a second valid p field', 'pass'),
]
base = outcomes(*load(SRC_B, SRC_P))
res = []
for which, name, old, new in M:
    src_b, src_p = SRC_B, SRC_P
    if which == "B":
        assert SRC_B.count(old) >= 1, name; src_b = SRC_B.replace(old, new, 1)
    else:
        assert SRC_P.count(old) >= 1, name; src_p = SRC_P.replace(old, new, 1)
    try:
        got = outcomes(*load(src_b, src_p)); lost = sorted(base - got); gained = sorted(got - base)
        res.append({"mutant": name, "caught": bool(lost), "by": ["%s/%s" % k for k in lost][:8], "newly_agree": ["%s/%s" % k for k in gained]})
    except Exception as e:
        res.append({"mutant": name, "caught": True, "by": ["raised " + type(e).__name__]})
json.dump({"baseline_outcome": len(base), "mutants": res}, open(OUT, "w"), indent=1)
print("baseline", len(base), "caught", sum(r["caught"] for r in res), "of", len(res))
for r in res: print(("CAUGHT " if r["caught"] else "survives ") + r["mutant"], r["by"][:3])
