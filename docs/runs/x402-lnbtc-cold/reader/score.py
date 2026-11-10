"""Score a run against the sealed vectors. Usage: python3 -I -B reader/score.py run.json sealed/exact_lnbtc.json score.json
Two levels per case: 'outcome' (accepted with the same digest / rejected; for settle: per step success and, when
successful, every listed field) and 'reason' (the error string as well). Open cases: outcome must be one of the listed
outcomes and never the forbidden digest."""
import json, sys
run = json.load(open(sys.argv[1])); vec = json.load(open(sys.argv[2]))
rows = []
def add(sec, cid, exp, got, outcome, reason):
    rows.append({"section": sec, "id": cid, "outcome": outcome, "reason": reason, "expect": exp, "got": got})
def binding_ok(exp, got):
    if "open" in exp:
        okd = any((("request_hash" in o and got.get("request_hash") == o["request_hash"]) or
                   ("error" in o and "error" in got)) for o in exp["outcomes"])
        if exp.get("forbidden_request_hash") and got.get("request_hash") == exp["forbidden_request_hash"]:
            okd = False
        rs = any(("request_hash" in o and got.get("request_hash") == o["request_hash"]) or
                 ("error" in o and got.get("error") == o["error"]) for o in exp["outcomes"]) and okd
        return okd, rs
    if "request_hash" in exp:
        o = got.get("request_hash") == exp["request_hash"]
        return o, o
    return "error" in got, got.get("error") == exp.get("error")
for sec in ("http_binding", "http_server_adapter", "mcp_binding"):
    for c in vec[sec]:
        g = run[sec][c["id"]]; o, r = binding_ok(c["expect"], g); add(sec, c["id"], c["expect"], g, o, r)
for c in vec["client"]["cases"]:
    e, g = c["expect"], run["client"][c["id"]]
    if "open" in e:
        o = any(all(g.get(k) == v for k, v in out.items() if k != "error") and (("error" in out) == ("error" in g)) for out in e["outcomes"])
        r = any(all(g.get(k) == v for k, v in out.items()) for out in e["outcomes"])
    elif "preimage" in e:
        o = r = g.get("preimage") == e["preimage"]
    else:
        o = "error" in g and g.get("payer_called") == e.get("payer_called")
        r = o and g.get("error") == e["error"]
    add("client", c["id"], e, g, o, r)
for c in vec["facilitator_settle"]["cases"]:
    e, g = c["expect"], run["facilitator_settle"][c["id"]]
    exps = e if isinstance(e, list) else [e]
    if "open" in (exps[0] if exps else {}):
        o = r = None
    else:
        steps = exps if len(exps) == len(g) else None
        if steps is None:
            o = r = False
        else:
            o = r = True
            for ex, gt in zip(steps, g):
                if ex.get("success"):
                    ok = all(gt.get(k) == v for k, v in ex.items())
                    o &= ok; r &= ok
                else:
                    ok = gt.get("success") is False and gt.get("step") == ex.get("step")
                    o &= gt.get("success") is False
                    r &= ok and gt.get("error_reason") == ex.get("error_reason")
    add("facilitator_settle", c["id"], e, g, o, r)
summ = {}
for row in rows:
    s = summ.setdefault(row["section"], {"n": 0, "outcome": 0, "reason": 0, "unscored": 0})
    s["n"] += 1
    if row["outcome"] is None: s["unscored"] += 1; continue
    s["outcome"] += bool(row["outcome"]); s["reason"] += bool(row["reason"])
json.dump({"summary": summ, "rows": rows}, open(sys.argv[3], "w"), indent=1, ensure_ascii=False)
for k, v in summ.items(): print(k, v)
print("total", {x: sum(v[x] for v in summ.values()) for x in ("n", "outcome", "reason", "unscored")})
