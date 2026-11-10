"""Scorer v2, written after score.py (v1) crashed on the shape of open outcomes and per-step settle expectations.
The run file is the one produced by the frozen readers; only the comparison changed. Same two levels as v1."""
import json, sys
run = json.load(open(sys.argv[1])); vec = json.load(open(sys.argv[2]))
rows = []
def match(exp, got, reason):
    if "request_hash" in exp:
        return got.get("request_hash") == exp["request_hash"]
    if "preimage" in exp:
        return got.get("preimage") == exp["preimage"]
    if "error" in exp:
        if "error" not in got:
            return False
        if "payer_called" in exp and got.get("payer_called") != exp["payer_called"]:
            return False
        return (got.get("error") == exp["error"]) if reason else True
    return False
def judge(exp, got):
    if "open" in exp:
        outs = list(exp["outcomes"].values())
        if exp.get("forbidden_request_hash") and got.get("request_hash") == exp["forbidden_request_hash"]:
            return False, False, "forbidden"
        o = any(match(x, got, False) for x in outs); r = any(match(x, got, True) for x in outs)
        return o, r, "open:" + exp["open"]
    return match(exp, got, False), match(exp, got, True), ""
for sec in ("http_binding", "http_server_adapter", "mcp_binding"):
    for c in vec[sec]:
        g = run[sec][c["id"]]; o, r, t = judge(c["expect"], g)
        rows.append({"section": sec, "id": c["id"], "outcome": o, "reason": r, "tag": t, "expect": c["expect"], "got": g})
for c in vec["client"]["cases"]:
    g = run["client"][c["id"]]; o, r, t = judge(c["expect"], g)
    rows.append({"section": "client", "id": c["id"], "outcome": o, "reason": r, "tag": t, "expect": c["expect"], "got": g})
for c in vec["facilitator_settle"]["cases"]:
    g = run["facilitator_settle"][c["id"]]; o = r = len(g) == len(c["steps"]); tags = []
    for st, gt in zip(c["steps"], g):
        ex = st["expect"]
        if "open" in ex:
            tags.append("open:" + ex["open"]); outs = list(ex["outcomes"].values())
        else:
            outs = [ex]
        so = sr = False
        for x in outs:
            if x.get("success"):
                ok = all(gt.get(k) == v for k, v in x.items()); so |= ok; sr |= ok
            else:
                so |= gt.get("success") is False
                sr |= gt.get("success") is False and gt.get("step") == x.get("step") and gt.get("error_reason") == x.get("error_reason")
        o &= so; r &= sr
    rows.append({"section": "facilitator_settle", "id": c["id"], "outcome": o, "reason": r, "tag": ",".join(tags),
                 "expect": [s["expect"] for s in c["steps"]], "got": g})
summ = {}
for row in rows:
    s = summ.setdefault(row["section"], {"n": 0, "outcome": 0, "reason": 0})
    s["n"] += 1; s["outcome"] += bool(row["outcome"]); s["reason"] += bool(row["reason"])
json.dump({"summary": summ, "rows": rows}, open(sys.argv[3], "w"), indent=1, ensure_ascii=False)
for k, v in summ.items(): print(k, v)
print("total", {x: sum(v[x] for v in summ.values()) for x in ("n", "outcome", "reason")})
