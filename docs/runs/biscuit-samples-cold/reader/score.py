"""Score a run against the sealed expected values. Compares the outcome class, the failed checks and the policy,
and the revocation ids. usage: score.py run.json expected_SEALED.json"""
import json, sys
run = {r["n"]: r for r in json.load(open(sys.argv[1]))}
E = json.load(open(sys.argv[2]))["cases"]

def norm_expected(res):
    if "Ok" in res:
        return ("ok", res["Ok"], None)
    err = res["Err"]
    k = list(err.keys())[0]; v = err[k]
    if k == "FailedLogic":
        sub = list(v.keys())[0]; d = v[sub]
        if sub == "Unauthorized":
            checks = sorted(("authorizer", c["Authorizer"]["check_id"]) if "Authorizer" in c else
                            ("block", c["Block"]["block_id"], c["Block"]["check_id"]) for c in d["checks"])
            pol = d.get("policy"); pol = (list(pol.keys())[0].lower(), list(pol.values())[0]) if pol else None
            return ("failed_logic", tuple(checks), pol)
        if sub == "NoMatchingPolicy":
            checks = sorted(("authorizer", c["Authorizer"]["check_id"]) if "Authorizer" in c else
                            ("block", c["Block"]["block_id"], c["Block"]["check_id"]) for c in d.get("checks", []))
            return ("no_matching_policy" if not checks else "failed_logic", tuple(checks), None)
        return ("failed_logic:" + sub, json.dumps(d, sort_keys=True), None)
    return (k.lower(), json.dumps(v, sort_keys=True), None)

def norm_got(res):
    r = res["result"]
    if r[0] == "ok":
        return ("ok", r[1], None)
    if r[1] == "failed_logic":
        checks = tuple(sorted(tuple(c) for c in r[2]["checks"]))
        pol = tuple(r[2]["policy"]) if r[2]["policy"] else None
        return ("failed_logic", checks, pol)
    if r[1] == "deny":
        return ("failed_logic", (), ("deny", r[2]))
    return (r[1], r[2], None)

rows = []
for e in E:
    g = run[e["n"]]
    ex, go = norm_expected(e["result"]), norm_got(g)
    cls = ex[0] == go[0]
    detail = cls and (ex[0] not in ("ok", "failed_logic") or (ex[1] == go[1] and ex[2] == go[2]))
    rev = e["revocation_ids"] == g["revocation_ids"]
    rows.append({"n": e["n"], "test": e["title"], "filename": g["filename"], "class_agree": cls, "detail_agree": detail,
                 "revocation_ids_agree": rev, "expected": [str(x) for x in ex], "got": [str(x) for x in go]})
s = {"class": "%d/%d" % (sum(r["class_agree"] for r in rows), len(rows)),
     "detail": "%d/%d" % (sum(r["detail_agree"] for r in rows), len(rows)),
     "revocation_ids": "%d/%d" % (sum(r["revocation_ids_agree"] for r in rows), len(rows))}
print(json.dumps({"summary": s, "rows": rows}, indent=1, ensure_ascii=False))
