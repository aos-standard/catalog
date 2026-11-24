#!/usr/bin/env python3
"""The tests of certification/authorization-api-1_0-scenario.md, transcribed as executable checks against an in-process
PDP (handle(method, path, headers, body)). Written after the PDP was frozen. Each check returns (ok, note).
Only what the scenario says the harness validates is checked."""
import json

H = {"Content-Type": "application/json"}
A = {"type": "user", "id": "alice"}
B = {"type": "user", "id": "bob"}
BADMIN = {"type": "user", "id": "bob", "properties": {"role": "admin"}}
R1 = {"type": "record", "id": "record-1"}
R2 = {"type": "record", "id": "record-2"}
R2ARCH = {"type": "record", "id": "record-2", "properties": {"status": "archived"}}
R1ACT = {"type": "record", "id": "record-1", "properties": {"status": "active"}}
CTX = {"time": "2025-06-27T18:03-07:00", "ip": "192.168.1.1"}
EV, EVS = "/access/v1/evaluation", "/access/v1/evaluations"
SS, RS, AS = "/access/v1/search/subject", "/access/v1/search/resource", "/access/v1/search/action"


def call(p, path, body, headers=None, method="POST", raw=None):
    st, h, b = p.handle(method, path, headers if headers is not None else H, raw if raw is not None else json.dumps(body).encode())
    try:
        j = json.loads(b) if st == 200 else None
    except Exception:
        j = "INVALID_JSON"
    return st, h, j


def ct_json(h):
    return any(k.lower() == "content-type" and v.split(";")[0].strip() == "application/json" for k, v in h.items())


def decision(p, path, body, want=None):
    st, h, j = call(p, path, body)
    if st != 200 or not ct_json(h) or not isinstance(j, dict) or not isinstance(j.get("decision"), bool):
        return False, "status %s body %s" % (st, j)
    if "context" in j and not isinstance(j["context"], dict):
        return False, "context not an object"
    if want is not None and j["decision"] is not want:
        return False, "decision %s" % j["decision"]
    return True, ""


def batch(p, body, n, want=None):
    st, h, j = call(p, EVS, body)
    if st != 200 or not isinstance(j, dict) or not isinstance(j.get("evaluations"), list) or len(j["evaluations"]) != n:
        return False, "status %s body %s" % (st, j)
    if not all(isinstance(e, dict) and isinstance(e.get("decision"), bool) for e in j["evaluations"]):
        return False, "item without boolean decision"
    if want is not None:
        got = [e["decision"] for e in j["evaluations"]]
        if any(w is not None and g is not w for g, w in zip(got, want)):
            return False, "decisions %s" % got
    return True, ""


def status(p, path, body=None, want=400, headers=None, raw=None):
    st, _, _ = call(p, path, body, headers=headers, raw=raw)
    return st == want, "status %s" % st


def search(p, path, body, must, key):
    st, h, j = call(p, path, body)
    if st != 200 or not isinstance(j, dict) or not isinstance(j.get("results"), list):
        return False, "status %s body %s" % (st, j)
    res = j["results"]
    if key == "name":
        if not all(isinstance(r, dict) and "name" in r for r in res):
            return False, "result without name"
        names = {r["name"] for r in res}
    else:
        typ = body["subject" if path == SS else "resource"]["type"]
        if not all(isinstance(r, dict) and "type" in r and "id" in r and r["type"] == typ for r in res):
            return False, "result with wrong shape or type"
        names = {r["id"] for r in res}
    if must == "EMPTY":
        return (res == []), "results %s" % res
    missing = set(must) - names
    return (not missing), "missing %s" % sorted(missing)


def same_results(p, path, a, b):
    ra, rb = call(p, path, a)[2], call(p, path, b)[2]
    return (isinstance(ra, dict) and isinstance(rb, dict) and ra.get("results") == rb.get("results")), "differs"


def pagination(p):
    body = {"subject": {"type": "user"}, "action": {"name": "read"}, "resource": R1, "page": {"limit": 1}}
    st, h, j = call(p, SS, body)
    if st != 200 or not isinstance(j, dict) or not isinstance(j.get("results"), list):
        return False, "limit: status %s" % st
    pg = j.get("page")
    if pg is not None and not isinstance(pg, dict):
        return False, "page not object"
    if pg and "next_token" in pg and not isinstance(pg["next_token"], str):
        return False, "next_token not string"
    tok = (pg or {}).get("next_token")
    if tok:
        body2 = {"subject": {"type": "user"}, "action": {"name": "read"}, "resource": R1, "page": {"token": tok}}
        st2, _, j2 = call(p, SS, body2)
        if st2 != 200 or not isinstance(j2, dict) or not isinstance(j2.get("results"), list):
            return False, "token follow-up: status %s" % st2
        if not isinstance(j2.get("page"), dict) or not isinstance(j2["page"].get("next_token"), str):
            return False, "token follow-up: page/next_token missing"
    return True, ""


def request_id(p):
    st, h, _ = call(p, EV, {"subject": A, "action": {"name": "read"}, "resource": R1}, headers=dict(H, **{"X-Request-ID": "req-7f3a"}))
    echo = {k.lower(): v for k, v in h.items()}.get("x-request-id")
    st2, _, _ = call(p, EV, {"subject": A, "action": {"name": "read"}, "resource": R1})
    return (st == 200 and echo == "req-7f3a" and st2 == 200), "echo %r, absent-status %s" % (echo, st2)


def idempotent(p):
    ds = [call(p, EV, {"subject": B, "action": {"name": "write"}, "resource": R1})[2] for _ in range(5)]
    return (all(d == ds[0] for d in ds) and isinstance(ds[0], dict)), "varies"


def metadata(p):
    st, h, j = call(p, "/.well-known/authzen-configuration", None, headers={}, method="GET", raw=b"")
    if st != 200 or not ct_json(h) or not isinstance(j, dict):
        return False, "status %s" % st
    base = p.BASE if hasattr(p, "BASE") else None
    ok = j.get("policy_decision_point") == base and str(j.get("access_evaluation_endpoint", "")).startswith("https://")
    for k in ("access_evaluations_endpoint", "search_subject_endpoint", "search_resource_endpoint", "search_action_endpoint"):
        if k in j and not str(j[k]).startswith("https://"):
            ok = False
    if "capabilities" in j and not (isinstance(j["capabilities"], list) and all(isinstance(c, str) for c in j["capabilities"])):
        ok = False
    return ok, "metadata %s" % j


CASES = [
    ("c-2-2-1", "values", lambda p: decision(p, EV, {"subject": A, "action": {"name": "read"}, "resource": R1}, True)),
    ("c-2-2-2", "values", lambda p: decision(p, EV, {"subject": B, "action": {"name": "write"}, "resource": R1}, False)),
    ("c-2-2-3", "values", lambda p: decision(p, EV, {"subject": A, "action": {"name": "read"}, "resource": R1, "context": CTX}, True)),
    ("c-2-2-4", "values", lambda p: decision(p, EV, {"subject": A, "action": {"name": "write"}, "resource": R2ARCH}, False)),
    ("c-2-2-5", "values", lambda p: decision(p, EV, {"subject": BADMIN, "action": {"name": "write"}, "resource": R2ARCH}, True)),
    ("c-2-2-6", "values", lambda p: decision(p, EV, {"subject": A, "action": {"name": "delete", "properties": {"soft": True}}, "resource": R1}, True)),
    ("c-2-2-7", "values", lambda p: decision(p, EV, {"subject": A, "action": {"name": "delete", "properties": {"soft": False}}, "resource": R1}, False)),
    ("c-2-2-8", "values", lambda p: decision(p, EV, {"subject": {"type": "user", "id": "alice", "properties": {"department": "Sales", "role": "manager"}},
                                                    "action": {"name": "read", "properties": {"method": "GET"}},
                                                    "resource": {"type": "record", "id": "record-1", "properties": {"status": "active", "owner": "bob"}}}, True)),
    ("c-2-2-9", "values", lambda p: decision(p, EV, {"subject": A, "action": {"name": "read"}, "resource": R1, "foo": "bar", "futureField": {"nested": True}}, True)),
    ("c-2-4-1/subject", "status", lambda p: status(p, EV, {"action": {"name": "read"}, "resource": R1})),
    ("c-2-4-1/action", "status", lambda p: status(p, EV, {"subject": A, "resource": R1})),
    ("c-2-4-1/resource", "status", lambda p: status(p, EV, {"subject": A, "action": {"name": "read"}})),
    ("c-2-4-2/subject.type", "status", lambda p: status(p, EV, {"subject": {"id": "alice"}, "action": {"name": "read"}, "resource": R1})),
    ("c-2-4-2/subject.id", "status", lambda p: status(p, EV, {"subject": {"type": "user"}, "action": {"name": "read"}, "resource": R1})),
    ("c-2-4-2/action.name", "status", lambda p: status(p, EV, {"subject": A, "action": {}, "resource": R1})),
    ("c-2-4-2/resource.type", "status", lambda p: status(p, EV, {"subject": A, "action": {"name": "read"}, "resource": {"id": "record-1"}})),
    ("c-2-4-2/resource.id", "status", lambda p: status(p, EV, {"subject": A, "action": {"name": "read"}, "resource": {"type": "record"}})),
    ("c-2-4-3", "status", lambda p: status(p, EV, {"subject": A, "action": {"name": "read"}, "resource": R1}, headers={"Content-Type": "text/plain"})),
    ("c-2-4-4", "status", lambda p: status(p, EV, raw=b'{"subject": ')),
    ("c-2-4-5", "status", lambda p: status(p, EV, raw=b"")),
    ("c-2-4-6/subject-string", "status", lambda p: status(p, EV, {"subject": "alice", "action": {"name": "read"}, "resource": R1})),
    ("c-2-4-6/name-number", "status", lambda p: status(p, EV, {"subject": A, "action": {"name": 123}, "resource": R1})),
    ("c-2-5", "headers", request_id),
    ("c-2-6", "values", idempotent),
    ("c-3-2-1", "structure", lambda p: batch(p, {"subject": A, "action": {"name": "read"}, "evaluations": [{"resource": R1}, {"resource": R2}]}, 2)),
    ("c-3-2-2", "values", lambda p: batch(p, {"subject": B, "resource": R1, "evaluations": [{"action": {"name": "read"}}, {"action": {"name": "write"}}]}, 2, [True, False])),
    ("c-3-2-3", "values", lambda p: batch(p, {"subject": A, "action": {"name": "write"}, "evaluations": [{"resource": R1ACT}, {"resource": R2ARCH}]}, 2, [True, False])),
    ("c-3-2-4", "values", lambda p: batch(p, {"action": {"name": "write"}, "resource": R2ARCH, "evaluations": [{"subject": A}, {"subject": BADMIN}]}, 2, [False, True])),
    ("c-3-2-5", "values", lambda p: batch(p, {"evaluations": [{"subject": A, "action": {"name": "read"}, "resource": R1}, {"subject": B, "action": {"name": "write"}, "resource": R1}]}, 2, [True, False])),
    ("c-3-2-6", "structure", lambda p: batch(p, {"subject": A, "action": {"name": "read"}, "context": {"time": "2025-06-27T18:03-07:00"},
                                                 "evaluations": [{"resource": R1}, {"resource": R2, "context": {"time": "2025-06-27T19:00-07:00", "source": "batch-override"}}]}, 2)),
    ("c-3-2-7", "values", lambda p: batch(p, {"subject": A, "action": {"name": "write"}, "resource": R1ACT, "evaluations": [{}, {"resource": R2ARCH}]}, 2, [True, False])),
    ("c-3-4-1", "values", lambda p: batch(p, {"subject": A, "action": {"name": "read"}, "options": {"evaluations_semantic": "execute_all"},
                                              "evaluations": [{"resource": R1}, {}]}, 2, [None, False])),
    ("c-3-4-2", "values", lambda p: decision(p, EVS, {"subject": A, "action": {"name": "read"}, "resource": R1}, True)),
    ("c-3-4-3", "values", lambda p: decision(p, EVS, {"subject": A, "action": {"name": "read"}, "resource": R1, "evaluations": []}, True)),
    ("c-4-2-1", "values", lambda p: search(p, SS, {"subject": {"type": "user"}, "action": {"name": "read"}, "resource": R1}, {"alice", "bob"}, "id")),
    ("c-4-2-2", "values", lambda p: search(p, SS, {"subject": {"type": "user"}, "action": {"name": "read"}, "resource": R1, "context": CTX}, {"alice", "bob"}, "id")),
    ("c-4-2-3", "values", lambda p: (lambda a, b: (a[0] and b[0], a[1] + b[1]))(
        search(p, SS, {"subject": A, "action": {"name": "read"}, "resource": R1}, {"alice", "bob"}, "id"),
        same_results(p, SS, {"subject": A, "action": {"name": "read"}, "resource": R1}, {"subject": {"type": "user"}, "action": {"name": "read"}, "resource": R1}))),
    ("c-4-2-4", "values", lambda p: search(p, SS, {"subject": {"type": "user"}, "action": {"name": "write"}, "resource": R2ARCH}, {"bob"}, "id")),
    ("c-4-3-1", "values", lambda p: search(p, RS, {"subject": A, "action": {"name": "read"}, "resource": {"type": "record"}}, {"record-1"}, "id")),
    ("c-4-3-2", "values", lambda p: search(p, RS, {"subject": A, "action": {"name": "read"}, "resource": {"type": "record"}, "context": CTX}, {"record-1"}, "id")),
    ("c-4-3-3", "values", lambda p: (lambda a, b: (a[0] and b[0], a[1] + b[1]))(
        search(p, RS, {"subject": A, "action": {"name": "read"}, "resource": R1}, {"record-1"}, "id"),
        same_results(p, RS, {"subject": A, "action": {"name": "read"}, "resource": R1}, {"subject": A, "action": {"name": "read"}, "resource": {"type": "record"}}))),
    ("c-4-3-4", "values", lambda p: search(p, RS, {"subject": BADMIN, "action": {"name": "write"}, "resource": {"type": "record"}}, {"record-2"}, "id")),
    ("c-4-4-1", "values", lambda p: search(p, AS, {"subject": A, "resource": R1}, {"read", "write"}, "name")),
    ("c-4-4-2", "values", lambda p: search(p, AS, {"subject": A, "resource": R1, "context": CTX}, {"read", "write"}, "name")),
    ("c-4-4-3", "values", lambda p: search(p, AS, {"subject": BADMIN, "resource": R2ARCH}, {"write"}, "name")),
    ("c-4-5", "structure", pagination),
    ("c-4-6-1", "values", lambda p: search(p, AS, {"subject": {"type": "user", "id": "nonexistent-user"}, "resource": R1}, "EMPTY", "name")),
    ("c-4-6-2", "values", lambda p: search(p, SS, {"subject": {"type": "spaceship"}, "action": {"name": "read"}, "resource": R1}, "EMPTY", "id")),
    ("c-4-7-1/subject-search", "status", lambda p: status(p, SS, {"subject": {"type": "user"}, "resource": R1})),
    ("c-4-7-1/resource-search", "status", lambda p: status(p, RS, {"action": {"name": "read"}, "resource": {"type": "record"}})),
    ("c-4-7-1/action-search", "status", lambda p: status(p, AS, {"subject": A})),
    ("c-4-7-2/subject-search", "status", lambda p: status(p, SS, {"subject": {"type": "user"}, "action": {"name": "read"}, "resource": {"type": "record"}})),
    ("c-4-7-2/resource-search", "status", lambda p: status(p, RS, {"subject": {"type": "user"}, "action": {"name": "read"}, "resource": {"type": "record"}})),
    ("c-4-7-2/action-search", "status", lambda p: status(p, AS, {"subject": {"type": "user"}, "resource": R1})),
    ("c-6", "metadata", metadata),
]


def run(p):
    out = []
    for cid, kind, fn in CASES:
        try:
            ok, note = fn(p)
        except Exception as e:
            ok, note = False, "exception %s: %s" % (type(e).__name__, e)
        out.append({"id": cid, "kind": kind, "ok": bool(ok), "note": "" if ok else note})
    return out


if __name__ == "__main__":
    import sys, importlib.util
    s = importlib.util.spec_from_file_location("p", sys.argv[1]); p = importlib.util.module_from_spec(s); s.loader.exec_module(p)
    rows = run(p)
    json.dump(rows, open(sys.argv[2], "w"), indent=1)
    print("%d/%d pass" % (sum(r["ok"] for r in rows), len(rows)))
    for r in rows:
        if not r["ok"]:
            print("FAIL", r["id"], r["note"][:200])
