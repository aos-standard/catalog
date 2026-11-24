#!/usr/bin/env python3
"""A minimal AuthZEN Authorization API 1.0 PDP, written from the text only, in-process (no network).

Text: api/authorization-api-1_0.md (Information Model, Access Evaluation(s), Search, PDP Metadata, Transport) and, of
certification/authorization-api-1_0-scenario.md, only the Introduction, Certification Levels and the Required Fixture
section (c-1). No test section of the scenario, no interop code and no other implementation was read before freezing.

handle(method, path, headers, body_bytes) -> (status:int, headers:dict, body_bytes)

Readings the text leaves open are marked R1..R12.
"""
import base64
import hashlib
import json

BASE = "https://pdp.example"
PATHS = {
    "/access/v1/evaluation": "evaluation",
    "/access/v1/evaluations": "evaluations",
    "/access/v1/search/subject": "search_subject",
    "/access/v1/search/resource": "search_resource",
    "/access/v1/search/action": "search_action",
}
WELL_KNOWN = "/.well-known/authzen-configuration"

# ---------------------------------------------------------------- fixture (scenario c-1)
SUBJECTS = {("user", "alice"): {}, ("user", "bob"): {"role": "admin"}}
RESOURCES = {("record", "record-1"): {"status": "active"}, ("record", "record-2"): {"status": "archived"}}
ACTIONS = ["read", "write", "delete"]


class BadRequest(Exception):
    pass


def _props(stored, given):
    # R1: properties passed in the request take precedence over stored ones ("stateless ... the PEP passes in all
    # relevant attributes"); stored fixture properties fill in the rest.
    out = dict(stored or {})
    out.update(given or {})
    return out


def decide(subject, action, resource, context=None):
    """The fixture policy of c-1-4. Unknown subjects or resources are denied (R2)."""
    skey, rkey = (subject["type"], subject["id"]), (resource["type"], resource["id"])
    if skey not in SUBJECTS or rkey not in RESOURCES:
        return False
    sp = _props(SUBJECTS[skey], subject.get("properties"))
    rp = _props(RESOURCES[rkey], resource.get("properties"))
    ap = action.get("properties") or {}
    name = action["name"]
    if name == "read":
        return True                                    # rules 1, 3
    if name == "write":
        if rp.get("status") == "archived":
            return sp.get("role") == "admin"           # rules 5, 6
        return skey == ("user", "alice")              # rules 2, 4 (R3: write on active is alice only)
    if name == "delete":
        return ap.get("soft") is True                  # rules 7, 8 (R4: soft must be the JSON literal true)
    return False


# ---------------------------------------------------------------- request validation (Information Model, Transport)
def _is_str(v):
    return isinstance(v, str)


def _check_entity(e, kind, need_id=True):
    if not isinstance(e, dict):
        raise BadRequest("%s must be an object" % kind)
    if kind == "action":
        if not _is_str(e.get("name")):
            raise BadRequest("action.name is required and must be a string")
    else:
        if not _is_str(e.get("type")):
            raise BadRequest("%s.type is required and must be a string" % kind)
        if need_id and not _is_str(e.get("id")):
            raise BadRequest("%s.id is required and must be a string" % kind)
        if not need_id and "id" in e and not _is_str(e.get("id")):
            pass  # R5: an id that "MUST be ignored" is ignored whatever its type
    if "properties" in e and not isinstance(e["properties"], dict):
        raise BadRequest("%s.properties must be an object" % kind)


def _check_context(req):
    if "context" in req and not isinstance(req["context"], dict):
        raise BadRequest("context must be an object")


def _evaluation(req):
    for k in ("subject", "action", "resource"):
        if k not in req:
            raise BadRequest("%s is required" % k)
        _check_entity(req[k], k)
    _check_context(req)
    return {"decision": decide(req["subject"], req["action"], req["resource"], req.get("context"))}


def _evaluations(req):
    evs = req.get("evaluations")
    if evs is None or evs == []:
        return _evaluation(req)                         # backwards-compatible single evaluation
    if not isinstance(evs, list):
        raise BadRequest("evaluations must be an array")
    opts = req.get("options", {})
    if not isinstance(opts, dict):
        raise BadRequest("options must be an object")
    sem = opts.get("evaluations_semantic", "execute_all")
    if sem not in ("execute_all", "deny_on_first_deny", "permit_on_first_permit"):
        raise BadRequest("unknown evaluations_semantic")  # R6: an unknown value is a bad request
    for k in ("subject", "action", "resource"):           # top-level defaults, if present, must be valid
        if k in req:
            _check_entity(req[k], k)
    _check_context(req)
    merged = []
    for ev in evs:
        if not isinstance(ev, dict):
            raise BadRequest("each evaluation must be an object")
        m = {}
        for k in ("subject", "action", "resource", "context"):
            # R7: a key in the evaluation replaces the top-level default as a whole (no merge of sub-fields)
            if k in ev:
                m[k] = ev[k]
            elif k in req:
                m[k] = req[k]
        for k in ("subject", "action", "resource"):
            if k not in m:
                raise BadRequest("%s missing from an evaluation and from the defaults" % k)  # R8: whole payload
            _check_entity(m[k], k)
        if "context" in m and not isinstance(m["context"], dict):
            raise BadRequest("context must be an object")
        merged.append(m)
    out = []
    for m in merged:
        d = decide(m["subject"], m["action"], m["resource"], m.get("context"))
        out.append({"decision": d})
        if sem == "deny_on_first_deny" and not d:
            break
        if sem == "permit_on_first_permit" and d:
            break
    return {"evaluations": out}                           # R9: top-level `decision` omitted (RECOMMENDED)


# ---------------------------------------------------------------- search
def _page(req, results):
    page = req.get("page")
    if page is None:
        return {"results": results}
    if not isinstance(page, dict):
        raise BadRequest("page must be an object")
    limit = page.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit < 0):
        raise BadRequest("page.limit must be a non-negative integer")
    # the token binds the offset to everything else in the request (R10: a changed request is a bad request)
    fp = dict(req)
    fp["page"] = {k: v for k, v in page.items() if k != "token"}
    digest = hashlib.sha256(json.dumps(fp, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    offset = 0
    tok = page.get("token")
    if tok not in (None, ""):
        try:
            raw = base64.urlsafe_b64decode(tok.encode()).decode()
            off_s, d = raw.split(":", 1)
            offset = int(off_s)
        except Exception as e:
            raise BadRequest("bad page token") from e
        if d != digest:
            raise BadRequest("request changed mid-pagination")
    n = len(results) - offset if limit is None else limit
    chunk = results[offset:offset + n]
    nxt = offset + len(chunk)
    next_token = base64.urlsafe_b64encode(("%d:%s" % (nxt, digest)).encode()).decode() if nxt < len(results) else ""
    return {"page": {"next_token": next_token, "count": len(chunk), "total": len(results)}, "results": chunk}


def _search(kind, req):
    if kind == "subject":
        _check_entity(req.get("subject"), "subject", need_id=False)
        _check_entity(req.get("action"), "action")
        _check_entity(req.get("resource"), "resource")
    elif kind == "resource":
        _check_entity(req.get("subject"), "subject")
        _check_entity(req.get("action"), "action")
        _check_entity(req.get("resource"), "resource", need_id=False)
    else:
        _check_entity(req.get("subject"), "subject")
        _check_entity(req.get("resource"), "resource")
        # R11: an `action` key in an Action Search request is an unknown field and is ignored
    _check_context(req)
    results = []
    if kind == "subject":
        t = req["subject"]["type"]
        for (st, sid) in SUBJECTS:
            if st != t:
                continue
            s = {"type": st, "id": sid, "properties": req["subject"].get("properties")}
            if decide(s, req["action"], req["resource"]):
                results.append({"type": st, "id": sid})
    elif kind == "resource":
        t = req["resource"]["type"]
        for (rt, rid) in RESOURCES:
            if rt != t:
                continue
            r = {"type": rt, "id": rid, "properties": req["resource"].get("properties")}
            if decide(req["subject"], req["action"], r):
                results.append({"type": rt, "id": rid})
    else:
        for name in ACTIONS:
            if decide(req["subject"], {"name": name}, req["resource"]):
                results.append({"name": name})
    return _page(req, results)


# ---------------------------------------------------------------- transport
def metadata():
    return {"policy_decision_point": BASE,
            "access_evaluation_endpoint": BASE + "/access/v1/evaluation",
            "access_evaluations_endpoint": BASE + "/access/v1/evaluations",
            "search_subject_endpoint": BASE + "/access/v1/search/subject",
            "search_resource_endpoint": BASE + "/access/v1/search/resource",
            "search_action_endpoint": BASE + "/access/v1/search/action"}


def _hdr(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def handle(method, path, headers, body):
    out_h = {}
    rid = _hdr(headers, "X-Request-ID")
    if rid is not None:
        out_h["X-Request-ID"] = rid                      # MUST echo the same identifier

    def reply(status, obj):
        h = dict(out_h)
        if status == 200:
            h["Content-Type"] = "application/json"
            return status, h, json.dumps(obj).encode()
        h["Content-Type"] = "text/plain"
        return status, h, str(obj).encode()              # error body: "An error message string"

    if path == WELL_KNOWN:
        if method != "GET":
            return reply(405, "method not allowed")      # R12: outside the spec's error table
        return reply(200, metadata())
    api = PATHS.get(path)
    if api is None:
        return reply(404, "not found")
    if method != "POST":
        return reply(405, "method not allowed")          # R12
    ct = _hdr(headers, "Content-Type")
    if ct is None or ct.split(";")[0].strip().lower() != "application/json":
        return reply(400, "Content-Type must be application/json")  # R12: the error table has no 415
    if not body:
        return reply(400, "empty request body")
    try:
        req = json.loads(body)
    except Exception:
        return reply(400, "malformed JSON")
    if not isinstance(req, dict):
        return reply(400, "the top-level element must be a JSON object")
    try:
        if api == "evaluation":
            return reply(200, _evaluation(req))
        if api == "evaluations":
            return reply(200, _evaluations(req))
        return reply(200, _search(api.split("_")[1], req))
    except BadRequest as e:
        return reply(400, str(e))
