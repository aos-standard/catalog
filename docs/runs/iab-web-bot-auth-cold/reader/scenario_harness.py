#!/usr/bin/env python3
"""Sign the scenarios of scenarios.json from the published test seeds and grade them with the frozen verifier.

Written from the "Scenarios" section of vectors/README.md. Inputs: inputs/scenarios_inputs.json (scenarios.json with
expected, basis, tier, name and $comment removed) and keys.json. The signature base is built with the verifier's own
signature_base(), which reproduced all 19 expected_signature_base values of the committed vectors byte for byte.
For target_uris, each GET is signed over the scenario's `wire` value and verified from its `url`, so the verifier's
target-URI rule is checked against the stated wire form, not against itself.

Usage: scenario_harness.py [--score]   (--score reads answers/scenarios_answers.json after the run)
"""
import base64
import hashlib
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
W = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import wba_cold_verifier as V  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

NOW = 1794052810  # the vectors' reference_now
RNG = random.Random(20261117)
S = json.load(open(os.path.join(W, "inputs", "scenarios_inputs.json"), encoding="utf-8"))
KEYS = json.load(open(os.path.join(W, "upstream/src/iab_agentic_primitives/web_bot_auth/vectors/keys.json")))["keys"]
JWK = {k["kid"]: {f: k[f] for f in ("kty", "crv", "kid", "x", "use")} for k in KEYS}
PRIV = {k["kid"]: Ed25519PrivateKey.from_private_bytes(V.b64url_decode(k["_private_d_for_test_only"])) for k in KEYS}
PARAM_ORDER = ["created", "keyid", "alg", "expires", "nonce", "tag"]


def comp(spec, label, req_label=None):
    parts = spec.replace("{label}", label).replace("{request_label}", req_label or "").split(";")
    params = []
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            params.append((k, v))
        else:
            params.append((p, True))
    return (parts[0], params)


def nonce(spec):
    raw = bytes(RNG.getrandbits(8) for _ in range(spec["bytes"]))
    enc = spec["encoding"]
    if enc == "base64url":
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    if enc == "base64":
        return base64.b64encode(raw).decode()
    if enc == "base64url-padded":
        return base64.urlsafe_b64encode(raw).decode()
    raise ValueError(enc)


def build_params(defaults, overrides, kid, now):
    p = dict(defaults)
    p.setdefault("keyid", kid)
    p.setdefault("alg", "ed25519")
    for k, v in (overrides or {}).items():
        p[k] = v
    out = []
    for k in PARAM_ORDER + [k for k in p if k not in PARAM_ORDER]:
        if k not in p or p[k] is None:
            continue
        v = p[k]
        if k in ("created", "expires"):
            v = now + v
        elif k == "nonce" and isinstance(v, dict):
            v = nonce(v)
        out.append((k, v))
    return out


def sign(msg_for_base, items, plist, kid, req_for_base=None):
    base = V.signature_base(items, plist, msg_for_base, req_for_base, None)
    return PRIV[kid].sign(base)


def si_member(label, items, plist):
    return label + "=" + V.ser_member(("inner", items, plist))


def digest_header(body):
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def directory(origin, kids, now, sc=None):
    sc = sc or {}
    host = origin.split("://", 1)[1]
    listed = [JWK[k] for k in kids] if "keys" not in sc else list(sc["keys"])
    signers = [k for k in kids] if "keys" not in sc else [j["kid"] for j in sc["keys"] if j["kid"] in PRIV]
    listed = listed + list(sc.get("unsigned_keys") or [])
    body = json.dumps({"keys": listed}, indent=2).encode()
    ct = sc.get("content_type", "application/http-message-signatures-directory+json")
    headers = [["Content-Type", ct], ["Cache-Control", "max-age=%d" % S["directory_max_age"]], ["Content-Digest", digest_header(body)]]
    dparams = dict(S["directory_parameters"])
    dparams.update(sc.get("parameters") or {})
    comps = sc.get("components") or ["@authority;req", "content-digest"]
    si, sg = [], []
    sign_auth = sc.get("authority", host)
    for i, kid in enumerate(signers, 1):
        lab = "key%d" % i
        items = [comp(c, lab) for c in comps]
        plist = [("created", now + dparams["created"]), ("keyid", kid), ("alg", "ed25519"),
                 ("expires", now + dparams["expires"]), ("tag", "http-message-signatures-directory")]
        req = {"method": "GET", "headers": [], "_authority": sign_auth, "_target_uri": "https://" + sign_auth + V.DIRECTORY_PATH}
        sig = sign({"headers": headers, "status": 200}, items, plist, kid, req)
        si.append(si_member(lab, items, plist))
        sg.append(lab + "=:" + base64.b64encode(sig).decode() + ":")
    if si:
        headers += [["Signature-Input", ", ".join(si)], ["Signature", ", ".join(sg)]]
    after = sc.get("after_signing") or {}
    if "append_to_body" in after:
        body += after["append_to_body"].encode()
    return {"url": origin + V.DIRECTORY_PATH, "status": 200, "headers": headers, "body": body.decode()}


def signed_request(sc, now, verifier_auth, wire=None):
    base = json.loads(json.dumps(S["requests"][sc.get("base", "post")]))
    if "url" in sc:
        base["url"] = sc["url"]
    label = sc.get("label", "sig1")
    signer = S["signer"]
    body = base["body"].encode()
    headers = [list(h) for h in base["headers"]]
    if body:
        headers.append(["Content-Digest", digest_header(body)])
    sa_value = sc.get("signature_agent", '%s="%s"' % (label, signer["signature_agent"]))
    headers.append(["Signature-Agent", sa_value])
    comps = sc.get("components") or S["components"][sc.get("base", "post")]
    items = [comp(c, label) for c in comps]
    plist = build_params(S["parameters"], sc.get("parameters"), signer["kid"], now)
    tu, auth = V.target_uri(base["url"], None)
    if wire is not None:
        tu = wire
    msg = {"method": base["method"], "headers": headers, "_target_uri": tu, "_authority": auth}
    sig = sign(msg, items, plist, signer["kid"])
    si = [si_member(label, items, plist)]
    sg = ["%s=:%s:" % (label, base64.b64encode(sig).decode())]
    extra = sc.get("extra_signature")
    if extra:
        eitems = [comp(c, extra["label"]) for c in extra["components"]]
        eplist = build_params({}, extra.get("parameters"), extra["kid"], now)
        esig = sign(msg, eitems, eplist, extra["kid"])
        si.append(si_member(extra["label"], eitems, eplist))
        sg.append("%s=:%s:" % (extra["label"], base64.b64encode(esig).decode()))
    after = sc.get("after_signing") or {}
    for name, val in (after.get("headers") or {}).items():
        headers = [h for h in headers if h[0].lower() != name.lower()] + [[name, val]]
    if "append_to_body" in after:
        body += after["append_to_body"].encode()
    am = after.get("append_members") or {}
    if "signature-input" in am:
        si.append(am["signature-input"])
    if "signature" in am:
        sg.append(am["signature"])
    headers += [["Signature-Input", ", ".join(si)], ["Signature", ", ".join(sg)]]
    return {"method": base["method"], "url": base["url"], "headers": headers, "body": body.decode()}, label


def request_op(sc, now):
    auth = sc.get("authority", S["verifier"])
    req, _ = signed_request(sc, now, auth)
    dirs = sc.get("directories") or {S["signer"]["identity"]: [S["signer"]["kid"]]}
    return {"op": "verify_request", "request": req, "authority": auth, "now": now, "prior": [],
            "directories": {o: directory(o, kids, now) for o, kids in dirs.items()}}


def directory_op(sc, now):
    req, _ = signed_request({"base": "post", "label": "sig1"}, now, S["verifier"])
    o = S["signer"]["identity"]
    return {"op": "verify_request", "request": req, "authority": S["verifier"], "now": now, "prior": [],
            "directories": {o: directory(o, [S["signer"]["kid"]], now, sc)}}


def response_op(sc, now):
    req, req_label = signed_request({"base": "post", "label": "sig1"}, now, S["verifier"])
    if sc.get("request", "bound") == "unbound":
        req = dict(req)
        req["headers"] = [h for h in req["headers"] if h[0].lower() not in ("signature", "signature-input", "signature-agent")]
    r = json.loads(json.dumps(S["response"]))
    label = sc.get("label", "sig1")
    resp = S["responder"]
    body = r["body"].encode()
    headers = [list(h) for h in r["headers"]]
    if body:
        headers.append(["Content-Digest", digest_header(body)])
    headers.append(["Signature-Agent", '%s="%s"' % (label, resp["signature_agent"])])
    kind = "bound" if sc.get("request", "bound") == "bound" else "unbound"
    comps = sc.get("components") or S["response_components"][kind]
    items = [comp(c, label, req_label) for c in comps]
    plist = build_params(S["response_parameters"], sc.get("parameters"), resp["kid"], now)
    reqp = V.prepare_request(req, None)
    sig = sign({"headers": headers, "status": r["status"]}, items, plist, resp["kid"], reqp)
    headers += [["Signature-Input", si_member(label, items, plist)], ["Signature", "%s=:%s:" % (label, base64.b64encode(sig).decode())]]
    after = sc.get("after_signing") or {}
    status = after.get("status", r["status"])
    if "append_to_body" in after:
        body += after["append_to_body"].encode()
    for name, val in (after.get("request_headers") or {}).items():
        req = dict(req)
        req["headers"] = [h for h in req["headers"] if h[0].lower() != name.lower()] + [[name, val]]
    o = resp["identity"]
    return {"op": "verify_response", "request": req, "response": {"status": status, "headers": headers, "body": body.decode()},
            "now": now, "directories": {o: directory(o, [resp["kid"]], now)}}


def target_op(sc, now):
    rq = {"base": "get", "label": "sig1", "url": sc["url"]}
    req, _ = signed_request(rq, now, S["verifier"], wire=sc["wire"])
    o = S["signer"]["identity"]
    return {"op": "verify_request", "request": req, "authority": S["verifier"], "now": now, "prior": [],
            "directories": {o: directory(o, [S["signer"]["kid"]], now)}}


def main():
    out = {}
    for group, fn in (("request_scenarios", request_op), ("directory_scenarios", directory_op),
                      ("response_scenarios", response_op), ("target_uris", target_op)):
        for sc in S[group]:
            try:
                op = fn(sc, NOW)
                res = V.run(op)
            except Exception as e:  # noqa: BLE001
                res = {"harness_error": type(e).__name__ + ": " + str(e)}
            if group == "target_uris":
                res["computed_wire"] = V.target_uri(sc["url"])[0]
            out[sc["id"]] = res
    json.dump(out, sys.stdout, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
