#!/usr/bin/env python3
"""A reader of openabdev/openab-computer's three conformance vector sets, written from the public text only:
README.md (## Auth, ## Lending this Mac), docs/requirements/authn.md, docs/tool-profiles.md, docs/adr/reverse-attach.md,
openabdev/openab-pty runtime/CLIENT-CONTRACT.md section 9, MCP 2025-06-18 (lifecycle, tools) and JSON-RPC 2.0.
Not opened: any .swift or .rs file, scripts/, poc/ code. Where the text does not decide, the reading is named O<n>.

Answer exposure, before writing: the comments on issue #24 were read. They name the Swift stop reasons (grantExpired,
replaced, sessionEnded, revoked), say Swift treats 4003/4999/4006/1000/1006 as redial and that the shipped Linux AuthPolicy
differed by a case-sensitive `Bearer`, deny reasons, and X-Forwarded-For. Where this reader follows the text against
those comments, it says so (O7).
"""
from __future__ import annotations

import hmac
import json

# ------------------------------------------------------------------ AuthPolicy
def validate(config: dict) -> str | None:
    # README: "the server refuses to start with nothing configured"
    if not config.get("allowedLogins") and config.get("bearerToken") is None and not config.get("allowLocalUnauthenticated"):
        return "error"
    return None


def _header(h: dict, name: str):
    for k, v in (h or {}).items():
        if k.lower() == name:
            return v
    return None


def decide(config: dict, headers: dict, remote_is_loopback: bool) -> dict:
    """Returns {"allow": principal} or {"deny": reason}. Reasons are this reader's words (the text names none)."""
    logins = config.get("allowedLogins") or []
    token = config.get("bearerToken")
    local_ok = bool(config.get("allowLocalUnauthenticated"))
    login = _header(headers, "tailscale-user-login")
    xff = _header(headers, "x-forwarded-for")
    auth = _header(headers, "authorization")
    # O1: --insecure-local admits a *bare* loopback request: loopback peer and no proxy headers at all
    # (no Tailscale-User-Login, no X-Forwarded-For). It waives the login check only; a configured token is still
    # required, because configured checks are AND-combined (README ## Auth).
    bare_local = local_ok and remote_is_loopback and login is None and xff is None
    principal = None
    if token is not None:
        if auth is None:
            return {"deny": "missing bearer token"}
        value = auth.strip(" \t")  # O2: RFC 9110 5.5 field values carry no leading/trailing whitespace
        scheme, _, cred = value.partition(" ")
        if scheme.lower() != "bearer":  # O3: RFC 9110 11.1, the auth-scheme is case-insensitive
            return {"deny": "authorization is not a bearer token"}
        cred = cred.lstrip(" ")
        if not hmac.compare_digest(cred.encode(), token.encode()):  # README: constant-time compared
            return {"deny": "bad bearer token"}
        principal = "token"
    if logins:
        if login is None:
            if not bare_local:
                return {"deny": "missing Tailscale-User-Login"}
            principal = principal or "local"
        elif login not in logins:  # O4: exact string match (README "matches"); no case folding of the login
            return {"deny": "login not allowed"}
        else:
            principal = login
    elif local_ok and token is None:
        if not bare_local:
            return {"deny": "not a bare loopback request"}
        principal = "local"
    if principal is None:  # nothing configured that this request passed
        return {"deny": "no check passed"}
    return {"allow": principal}


# ------------------------------------------------------------------ reverse attach (§9.2)
STOP_NAMES = {4001: "grantExpired", 4002: "replaced", 4004: "sessionEnded", 4010: "revoked"}  # names: exposure (#24)


def close_disposition(code: int) -> dict:
    # CLIENT-CONTRACT 9.2: stop on 4001/4002/4004/4010; redial on 4006 and 1000; "give up on any 4xxx except 4006".
    if code in STOP_NAMES:
        return {"stop": STOP_NAMES[code]}
    if code == 4006:
        return {"redial": True}
    if 4000 <= code <= 4999:
        return {"stop": "close%d" % code}  # O7: follows the contract text; #24 says Swift redials here
    return {"redial": True}  # 1000 "you closed, or the socket dropped"; 1006 and other transport closes the same (O5)


def handshake_disposition(status: int) -> dict:
    # README: stop on "handshake 401". O6: every other status (101/2xx a non-rejection, 429 throttle, 5xx, other 4xx)
    # is redial; the text names only 401 as a stop.
    if status == 401:
        return {"stop_rejected": 401}
    return {"redial": True}


def attach_url(runtime: str, session: str) -> str:
    # CLIENT-CONTRACT 9.2: GET /tools/attach/{session}, under the runtime base the operator gave (README example ws://…:8090).
    # O8: join under the base path without doubling the slash; scheme kept as given; session not re-encoded.
    return runtime.rstrip("/") + "/tools/attach/" + session


# ------------------------------------------------------------------ MCP wire (server side)
SUPPORTED = ["2025-06-18", "2025-03-26", "2024-11-05"]  # O9: the versions current at the time of the contract


def answer(raw: str, profile: str | None = None) -> dict | None:
    """Returns None for no response, else {"error": code} or {"result": {...}}."""
    try:
        msg = json.loads(raw)
    except Exception:
        return {"error": -32700}
    if isinstance(msg, list):
        return {"error": -32600}  # O10: MCP 2025-06-18 removed JSON-RPC batching; a batch is an invalid request
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return {"error": -32600}
    if "id" not in msg:
        return None  # notification
    m = msg["method"]; p = msg.get("params") or {}
    if m == "initialize":
        want = p.get("protocolVersion")
        return {"result": {"protocolVersion": want if want in SUPPORTED else SUPPORTED[0]}}
    if m == "ping":
        return {"result": {}}
    if m == "tools/list":
        return {"result": {"tools": [{"name": "sys_info", "description": "…", "inputSchema": {"type": "object"}}]}}
    if m == "tools/call":
        name = p.get("name") if isinstance(p, dict) else None
        if not isinstance(name, str):
            return {"error": -32602}
        return {"error": -32602}  # MCP tools: unknown tool is a protocol error -32602 (README: "unknown tool error")
    return {"error": -32601}
