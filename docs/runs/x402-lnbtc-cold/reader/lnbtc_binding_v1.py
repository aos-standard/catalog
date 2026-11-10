"""x402 exact/lnbtc request binding (http:1, mcp:1), written from scheme_exact_lnbtc.md at 63d5640 only.

Sections read: Amounts, Request Binding, Description Hash Encoding, HTTP Profile, MCP Profile, and the README's
Layout / Inputs / Expectations. Not read before freezing: the spec's "Request Binding Test Vectors", the README's
"Case groups" and "Not covered", the vectors' expect/note, any SDK code. Standard library only.

Readings this file takes where the text is not explicit are marked R1..Rn.
"""
from __future__ import annotations

import hashlib
import json
import math
import re

BINDING_ERROR = "invalid_exact_lnbtc_request_binding"  # R1: binding failures use the facilitator's binding reason


class Reject(Exception):
    pass


# ------------------------------------------------------------------ JCS (RFC 8785)
def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Reject("duplicate member name")
        out[k] = v
    return out


def _check_str(s: str) -> None:
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise Reject("lone surrogate")


def _num(x) -> str:
    if isinstance(x, bool):
        raise TypeError
    f = float(x)
    if math.isnan(f) or math.isinf(f):
        raise Reject("non-finite number")
    if f == 0:
        return "0"
    # ECMAScript Number::toString: shortest round-trip digits, then the ES layout.
    r = repr(f)
    sign = "-" if f < 0 else ""
    r = r.lstrip("-")
    if "e" in r or "E" in r:
        mant, exp = r.lower().split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    point = len(ip) + exp  # position of the decimal point relative to the digit string start (before stripping)
    lead = len(ip + fp) - len((ip + fp).lstrip("0"))
    point -= lead
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    n = point
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    es = ("+" if e >= 0 else "-") + str(abs(e))
    if k == 1:
        return sign + digits + "e" + es
    return sign + digits[0] + "." + digits[1:] + "e" + es


def _str(s: str) -> str:
    _check_str(s)
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s: str):
    return s.encode("utf-16-be")


def jcs(v) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _num(v)
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            _check_str(k)
        return "{" + ",".join(_str(k) + ":" + jcs(v[k]) for k in sorted(v, key=_utf16_key)) + "}"
    raise Reject("outside the JSON data model")


def parse_json(text: str):
    """The 'SDK's normal JSON parser', refusing what JCS cannot represent (duplicates, NaN/Infinity)."""
    def bad_const(_):
        raise Reject("non-finite literal")
    try:
        return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=bad_const)
    except Reject:
        raise
    except ValueError as e:
        raise Reject("JSON parse: %s" % e)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def request_hash(binding: dict) -> tuple[str, str]:
    text = jcs(binding)
    return sha(text.encode("utf-8")), text


# ------------------------------------------------------------------ HTTP helpers (RFC 9110 / 9421 / 3986)
TCHAR = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
FIELD_NAME_LC = re.compile(r"^[!#$%&'*+\-.^_`|~0-9a-z]+$")
URI_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$")
PCT_OK = re.compile(r"%(?![0-9A-Fa-f]{2})")
REG_NAME = re.compile(r"^(?:[A-Za-z0-9\-._~!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$")


def check_bound_headers(names) -> list[str]:
    if not isinstance(names, list):
        raise Reject("headers not an array")
    for n in names:
        if not isinstance(n, str) or not FIELD_NAME_LC.match(n):
            raise Reject("header name not a lowercase token")
        if n == "payment-signature":
            raise Reject("payment-signature bound")
    if any(names[i] >= names[i + 1] for i in range(len(names) - 1)):  # ascending ASCII, no duplicates
        raise Reject("header names not strictly ascending")
    return names


def split_authority(auth: str):
    """RFC 3986 authority without userinfo -> (host_lower, port or None). Rejects anything else (R2)."""
    if not isinstance(auth, str) or auth == "":
        raise Reject("empty authority")
    if any(c in auth for c in "/?#\\@") or any(ord(c) < 0x21 or ord(c) > 0x7E for c in auth):
        raise Reject("authority has path, query, fragment, backslash, userinfo or a control/non-ASCII char")
    if auth.startswith("["):
        end = auth.find("]")
        if end < 0:
            raise Reject("unterminated IP-literal")
        host, rest = auth[: end + 1], auth[end + 1 :]
        inner = host[1:-1]
        if not inner or not re.match(r"^[0-9A-Fa-f:.]+$", inner):
            raise Reject("bad IP-literal")
        if rest and not rest.startswith(":"):
            raise Reject("junk after IP-literal")
        port = rest[1:] if rest else None
    else:
        if "[" in auth or "]" in auth:
            raise Reject("bracket outside an IP-literal")
        host, _, port = auth.partition(":")
        port = port if ":" in auth else None
        if host == "" or not REG_NAME.match(host):
            raise Reject("bad reg-name")
    if port is not None:
        if port == "":
            port = None  # RFC 3986 allows an empty port; treat as default (R3)
        elif not port.isdigit() or not port.isascii() or int(port) > 65535:
            raise Reject("bad port")
        else:
            port = int(port)
    return host.lower(), port


DEFAULT_PORT = {"http": 80, "https": 443}


def parse_abs_url(url: str):
    """Absolute http(s) URL in ASCII URI syntax, no userinfo, no fragment. Returns (scheme_lower, authority, rest)."""
    if not isinstance(url, str) or not URI_CHARS.match(url) or PCT_OK.search(url):
        raise Reject("URL not ASCII URI syntax")
    if "#" in url:
        raise Reject("fragment")
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?]*)(.*)$", url)
    if not m:
        raise Reject("not absolute")
    scheme, auth, rest = m.group(1), m.group(2), m.group(3)
    if scheme.lower() not in DEFAULT_PORT:
        raise Reject("not http or https")
    split_authority(auth)
    if rest and not (rest.startswith("/") or rest.startswith("?")):
        raise Reject("bad path")
    return scheme.lower(), auth, rest


def field_value(header_lines, name: str):
    """RFC 9421 2.1 default field value: lines in order, each trimmed of SP/HTAB, joined with ', '. None if absent."""
    vals = [v for (n, v) in header_lines if isinstance(n, str) and n.lower() == name]
    if not vals:
        return None
    out = []
    for v in vals:
        if not isinstance(v, str):
            raise Reject("field value not a string")
        v = re.sub(r"\r\n[ \t]+", " ", v)  # obs-fold (RFC 9421 2.1)
        v = v.strip(" \t")
        if any(not (c == "\t" or 0x20 <= ord(c) <= 0x7E) for c in v):  # R4: unsupported values (controls, non-ASCII)
            raise Reject("unsupported field value")
        out.append(v)
    return ", ".join(out)


def header_entries(bound, header_lines):
    entries = []
    for n in bound:
        v = field_value(header_lines, n)
        h = sha(b"\x00") if v is None else sha(b"\x01" + v.encode("ascii"))
        entries.append({"name": n, "valueHash": h})
    return entries


def http_binding(inp: dict) -> dict:
    method = inp.get("method")
    if not isinstance(method, str) or not TCHAR.match(method):
        raise Reject("method not a token")
    url = inp.get("url")
    parse_abs_url(url)
    bound = check_bound_headers(inp.get("bound_headers"))
    body_hex = inp.get("body_hex", "")
    try:
        body = bytes.fromhex(body_hex)
    except (ValueError, TypeError):
        raise Reject("body_hex")
    return {
        "domain": "x402:exact:lnbtc:bolt11:http:1",
        "method": method,
        "url": url,
        "bodyHash": sha(body),
        "headers": header_entries(bound, inp.get("header_lines") or []),
    }


def http_server_adapter(config: dict, inp: dict) -> dict:
    """R5: the adapter reconstructs the URL from the configured public origin and the request's path and query.
    The request's own authority (Host, or :authority when Host is absent) must be well formed and name the configured
    origin (host case-insensitive, default port equivalent). No trusted proxy is configured in these inputs, so
    X-Forwarded-* are not used and not parsed (R6). A request whose framework URL names another origin is refused."""
    o_scheme, o_auth, o_rest = parse_abs_url(config.get("public_origin"))
    if o_rest not in ("", "/"):
        raise Reject("public origin has a path")
    o_host, o_port = split_authority(o_auth)
    o_port = o_port if o_port is not None else DEFAULT_PORT[o_scheme]

    lines = inp.get("header_lines") or []
    host_v = field_value(lines, "host")
    auth_v = field_value(lines, ":authority")
    req_auth = host_v if host_v is not None else auth_v
    if req_auth is None:
        raise Reject("no authority")
    if host_v is not None and auth_v is not None and host_v != auth_v:
        raise Reject("Host and :authority differ")
    r_host, r_port = split_authority(req_auth)
    r_port = r_port if r_port is not None else DEFAULT_PORT[o_scheme]
    if (r_host, r_port) != (o_host, o_port):
        raise Reject("request authority is not the configured origin")

    f_scheme, f_auth, f_rest = parse_abs_url(inp.get("url"))
    f_host, f_port = split_authority(f_auth)
    f_port = f_port if f_port is not None else DEFAULT_PORT[f_scheme]
    if (f_scheme, f_host, f_port) != (o_scheme, o_host, o_port):
        raise Reject("framework URL names another origin")
    url = config["public_origin"].rstrip("/") + (f_rest or "/")  # R7: an empty path becomes "/"
    return http_binding({
        "method": inp.get("method"),
        "url": url,
        "body_hex": inp.get("body_hex", ""),
        "bound_headers": config.get("bound_headers"),
        "header_lines": lines,
    })


# ------------------------------------------------------------------ MCP
EXCLUDED_META = {"x402/payment", "progressToken"}


def mcp_binding(inp: dict) -> dict:
    server = inp.get("server")
    if not isinstance(server, str) or not re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", server) \
            or not URI_CHARS.match(server) or PCT_OK.search(server) or "#" in server:
        raise Reject("server not an absolute ASCII URI without fragment")
    m = re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*://([^/?]*)", server)
    if m and "@" in m.group(1):
        raise Reject("server has userinfo")
    names = inp.get("bound_metadata")
    if not isinstance(names, list) or any(not isinstance(n, str) or n == "" for n in names):
        raise Reject("metadata names")
    for n in names:
        _check_str(n)
        if n in EXCLUDED_META:
            raise Reject("excluded metadata name bound")
    keys = [_utf16_key(n) for n in names]
    if any(keys[i] >= keys[i + 1] for i in range(len(keys) - 1)):
        raise Reject("metadata names not in JCS order or duplicated")
    if "params_json" in inp:
        params = parse_json(inp["params_json"])
    else:
        params = inp.get("params")
    if not isinstance(params, dict):
        raise Reject("params not an object")
    name = params.get("name")
    if not isinstance(name, str) or name == "":
        raise Reject("name")
    if "arguments" in params:
        args = params["arguments"]
        if not isinstance(args, dict):
            raise Reject("arguments null or not an object")
    else:
        args = {}
    if "_meta" in params:
        meta = params["_meta"]
        if not isinstance(meta, dict):
            raise Reject("_meta not an object")
    else:
        meta = {}
    entries = []
    for n in names:
        if n in meta:
            entries.append({"name": n, "valueHash": sha(b"\x01" + jcs(meta[n]).encode("utf-8"))})
        else:
            entries.append({"name": n, "valueHash": sha(b"\x00")})
    return {
        "domain": "x402:exact:lnbtc:bolt11:mcp:1",
        "server": server,
        "method": "tools/call",
        "name": name,
        "arguments": args,
        "metadata": entries,
    }


def run_case(section: str, case: dict) -> dict:
    try:
        if section == "http_binding":
            b = http_binding(case["input"])
        elif section == "http_server_adapter":
            b = http_server_adapter(case["config"], case["input"])
        elif section == "mcp_binding":
            b = mcp_binding(case["input"])
        else:
            raise ValueError(section)
        h, text = request_hash(b)
        return {"request_hash": h, "canonical_description": text}
    except Reject as e:
        return {"error": BINDING_ERROR, "why": str(e)}
