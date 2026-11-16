#!/usr/bin/env python3
"""Clean-room verifier for the IAB Web Bot Auth profile (iab-agentic-primitives PR #4).

Written from WEB_BOT_AUTH.md ("Profile rules", "The target URI", "Verification procedure",
"Choices the profile leaves open"), the vectors README (input format only), RFC 9421, RFC 8941,
RFC 9530 and RFC 7638/8037. The module's Python code, its tests, and the vectors' expected
members were not opened. Python standard library plus `cryptography` for Ed25519.

Input: one operation (the vector's `operation` member) on stdin or as a file argument.
Output: {"ok": true, "identity": ...} or {"ok": false, "status": N, "rule": "..."}.
"""
import base64
import hashlib
import json
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SKEW = 60
MAX_LIFETIME = 300
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA = "application/http-message-signatures-directory+json"
DIRECTORY_TAG = "http-message-signatures-directory"
SIGNATURE_TAG = "web-bot-auth"
MAX_DIRECTORY_BYTES = 256 * 1024
MAX_DIRECTORY_KEYS = 16
STATUS = {"parse": 400, "nonce-replayed": 429, "nonce-store-unavailable": 503}


class Refusal(Exception):
    def __init__(self, rule, detail=""):
        super().__init__(rule)
        self.rule = rule
        self.detail = detail

    def result(self):
        return {"ok": False, "status": STATUS.get(self.rule, 403), "rule": self.rule}


# ---------------------------------------------------------------- RFC 8941 structured fields


class SFError(Exception):
    pass


class Token(str):
    pass


class _P:
    def __init__(self, s):
        if any(ord(c) > 0x7E or (ord(c) < 0x20) for c in s):
            raise SFError("non-ascii or control")
        self.s = s
        self.i = 0

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def ows(self):
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1

    def sp(self):
        while self.peek() == " ":
            self.i += 1

    def key(self):
        c = self.peek()
        if not (c.islower() and c.isascii() or c == "*"):
            raise SFError("key")
        st = self.i
        while self.peek() and (self.peek().islower() and self.peek().isascii() or self.peek().isdigit() or self.peek() in "_-.*"):
            self.i += 1
        return self.s[st:self.i]

    def bare_item(self):
        c = self.peek()
        if c == '"':
            return self.string()
        if c == ":":
            return self.binary()
        if c == "?":
            self.i += 1
            v = self.peek()
            if v not in ("0", "1"):
                raise SFError("bool")
            self.i += 1
            return v == "1"
        if c == "-" or c.isdigit():
            return self.number()
        if c.isalpha() and c.isascii() or c == "*":
            return self.token()
        raise SFError("bare item")

    def string(self):
        self.i += 1
        out = []
        while True:
            c = self.peek()
            if not c:
                raise SFError("unterminated string")
            self.i += 1
            if c == "\\":
                n = self.peek()
                if n not in ('"', "\\"):
                    raise SFError("escape")
                out.append(n)
                self.i += 1
            elif c == '"':
                return "".join(out)
            else:
                out.append(c)

    def binary(self):
        self.i += 1
        st = self.i
        while self.peek() and self.peek() != ":":
            if not (self.peek().isalnum() or self.peek() in "+/="):
                raise SFError("binary char")
            self.i += 1
        if self.peek() != ":":
            raise SFError("unterminated binary")
        raw = self.s[st:self.i]
        self.i += 1
        try:
            return base64.b64decode(raw, validate=True)
        except Exception as e:  # noqa: BLE001
            raise SFError("binary") from e

    def number(self):
        st = self.i
        if self.peek() == "-":
            self.i += 1
        if not self.peek().isdigit():
            raise SFError("number")
        while self.peek().isdigit() or self.peek() == ".":
            self.i += 1
        txt = self.s[st:self.i]
        if "." in txt:
            ip, _, fp = txt.lstrip("-").partition(".")
            if "." in fp or not fp or len(ip) > 12 or len(fp) > 3:
                raise SFError("decimal")
            return float(txt)
        if len(txt.lstrip("-")) > 15:
            raise SFError("integer")
        return int(txt)

    def token(self):
        st = self.i
        while self.peek() and (self.peek().isalnum() and self.peek().isascii() or self.peek() in "!#$%&'*+-.^_`|~:/"):
            self.i += 1
        return Token(self.s[st:self.i])

    def params(self):
        ps = []
        seen = set()
        while self.peek() == ";":
            self.i += 1
            self.sp()
            k = self.key()
            v = True
            if self.peek() == "=":
                self.i += 1
                v = self.bare_item()
            if k in seen:
                raise SFError("repeated parameter")  # profile: a repeated parameter is 400
            seen.add(k)
            ps.append((k, v))
        return ps

    def item_or_inner(self):
        if self.peek() == "(":
            self.i += 1
            items = []
            while True:
                self.sp()
                if self.peek() == ")":
                    self.i += 1
                    return ("inner", items, self.params())
                v = self.bare_item()
                items.append((v, self.params()))
                if self.peek() not in (" ", ")"):
                    raise SFError("inner list")
        v = self.bare_item()
        return ("item", v, self.params())

    def dictionary(self):
        members = []  # list, so repeated keys stay visible
        self.sp()
        if not self.peek():
            return members
        while True:
            k = self.key()
            if self.peek() == "=":
                self.i += 1
                m = self.item_or_inner()
            else:
                m = ("item", True, self.params())
            members.append((k, m))
            self.ows()
            if not self.peek():
                return members
            if self.peek() != ",":
                raise SFError("dict sep")
            self.i += 1
            self.ows()
            if not self.peek():
                raise SFError("trailing comma")


def parse_dict(value):
    p = _P(value)
    return p.dictionary()


def ser_bare(v):
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, Token):
        return str(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return ("%.3f" % v).rstrip("0").rstrip(".") if "." in ("%.3f" % v) else str(v)
    if isinstance(v, (bytes, bytearray)):
        return ":" + base64.b64encode(v).decode() + ":"
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise SFError("serialize")


def ser_params(ps):
    out = ""
    for k, v in ps:
        out += ";" + k + ("" if v is True else "=" + ser_bare(v))
    return out


def ser_member(m):
    kind, v, ps = m
    if kind == "inner":
        return "(" + " ".join(ser_bare(x) + ser_params(xp) for x, xp in v) + ")" + ser_params(ps)
    return ser_bare(v) + ser_params(ps)


# ---------------------------------------------------------------- messages


def field_lines(headers, name):
    return [v for n, v in headers if n.lower() == name]


def field_value(headers, name):
    lines = field_lines(headers, name)
    if not lines:
        return None
    return ", ".join(v.strip(" \t") for v in lines)


def body_bytes(body):
    if isinstance(body, dict):
        return base64.b64decode(body["base64"])
    return body.encode("utf-8")


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---------------------------------------------------------------- target URI


_PCT_ALWAYS = set('"<> ')


def _enc(s, extra):
    out = []
    for ch in s:
        o = ord(ch)
        if o < 0x21 or o == 0x7F or o > 0x7E or ch in _PCT_ALWAYS or ch in extra:
            out.append("".join("%%%02X" % b for b in ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


def _remove_dots(path):
    segs = path.split("/")
    out = []
    for i, seg in enumerate(segs):
        low = seg.lower().replace("%2e", ".")
        last = i == len(segs) - 1
        if low == ".":
            if last:
                out.append("")
            continue
        if low == "..":
            if len(out) > 1:
                out.pop()
            if last:
                out.append("")
            continue
        out.append(seg)
    res = "/".join(out)
    if not res.startswith("/"):
        res = "/" + res
    return res


def canonical_host(host):
    if host.startswith("["):
        import ipaddress
        inner = host[1:-1]
        if "%" in inner:
            raise ValueError("zone")
        return "[" + ipaddress.IPv6Address(inner).compressed + "]"
    h = host.lower()
    if any(ord(c) > 0x7E for c in h):
        h = h.encode("idna").decode("ascii")
    return h


def split_url(url):
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$", url, re.S)
    if not m:
        raise ValueError("url")
    scheme, auth, path, query, _frag = m.groups()
    scheme = scheme.lower()
    if "@" in auth:
        auth = auth.rsplit("@", 1)[1]
    if auth.startswith("["):
        end = auth.index("]")
        host, rest = auth[: end + 1], auth[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = auth.partition(":")
    host = canonical_host(host)
    default = {"https": "443", "http": "80"}.get(scheme)
    if port == default:
        port = ""
    authority = host + (":" + port if port else "")
    return scheme, authority, path, query


def target_uri(url, authority=None):
    scheme, auth, path, query = split_url(url)
    if authority is not None:
        auth = authority
    path = _remove_dots(_enc(path or "/", "`{}"))
    q = ""
    if query and query != "?":
        q = "?" + _enc(query[1:], "'")
    return f"{scheme}://{auth}{path}{q}", auth


# ---------------------------------------------------------------- signature fields


def parse_signature_fields(headers):
    """Step 1: every member parsed and type-checked; any failure is 400 parse."""
    try:
        si = parse_dict(field_value(headers, "signature-input") or "")
        sg = parse_dict(field_value(headers, "signature") or "")
        sa_raw = field_value(headers, "signature-agent")
        sa = parse_dict(sa_raw) if sa_raw is not None else []
    except (SFError, ValueError) as e:
        raise Refusal("parse", str(e)) from e
    types = {"created": int, "expires": int, "keyid": str, "alg": str, "nonce": str, "tag": str}
    for _label, m in si:
        kind, items, ps = m
        if kind != "inner":
            raise Refusal("parse", "SI member not inner list")
        for v, _vp in items:
            if not isinstance(v, str) or isinstance(v, Token):
                raise Refusal("parse", "component not string")
        for k, v in ps:
            t = types.get(k)
            if t is int and (not isinstance(v, int) or isinstance(v, bool)):
                raise Refusal("parse", f"{k} type")
            if t is str and (not isinstance(v, str) or isinstance(v, Token)):
                raise Refusal("parse", f"{k} type")
    for _label, m in sg:
        kind, v, _ps = m
        if kind != "item" or not isinstance(v, (bytes, bytearray)):
            raise Refusal("parse", "Signature member not byte sequence")
    return si, sg, sa


def origin_of_agent(value):
    if not isinstance(value, str) or isinstance(value, Token):
        raise Refusal("signature-agent-value")
    m = re.match(r"^https://([^/?#@:]+)(/\.well-known/http-message-signatures-directory)?$", value)
    if not m:
        raise Refusal("signature-agent-value")
    host = m.group(1)
    if host != host.lower() or not host_ok(host):
        raise Refusal("signature-agent-value")
    return "https://" + host


def host_ok(host):
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return False
    labels = host.split(".")
    if any(not lb for lb in labels):
        return False
    if all(lb.isdigit() for lb in labels) and len(labels) == 4:
        return all(0 <= int(lb) <= 255 for lb in labels)
    if labels[-1].isdigit():
        return False
    return all(re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", lb) for lb in labels)


def select_signature(si, sg, sa, tag):
    """Step 2."""
    tagged = [(lab, m) for lab, m in si if dict(m[2]).get("tag") == tag]
    if not tagged:
        raise Refusal("signature-missing")
    labels = {lab for lab, _ in tagged}
    if len(labels) > 1:
        raise Refusal("multiple-signatures")
    label = tagged[0][0]
    if len(tagged) > 1 or sum(1 for lab, _ in sg if lab == label) > 1:
        raise Refusal("multiple-signatures")
    sig_members = [m for lab, m in sg if lab == label]
    if not sig_members:
        raise Refusal("signature-missing")
    items, params = tagged[0][1][1], tagged[0][1][2]
    return label, items, dict(params), list(params), sig_members[0][1]


def select_agent(sa, label, items):
    with_params = [lab for lab, m in sa if m[2]]
    plain = [(lab, m) for lab, m in sa if not m[2]]
    covered = [(v, dict(vp)) for v, vp in items if v == "signature-agent"]
    mine = [m for lab, m in plain if lab == label]
    if not mine:
        if label in with_params:
            raise Refusal("signature-agent-parameters")
        raise Refusal("signature-agent-missing")
    if len(plain) > 1:
        raise Refusal("multiple-signature-agents")
    if not any(p.get("key") == label for _v, p in covered):
        raise Refusal("signature-agent-not-covered")
    kind, value, _ps = mine[0]
    if kind != "item":
        raise Refusal("signature-agent-value")
    return origin_of_agent(value)


def check_params(params, now, need_nonce):
    """Step 4."""
    kid = params.get("keyid")
    if not kid:
        raise Refusal("keyid")
    if params.get("alg") != "ed25519":
        raise Refusal("alg")
    created, expires = params.get("created"), params.get("expires")
    if created is None or expires is None or expires <= created:
        raise Refusal("window")
    if expires - created > MAX_LIFETIME:
        raise Refusal("lifetime")
    if created > now + SKEW:
        raise Refusal("created-in-future")
    if now > expires + SKEW:
        raise Refusal("expired")
    if need_nonce:
        n = params.get("nonce")
        if n is None:
            raise Refusal("nonce-missing")
        if not nonce_ok(n):
            raise Refusal("nonce-invalid")


def nonce_ok(n):
    if re.fullmatch(r"[A-Za-z0-9_-]+", n):
        try:
            return len(b64url_decode(n)) == 64 and len(n) == 86
        except Exception:  # noqa: BLE001
            return False
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", n) and len(n) % 4 == 0:
        try:
            return len(base64.b64decode(n, validate=True)) == 64
        except Exception:  # noqa: BLE001
            return False
    return False


def covers(items, name, **want):
    for v, vp in items:
        if v != name:
            continue
        d = dict(vp)
        if all(d.get(k) == w for k, w in want.items()) and set(d) <= set(want):
            return True
    return False


def check_digest(headers, body):
    raw = field_value(headers, "content-digest")
    try:
        d = parse_dict(raw or "")
    except SFError as e:
        raise Refusal("content-digest") from e
    sha = [m for k, m in d if k == "sha-256"]
    if len(sha) != 1 or sha[0][0] != "item" or not isinstance(sha[0][1], (bytes, bytearray)):
        raise Refusal("content-digest")
    if sha[0][1] != hashlib.sha256(body).digest():
        raise Refusal("content-digest")


# ---------------------------------------------------------------- signature base (RFC 9421 2.5)


def component_value(name, cparams, msg, req, ctx):
    src = msg
    if cparams.get("req"):
        src = req
        if src is None:
            raise Refusal("components")
    if name == "@method":
        return src["method"]
    if name == "@target-uri":
        return src["_target_uri"]
    if name == "@authority":
        return src["_authority"]
    if name == "@status":
        return str(src["status"])
    if name.startswith("@"):
        raise Refusal("components", "unsupported derived component " + name)
    if "key" in cparams:
        raw = field_value(src["headers"], name)
        if raw is None:
            raise Refusal("components")
        try:
            members = parse_dict(raw)
        except SFError as e:
            raise Refusal("parse") from e
        hit = [m for k, m in members if k == cparams["key"]]
        if len(hit) != 1:
            raise Refusal("components")
        return ser_member(hit[0])
    v = field_value(src["headers"], name)
    if v is None:
        raise Refusal("components")
    return v


def signature_base(items, params_list, msg, req, ctx):
    lines = []
    for v, vp in items:
        cp = dict(vp)
        ident = ser_bare(v) + ser_params(vp)
        lines.append(f"{ident}: {component_value(v, cp, msg, req, ctx)}")
    inner = "(" + " ".join(ser_bare(v) + ser_params(vp) for v, vp in items) + ")" + ser_params(params_list)
    lines.append(f'"@signature-params": {inner}')
    return "\n".join(lines).encode("ascii")


def ed25519_verify(x, sig, data):
    try:
        Ed25519PublicKey.from_public_bytes(b64url_decode(x)).verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def thumbprint(jwk):
    canon = json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canon.encode()).digest())


# ---------------------------------------------------------------- directory


def verify_directory(resp, origin, now):
    headers = resp["headers"]
    if resp.get("status", 200) != 200:
        raise Refusal("directory-status")
    enc = field_value(headers, "content-encoding")
    if enc is not None and enc.strip().lower() != "identity":
        raise Refusal("directory-encoding")
    ct = (field_value(headers, "content-type") or "").split(";")[0].strip().lower()
    if ct != DIRECTORY_MEDIA:
        raise Refusal("directory-media-type")
    body = body_bytes(resp["body"])
    if len(body) > MAX_DIRECTORY_BYTES:
        raise Refusal("directory-too-large")
    raw = field_value(headers, "content-digest")
    try:
        cd = parse_dict(raw or "")
    except SFError as e:
        raise Refusal("directory-content-digest") from e
    sha = [m for k, m in cd if k == "sha-256"]
    if len(sha) != 1 or not isinstance(sha[0][1], (bytes, bytearray)) or sha[0][1] != hashlib.sha256(body).digest():
        raise Refusal("directory-content-digest")
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        raise Refusal("directory-format") from e
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise Refusal("directory-format")
    if len(doc["keys"]) > MAX_DIRECTORY_KEYS:
        raise Refusal("directory-too-many-keys")
    ed = {}
    for k in doc["keys"]:
        if not isinstance(k, dict):
            raise Refusal("directory-format")
        if k.get("kty") == "OKP" and k.get("crv") == "Ed25519":
            if not isinstance(k.get("x"), str):
                raise Refusal("directory-format")
            tp = thumbprint(k)
            if "kid" in k and k["kid"] != tp:
                raise Refusal("directory-kid")
            if tp in ed:
                raise Refusal("directory-format")
            ed[tp] = k
    if not ed:
        raise Refusal("directory-no-usable-key")
    try:
        si = parse_dict(field_value(headers, "signature-input") or "")
        sg = parse_dict(field_value(headers, "signature") or "")
    except SFError as e:
        raise Refusal("directory-signature-parse") from e
    sigs = dict()
    for lab, m in sg:
        if m[0] != "item" or not isinstance(m[1], (bytes, bytearray)):
            raise Refusal("directory-signature-parse")
        if lab in sigs:
            raise Refusal("directory-signature-parse")
        sigs[lab] = m[1]
    host = origin[len("https://"):]
    by_key = {}
    earliest = None
    for lab, m in si:
        if m[0] != "inner":
            raise Refusal("directory-signature-parse")
        p = dict(m[2])
        kid = p.get("keyid")
        if kid not in ed:
            continue  # other key types and their signatures are ignored
        by_key.setdefault(kid, []).append((lab, m))
    for kid in ed:
        got = by_key.get(kid, [])
        if len(got) != 1:
            raise Refusal("directory-one-signature-per-key")
        lab, m = got[0]
        items, plist = m[1], m[2]
        p = dict(plist)
        if p.get("tag") != DIRECTORY_TAG:
            raise Refusal("directory-tag")
        if "alg" in p and p["alg"] != "ed25519":
            raise Refusal("directory-signature")
        names = [(v, dict(vp)) for v, vp in items]
        if not (covers(items, "@authority", req=True) and covers(items, "content-digest")):
            raise Refusal("directory-components")
        created, expires = p.get("created"), p.get("expires")
        if not isinstance(created, int) or not isinstance(expires, int):
            raise Refusal("directory-window")
        if created > now + SKEW or now > expires:
            raise Refusal("directory-window")
        if lab not in sigs:
            raise Refusal("directory-signature")
        msg = {"headers": headers, "status": 200}
        req = {"method": "GET", "headers": [], "_authority": host, "_target_uri": origin + DIRECTORY_PATH}
        base = signature_base(items, plist, msg, req, None)
        if not ed25519_verify(ed[kid]["x"], sigs[lab], base):
            raise Refusal("directory-signature")
        earliest = expires if earliest is None else min(earliest, expires)
        del names
    return ed


def resolve_key(op, origin, kid, now):
    dirs = op.get("directories") or {}
    d = dirs.get(origin)
    if d is None:
        raise Refusal("directory-unavailable")
    if d.get("url") not in (None, origin + DIRECTORY_PATH):
        raise Refusal("directory-unavailable")
    keys = verify_directory(d, origin, now)
    if kid not in keys:
        raise Refusal("key-not-found")
    return keys[kid]


# ---------------------------------------------------------------- request / response


class State:
    def __init__(self):
        self.nonces = {}  # (origin, nonce) -> expires

    def seen(self, origin, nonce, now):
        exp = self.nonces.get((origin, nonce))
        return exp is not None and now <= exp + SKEW

    def record(self, origin, nonce, expires):
        self.nonces[(origin, nonce)] = expires


def prepare_request(req, authority):
    r = dict(req)
    tu, auth = target_uri(req["url"], authority)
    r["_target_uri"], r["_authority"] = tu, auth
    return r


def verify_request(op, req, now, state):
    headers = req["headers"]
    if field_value(headers, "signature-input") is None:
        raise Refusal("signature-missing")
    si, sg, sa = parse_signature_fields(headers)
    label, items, params, plist, sig = select_signature(si, sg, sa, SIGNATURE_TAG)
    origin = select_agent(sa, label, items)
    try:
        _scheme, url_auth, _p, _q = split_url(req["url"])
    except ValueError as e:
        raise Refusal("authority") from e
    if url_auth != op["authority"]:
        raise Refusal("authority")
    check_params(params, now, need_nonce=True)
    body = body_bytes(req.get("body", ""))
    need = [("@method", {}), ("@target-uri", {}), ("@authority", {})]
    if body:
        need += [("content-type", {}), ("content-digest", {})]
    for name, want in need:
        if not covers(items, name, **want):
            raise Refusal("components")
    key = resolve_key(op, origin, params["keyid"], now)
    if any(v == "content-digest" for v, _ in items):
        check_digest(headers, body)
    r = prepare_request(req, op["authority"])
    base = signature_base(items, plist, r, None, None)
    if not ed25519_verify(key["x"], sig, base):
        raise Refusal("signature-invalid")
    if state.seen(origin, params["nonce"], now):
        raise Refusal("nonce-replayed")
    state.record(origin, params["nonce"], params["expires"])
    return origin


def verify_response(op, now):
    resp, req = op["response"], op["request"]
    headers = resp["headers"]
    if field_value(headers, "signature-input") is None:
        raise Refusal("signature-missing")
    si, sg, sa = parse_signature_fields(headers)
    label, items, params, plist, sig = select_signature(si, sg, sa, SIGNATURE_TAG)
    origin = select_agent(sa, label, items)
    check_params(params, now, need_nonce=False)
    body = b"" if req.get("method", "").upper() == "HEAD" else body_bytes(resp.get("body", ""))
    need = [("@status", {}), ("@method", {"req": True}), ("@target-uri", {"req": True})]
    if body:
        need += [("content-type", {}), ("content-digest", {})]
    for name, want in need:
        if not covers(items, name, **want):
            raise Refusal("components")
    req_label = request_wba_label(req)
    if req_label is not None and not covers(items, "signature", req=True, key=req_label):
        raise Refusal("response-not-bound")
    key = resolve_key(op, origin, params["keyid"], now)
    if any(v == "content-digest" for v, _ in items):
        check_digest(headers, body)
    r = prepare_request(req, None)
    msg = {"headers": headers, "status": resp["status"]}
    base = signature_base(items, plist, msg, r, None)
    if not ed25519_verify(key["x"], sig, base):
        raise Refusal("signature-invalid")
    exp = op.get("expected_origin", "same")
    if exp == "same" or exp is None and "expected_origin" not in op:
        want = "https://" + split_url(req["url"])[1].split(":")[0]
    else:
        want = exp
    if want is not None and origin != want:
        raise Refusal("origin-mismatch")
    return origin


def request_wba_label(req):
    """The label of the request's web-bot-auth signature, when it has a Signature member."""
    h = req.get("headers", [])
    if field_value(h, "signature-input") is None:
        return None
    try:
        si = parse_dict(field_value(h, "signature-input"))
        sg = parse_dict(field_value(h, "signature") or "")
    except SFError:
        return None
    for lab, m in si:
        if m[0] == "inner" and dict(m[2]).get("tag") == SIGNATURE_TAG:
            if any(k == lab for k, _ in sg):
                return lab
    return None


def run(op):
    try:
        kind = op["op"]
        now = op["now"]
        if kind == "verify_directory":
            verify_directory(op["response"], op["origin"], now)
            return {"ok": True}
        if kind == "verify_request":
            state = State()
            for p in op.get("prior") or []:
                try:
                    verify_request(op, p, now, state)
                except Refusal:
                    pass
            return {"ok": True, "identity": verify_request(op, op["request"], now, state)}
        if kind == "verify_response":
            return {"ok": True, "identity": verify_response(op, now)}
        return {"ok": False, "status": 0, "rule": "unknown-op"}
    except Refusal as r:
        return r.result()


def main():
    src = open(sys.argv[1], encoding="utf-8") if len(sys.argv) > 1 else sys.stdin
    data = json.load(src)
    op = data.get("operation", data)
    print(json.dumps(run(op), sort_keys=True))


if __name__ == "__main__":
    main()
