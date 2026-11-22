#!/usr/bin/env python3
"""Agent-DID RFC-001 1.0.0-rc.5 HTTP signature verifier and payload-signature check, written from the text only.

Text: docs/RFC-001-Agent-DID-Specification.md section 6.2.1, 6.2.3, 6.5; docs/Anti-Replay-HTTP-Signatures.md
("Verifying", "Why a request was rejected", NonceStore); docs/ADR-006-Wire-Alignment-rc5.md D-8a; RFC 9421 section 2;
RFC 8941; RFC 9530. No SDK code was opened.

Readings the text leaves open are marked R1..R9 below.
"""
import base64
import hashlib
import re
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# ------------------------------------------------------------------ keys
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            raise ValueError("not base58btc")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def ed25519_from_multibase(mb: str) -> Ed25519PublicKey:
    # Multikey / Ed25519VerificationKey2020 (ADR-006 D-8b): 'z' + base58btc(0xed 0x01 || 32-byte key)
    if not mb.startswith("z"):
        raise ValueError("not base58btc multibase")
    raw = b58decode(mb[1:])
    if raw[:2] != b"\xed\x01" or len(raw) != 34:
        raise ValueError("not an ed25519-pub multicodec key")
    return Ed25519PublicKey.from_public_bytes(raw[2:])


def _verify(pk: Ed25519PublicKey, sig: bytes, msg: bytes) -> bool:
    try:
        pk.verify(sig, msg)
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------------------ 6.2.3 payload signatures
MESSAGE_PREFIX = b"agent-did/v1/message\n"


def verify_message(public_key_multibase: str, payload: str, signature_hex: str) -> bool:
    # 6.2.3: Ed25519 over UTF-8 "agent-did/v1/message", LF, UTF-8 payload; signature as lowercase hex.
    if not re.fullmatch(r"(?:[0-9a-f]{2})+", signature_hex):
        return False
    return _verify(ed25519_from_multibase(public_key_multibase), bytes.fromhex(signature_hex),
                   MESSAGE_PREFIX + payload.encode("utf-8"))


# ------------------------------------------------------------------ RFC 8941 (strict enough for these headers)
class SFError(ValueError):
    pass


class Token(str):
    pass


KEY_RE = re.compile(r"[a-z*][a-z0-9_\-.*]*")
TOKEN_RE = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*")
INT_RE = re.compile(r"-?[0-9]{1,15}(?![0-9.])")


def _sp(s, i):
    while i < len(s) and s[i] == " ":
        i += 1
    return i


def _ows(s, i):
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _bare_item(s, i):
    if i >= len(s):
        raise SFError("eof")
    c = s[i]
    if c == '"':
        out, i = [], i + 1
        while True:
            if i >= len(s):
                raise SFError("unterminated string")
            c = s[i]
            if c == "\\":
                if i + 1 >= len(s) or s[i + 1] not in '"\\':
                    raise SFError("bad escape")
                out.append(s[i + 1])
                i += 2
            elif c == '"':
                return "".join(out), i + 1
            elif ord(c) < 0x20 or ord(c) > 0x7E:
                raise SFError("bad string char")
            else:
                out.append(c)
                i += 1
    if c == ":":
        j = s.find(":", i + 1)
        if j < 0:
            raise SFError("unterminated bytes")
        body = s[i + 1:j]
        if not re.fullmatch(r"[A-Za-z0-9+/=]*", body):
            raise SFError("bad bytes")
        try:
            return bytes(base64.b64decode(body, validate=True)), j + 1
        except Exception as e:
            raise SFError("bad base64") from e
    if c == "?":
        if s[i + 1:i + 2] in ("0", "1"):
            return s[i + 1] == "1", i + 2
        raise SFError("bad boolean")
    m = INT_RE.match(s, i)
    if m:
        return int(m.group(0)), m.end()
    m = TOKEN_RE.match(s, i)
    if m:
        return Token(m.group(0)), m.end()
    raise SFError("bad item at %d" % i)


def _params(s, i):
    params = []
    while i < len(s) and s[i] == ";":
        i = _sp(s, i + 1)
        m = KEY_RE.match(s, i)
        if not m:
            raise SFError("bad param key")
        k, i = m.group(0), m.end()
        v = True
        if i < len(s) and s[i] == "=":
            v, i = _bare_item(s, i + 1)
        params = [(a, b) for a, b in params if a != k] + [(k, v)]
    return params, i


def parse_dictionary(s: str) -> list:
    """Returns [(key, member)], member = ("item", value, params) or ("inner", [(value, params)], params)."""
    out, i = [], _sp(s, 0)
    if i == len(s):
        return out
    while True:
        m = KEY_RE.match(s, i)
        if not m:
            raise SFError("bad dict key")
        key, i = m.group(0), m.end()
        if i < len(s) and s[i] == "=":
            i += 1
            if i < len(s) and s[i] == "(":
                i += 1
                items = []
                while True:
                    i = _sp(s, i)
                    if i >= len(s):
                        raise SFError("unterminated inner list")
                    if s[i] == ")":
                        i += 1
                        break
                    v, i = _bare_item(s, i)
                    p, i = _params(s, i)
                    items.append((v, p))
                    if i < len(s) and s[i] not in " )":
                        raise SFError("bad inner list")
                p, i = _params(s, i)
                member = ("inner", items, p)
            else:
                v, i = _bare_item(s, i)
                p, i = _params(s, i)
                member = ("item", v, p)
        else:
            p, i = _params(s, i)
            member = ("item", True, p)
        out = [(k, v) for k, v in out if k != key] + [(key, member)]
        i = _ows(s, i)
        if i == len(s):
            return out
        if s[i] != ",":
            raise SFError("expected comma")
        i = _ows(s, i + 1)
        if i == len(s):
            raise SFError("trailing comma")


def _ser_bare(v) -> str:
    if v is True:
        return "?1"
    if v is False:
        return "?0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, bytes):
        return ":" + base64.b64encode(v).decode() + ":"
    if isinstance(v, Token):
        return str(v)
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ser_params(params) -> str:
    return "".join(";" + k + ("" if v is True else "=" + _ser_bare(v)) for k, v in params)


def ser_item(v, params) -> str:
    return _ser_bare(v) + _ser_params(params)


def ser_inner(items, params) -> str:
    return "(" + " ".join(ser_item(v, p) for v, p in items) + ")" + _ser_params(params)


# ------------------------------------------------------------------ 6.5 item 4: normalized URL
UNRESERVED = r"A-Za-z0-9\-._~"
SUBDELIM = r"!$&'()*+,;="
PCT = r"%[0-9A-Fa-f]{2}"
PATH_RE = re.compile(r"(?:[%s%s:@/]|%s)*" % (UNRESERVED, SUBDELIM, PCT))
QUERY_RE = re.compile(r"(?:[%s%s:@/?]|%s)*" % (UNRESERVED, SUBDELIM.replace("'", ""), PCT))


def _ipv4_canonical(h):
    parts = h.split(".")
    return len(parts) == 4 and all(p.isdigit() and str(int(p)) == p and int(p) < 256 for p in parts)


def url_normalized(url: str) -> bool:
    m = re.fullmatch(r"(https?)://([^/?#]*)([^?#]*)(\?[^#]*)?", url)
    if not m:
        return False  # scheme not lowercase http(s), or a fragment
    authority, path, query = m.group(2), m.group(3), m.group(4)
    if "@" in authority:
        return False  # user information
    hm = re.fullmatch(r"(\[[0-9a-f:.]+\]|[^:\[\]]*)(?::([0-9]+))?", authority)
    if not hm:
        return False
    host, port = hm.group(1), hm.group(2)
    if port is not None and (port == "" or (len(port) > 1 and port[0] == "0")):
        return False
    if host.startswith("["):
        import ipaddress
        try:
            a = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return False
        if a.compressed != host[1:-1]:
            return False  # RFC 5952 form
    elif re.fullmatch(r"[0-9.]+", host):
        if not _ipv4_canonical(host):
            return False
    else:
        if host == "" or host != host.lower() or not re.fullmatch(r"[a-z0-9\-.]+", host):
            return False  # lowercase ASCII (punycode for IDN)
        if any(label == "" for label in host.split(".")):
            return False  # no empty label
    if not PATH_RE.fullmatch(path):
        return False
    for seg in path.split("/"):
        dec = re.sub(r"%2[eE]", ".", seg)
        if dec in (".", ".."):
            return False  # no dot segment, also when percent-encoded
    if query is not None:
        if query == "?":
            return False  # no '?' without a query
        if not QUERY_RE.fullmatch(query[1:]):
            return False
    return True


# ------------------------------------------------------------------ RFC 9421 components
def _field(headers: dict, name: str):
    # R1: field names compared case-insensitively (RFC 9110 5.1); several fields of one name joined by ", " (RFC 9421 2.1)
    vals = [v for k, v in headers.items() if k.lower() == name]
    if not vals:
        return None
    return ", ".join(v.strip() for v in vals)


def derived(name: str, method: str, url: str):
    u = urlsplit(url)
    if name == "@method":
        return method
    if name == "@authority":
        host = u.hostname or ""
        port = u.port
        default = {"https": 443, "http": 80}[u.scheme]
        return host + (":%d" % port if port is not None and port != default else "")  # explicit default port dropped
    if name == "@path":
        return u.path or "/"
    if name == "@query":
        return "?" + u.query
    raise KeyError(name)


class Missing(Exception):
    pass


def component_line(item, iparams, method, url, headers, agent_dict):
    name = item
    if name.startswith("@"):
        val = derived(name, method, url)
    else:
        key = dict(iparams).get("key")
        if key is not None:
            # RFC 9421 2.1.2: the serialized member of the named dictionary field
            if name == "agent-did":
                d = agent_dict
            else:
                raw = _field(headers, name)
                if raw is None:
                    raise Missing(name)
                d = parse_dictionary(raw)
            mem = dict(d).get(key)
            if mem is None:
                raise Missing(name + ";key=" + key)
            if mem[0] == "item":
                val = ser_item(mem[1], mem[2])
            else:
                val = ser_inner(mem[1], mem[2])
        else:
            val = _field(headers, name)
            if val is None:
                raise Missing(name)
    return ser_item(item, iparams) + ": " + val


def signature_base(method, url, headers, items, params, agent_dict) -> str:
    lines = [component_line(v, p, method, url, headers, agent_dict) for v, p in items]
    lines.append('"@signature-params": ' + ser_inner(items, params))
    return "\n".join(lines)


def content_digest(body: str) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + ":"


# ------------------------------------------------------------------ 6.5 verification
NONCE_RE = re.compile(r"[A-Za-z0-9._~+/=\-]{1,256}")


def profile_for(label):
    return [("@method", []), ("@authority", []), ("@path", []), ("@query", []), ("content-digest", []),
            ("date", []), ("agent-did", [("key", label)])]


class Resolver:
    """did -> {"vms": {id: (multibase, relationships)}}. R2: the fixture's usage builds one agent document from all keys."""

    def __init__(self, docs: dict):
        self.docs = docs

    def resolve(self, did):
        return self.docs.get(did)


def _check_label(label, items, params, sig_value, agent_dict, method, url, body, headers, resolver, now,
                 max_skew, max_lifetime, store, rules):
    """Returns (ok, reason, base). Checks run in the order of the Anti-Replay guide's reason table (R3)."""
    p = dict(params)
    if rules.get("tag", True) and p.get("tag") != "agent-did":
        return False, "tag_mismatch", None
    if rules.get("alg", True) and p.get("alg") != "ed25519":
        return False, "alg_unsupported", None
    for k, t in (("created", int), ("expires", int), ("nonce", str), ("keyid", str)):
        if k == "nonce" and not rules.get("nonce_required", True) and k not in p:
            continue
        if k not in p or not isinstance(p[k], t) or isinstance(p[k], (bool, Token)):
            return False, "params_missing", None
    if rules.get("nonce_grammar", True) and "nonce" in p and not NONCE_RE.fullmatch(p["nonce"]):
        return False, "params_missing", None
    mem = dict(agent_dict).get(label)
    if mem is None:
        did = None  # R4: no member for the label -> signed_component_missing when the base is built
    elif mem[0] != "item" or not isinstance(mem[1], str) or isinstance(mem[1], Token) or mem[2]:
        return False, "malformed_headers", None
    else:
        did = mem[1]
    keyid = p["keyid"]
    if did is not None and rules.get("keyid_bound", True) and not keyid.startswith(did + "#"):
        return False, "keyid_not_bound", None
    comps = [(v, list(ip)) for v, ip in items]
    prof = profile_for(label)
    if rules.get("order", True) or rules.get("required", True):
        missing = [c for c in prof if c not in comps]
        if rules.get("required", True) and missing:
            return False, "components_missing", None
        if rules.get("order", True) and comps[:len(prof)] != prof:
            return False, "components_order", None
    if rules.get("skew", True) and abs(now - p["created"]) > max_skew:
        return False, "created_skew", None
    if rules.get("expires_ge_created", True) and p["expires"] < p["created"]:
        return False, "expires_before_created", None
    if rules.get("lifetime", True) and p["expires"] - p["created"] > max_lifetime:
        return False, "lifetime_exceeded", None
    if rules.get("now_le_expires", True) and now > p["expires"]:
        return False, "expired", None
    if rules.get("url_normalized", True) and not url_normalized(url):
        return False, "url_not_normalized", None  # 6.5 item 4 (not in the guide's table; R5: placed here)
    try:
        base = signature_base(method, url, headers, items, params, agent_dict)
    except Missing:
        return False, "signed_component_missing", None
    if did is None:
        return False, "signed_component_missing", base
    doc = resolver.resolve(did)
    if doc is None:
        return False, "did_resolution_failed", base
    vm = doc["vms"].get(keyid)
    if vm is None:
        if rules.get("keyid_in_doc", True):
            return False, "keyid_not_bound", base  # "keyid is not a key of the agent DID"
        vm = (None, [])
    mb, rels = vm
    if rules.get("assertion_method", True) and "assertionMethod" not in rels:
        return False, "keyid_not_authorized", base  # 6.2.1: keyAgreement-only keys never sign
    if not isinstance(sig_value, bytes):
        return False, "malformed_headers", base
    if mb is None or not _verify(ed25519_from_multibase(mb), sig_value, base.encode("utf-8")):
        return False, "signature_invalid", base
    if rules.get("replay", True) and "nonce" in p:
        k = keyid + " " + p["nonce"]
        if k in store and store[k] >= now:
            return False, "nonce_replayed", base
        store[k] = p["expires"]  # 6.5 item 6: recorded only after the signature verified, kept until expires
    return True, "ok", base


def verify_request(method, url, body, headers, resolver, now, max_skew=300, max_lifetime=300, store=None,
                   rules=None):
    """Returns {"ok": bool, "reason": str, "base": str|None, "label": str|None}."""
    rules = rules or {}
    store = {} if store is None else store
    sig_in, sig, agent = _field(headers, "signature-input"), _field(headers, "signature"), _field(headers, "agent-did")
    if sig_in is None or sig is None or agent is None:
        return {"ok": False, "reason": "missing_headers", "base": None, "label": None}
    try:
        inputs, sigs, agent_dict = parse_dictionary(sig_in), dict(parse_dictionary(sig)), parse_dictionary(agent)
    except SFError:
        return {"ok": False, "reason": "malformed_headers", "base": None, "label": None}
    if rules.get("digest", True):
        cd = _field(headers, "content-digest")
        if cd is None or cd != content_digest(body):  # 6.5 item 1: exactly sha-256=:<b64>:
            return {"ok": False, "reason": "digest_mismatch", "base": None, "label": None}
    labels = [(l, m) for l, m in inputs if m[0] == "inner" and l in sigs]
    if not labels:
        return {"ok": False, "reason": "malformed_headers", "base": None, "label": None}  # no matching label
    # R6: the reason reported is that of the first signature with tag="agent-did"; any valid Agent-DID label accepts.
    if rules.get("tag", True):
        tagged = [(l, m) for l, m in labels if dict(m[2]).get("tag") == "agent-did"]
        if not tagged:
            return {"ok": False, "reason": "tag_mismatch", "base": None, "label": labels[0][0]}
    else:
        tagged = labels
    first = None
    for label, (_k, items, params) in tagged:
        sv = sigs[label]
        sig_value = sv[1] if sv[0] == "item" else None
        ok, reason, base = _check_label(label, items, params, sig_value, agent_dict, method, url, body, headers,
                                        resolver, now, max_skew, max_lifetime, store, rules)
        if ok:
            return {"ok": True, "reason": "ok", "base": base, "label": label}
        if first is None:
            first = {"ok": False, "reason": reason, "base": base, "label": label}
    return first
