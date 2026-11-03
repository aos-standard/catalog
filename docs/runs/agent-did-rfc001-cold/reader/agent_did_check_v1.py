#!/usr/bin/env python3
"""A reader of edisonduran/agent-did's RFC-001 fixtures, written from the public text only, at 37a3190:
docs/RFC-001-Agent-DID-Specification.md (sections 4.3, 6.1, 6.2, 6.5), docs/Anti-Replay-HTTP-Signatures.md,
RFC 8785 (JCS), RFC 9421 (HTTP Message Signatures, section 2), RFC 8941 (structured fields), RFC 9530 (Content-Digest),
RFC 2104 (HMAC), and the multibase/multicodec convention for Ed25519 keys (base58btc 'z', prefix 0xed 0x01).
Not opened: sdk/, sdk-python/, integrations/, scripts/, any test file.
Where the text does not decide, the reading is named A<n>.
Standard library plus `cryptography` (Ed25519 only).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# ------------------------------------------------------------------ RFC 8785 (JCS)
class JcsError(Exception):
    pass


def es_number(x: float) -> str:
    """ECMAScript Number::toString for a binary64 value (RFC 8785 section 3.2.2.3)."""
    if x != x or x in (float("inf"), float("-inf")):
        raise JcsError("NaN or Infinity")
    if x == 0:
        return "0"  # -0 serializes as 0
    sign = "-" if x < 0 else ""
    r = repr(abs(x))  # shortest round-trip digits
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:e([+-]\d+))?", r)
    ip, fp, ex = m.group(1), m.group(2) or "", int(m.group(3) or 0)
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + ex - lead_zeros  # decimal point position relative to the first significant digit
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + es
    return sign + s


def _jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if 0xD800 <= o <= 0xDFFF:
            raise JcsError("lone surrogate")
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
        return es_number(float(v))  # A1: every JSON number is an IEEE-754 binary64 (RFC 8785 3.2.2.3)
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=_utf16_key)  # property names sorted by UTF-16 code units (3.2.3)
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise JcsError("unsupported type")


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise JcsError("duplicate property name")  # I-JSON (RFC 7493), required by RFC 8785 section 3.1
        d[k] = v
    return d


def jcs_text(raw: str) -> bytes:
    """Raw JSON text in, canonical UTF-8 out."""
    v = json.loads(raw, object_pairs_hook=_no_dupes, parse_constant=lambda c: (_ for _ in ()).throw(JcsError(c)))
    return jcs(v).encode("utf-8")


def jcs_number_from_hex(h: str) -> str:
    return es_number(struct.unpack(">d", bytes.fromhex(h))[0])


# ------------------------------------------------------------------ section 6.1 documentRef, section 4.3 commitments
def document_ref(doc: dict) -> str:
    # 6.1: hash://sha256/ + lowercase hex SHA-256 of UTF-8(JCS(document)); values hashed as written.
    return "hash://sha256/" + hashlib.sha256(jcs(doc).encode("utf-8")).hexdigest()


def salt_bytes(salt: str) -> bytes:
    # A2: the fixture's salt is a string; 4.3 says the salt is the HMAC key and at least 32 bytes. A 64-hex-digit
    # string read as hex is exactly 32 bytes; read as UTF-8 it would be 64. Hex is taken.
    return bytes.fromhex(salt)


def hmac_commitment(value: str, salt: str) -> str:
    return "hash://hmac-sha256/" + hmac.new(salt_bytes(salt), value.encode("utf-8"), hashlib.sha256).hexdigest()


def legacy_commitment(value: str) -> str:
    return "hash://sha256/" + hashlib.sha256(value.encode("utf-8")).hexdigest()


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
    # Ed25519VerificationKey2020: 'z' + base58btc(0xed 0x01 || 32-byte key)
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


# ------------------------------------------------------------------ signMessage / verifySignature
def verify_message(vm: dict, payload: str, signature_hex: str) -> bool:
    # A3: RFC-001 section 7 names signMessage(payload, privateKey) and verifySignature(did, payload, signature) but does
    # not define the signed bytes. Read: Ed25519 over the UTF-8 bytes of the payload string, signature as hex.
    return _verify(ed25519_from_multibase(vm["publicKeyMultibase"]), bytes.fromhex(signature_hex), payload.encode("utf-8"))


# ------------------------------------------------------------------ RFC 8941 (only what Signature-Input / Signature need)
def _parse_sf_string(s: str, i: int):
    assert s[i] == '"'
    i += 1
    out = []
    while True:
        c = s[i]
        if c == "\\":
            out.append(s[i + 1])
            i += 2
        elif c == '"':
            return "".join(out), i + 1
        else:
            out.append(c)
            i += 1


def _parse_bare(s: str, i: int):
    m = re.compile(r"-?\d+|[A-Za-z*][A-Za-z0-9_\-.:%*/]*").match(s, i)
    tok = m.group(0)
    return (int(tok) if re.fullmatch(r"-?\d+", tok) else tok), m.end()


def _parse_item(s: str, i: int):
    if s[i] == '"':
        return _parse_sf_string(s, i)
    if s[i] == ":":
        j = s.index(":", i + 1)
        return ("bytes", base64.b64decode(s[i + 1 : j])), j + 1
    if s[i] == "?":
        return s[i + 1] == "1", i + 2
    return _parse_bare(s, i)


def _parse_params(s: str, i: int):
    params = []
    while i < len(s) and s[i] == ";":
        i += 1
        while s[i] == " ":
            i += 1
        k, i = _parse_bare(s, i)
        v = True
        if i < len(s) and s[i] == "=":
            v, i = _parse_item(s, i + 1)
        params.append((k, v))
    return params, i


def parse_dictionary(s: str) -> dict:
    out = {}
    i = 0
    while i < len(s):
        while i < len(s) and s[i] in " \t,":
            i += 1
        if i >= len(s):
            break
        key, i = _parse_bare(s, i)
        assert s[i] == "="
        i += 1
        if s[i] == "(":
            i += 1
            items = []
            while True:
                while s[i] == " ":
                    i += 1
                if s[i] == ")":
                    i += 1
                    break
                it, i = _parse_item(s, i)
                ip, i = _parse_params(s, i)
                items.append((it, ip))
            params, i = _parse_params(s, i)
            out[key] = ("inner", items, params)
        else:
            it, i = _parse_item(s, i)
            params, i = _parse_params(s, i)
            out[key] = ("item", it, params)
    return out


def _ser_item(v) -> str:
    if v is True:
        return "?1"
    if v is False:
        return "?0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, tuple) and v[0] == "bytes":
        return ":" + base64.b64encode(v[1]).decode() + ":"
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _ser_params(params) -> str:
    return "".join(";" + k + ("" if v is True else "=" + _ser_item(v)) for k, v in params)


def serialize_inner(items, params) -> str:
    return "(" + " ".join(_ser_item(it) + _ser_params(ip) for it, ip in items) + ")" + _ser_params(params)


# ------------------------------------------------------------------ RFC 9421 signature base, RFC-001 section 6.5
PROFILE = ["@method", "@authority", "@path", "@query", "content-digest", "date", "signature-agent"]
REQUIRED_PARAMS = {"created", "expires", "nonce", "keyid", "alg", "tag"}


def _header(headers: dict, name: str):
    vals = [v for k, v in headers.items() if k.lower() == name]
    if not vals:
        return None
    return ", ".join(v.strip() for v in vals)  # RFC 9421 2.1: trimmed, multiple values joined by ", "


def component_value(name: str, method: str, url: str, headers: dict):
    u = urlsplit(url)
    if name == "@method":
        return method.upper()  # A4: RFC 9421 2.2.1 says the method as given; the fixture's is already upper case
    if name == "@authority":
        host = (u.hostname or "").lower()
        port = u.port
        default = {"https": 443, "http": 80}.get(u.scheme.lower())
        return host + (":%d" % port if port is not None and port != default else "")
    if name == "@path":
        return u.path or "/"
    if name == "@query":
        return "?" + u.query  # 2.2.7: '?' followed by the query, '?' alone when there is none
    v = _header(headers, name)
    if v is None:
        raise KeyError(name)
    return v


def signature_base(method: str, url: str, headers: dict, items, params) -> str:
    lines = []
    for it, _ip in items:
        lines.append('"%s": %s' % (it, component_value(it, method, url, headers)))
    lines.append('"@signature-params": ' + serialize_inner(items, params))
    return "\n".join(lines)  # 2.5: no trailing newline


def content_digest(body: str) -> str:
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + ":"


def _digest_matches(header_value: str, body: str) -> bool:
    d = parse_dictionary(header_value)
    if "sha-256" not in d or d["sha-256"][0] != "item" or not isinstance(d["sha-256"][1], tuple):
        return False
    return d["sha-256"][1][1] == hashlib.sha256(body.encode("utf-8")).digest()


def verify_http(method: str, url: str, body: str, headers: dict, vm: dict, now: int, max_skew: int = 300,
                seen: set | None = None) -> dict:
    """Returns {"valid": bool, "reason": str, "base": str|None}. Steps follow RFC-001 6.5 item 5 and 6."""
    agent = _header(headers, "signature-agent")
    sig_in = _header(headers, "signature-input")
    sig = _header(headers, "signature")
    if agent is None or sig_in is None or sig is None or _header(headers, "date") is None \
            or _header(headers, "content-digest") is None:
        return {"valid": False, "reason": "missing_header", "base": None}
    inputs, sigs = parse_dictionary(sig_in), parse_dictionary(sig)
    last = "no_profile_label"
    for label, (kind, items, params) in inputs.items():  # verifiers accept any label
        if kind != "inner":
            continue
        comps = [it for it, _ in items]
        p = dict(params)
        if comps[: len(PROFILE)] != PROFILE:  # 6.5 item 2: these, in this order; more MAY follow
            last = "components"
            continue
        if not REQUIRED_PARAMS <= set(p) or p["alg"] != "ed25519" or p["tag"] != "agent-did":
            last = "params"
            continue
        if not isinstance(p["keyid"], str) or not p["keyid"].startswith(agent + "#"):
            last = "keyid_not_under_signature_agent"  # 6.5 item 3: keyid is a verification method of that DID
            continue
        if p["keyid"] != vm["id"]:
            last = "keyid_not_the_given_method"  # A5: no DID document in the vector; the given method stands for it
            continue
        if abs(now - p["created"]) > max_skew:
            return {"valid": False, "reason": "created_skew", "base": None}
        if p["expires"] < p["created"] or now > p["expires"]:
            return {"valid": False, "reason": "expired", "base": None}
        if not _digest_matches(_header(headers, "content-digest"), body):
            return {"valid": False, "reason": "content_digest", "base": None}
        base = signature_base(method, url, headers, items, params)
        if label not in sigs or not isinstance(sigs[label][1], tuple):
            return {"valid": False, "reason": "no_signature_for_label", "base": base}
        ok = _verify(ed25519_from_multibase(vm["publicKeyMultibase"]), sigs[label][1][1], base.encode("utf-8"))
        if not ok:
            return {"valid": False, "reason": "signature", "base": base}
        if seen is not None:  # 6.5 item 6: record (keyid, nonce) only after the signature verified
            key = (p["keyid"], p["nonce"])
            if key in seen:
                return {"valid": False, "reason": "replay", "base": base}
            seen.add(key)
        # A6: the vector carries no DID document, so "active key listed under assertionMethod" is not checked here.
        return {"valid": True, "reason": "ok", "base": base}
    return {"valid": False, "reason": last, "base": None}
