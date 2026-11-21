"""WIMSE workload-to-workload HTTP signature reader, written from spec text only.

Sources read before writing (and nothing else about the vectors except their
section titles, key material and Section 2 conventions, which were on screen):
  - draft-ietf-wimse-http-signature-08 (Section 3, 3.1-3.6)
  - draft-ietf-wimse-workload-creds-02 Section 5.1 (WIT), -03 Section 5.1.3
  - RFC 9421 / RFC 8941 / RFC 9530 / RFC 7515 / RFC 7519 from memory

Usage as a library: verify_request(...), verify_response(...).
Outcome: ("accept", None) or ("reject", reason_code).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

TAG = "wimse-workload-to-workload"
REQ_HEADERS_IF_PRESENT = ["content-type", "content-digest", "authorization",
                          "txn-token", "workload-identity-token"]
RESP_HEADERS_IF_PRESENT = ["content-type", "content-digest"]
FORBIDDEN_PARAMS = ["keyid", "alg"]
SYMMETRIC = {"HS256", "HS384", "HS512"}


class Reject(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------- base64url
def b64u_dec(s):
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise Reject("wit_malformed")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- HTTP text
def parse_http(text):
    """Parse an unfolded HTTP/1.1 message. Returns dict."""
    head, sep, body = text.replace("\r\n", "\n").partition("\n\n")
    lines = head.split("\n")
    start = lines[0]
    msg = {"headers": [], "body": body.encode() if sep else b""}
    m = re.match(r"^HTTP/1\.1 (\d{3})(?: (.*))?$", start)
    if m:
        msg["kind"] = "response"
        msg["status"] = int(m.group(1))
    else:
        m = re.match(r"^([A-Z]+) (\S+) HTTP/1\.1$", start)
        if not m:
            raise ValueError("bad start line: " + start)
        msg["kind"] = "request"
        msg["method"] = m.group(1)
        msg["target"] = m.group(2)
    for ln in lines[1:]:
        name, _, val = ln.partition(":")
        msg["headers"].append((name.strip().lower(), val.strip()))
    return msg


def header_values(msg, name):
    return [v for n, v in msg["headers"] if n == name]


def header(msg, name):
    vals = header_values(msg, name)
    if not vals:
        return None
    return ", ".join(vals)


def split_target(msg):
    """Return (path, query or None, authority or None) for a request."""
    t = msg["target"]
    if msg["method"] == "CONNECT":
        return None, None, t
    if t.startswith("http://") or t.startswith("https://"):
        rest = t.split("://", 1)[1]
        auth, _, pq = rest.partition("/")
        pq = "/" + pq
    else:
        auth, pq = header(msg, "host"), t
    path, q, query = pq.partition("?")
    return (path or "/"), (query if q else None), auth


def norm_authority(auth, scheme="https"):
    """RFC 9421 2.2.3: lowercase host, omit default port."""
    if auth is None:
        return None
    host, _, port = auth.rpartition(":") if re.search(r":\d+$", auth) else (auth, "", "")
    host = host.lower()
    default = {"https": "443", "http": "80"}.get(scheme)
    if port and port != default:
        return f"{host}:{port}"
    return host


# ---------------------------------------------------------------- RFC 8941
class SFParser:
    def __init__(self, s):
        self.s, self.i = s, 0

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1

    def sp(self):
        while self.i < len(self.s) and self.s[self.i] == " ":
            self.i += 1

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def bare_item(self):
        c = self.peek()
        if c == '"':
            self.i += 1
            out = []
            while True:
                if self.i >= len(self.s):
                    raise ValueError("unterminated string")
                c = self.s[self.i]
                self.i += 1
                if c == "\\":
                    nxt = self.s[self.i]
                    if nxt not in '"\\':
                        raise ValueError("bad escape")
                    out.append(nxt)
                    self.i += 1
                elif c == '"':
                    return ("string", "".join(out))
                elif ord(c) < 0x20 or ord(c) > 0x7e:
                    raise ValueError("bad string char")
                else:
                    out.append(c)
        if c == ":":
            j = self.s.index(":", self.i + 1)
            raw = self.s[self.i + 1:j]
            if not re.fullmatch(r"[A-Za-z0-9+/=]*", raw):
                raise ValueError("bad byte seq")
            self.i = j + 1
            return ("bytes", base64.b64decode(raw))
        if c == "?":
            v = self.s[self.i + 1:self.i + 2]
            if v not in ("0", "1"):
                raise ValueError("bad bool")
            self.i += 2
            return ("bool", v == "1")
        m = re.compile(r"-?\d{1,15}(\.\d{1,3})?").match(self.s, self.i)
        if m and (c == "-" or c.isdigit()):
            self.i = m.end()
            return ("dec" if m.group(1) else "int", m.group(0))
        m = re.compile(r"[A-Za-z*][A-Za-z0-9_\-.:%*/!#$&'+^`|~]*").match(self.s, self.i)
        if m:
            self.i = m.end()
            return ("token", m.group(0))
        raise ValueError(f"bad item at {self.i}")

    def key(self):
        m = re.compile(r"[a-z*][a-z0-9_\-.*]*").match(self.s, self.i)
        if not m:
            raise ValueError("bad key")
        self.i = m.end()
        return m.group(0)

    def params(self):
        ps = []
        while self.peek() == ";":
            self.i += 1
            self.sp()
            k = self.key()
            v = ("bool", True)
            if self.peek() == "=":
                self.i += 1
                v = self.bare_item()
            ps = [p for p in ps if p[0] != k] + [(k, v)]
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
                it = self.bare_item()
                items.append((it, self.params()))
                if self.peek() not in (" ", ")"):
                    raise ValueError("bad inner list")
        it = self.bare_item()
        return ("item", it, self.params())

    def dictionary(self):
        out = []
        self.sp()
        while self.i < len(self.s):
            k = self.key()
            if self.peek() == "=":
                self.i += 1
                mem = self.item_or_inner()
            else:
                mem = ("item", ("bool", True), self.params())
            out = [m for m in out if m[0] != k] + [(k, mem)]
            self.ws()
            if self.i >= len(self.s):
                break
            if self.peek() != ",":
                raise ValueError("expected comma")
            self.i += 1
            self.ws()
            if self.i >= len(self.s):
                raise ValueError("trailing comma")
        return out


def ser_bare(it):
    t, v = it
    if t == "string":
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if t == "bool":
        return "?1" if v else "?0"
    if t == "bytes":
        return ":" + base64.b64encode(v).decode() + ":"
    return str(v)


def ser_params(ps):
    out = ""
    for k, v in ps:
        out += ";" + k
        if not (v[0] == "bool" and v[1] is True):
            out += "=" + ser_bare(v)
    return out


def ser_inner(items, ps):
    return "(" + " ".join(ser_bare(i) + ser_params(p) for i, p in items) + ")" + ser_params(ps)


# ---------------------------------------------------------------- WIT
def jwk_alg_ok(jwk):
    alg = jwk.get("alg")
    if not isinstance(alg, str) or alg == "none" or alg in SYMMETRIC:
        return False
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if alg in ("Ed25519", "EdDSA"):
        return kty == "OKP" and crv == "Ed25519"
    if alg == "ES256":
        return kty == "EC" and crv == "P-256"
    return False  # other algorithms: not acceptable under this reader's local policy


def verify_with_jwk(jwk, alg, data, sig):
    """alg is the algorithm to use; jwk must be consistent with it."""
    try:
        if alg in ("Ed25519", "EdDSA"):
            if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
                return False
            Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"])).verify(sig, data)
            return True
        if alg == "ES256":
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or len(sig) != 64:
                return False
            pub = ec.EllipticCurvePublicNumbers(
                int.from_bytes(b64u_dec(jwk["x"]), "big"),
                int.from_bytes(b64u_dec(jwk["y"]), "big"), ec.SECP256R1()).public_key()
            der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
            pub.verify(der, data, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, ValueError, KeyError):
        return False
    return False


def validate_wit(token, issuer_jwk, now):
    if token is None:
        raise Reject("wit_missing")
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token):
        raise Reject("wit_malformed")
    h64, p64, s64 = token.split(".")
    try:
        hdr = json.loads(b64u_dec(h64))
        claims = json.loads(b64u_dec(p64))
    except (ValueError, UnicodeDecodeError):
        raise Reject("wit_malformed")
    if not isinstance(hdr, dict) or not isinstance(claims, dict):
        raise Reject("wit_malformed")
    if hdr.get("typ") not in ("wit+jwt", "application/wit+jwt"):
        raise Reject("wit_typ")
    alg = hdr.get("alg")
    if alg in (None, "none") or alg in SYMMETRIC:
        raise Reject("wit_alg")
    if "kid" in hdr and "kid" in issuer_jwk and hdr["kid"] != issuer_jwk["kid"]:
        raise Reject("wit_unknown_key")
    if not verify_with_jwk(issuer_jwk, alg, f"{h64}.{p64}".encode(), b64u_dec(s64)):
        raise Reject("wit_signature")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not re.match(r"^[a-z][a-z0-9+.-]*://[^/]+", sub):
        raise Reject("wit_sub")
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        raise Reject("wit_exp")
    if now >= exp:
        raise Reject("wit_expired")
    cnf = claims.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if not isinstance(jwk, dict) or "alg" not in jwk:
        raise Reject("wit_cnf")
    if not jwk_alg_ok(jwk):
        raise Reject("wit_cnf_alg")
    return claims, jwk


# ---------------------------------------------------------------- signatures
def find_wimse_signature(msg):
    si_raw = header(msg, "signature-input")
    sg_raw = header(msg, "signature")
    if si_raw is None and sg_raw is None:
        return None
    try:
        si = SFParser(si_raw or "").dictionary()
        sg = SFParser(sg_raw or "").dictionary()
    except ValueError:
        raise Reject("sig_malformed")
    sg = dict(sg)
    found = []
    for label, mem in si:
        if mem[0] != "inner":
            raise Reject("sig_malformed")
        ps = dict(mem[2])
        if ps.get("tag") == ("string", TAG):
            found.append((label, mem))
    if not found:
        return None
    if len(found) > 1:
        raise Reject("multiple_wimse_signatures")
    label, mem = found[0]
    sv = sg.get(label)
    if sv is None or sv[0] != "item" or sv[1][0] != "bytes":
        raise Reject("sig_value_missing")
    return label, mem[1], mem[2], sv[1][1]


def comp_value(name, cparams, msg, req):
    """Value of one covered component. cparams: list of (k, v)."""
    keys = [k for k, _ in cparams]
    src = msg
    if "req" in keys:
        if req is None:
            raise Reject("req_component_without_request")
        src = req
    if name.startswith("@"):
        if name == "@status":
            if "req" in keys or msg["kind"] != "response":
                raise Reject("bad_component")
            return f"{msg['status']:03d}"
        if src["kind"] != "request":
            raise Reject("bad_component")
        path, query, auth = split_target(src)
        if name == "@method":
            return src["method"]
        if name == "@path":
            if path is None:
                raise Reject("bad_component")
            return path
        if name == "@query":
            if path is None:
                raise Reject("bad_component")
            return "?" + (query or "")
        if name == "@authority":
            return norm_authority(auth)
        raise Reject("unsupported_component")
    if [k for k in keys if k != "req"]:
        raise Reject("unsupported_component_param")
    v = header(src, name)
    if v is None:
        raise Reject("covered_header_absent")
    return v


def signature_base(items, ps, msg, req):
    lines, seen = [], set()
    for (t, name), cparams in items:
        if t != "string":
            raise Reject("sig_malformed")
        ident = ser_bare((t, name)) + ser_params(cparams)
        if ident in seen:
            raise Reject("duplicate_component")
        seen.add(ident)
        lines.append(f"{ident}: {comp_value(name, cparams, msg, req)}")
    lines.append('"@signature-params": ' + ser_inner(items, ps))
    return "\n".join(lines)


def check_digest(msg):
    body = msg["body"]
    cd = header(msg, "content-digest")
    if body and cd is None:
        raise Reject("content_digest_missing")
    if cd is None:
        return
    try:
        d = SFParser(cd).dictionary()
    except ValueError:
        raise Reject("content_digest_malformed")
    known = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}
    checked = False
    for alg, mem in d:
        if alg in known:
            if mem[0] != "item" or mem[1][0] != "bytes":
                raise Reject("content_digest_malformed")
            if mem[1][1] != known[alg](body).digest():
                raise Reject("content_digest_mismatch")
            checked = True
    if not checked:
        raise Reject("content_digest_unsupported")


def common_checks(msg, req, items, ps, sig, now, issuer_jwk, is_request):
    names = [(n, tuple(k for k, _ in cp)) for (_, n), cp in items]
    pd = dict(ps)
    # 1. WIT first (base spec Section 3: validate WIT before the signature)
    claims, jwk = validate_wit(header(msg, "workload-identity-token"), issuer_jwk, now)
    # 2. required / forbidden parameters
    for p in ("created", "expires", "nonce", "tag"):
        if p not in pd:
            raise Reject(f"param_missing_{p}")
    for p in FORBIDDEN_PARAMS:
        if p in pd:
            raise Reject(f"param_forbidden_{p}")
    if pd["created"][0] != "int" or pd["expires"][0] != "int" or pd["nonce"][0] != "string":
        raise Reject("param_type")
    created, expires = int(pd["created"][1]), int(pd["expires"][1])
    if now < created or now > expires:
        raise Reject("outside_validity_window")
    # 3. covered components
    def has(n, req_flag=False):
        return (n, ("req",) if req_flag else ()) in names
    if is_request:
        if "wimse-aud" not in pd:
            raise Reject("param_missing_wimse-aud")
        if pd["wimse-aud"][0] != "string":
            raise Reject("param_type")
        if not has("@method"):
            raise Reject("coverage_missing_@method")
        if msg["method"] == "CONNECT":
            if has("@path") or has("@query"):
                raise Reject("connect_covers_path_or_query")
            if not has("@authority"):
                raise Reject("coverage_missing_@authority")
        else:
            for n in ("@path", "@query"):
                if not has(n):
                    raise Reject(f"coverage_missing_{n}")
        for h in REQ_HEADERS_IF_PRESENT:
            if header(msg, h) is not None and not has(h):
                raise Reject(f"coverage_missing_{h}")
        if "wimse-sign-response" in pd and pd["wimse-sign-response"][0] != "bool":
            raise Reject("param_type")
    else:
        if "wimse-req-nonce" not in pd:
            raise Reject("param_missing_wimse-req-nonce")
        if pd["wimse-req-nonce"][0] != "string":
            raise Reject("param_type")
        if not has("@status") or not has("@method", True):
            raise Reject("coverage_missing_response_core")
        if req is not None and req["method"] == "CONNECT":
            if has("@path", True) or has("@query", True):
                raise Reject("connect_response_covers_path_or_query")
            if not has("@authority", True):
                raise Reject("coverage_missing_@authority;req")
        else:
            for n in ("@path", "@query"):
                if not has(n, True):
                    raise Reject(f"coverage_missing_{n};req")
        for h in RESP_HEADERS_IF_PRESENT:
            if header(msg, h) is not None and not has(h):
                raise Reject(f"coverage_missing_{h}")
        if not has("workload-identity-token"):
            raise Reject("coverage_missing_workload-identity-token")
    # 4. body integrity
    check_digest(msg)
    # 5. the signature, with cnf.jwk.alg
    base = signature_base(items, ps, msg, req)
    if not verify_with_jwk(jwk, jwk["alg"], base.encode(), sig):
        raise Reject("signature_invalid")
    return pd, base, claims


def verify_request(text_or_msg, *, now, trusted_aud, issuer_jwk):
    """Server side. Returns (outcome, reason, info)."""
    msg = parse_http(text_or_msg) if isinstance(text_or_msg, str) else text_or_msg
    try:
        found = find_wimse_signature(msg)
        if found is None:
            raise Reject("no_wimse_signature")
        label, items, ps, sig = found
        pd, base, claims = common_checks(msg, None, items, ps, sig, now, issuer_jwk, True)
        if pd["wimse-aud"][1] not in trusted_aud:
            raise Reject("audience_mismatch")
        return "accept", None, {"label": label, "base": base, "sub": claims["sub"],
                                "nonce": pd["nonce"][1],
                                "sign_response": pd.get("wimse-sign-response") == ("bool", True)}
    except Reject as r:
        return "reject", r.code, {"http_status": 400,
                                  "problem_type": "https://iana.org/assignments/http-problem-types#wimse-signature-invalid"}


def verify_response(text_or_msg, *, request, now, issuer_jwk):
    """Client side. request: the request text/msg that this client sent."""
    msg = parse_http(text_or_msg) if isinstance(text_or_msg, str) else text_or_msg
    req = parse_http(request) if isinstance(request, str) else request
    try:
        rfound = find_wimse_signature(req)
        if rfound is None:
            raise Reject("request_not_wimse_signed")
        rps = dict(rfound[2])
        req_nonce = rps["nonce"][1]
        required = rps.get("wimse-sign-response") == ("bool", True)
        found = find_wimse_signature(msg)
        if found is None:
            if required:
                raise Reject("signed_response_required")
            return "accept", None, {"signed": False}
        label, items, ps, sig = found
        pd, base, claims = common_checks(msg, req, items, ps, sig, now, issuer_jwk, False)
        if pd["wimse-req-nonce"][1] != req_nonce:
            raise Reject("req_nonce_mismatch")
        return "accept", None, {"signed": True, "label": label, "base": base, "sub": claims["sub"]}
    except Reject as r:
        return "reject", r.code, {}
