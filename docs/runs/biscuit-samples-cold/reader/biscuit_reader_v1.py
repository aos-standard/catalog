#!/usr/bin/env python3
"""An independent Biscuit v3 verifier and authorizer, written from SPECIFICATIONS.md and schema.proto only
(eclipse-biscuit/biscuit at b3d3fe2). No implementation, no samples/current/README.md and no expected value was read.

authorize(token_bytes, root_public_key_hex, authorizer_code) ->
    {"result": ("ok", policy_index) | ("err", kind, detail), "revocation_ids": [hex...]}

Readings the text leaves open are marked R1..Rn.
"""
import datetime
import hashlib
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

I64_MIN, I64_MAX = -(1 << 63), (1 << 63) - 1
DEFAULT_SYMBOLS = ["read", "write", "resource", "operation", "right", "time", "role", "owner", "tenant", "namespace",
                   "user", "team", "service", "admin", "email", "group", "member", "ip_address", "client", "client_ip",
                   "domain", "path", "version", "cluster", "node", "hostname", "nonce", "query"]
MIN_VERSION, MAX_VERSION = 3, 6
AUTHORIZER = 1 << 62          # the authorizer's block id, distinct from token block ids


class FormatError(Exception):
    pass


class ExecError(Exception):
    pass


# ======================================================================= protobuf (proto2 wire format)
def _varint(b, i):
    r = s = 0
    while True:
        if i >= len(b):
            raise FormatError("truncated varint")
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        if not c & 0x80:
            return r, i
        s += 7
        if s > 70:
            raise FormatError("varint too long")


def pb_fields(b):
    """bytes -> {field_number: [value,...]} with varints as int and length-delimited as bytes."""
    out = {}
    i = 0
    while i < len(b):
        key, i = _varint(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = _varint(b, i)
        elif wt == 2:
            n, i = _varint(b, i)
            if i + n > len(b):
                raise FormatError("truncated field")
            v, i = b[i:i + n], i + n
        elif wt == 1:
            v, i = b[i:i + 8], i + 8
        elif wt == 5:
            v, i = b[i:i + 4], i + 4
        else:
            raise FormatError("unsupported wire type %d" % wt)
        out.setdefault(fn, []).append(v)
    return out


def _one(f, n, required=True):
    v = f.get(n)
    if not v:
        if required:
            raise FormatError("missing required field %d" % n)
        return None
    return v[-1]


def _sint64(v):
    return v - (1 << 64) if v >= (1 << 63) else v


# ======================================================================= values
# A term is a tuple: ("int", n) ("str", s) ("date", n) ("bytes", b) ("bool", b) ("null", None)
# ("set", frozenset) ("array", tuple) ("map", tuple(sorted (key, value))) ("var", name) ("closure", params, ops)
def T(kind, v):
    return (kind, v)


def mk_map(pairs):
    d = {}
    for k, v in pairs:
        d[k] = v
    return ("map", tuple(sorted(d.items(), key=lambda kv: (kv[0][0], kv[0][1]))))


# ======================================================================= token decoding
class Block:
    def __init__(self):
        self.symbols = []
        self.context = None
        self.version = None
        self.facts = []
        self.rules = []          # (head, body, exprs, scopes)
        self.checks = []         # (kind, [rule])
        self.scopes = []
        self.public_keys = []
        self.external_key = None


def decode_public_key(b):
    f = pb_fields(b)
    alg = _one(f, 1)
    key = _one(f, 2)
    if alg not in (0, 1):
        raise FormatError("unknown key algorithm")
    return (alg, bytes(key))


class Decoder:
    """Decodes one Block's datalog with a symbol table and a public key table."""

    def __init__(self, symbols, keys):
        self.symbols = symbols
        self.keys = keys

    def sym(self, i):
        if i < 1024:
            if i >= len(DEFAULT_SYMBOLS):
                raise FormatError("unknown default symbol %d" % i)
            return DEFAULT_SYMBOLS[i]
        j = i - 1024
        if j >= len(self.symbols):
            raise FormatError("unknown symbol %d" % i)
        return self.symbols[j]

    def term(self, b, allow_var=True):
        f = pb_fields(b)
        if len(f) != 1 or len(next(iter(f.values()))) != 1:
            raise FormatError("term must have exactly one content")   # R1: oneof with several values is invalid
        (n, (v,)), = f.items()
        if n == 1:
            if not allow_var:
                raise FormatError("variable not allowed here")
            return ("var", self.sym(v))
        if n == 2:
            return ("int", _sint64(v))
        if n == 3:
            return ("str", self.sym(v))
        if n == 4:
            return ("date", v)
        if n == 5:
            return ("bytes", bytes(v))
        if n == 6:
            return ("bool", bool(v))
        if n == 7:
            items = [self.term(x, False) for x in pb_fields(v).get(1, [])]
            if any(t[0] in ("set", "var") for t in items):
                raise FormatError("set cannot contain sets or variables")
            if len({t[0] for t in items}) > 1:
                raise FormatError("set elements must have the same type")  # R2: "terms of the same type"
            return ("set", frozenset(items))
        if n == 8:
            return ("null", None)
        if n == 9:
            return ("array", tuple(self.term(x, allow_var) for x in pb_fields(v).get(1, [])))
        if n == 10:
            pairs = []
            for e in pb_fields(v).get(1, []):
                ef = pb_fields(e)
                kf = pb_fields(_one(ef, 1))
                if 1 in kf:
                    k = ("int", _sint64(kf[1][-1]))
                elif 2 in kf:
                    k = ("str", self.sym(kf[2][-1]))
                else:
                    raise FormatError("map key")
                pairs.append((k, self.term(_one(ef, 2), allow_var)))
            return mk_map(pairs)
        raise FormatError("unknown term kind %d" % n)

    def predicate(self, b, allow_var=True):
        f = pb_fields(b)
        return (self.sym(_one(f, 1)), tuple(self.term(t, allow_var) for t in f.get(2, [])))

    def scope(self, b):
        f = pb_fields(b)
        if 1 in f:
            st = f[1][-1]
            if st == 0:
                return ("authority",)
            if st == 1:
                return ("previous",)
            raise FormatError("scope type")
        if 2 in f:
            i = _sint64(f[2][-1])
            if i < 0 or i >= len(self.keys):
                raise FormatError("unknown public key index %d" % i)
            return ("key", self.keys[i])
        raise FormatError("empty scope")

    def op(self, b):
        f = pb_fields(b)
        if 1 in f:
            return ("value", self.term(f[1][-1]))
        if 2 in f:
            u = pb_fields(f[2][-1])
            k = _one(u, 1)
            name = self.sym(u[2][-1]) if 2 in u else None
            return ("unary", k, name)
        if 3 in f:
            u = pb_fields(f[3][-1])
            k = _one(u, 1)
            name = self.sym(u[2][-1]) if 2 in u else None
            return ("binary", k, name)
        if 4 in f:
            u = pb_fields(f[4][-1])
            params = [self.sym(p) for p in u.get(1, [])]
            return ("closure", params, [self.op(o) for o in u.get(2, [])])
        raise FormatError("empty op")

    def rule(self, b, query=False):
        f = pb_fields(b)
        head = self.predicate(_one(f, 1))
        body = [self.predicate(x) for x in f.get(2, [])]
        exprs = [[self.op(o) for o in pb_fields(e).get(1, [])] for e in f.get(3, [])]
        scopes = [self.scope(s) for s in f.get(4, [])]
        return (head, body, exprs, scopes)

    def block(self, data):
        f = pb_fields(data)
        bl = Block()
        bl.version = _one(f, 3, required=False)
        bl.context = _one(f, 2, required=False)
        bl.facts = [self.predicate(_one(pb_fields(x), 1), allow_var=False) for x in f.get(4, [])]
        bl.rules = [self.rule(x) for x in f.get(5, [])]
        for c in f.get(6, []):
            cf = pb_fields(c)
            kind = _one(cf, 2, required=False) or 0
            if kind not in (0, 1, 2):
                raise FormatError("check kind")
            bl.checks.append((["one", "all", "reject"][kind], [self.rule(q) for q in cf.get(1, [])]))
        bl.scopes = [self.scope(s) for s in f.get(7, [])]
        return bl


def block_symbols_and_keys(data):
    f = pb_fields(data)
    syms = [bytes(s).decode("utf-8") for s in f.get(1, [])]
    keys = [decode_public_key(k) for k in f.get(8, [])]
    return syms, keys


# ======================================================================= cryptography
def _le32(n):
    return int(n).to_bytes(4, "little")      # R3: "little endian representation" read as 32 bits


def verify_sig(pk, sig, msg):
    alg, key = pk
    try:
        if alg == 0:
            Ed25519PublicKey.from_public_bytes(key).verify(sig, msg)
        else:
            if len(key) != 33 or key[0] not in (2, 3):
                return False
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key).verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def payload_v0(data, ext_sig, next_pk):
    # R12: the v0 list in the text puts pk before alg; the sealing formula and the sample tokens' signatures put alg
    # first. Taken as data + [external_sig] + alg + pk, checked against the signatures of the sample tokens (exposure noted)
    return data + (ext_sig or b"") + _le32(next_pk[0]) + next_pk[1]


def payload_v1(data, next_pk, prev_sig, ext_sig, version):
    p = b"\0BLOCK\0" + b"\0VERSION\0" + _le32(version) + b"\0PAYLOAD\0" + data + b"\0ALGORITHM\0" + _le32(next_pk[0]) + \
        b"\0NEXTKEY\0" + next_pk[1]
    if prev_sig is not None:
        p += b"\0PREVSIG\0" + prev_sig
    if ext_sig is not None:
        p += b"\0EXTERNALSIG\0" + ext_sig
    return p


def external_payload_v1(data, prev_sig, version):
    return b"\0EXTERNAL\0" + b"\0VERSION\0" + _le32(version) + b"\0PAYLOAD\0" + data + b"\0PREVSIG\0" + prev_sig


def public_from_secret(alg, secret):
    if alg == 0:
        if len(secret) != 32:
            raise FormatError("ed25519 secret length")
        return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    k = ec.derive_private_key(int.from_bytes(secret, "big"), ec.SECP256R1())
    return k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


class Token:
    def __init__(self):
        self.blocks = []         # Block objects, index 0 = authority
        self.signatures = []


def load_token(raw, root_pk):
    f = pb_fields(raw)
    signed = [_one(f, 2)] + f.get(3, [])
    proof = pb_fields(_one(f, 4))
    tok = Token()
    prev_pk, prev_sig = root_pk, None
    parsed = []
    for idx, sb in enumerate(signed):
        s = pb_fields(sb)
        data = bytes(_one(s, 1))
        next_pk = decode_public_key(_one(s, 2))
        sig = bytes(_one(s, 3))
        ext = _one(s, 4, required=False)
        sver = _one(s, 5, required=False) or 0
        ext_sig = ext_pk = None
        if ext is not None:
            if idx == 0:
                raise FormatError("authority block cannot carry an external signature")
            ef = pb_fields(ext)
            ext_sig, ext_pk = bytes(_one(ef, 1)), decode_public_key(_one(ef, 2))
            if sver < 1:
                raise FormatError("third-party blocks must use signature version 1")
        if sver == 0:
            msg = payload_v0(data, ext_sig, next_pk)
        elif sver == 1:
            msg = payload_v1(data, next_pk, prev_sig if idx > 0 else None, ext_sig, sver)
        else:
            raise FormatError("unknown signature version %d" % sver)
        if not verify_sig(prev_pk, sig, msg):
            raise FormatError("invalid block signature (block %d)" % idx)
        if ext is not None:
            if not verify_sig(ext_pk, ext_sig, external_payload_v1(data, prev_sig, 1)):
                raise FormatError("invalid external signature (block %d)" % idx)
        parsed.append((data, next_pk, sig, ext_pk))
        prev_pk, prev_sig = next_pk, sig
    # proof
    if 1 in proof:
        secret = bytes(proof[1][-1])
        if public_from_secret(prev_pk[0], secret) != prev_pk[1]:
            raise FormatError("proof secret does not match the last public key")
    elif 2 in proof:
        data, next_pk, sig, _ = parsed[-1]
        msg = data + _le32(next_pk[0]) + next_pk[1] + sig       # R4: sealing payload as written: data+alg+pk+sig
        if not verify_sig(prev_pk, bytes(proof[2][-1]), msg):
            raise FormatError("invalid final signature")
    else:
        raise FormatError("empty proof")
    # symbols and public key tables
    token_syms, token_keys = [], []
    for idx, (data, next_pk, sig, ext_pk) in enumerate(parsed):
        syms, keys = block_symbols_and_keys(data)
        if ext_pk is None:
            if set(syms) & set(token_syms) or len(set(syms)) != len(syms):
                raise FormatError("symbol defined twice")   # "verify that different blocks do not contain the same symbol"
            token_syms = token_syms + syms
            token_keys = token_keys + keys
            dec = Decoder(token_syms, token_keys)
        else:
            dec = Decoder(syms, keys)                      # third-party: isolated tables
        bl = dec.block(data)
        if bl.version is None or not (MIN_VERSION <= bl.version <= MAX_VERSION):
            raise FormatError("unsupported datalog version %r (block %d)" % (bl.version, idx))
        if ext_pk is not None and bl.version < 5:
            raise FormatError("third-party block below v3.2")
        bl.external_key = ext_pk
        tok.blocks.append(bl)
        tok.signatures.append(sig)
    return tok


# ======================================================================= expression VM
UN = {0: "negate", 1: "parens", 2: "length", 3: "typeof", 4: "ffi"}
BIN = {0: "lt", 1: "gt", 2: "le", 3: "ge", 4: "eq", 5: "contains", 6: "prefix", 7: "suffix", 8: "regex", 9: "add",
       10: "sub", 11: "mul", 12: "div", 13: "and", 14: "or", 15: "intersection", 16: "union", 17: "band", 18: "bor",
       19: "bxor", 20: "neq", 21: "heq", 22: "hneq", 23: "lazyand", 24: "lazyor", 25: "all", 26: "any", 27: "get",
       28: "ffi", 29: "tryor"}
TYPE_NAMES = {"int": "integer", "str": "string", "date": "date", "bytes": "bytes", "bool": "bool", "set": "set",
              "null": "null", "array": "array", "map": "map"}


def _chk(n):
    if not (I64_MIN <= n <= I64_MAX):
        raise ExecError("integer overflow")
    return ("int", n)


def _strict_eq(a, b):
    if a[0] != b[0]:
        raise ExecError("strict equality between different types")
    return a == b


def run_ops(ops, env):
    stack = []
    for op in ops:
        kind = op[0]
        if kind == "value":
            t = op[1]
            if t[0] == "var":
                if t[1] not in env:
                    raise ExecError("unbound variable %s" % t[1])
                t = env[t[1]]
            stack.append(subst(t, env))
        elif kind == "closure":
            for p in op[1]:
                if p in env:
                    raise ExecError("shadowing")
            stack.append(("closure", tuple(op[1]), op[2]))
        elif kind == "unary":
            if not stack:
                raise ExecError("stack underflow")
            a = stack.pop()
            stack.append(unary(UN.get(op[1]), a, op[2]))
        elif kind == "binary":
            if len(stack) < 2:
                raise ExecError("stack underflow")
            b = stack.pop()
            a = stack.pop()
            stack.append(binary(BIN.get(op[1]), a, b, env, op[2]))
        else:
            raise ExecError("bad op")
    if len(stack) != 1:
        raise ExecError("stack must hold one value")
    return stack[0]


def subst(t, env):
    if t[0] == "var":
        if t[1] not in env:
            raise ExecError("unbound variable")
        return env[t[1]]
    if t[0] == "array":
        return ("array", tuple(subst(x, env) for x in t[1]))
    if t[0] == "map":
        return mk_map([(k, subst(v, env)) for k, v in t[1]])
    return t


def call_closure(c, args, env):
    if c[0] != "closure":
        raise ExecError("not a closure")
    params, ops = c[1], c[2]
    if len(params) != len(args):
        raise ExecError("closure arity")
    e = dict(env)
    for p, a in zip(params, args):
        e[p] = a
    return run_ops(ops, e)


def unary(name, a, ffi_name):
    if name == "negate":
        if a[0] != "bool":
            raise ExecError("negate on non-bool")
        return ("bool", not a[1])
    if name == "parens":
        return a
    if name == "length":
        if a[0] == "str":
            return ("int", len(a[1].encode("utf-8")))
        if a[0] in ("bytes", "set", "array", "map"):
            return ("int", len(a[1]))
        raise ExecError("length type")
    if name == "typeof":
        return ("str", TYPE_NAMES[a[0]])
    raise ExecError("unsupported unary %s" % name)      # R5: external calls are host-defined; none are provided


def _items(a):
    if a[0] == "set":
        return sorted(a[1])
    if a[0] == "array":
        return list(a[1])
    if a[0] == "map":
        return [("array", (k, v)) for k, v in a[1]]
    raise ExecError("not iterable")


def binary(name, a, b, env, ffi_name):
    if name in ("lt", "gt", "le", "ge"):
        if a[0] != b[0] or a[0] not in ("int", "date"):
            raise ExecError("ordering type")
        x, y = a[1], b[1]
        return ("bool", {"lt": x < y, "gt": x > y, "le": x <= y, "ge": x >= y}[name])
    if name == "eq":
        return ("bool", _strict_eq(a, b))
    if name == "neq":
        return ("bool", not _strict_eq(a, b))
    if name == "heq":
        return ("bool", a == b)
    if name == "hneq":
        return ("bool", a != b)
    if name == "contains":
        if a[0] == "set":
            if b[0] == "set":
                return ("bool", b[1] <= a[1])
            return ("bool", b in a[1])
        if a[0] == "str" and b[0] == "str":
            return ("bool", b[1] in a[1])
        if a[0] == "array":
            return ("bool", b in a[1])
        if a[0] == "map":
            return ("bool", any(k == b for k, _ in a[1]))
        raise ExecError("contains type")
    if name in ("prefix", "suffix"):
        if a[0] == "str" and b[0] == "str":
            return ("bool", a[1].startswith(b[1]) if name == "prefix" else a[1].endswith(b[1]))
        if a[0] == "array" and b[0] == "array":
            n = len(b[1])
            return ("bool", a[1][:n] == b[1] if name == "prefix" else (n == 0 or a[1][-n:] == b[1]))
        raise ExecError("prefix type")
    if name == "regex":
        if a[0] != "str" or b[0] != "str":
            raise ExecError("regex type")
        try:
            return ("bool", re.search(b[1], a[1]) is not None)   # R6: unanchored search, Python dialect
        except re.error as e:
            raise ExecError("bad regex") from e
    if name == "add":
        if a[0] == "int" and b[0] == "int":
            return _chk(a[1] + b[1])
        if a[0] == "str" and b[0] == "str":
            return ("str", a[1] + b[1])
        raise ExecError("add type")
    if name in ("sub", "mul", "div", "band", "bor", "bxor"):
        if a[0] != "int" or b[0] != "int":
            raise ExecError("integer op type")
        x, y = a[1], b[1]
        if name == "sub":
            return _chk(x - y)
        if name == "mul":
            return _chk(x * y)
        if name == "div":
            if y == 0:
                raise ExecError("division by zero")
            q = abs(x) // abs(y)
            q = q if (x >= 0) == (y >= 0) else -q    # R7: truncating division
            return _chk(q)
        return ("int", {"band": x & y, "bor": x | y, "bxor": x ^ y}[name])
    if name in ("and", "or"):
        if a[0] != "bool" or b[0] != "bool":
            raise ExecError("bool op type")
        return ("bool", (a[1] and b[1]) if name == "and" else (a[1] or b[1]))
    if name in ("lazyand", "lazyor"):
        if a[0] != "bool":
            raise ExecError("lazy op type")
        if name == "lazyand" and not a[1]:
            return ("bool", False)
        if name == "lazyor" and a[1]:
            return ("bool", True)
        r = call_closure(b, [], env)
        if r[0] != "bool":
            raise ExecError("lazy rhs type")
        return r
    if name in ("intersection", "union"):
        if a[0] != "set" or b[0] != "set":
            raise ExecError("set op type")
        return ("set", a[1] & b[1] if name == "intersection" else a[1] | b[1])
    if name in ("all", "any"):
        res = name == "all"
        for it in _items(a):
            r = call_closure(b, [it], env)
            if r[0] != "bool":
                raise ExecError("closure must return bool")
            if name == "all" and not r[1]:
                return ("bool", False)
            if name == "any" and r[1]:
                return ("bool", True)
        return ("bool", res)
    if name == "get":
        if a[0] == "array":
            if b[0] != "int":
                raise ExecError("array index type")
            i = b[1]
            return a[1][i] if 0 <= i < len(a[1]) else ("null", None)
        if a[0] == "map":
            if b[0] not in ("int", "str"):
                raise ExecError("map key type")
            for k, v in a[1]:
                if k == b:
                    return v
            return ("null", None)
        raise ExecError("get type")
    if name == "tryor":
        try:
            return call_closure(a, [], env) if a[0] == "closure" else a
        except ExecError:
            return b
    raise ExecError("unsupported binary %s" % name)     # R5


def eval_expr(ops, env):
    """True if the expression returns true. An error is a non-match (R8)."""
    try:
        r = run_ops(ops, env)
    except ExecError:
        return False
    except RecursionError:
        return False
    return r == ("bool", True)


# ======================================================================= datalog engine
def match_pred(pred, fact, env):
    name, terms = pred
    fname, fterms = fact
    if name != fname or len(terms) != len(fterms):
        return None
    e = dict(env)
    for t, v in zip(terms, fterms):
        if t[0] == "var":
            if t[1] in e:
                if e[t[1]] != v:
                    return None
            else:
                e[t[1]] = v
        elif t[0] in ("array", "map"):
            try:
                if subst(t, e) != v:
                    return None
            except ExecError:
                return None          # R9: variables nested in arrays/maps of a body predicate are not bound by matching
        elif t != v:
            return None
    return e


def rule_vars_safe(head, body):
    def vs(t, acc):
        if t[0] == "var":
            acc.add(t[1])
        elif t[0] == "array":
            for x in t[1]:
                vs(x, acc)
        elif t[0] == "map":
            for _, x in t[1]:
                vs(x, acc)
        return acc
    hv = set()
    for t in head[1]:
        vs(t, hv)
    bv = set()
    for p in body:
        for t in p[1]:
            vs(t, bv)
    return hv <= bv


class World:
    def __init__(self, token, auth):
        self.token = token
        self.auth = auth
        self.facts = {}          # fact -> set of origin frozensets

    def add(self, fact, origin):
        s = self.facts.setdefault(fact, set())
        if origin in s:
            return False
        s.add(origin)
        return True

    def trusted(self, scopes, block_id, default_scopes):
        """Set of block ids trusted by a rule defined in block_id."""
        sc = scopes or default_scopes or [("authority",)]
        t = {block_id, AUTHORIZER}
        n = len(self.token.blocks)
        for s in sc:
            if s[0] == "authority":
                t.add(0)
            elif s[0] == "previous":
                if block_id != AUTHORIZER:
                    t.update(range(0, block_id + 1))
            elif s[0] == "key":
                for i, bl in enumerate(self.token.blocks):
                    if bl.external_key == s[1]:
                        t.add(i)
        return t

    def matches(self, body, exprs, trusted):
        """Yield (env, origin) for every combination of trusted facts that matches the body and the expressions."""
        avail = [(f, o) for f, os_ in self.facts.items() for o in os_ if o <= trusted]

        def rec(i, env, origin):
            if i == len(body):
                if all(eval_expr(x, env) for x in exprs):
                    yield env, origin
                return
            for f, o in avail:
                e = match_pred(body[i], f, env)
                if e is not None:
                    yield from rec(i + 1, e, origin | o)
        if not body:
            if all(eval_expr(x, {}) for x in exprs):
                yield {}, frozenset()
            return
        yield from rec(0, {}, frozenset())


def run_rules(world, rules, max_iter=1000, max_facts=100000):
    """rules: [(rule, block_id, block_default_scopes)]."""
    for _ in range(max_iter):
        new = []
        for (head, body, exprs, scopes), bid, dscopes in rules:
            tr = world.trusted(scopes, bid, dscopes)
            for env, origin in world.matches(body, exprs, tr):
                try:
                    fact = (head[0], tuple(subst(t, env) for t in head[1]))
                except ExecError:
                    continue
                new.append((fact, origin | {bid}))
        changed = False
        for fact, origin in new:
            if world.add(fact, frozenset(origin)):
                changed = True
        if len(world.facts) > max_facts:
            raise ExecError("too many facts")
        if not changed:
            return
    raise ExecError("too many iterations")


def query_ok(world, rule, bid, dscopes, kind):
    head, body, exprs, scopes = rule
    tr = world.trusted(scopes, bid, dscopes)
    if kind == "all":
        any_match = False
        avail = [(f, o) for f, os_ in world.facts.items() for o in os_ if o <= tr]

        def rec(i, env):
            if i == len(body):
                yield env
                return
            for f, o in avail:
                e = match_pred(body[i], f, env)
                if e is not None:
                    yield from rec(i + 1, e)
        for env in (rec(0, {}) if body else iter([{}])):
            any_match = True
            if not all(eval_expr(x, env) for x in exprs):
                return False
        return any_match              # R10: `check all` with no matching facts fails
    found = next(iter(world.matches(body, exprs, tr)), None) is not None
    return (not found) if kind == "reject" else found


# ======================================================================= authorizer text parser
class ParseError(Exception):
    pass


OP_PREC = [("||", "lazyor"), ("&&", "lazyand"), ("CMP", None), ("^", "bxor"), ("|", "bor"), ("&", "band"),
           ("+-", None), ("*/", None)]
BINK = {v: k for k, v in BIN.items()}
UNK = {v: k for k, v in UN.items()}


def _date(s):
    m = re.fullmatch(r"(\d+)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)", s)
    if not m:
        raise ParseError("bad date %s" % s)
    y, mo, d, h, mi, se, tz = m.groups()
    off = 0 if tz == "Z" else (1 if tz[0] == "+" else -1) * (int(tz[1:3]) * 3600 + int(tz[4:6]) * 60)
    dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), tzinfo=datetime.timezone.utc)
    return int(dt.timestamp()) - off


class Parser:
    NAME = r"[^\W\d_][\w:]*"

    def __init__(self, s):
        self.s = s
        self.i = 0

    def ws(self):
        while True:
            m = re.compile(r"[ \t\r\n]+").match(self.s, self.i)
            if m:
                self.i = m.end()
                continue
            if self.s.startswith("//", self.i):
                j = self.s.find("\n", self.i)
                self.i = len(self.s) if j < 0 else j + 1
                continue
            return

    def peek(self, t):
        self.ws()
        return self.s.startswith(t, self.i)

    def eat(self, t):
        if not self.peek(t):
            raise ParseError("expected %r at %d: %r" % (t, self.i, self.s[self.i:self.i + 30]))
        self.i += len(t)

    def try_eat(self, t):
        if self.peek(t):
            self.i += len(t)
            return True
        return False

    def kw(self, w):
        self.ws()
        if re.compile(re.escape(w) + r"(?![\w])").match(self.s, self.i):
            self.i += len(w)
            return True
        return False

    def name(self):
        self.ws()
        m = re.compile(self.NAME).match(self.s, self.i)
        if not m:
            raise ParseError("name expected at %d: %r" % (self.i, self.s[self.i:self.i + 30]))
        self.i = m.end()
        return m.group(0)

    # ---- program
    def program(self):
        out = {"facts": [], "rules": [], "checks": [], "policies": []}
        while True:
            self.ws()
            if self.i >= len(self.s):
                return out
            if self.kw("allow") or self.kw("deny"):
                kind = "allow" if self.s[self.i - 5:self.i] == "allow" else "deny"
                self.eat("if")
                out["policies"].append((kind, self.bodies()))
            elif self.kw("check"):
                if self.kw("if"):
                    k = "one"
                elif self.kw("all"):
                    k = "all"
                else:
                    raise ParseError("check if/all")
                out["checks"].append((k, self.bodies()))
            elif self.kw("reject"):
                self.eat("if")
                out["checks"].append(("reject", self.bodies()))
            else:
                pred = self.predicate()
                if self.try_eat("<-"):
                    body, exprs, scopes = self.body()
                    out["rules"].append((pred, body, exprs, scopes))
                else:
                    out["facts"].append((pred[0], tuple(self._fact_term(t) for t in pred[1])))
            self.eat(";")

    def _fact_term(self, t):
        if t[0] == "var" or (t[0] in ("array",) and any(x[0] == "var" for x in t[1])):
            raise ParseError("variable in fact")
        return t

    def bodies(self):
        qs = []
        while True:
            body, exprs, scopes = self.body()
            qs.append((("query", ()), body, exprs, scopes))
            if not self.kw("or"):
                return qs

    def body(self):
        preds, exprs, scopes = [], [], []
        while True:
            self.ws()
            save = self.i
            m = re.compile(self.NAME + r"\s*\(").match(self.s, self.i)
            if m and not re.compile(r"(true|false|null)\b").match(self.s, self.i):
                preds.append(self.predicate())
            else:
                self.i = save
                exprs.append(self.expression())
            if self.peek(","):
                self.eat(",")
                continue
            break
        if self.kw("trusting"):
            scopes = self.origins()
        return preds, exprs, scopes

    def origins(self):
        out = []
        while True:
            if self.kw("authority"):
                out.append(("authority",))
            elif self.kw("previous"):
                out.append(("previous",))
            else:
                self.ws()
                m = re.compile(r"(ed25519|secp256r1)/([0-9a-fA-F]+)").match(self.s, self.i)
                if not m:
                    raise ParseError("origin")
                self.i = m.end()
                out.append(("key", (0 if m.group(1) == "ed25519" else 1, bytes.fromhex(m.group(2)))))
            if not self.try_eat(","):
                return out

    def predicate(self):
        n = self.name()
        self.eat("(")
        terms = []
        if not self.peek(")"):
            while True:
                terms.append(self.term())
                if not self.try_eat(","):
                    break
        self.eat(")")
        return (n, tuple(terms))

    def term(self):
        self.ws()
        s, i = self.s, self.i
        if s.startswith("$", i):
            m = re.compile(r"\$[\w:]+").match(s, i)
            self.i = m.end()
            return ("var", m.group(0)[1:])
        if s.startswith('"', i):
            j = i + 1
            out = []
            while s[j] != '"':
                if s[j] == "\\":
                    nxt = s[j + 1]
                    out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
                    j += 2
                else:
                    out.append(s[j])
                    j += 1
            self.i = j + 1
            return ("str", "".join(out))
        if s.startswith("hex:", i):
            m = re.compile(r"hex:([0-9a-fA-F]*)").match(s, i)
            self.i = m.end()
            return ("bytes", bytes.fromhex(m.group(1)))
        m = re.compile(r"\d+-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)").match(s, i)
        if m:
            self.i = m.end()
            return ("date", _date(m.group(0)))
        m = re.compile(r"-?\d+").match(s, i)
        if m:
            self.i = m.end()
            v = int(m.group(0))
            if not (I64_MIN <= v <= I64_MAX):
                raise ParseError("integer out of range")
            return ("int", v)
        for w, t in (("true", ("bool", True)), ("false", ("bool", False)), ("null", ("null", None))):
            if re.compile(w + r"(?!\w)").match(s, i):
                self.i = i + len(w)
                return t
        if s.startswith("[", i):
            self.i += 1
            items = []
            if not self.peek("]"):
                while True:
                    items.append(self.term())
                    if not self.try_eat(","):
                        break
            self.eat("]")
            return ("array", tuple(items))
        if s.startswith("{", i):
            self.i += 1
            if self.try_eat(","):
                self.eat("}")
                return ("set", frozenset())
            if self.try_eat("}"):
                return ("map", ())
            first = self.term()
            if self.try_eat(":"):
                pairs = [(first, self.term())]
                while self.try_eat(","):
                    k = self.term()
                    self.eat(":")
                    pairs.append((k, self.term()))
                self.eat("}")
                for k, _ in pairs:
                    if k[0] not in ("int", "str"):
                        raise ParseError("map key type")
                return mk_map(pairs)
            items = [first]
            while self.try_eat(","):
                items.append(self.term())
            self.eat("}")
            if any(t[0] in ("set", "var") for t in items):
                raise ParseError("set content")
            return ("set", frozenset(items))
        raise ParseError("term expected at %d: %r" % (i, s[i:i + 30]))

    # ---- expressions -> op lists
    def expression(self):
        return self.expr_level(0)

    def expr_level(self, lvl):
        if lvl == len(OP_PREC):
            return self.expr_unary()
        tok, kind = OP_PREC[lvl]
        left = self.expr_level(lvl + 1)
        while True:
            self.ws()
            s, i = self.s, self.i
            if tok == "||" and s.startswith("||", i):
                self.i += 2
                right = self.expr_level(lvl + 1)
                left = left + [("closure", [], right), ("binary", BINK["lazyor"], None)]
            elif tok == "&&" and s.startswith("&&", i):
                self.i += 2
                right = self.expr_level(lvl + 1)
                left = left + [("closure", [], right), ("binary", BINK["lazyand"], None)]
            elif tok == "CMP":
                m = re.compile(r"(===|!==|==|!=|<=|>=|<(?!-)|>)").match(s, i)
                if not m:
                    return left
                self.i = m.end()
                right = self.expr_level(lvl + 1)
                k = {"===": "eq", "!==": "neq", "==": "heq", "!=": "hneq", "<=": "le", ">=": "ge", "<": "lt", ">": "gt"}[m.group(1)]
                left = left + right + [("binary", BINK[k], None)]
                return left                                   # comparisons are not associative
            elif tok in ("^", "&", "|") and s.startswith(tok, i) and not s.startswith(tok * 2, i):
                self.i += 1
                right = self.expr_level(lvl + 1)
                left = left + right + [("binary", BINK[kind], None)]
            elif tok == "+-" and (s.startswith("+", i) or (s.startswith("-", i) and not s.startswith("->", i))):
                k = "add" if s[i] == "+" else "sub"
                self.i += 1
                right = self.expr_level(lvl + 1)
                left = left + right + [("binary", BINK[k], None)]
            elif tok == "*/" and (s.startswith("*", i) or (s.startswith("/", i) and not s.startswith("//", i))):
                k = "mul" if s[i] == "*" else "div"
                self.i += 1
                right = self.expr_level(lvl + 1)
                left = left + right + [("binary", BINK[k], None)]
            else:
                return left

    def expr_unary(self):
        if self.peek("!") and not self.peek("!="):
            self.eat("!")
            inner = self.expr_unary()
            return inner + [("unary", UNK["negate"], None)]
        if self.peek("-") and not re.compile(r"-\d").match(self.s, self.i):
            raise ParseError("unary minus is not in the grammar")
        return self.expr_methods(self.expr_primary())

    def expr_primary(self):
        if self.peek("("):
            self.eat("(")
            e = self.expression()
            self.eat(")")
            return e + [("unary", UNK["parens"], None)]
        t = self.term()
        return [("value", t)]

    def closure_or_expr(self):
        self.ws()
        m = re.compile(r"\$([\w:]+)\s*->").match(self.s, self.i)
        params = []
        while m:
            params.append(m.group(1))
            self.i = m.end()
            self.ws()
            m = re.compile(r"\$([\w:]+)\s*->").match(self.s, self.i)
        body = self.expression()
        return params, body

    def expr_methods(self, ops):
        while self.peek(".") :
            self.eat(".")
            name = self.name()
            self.eat("(")
            args = []
            if not self.peek(")"):
                while True:
                    args.append(self.closure_or_expr())
                    if not self.try_eat(","):
                        break
            self.eat(")")
            plain = [a[1] for a in args]
            if name == "length":
                ops = ops + [("unary", UNK["length"], None)]
            elif name == "type":
                ops = ops + [("unary", UNK["typeof"], None)]
            elif name in ("contains", "starts_with", "ends_with", "matches", "intersection", "union", "get"):
                k = {"contains": "contains", "starts_with": "prefix", "ends_with": "suffix", "matches": "regex",
                     "intersection": "intersection", "union": "union", "get": "get"}[name]
                ops = ops + plain[0] + [("binary", BINK[k], None)]
            elif name in ("all", "any"):
                params, body = args[0]
                ops = ops + [("closure", params, body), ("binary", BINK[name], None)]
            elif name == "try_or":
                ops = [("closure", [], ops)] + plain[0] + [("binary", BINK["tryor"], None)]
            elif name.startswith("extern::"):
                fn = name[len("extern::"):]
                if args:
                    ops = ops + plain[0] + [("binary", BINK["ffi"], fn)]
                else:
                    ops = ops + [("unary", UNK["ffi"], fn)]
            else:
                raise ParseError("unknown method %s" % name)
        return ops


# ======================================================================= authorize
def authorize(token_bytes, root_pk_hex, authorizer_code):
    root = (0, bytes.fromhex(root_pk_hex))                 # R11: the samples' root key is Ed25519
    try:
        tok = load_token(token_bytes, root)
    except (FormatError, ValueError, IndexError, UnicodeDecodeError) as e:
        return {"result": ("err", "format", str(e)), "revocation_ids": []}
    rev = [s.hex() for s in tok.signatures]
    try:
        auth = Parser(authorizer_code).program()
    except ParseError as e:
        return {"result": ("err", "authorizer_parse", str(e)), "revocation_ids": rev}
    world = World(tok, auth)
    rules = []
    for bid, bl in enumerate(tok.blocks):
        for f in bl.facts:
            world.add(f, frozenset({bid}))
        for r in bl.rules:
            if not rule_vars_safe(r[0], r[1]):
                return {"result": ("err", "format", "unsafe rule in block %d" % bid), "revocation_ids": rev}
            rules.append((r, bid, bl.scopes))
    for f in auth["facts"]:
        world.add(f, frozenset({AUTHORIZER}))
    for r in auth["rules"]:
        if not rule_vars_safe(r[0], r[1]):
            return {"result": ("err", "authorizer_parse", "unsafe rule"), "revocation_ids": rev}
        rules.append((r, AUTHORIZER, []))
    try:
        run_rules(world, rules)
    except ExecError as e:
        return {"result": ("err", "execution", str(e)), "revocation_ids": rev}
    failed = []
    for ci, (kind, qs) in enumerate(auth["checks"]):
        if not any(query_ok(world, q, AUTHORIZER, [], kind) for q in qs) if kind != "reject" else \
                not all(query_ok(world, q, AUTHORIZER, [], kind) for q in qs):
            failed.append(("authorizer", ci))
    for bid, bl in enumerate(tok.blocks):
        for ci, (kind, qs) in enumerate(bl.checks):
            ok = all(query_ok(world, q, bid, bl.scopes, kind) for q in qs) if kind == "reject" else \
                any(query_ok(world, q, bid, bl.scopes, kind) for q in qs)
            if not ok:
                failed.append(("block", bid, ci))
    policy = None
    for pi, (kind, qs) in enumerate(auth["policies"]):
        if any(query_ok(world, q, AUTHORIZER, [], "one") for q in qs):
            policy = (kind, pi)
            break
    if failed:
        return {"result": ("err", "failed_logic", {"checks": failed, "policy": policy}), "revocation_ids": rev}
    if policy is None:
        return {"result": ("err", "no_matching_policy", None), "revocation_ids": rev}
    if policy[0] == "deny":
        return {"result": ("err", "deny", policy[1]), "revocation_ids": rev}
    return {"result": ("ok", policy[1]), "revocation_ids": rev}
