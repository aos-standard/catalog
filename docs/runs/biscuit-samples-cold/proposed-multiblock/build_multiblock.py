#!/usr/bin/env python3
"""Proposed multi-block Biscuit samples for the gaps the first proposals left out: `previous` scope, block-level
`trusting`, `previous` in the authorizer, fact origins through a third-party block, external signatures, duplicate
symbols and the third-party version floor. Tokens are built from scratch with the samples' root key and deterministic
ephemeral keys (Ed25519 is deterministic), so the output is byte-reproducible. Signature payload v1 throughout.
usage: build_multiblock.py samples.json out_dir"""
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT = ["read", "write", "resource", "operation", "right", "time", "role", "owner", "tenant", "namespace", "user",
           "team", "service", "admin", "email", "group", "member", "ip_address", "client", "client_ip", "domain", "path",
           "version", "cluster", "node", "hostname", "nonce", "query"]


def varint(n):
    o = b""
    while True:
        c = n & 0x7F
        n >>= 7
        o += bytes([c | (0x80 if n else 0)])
        if not n:
            return o


def fld(fn, v):
    if isinstance(v, int):
        return varint(fn << 3 | 0) + varint(v)
    return varint(fn << 3 | 2) + varint(len(v)) + v


def key(seed):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"aos-biscuit-proposal/" + seed.encode()).digest())


def pub(sk):
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pk_msg(raw):
    return fld(1, 0) + fld(2, raw)            # PublicKey{algorithm: Ed25519, key}


class Table:
    def __init__(self, base=None):
        self.syms = list(base or [])
        self.new = []
        self.keys = []
        self.new_keys = []

    def sym(self, s):
        if s in DEFAULT:
            return DEFAULT.index(s)
        if s not in self.syms:
            self.syms.append(s)
            self.new.append(s)
        return 1024 + self.syms.index(s)

    def keyidx(self, raw):
        if raw not in self.keys:
            self.keys.append(raw)
            self.new_keys.append(raw)
        return self.keys.index(raw)


# terms: ("str", s) | ("var", name)
def term(t, tab):
    if t[0] == "var":
        return fld(1, tab.sym(t[1]))
    return fld(3, tab.sym(t[1]))


def pred(name, terms, tab):
    return fld(1, tab.sym(name)) + b"".join(fld(2, term(t, tab)) for t in terms)


def scope(s, tab):
    if s == "authority":
        return fld(1, 0)
    if s == "previous":
        return fld(1, 1)
    return fld(2, tab.keyidx(s))              # a raw public key


def rule(head, body, scopes, tab):
    out = fld(1, pred(head[0], head[1], tab))
    for b in body:
        out += fld(2, pred(b[0], b[1], tab))
    for s in scopes:
        out += fld(4, scope(s, tab))
    return out


def block(spec, tab, version=6, extra_symbols=()):
    """spec: {"facts": [(name, terms)], "rules": [(head, body, scopes)], "checks": [(body, scopes)], "scopes": [..]}"""
    body = b""
    for f in spec.get("facts", []):
        body += fld(4, fld(1, pred(f[0], f[1], tab)))
    for r in spec.get("rules", []):
        body += fld(5, rule(r[0], r[1], r[2], tab))
    for c in spec.get("checks", []):
        body += fld(6, fld(1, rule(("query", []), c[0], c[1], tab)))
    for s in spec.get("scopes", []):
        body += fld(7, scope(s, tab))
    syms = list(tab.new) + list(extra_symbols)
    out = b"".join(fld(1, s.encode()) for s in syms) + fld(3, version) + body
    out += b"".join(fld(8, pk_msg(k)) for k in tab.new_keys)
    tab.new, tab.new_keys = [], []
    return out


def le32(n):
    return n.to_bytes(4, "little")


def payload_v1(data, next_raw, prev_sig, ext_sig):
    p = b"\0BLOCK\0" + b"\0VERSION\0" + le32(1) + b"\0PAYLOAD\0" + data + b"\0ALGORITHM\0" + le32(0) + \
        b"\0NEXTKEY\0" + next_raw
    if prev_sig is not None:
        p += b"\0PREVSIG\0" + prev_sig
    if ext_sig is not None:
        p += b"\0EXTERNALSIG\0" + ext_sig
    return p


def external_v1(data, prev_sig):
    return b"\0EXTERNAL\0" + b"\0VERSION\0" + le32(1) + b"\0PAYLOAD\0" + data + b"\0PREVSIG\0" + prev_sig


def token(root_sk, datas, name, externals=None, corrupt_external=None):
    """datas: block payload bytes; externals: {index: third-party signing key}."""
    externals = externals or {}
    signed = []
    sk, prev_sig = root_sk, None
    for i, data in enumerate(datas):
        nxt = key("%s/next/%d" % (name, i))
        ext = None
        if i in externals:
            esig = externals[i].sign(external_v1(data, prev_sig))
            if corrupt_external == i:
                esig = esig[:-1] + bytes([esig[-1] ^ 1])
            ext = (esig, pub(externals[i]))
        sig = sk.sign(payload_v1(data, pub(nxt), prev_sig if i else None, ext[0] if ext else None))
        sb = fld(1, data) + fld(2, pk_msg(pub(nxt))) + fld(3, sig)
        if ext:
            sb += fld(4, fld(1, ext[0]) + fld(2, pk_msg(ext[1])))
        sb += fld(5, 1)
        signed.append(sb)
        sk, prev_sig = nxt, sig
    out = fld(2, signed[0]) + b"".join(fld(3, s) for s in signed[1:])
    secret = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return out + fld(4, fld(1, secret))


def S(x):
    return ("str", x)


def V(x):
    return ("var", x)


def main():
    sj, out = sys.argv[1:3]
    os.makedirs(out, exist_ok=True)
    samples = json.load(open(sj))
    root = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(samples["root_private_key"]))
    tp = key("third-party")
    tp_raw = pub(tp)
    cases = []

    def add(cid, datas, authz, expect, mutant, note, **kw):
        raw = token(root, datas, cid, **kw)
        open(os.path.join(out, cid + ".bc"), "wb").write(raw)
        cases.append({"id": cid, "token_file": cid + ".bc", "authorizer_code": authz, "expect": expect,
                      "mutant": mutant, "note": note})

    # 1. `previous` covers every earlier block, the authority included
    t = Table()
    d0 = block({"facts": [("right", [S("file1"), S("read")])]}, t)
    d1 = block({"facts": [("user", [S("alice")])]}, t)
    d2 = block({"checks": [([("right", [S("file1"), S("read")]), ("user", [S("alice")])], ["previous"])]}, t)
    add("proposed_previous_covers_all_earlier_blocks", [d0, d1, d2], "allow if true;", ["ok", 0],
        "`previous` trusts only the previous block",
        "Block 2 checks a fact of block 0 and one of block 1 under `trusting previous`. Both are earlier blocks, so the check passes.")
    # 2. block-level `trusting previous`
    t = Table()
    d0 = block({"facts": [("right", [S("file1"), S("read")])]}, t)
    d1 = block({"facts": [("user", [S("alice")])]}, t)
    d2 = block({"checks": [([("user", [S("alice")])], [])], "scopes": ["previous"]}, t)
    add("proposed_block_level_trusting_previous", [d0, d1, d2], "allow if true;", ["ok", 0],
        "block-level scope ignored",
        "Block 2 declares `trusting previous` at block level and its check has no scope of its own; the check needs block 1's fact.")
    # 3. `previous` in the authorizer is ignored
    t = Table()
    d0 = block({"facts": [("right", [S("file1"), S("read")])]}, t)
    d1 = block({"facts": [("user", [S("alice")])]}, t)
    add("proposed_previous_ignored_in_authorizer", [d0, d1], 'check if user("alice") trusting previous;\nallow if true;',
        ["err", "failed_logic", [["authorizer", 0]]], "`previous` honoured in the authorizer",
        "The authorizer asks for block 1's fact `trusting previous`. `previous` is ignored in the authorizer, so block 1 is not trusted and the check fails.")
    # 4. a fact derived through a third-party block keeps that block in its origin
    t = Table()
    d0 = block({"rules": [(("admin", [V("u")]), [("member", [V("u")])], [tp_raw])]}, t)
    tt = Table()                                   # third-party blocks use their own tables
    d1 = block({"facts": [("member", [S("alice")])]}, tt, version=6)
    add("proposed_origin_includes_matched_facts", [d0, d1], 'check if admin("alice");\nallow if true;',
        ["err", "failed_logic", [["authorizer", 0]]], "generated fact origin omits the matched facts",
        "The authority rule trusts the third-party key and derives admin(\"alice\") from block 1. The fact's origin is {0, 1}; the authorizer trusts {0, authorizer}, so its check fails.",
        externals={1: tp})
    # 5. an external signature that does not verify
    t = Table()
    d0 = block({"facts": [("right", [S("file1"), S("read")])]}, t)
    tt = Table()
    d1 = block({"facts": [("member", [S("alice")])]}, tt, version=6)
    add("proposed_bad_external_signature", [d0, d1], "allow if true;", ["err", "format"],
        "external signatures not verified",
        "Block 1's external signature has its last bit flipped; the regular signature is made over the flipped bytes, so only the external check can fail.",
        externals={1: tp}, corrupt_external=1)
    # 6. a symbol defined in two blocks
    t = Table()
    d0 = block({"facts": [("right", [S("file1"), S("read")])]}, t)
    d1 = block({"facts": [("user", [S("alice")])]}, t, extra_symbols=["file1"])
    add("proposed_duplicate_symbol", [d0, d1], "allow if true;", ["err", "format"],
        "duplicate symbols across blocks accepted",
        "Block 1's `symbols` repeats `file1`, already defined by block 0 (it is appended after the block's own symbols, so no index moves).")
    # 7. a third-party block below v3.2
    t = Table()
    d0 = block({"facts": [("right", [S("file1"), S("read")])]}, t)
    tt = Table()
    d1 = block({"facts": [("member", [S("alice")])]}, tt, version=4)
    add("proposed_third_party_below_v3_2", [d0, d1], "allow if true;", ["err", "format"],
        "third-party block version not checked",
        "Block 1 carries an external signature and declares datalog version 4 (v3.1); third-party blocks must be at least v3.2.",
        externals={1: tp})
    json.dump({"root_public_key": samples["root_public_key"], "third_party_public_key": tp_raw.hex(),
               "based_on": "eclipse-biscuit/biscuit samples/current at b3d3fe2 (root key); tokens built from scratch",
               "cases": cases}, open(os.path.join(out, "proposed_multiblock.json"), "w"), indent=1)
    print(len(cases), "proposed")


if __name__ == "__main__":
    main()
