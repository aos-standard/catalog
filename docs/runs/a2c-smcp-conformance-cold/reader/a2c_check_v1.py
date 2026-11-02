#!/usr/bin/env python3
"""A reader of three A2C-SMCP conformance vector sets, written from the protocol's normative text at 1a81dee:
data-structures.md (BundleID model, connection-identity), guides/computer-mcp-config-guide.md (env var naming),
blob-transfer.md (canonical_path), conformance-tests.md 2.7/2.8, and the `algorithm` block of each fixture, which the
spec says must agree with the body (where they part, the body wins). No python-sdk or rust-sdk code was opened.
Readings the text leaves open are named A<n>.
"""
from __future__ import annotations

import hashlib
import re
import struct

ASCII_BID = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
ASCII_ENV = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


# ------------------------------------------------------------------ bundle_id
def normalize_name(name: str) -> str:
    s = "".join(c if c in ASCII_BID else "_" for c in name)  # per code point; explicit ASCII class
    s = re.sub(r"_{2,}", "_", s)  # fold runs of '_' (incl. original '__'); '-' not folded
    return s.strip("_-")  # trim leading/trailing [_-]; no case folding


def _str(b: list, s: str):
    raw = s.encode("utf-8")
    b.append(struct.pack(">I", len(raw)) + raw)


def connection_identity(cfg: dict) -> bytes:
    # A1: list = u32-BE count, then each element framed as a string field (u32-BE byte length + UTF-8);
    #     map = u32-BE entry count, then key and value each framed as a string field, keys ascending by code point.
    # A2: a missing args/env/headers is the empty collection (body: "空 args / env → 空集").
    b: list[bytes] = []
    t = cfg["type"]
    _str(b, t)
    if t == "stdio":
        _str(b, cfg["command"])
        args = cfg.get("args") or []
        b.append(struct.pack(">I", len(args)))
        for a in args:
            _str(b, a)
        m = cfg.get("env") or {}
    else:
        _str(b, cfg["url"])
        m = cfg.get("headers") or {}
    keys = sorted(m)  # Python str order = code point order = UTF-8 byte order
    b.append(struct.pack(">I", len(keys)))
    for k in keys:
        _str(b, k)
        _str(b, m[k])
    return b"".join(b)


def resolve_bundle_id(name: str, cfg: dict) -> str:
    if cfg.get("bundle_id"):
        return cfg["bundle_id"]  # explicit value adopted as is
    n = normalize_name(name or "")
    if n:
        return n
    return "bundle_" + hashlib.sha256(connection_identity(cfg)).digest()[:8].hex()


# ------------------------------------------------------------------ env var name
def env_segment(s: str) -> str:
    return "".join(c if c in ASCII_ENV else "_" for c in s)  # per code point; case kept; no folding, no trim


def env_var_name(input_id: str, bundle_id: str | None, tool_name: str | None) -> str:
    out = "A2C_SMCP_" + env_segment(input_id)
    if bundle_id is not None:  # A3: an absent segment is None; the text does not say how an empty string is treated
        out += "_" + env_segment(bundle_id)
    if tool_name is not None:
        out += "_" + env_segment(tool_name)
    return out


# ------------------------------------------------------------------ canonical_path
class InvalidPath(Exception):
    pass


WIN_BAD = set('<>:"|?*') | {chr(c) for c in range(1, 0x20)}


def _segments(rest: str, windows: bool) -> list[str]:
    out: list[str] = []
    for seg in rest.split("/"):
        if seg in ("", "."):
            continue
        if windows and seg != "..":
            # checked while splitting, before '..' pops (fixture algorithm 7)
            if any(ch in WIN_BAD for ch in seg) or seg.endswith(".") or seg.endswith(" "):
                raise InvalidPath
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return out


def normalize_path(inp: str, platform: str) -> str:
    if inp == "" or "\x00" in inp:
        raise InvalidPath
    if platform == "posix":
        if not inp.startswith("/"):
            raise InvalidPath
        segs = _segments(inp, windows=False)
        return "/" + "/".join(segs)
    # windows
    if inp.startswith("\\\\.\\"):
        raise InvalidPath  # device namespace, judged before the \\?\ strip
    s = inp
    if s.startswith("\\\\?\\"):
        s = s[4:]
        if s[:4].upper() == "UNC\\":
            raise InvalidPath
    s = s.replace("\\", "/")
    if re.match(r"^/[A-Za-z]:(/|$)", s):
        s = s[1:]
        if len(s) == 2:
            s += "/"
    if not re.match(r"^[A-Za-z]:/", s):
        raise InvalidPath
    drive = s[0].upper()
    segs = _segments(s[3:], windows=True)
    return "/" + drive + ":/" + "/".join(segs)
