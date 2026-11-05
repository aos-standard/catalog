#!/usr/bin/env python3
"""A decoder of the x402 v2 HTTP payment headers, written from the text only, at x402 PR #4066 head c3e23c9:
specs/transports-v2/http.md (Header Summary: each header carries a base64-encoded object),
specs/transports-v2/vectors/README.md (Scope: base64, then UTF-8, then JSON, result must be an object; base64 read
as RFC 4648 section 4 with section 3.3's rejection of characters outside the alphabet), RFC 4648, RFC 3629, RFC 8259.
Not opened: any SDK source, typescript/packages/core/test/unit/http/headerVectors.test.ts, the cases' notes and
expectations. Readings the text leaves open are named B<n>. Standard library only.
"""
from __future__ import annotations

import json
import re

ALPHABET = re.compile(r"[A-Za-z0-9+/]*")
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class Reject(Exception):
    pass


def b64decode_strict(s: str) -> bytes:
    """RFC 4648 section 4, rejecting any character outside the alphabet (section 3.3)."""
    body = s.rstrip("=")
    pad = len(s) - len(body)
    if not ALPHABET.fullmatch(body):
        raise Reject("non-alphabet character")  # includes space, '%', '-', '_', CR/LF, and '=' before the end
    if pad > 2:
        raise Reject("too much padding")
    # B1: padding. The README leaves a missing '=' open (RFC 4648 3.2 has no decoder rule). This reader requires the
    #     encoded length, padding included, to be a multiple of 4, so a value without its padding is rejected.
    if len(s) % 4 != 0:
        raise Reject("length not a multiple of 4")
    if pad and len(body) % 4 == 0:
        raise Reject("padding after a full quantum")
    # B2: non-zero pad bits (RFC 4648 3.5 lets a decoder reject them). Accepted here: the text does not ask for it.
    bits = 0
    nbits = 0
    out = bytearray()
    for ch in body:
        bits = (bits << 6) | B64.index(ch)
        nbits += 6
        if nbits >= 8:
            nbits -= 8
            out.append((bits >> nbits) & 0xFF)
    return bytes(out)


def _no_constants(c):
    raise Reject("non-standard JSON constant " + c)  # NaN, Infinity, -Infinity are not JSON (RFC 8259 6)


def decode_header(value: str):
    """Returns the decoded JSON object, or raises Reject."""
    # B3: the value is decoded as given. Trimming of optional whitespace around a field value is the HTTP layer's job
    #     (RFC 9110 5.5); a decoder handed a value with a space rejects it under RFC 4648 3.3.
    raw = b64decode_strict(value)
    try:
        text = raw.decode("utf-8")  # strict: invalid UTF-8 rejects (RFC 3629)
    except UnicodeDecodeError:
        raise Reject("not UTF-8")
    # B4: a leading U+FEFF is not stripped (RFC 8259 8.1 says a parser MAY ignore it; the README leaves it open).
    try:
        v = json.loads(text, parse_constant=_no_constants)
    except Reject:
        raise
    except ValueError:
        raise Reject("not JSON")
    if not isinstance(v, dict):
        raise Reject("not a JSON object")  # each header carries an object
    # B5: duplicate member names are accepted, last one wins (README: not covered). No schema check (README: not covered).
    return v
