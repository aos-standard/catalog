#!/usr/bin/env python3
"""Build the grammar-valid variants of vectors 50 and 51: the imprint pattern sits in an unsigned CMS attribute.

Vectors 50 and 51 put `AlgorithmIdentifier(sha-256) || OCTET STRING(imprint) || GeneralizedTime(time)` in the
response's `PKIStatusInfo.statusString`. Those bytes are not UTF-8, so the statusString is outside `PKIFreeText`
(RFC 3161 2.4.2, RFC 4210 5.1.1), and a verifier that checks that grammar refuses the response before it reaches the
question the vectors ask: is the imprint read from the signed TSTInfo, or from other bytes of the response?

These variants put the same three values, as one `SEQUENCE`, in an unsigned attribute of the token's SignerInfo
(`unsignedAttrs`, RFC 5652 5.3: `SET OF Attribute`, each `AttributeValue ::= ANY`). The attribute type is a UUID OID
(`2.25.<uuid>`, X.667), so no registered meaning is claimed. Nothing signed is changed: the signature covers the
signed attributes, and the TSTInfo inside the encapsulated content is untouched. The response is well-formed DER
throughout, so the only thing a verifier can disagree on is where it reads the imprint from.

Usage: python3 build_vectors_unsigned_attr_imprint.py <vectors dir> <out dir>
Writes 56-criteria-token-imprint-only-in-unsigned-attribute.json and 57-record-token-imprint-only-in-unsigned-attribute.json.
"""
from __future__ import annotations

import base64
import copy
import json
import sys
import uuid
from pathlib import Path

# Fixed so the build is reproducible; any UUID would do.
ATTR_UUID = uuid.UUID("6b1d7c3e-5a0f-4f2e-9c1a-3d8e2b7f4a91")
SHA256_OID = bytes.fromhex("608648016503040201")


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def read(b: bytes, i: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the TLV at offset i (single-byte tags only)."""
    tag = b[i]
    ln = b[i + 1]
    j = i + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[j:j + n], "big")
        j += n
    return tag, j, j + ln


def children(b: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """List (tag, tlv_start, content_start, content_end) of the TLVs between start and end."""
    out, i = [], start
    while i < end:
        tag, cs, ce = read(b, i)
        out.append((tag, i, cs, ce))
        i = ce
    if i != end:
        raise ValueError("children overrun")
    return out


def oid_uuid(u: uuid.UUID) -> bytes:
    n, arcs = u.int, []
    arcs.append(n & 0x7F)
    n >>= 7
    while n:
        arcs.append(0x80 | (n & 0x7F))
        n >>= 7
    return tlv(0x06, bytes([2 * 40 + 25]) + bytes(reversed(arcs)))


def tst_info(tsr: bytes) -> tuple[bytes, bytes]:
    """Return (imprint, genTime bytes) of the TSTInfo inside a TimeStampResp."""
    _, cs, ce = read(tsr, 0)
    status, token = children(tsr, cs, ce)
    ci = children(tsr, token[2], token[3])               # contentType, [0]
    sd_tag, sd_cs, sd_ce = read(tsr, ci[1][2])           # SignedData
    sd = children(tsr, sd_cs, sd_ce)
    encap = children(tsr, sd[2][2], sd[2][3])            # eContentType, [0]
    _, oct_cs, oct_ce = read(tsr, encap[1][2])           # OCTET STRING
    _, t_cs, t_ce = read(tsr, oct_cs)                    # TSTInfo
    t = children(tsr, t_cs, t_ce)
    mi = children(tsr, t[2][2], t[2][3])                 # messageImprint
    imprint = tsr[mi[1][2]:mi[1][3]]
    gentime = tsr[t[4][2]:t[4][3]]
    return imprint, gentime


def add_unsigned_attr(tsr: bytes, value: bytes) -> bytes:
    """Return the TimeStampResp with one unsigned attribute appended to its only SignerInfo."""
    _, cs, ce = read(tsr, 0)
    status, token = children(tsr, cs, ce)
    ci = children(tsr, token[2], token[3])
    sd_tlv = ci[1]
    _, sd_cs, sd_ce = read(tsr, sd_tlv[2])
    sd = children(tsr, sd_cs, sd_ce)
    si_set = sd[-1]
    if si_set[0] != 0x31:
        raise ValueError("signerInfos not last")
    sis = children(tsr, si_set[2], si_set[3])
    if len(sis) != 1:
        raise ValueError("expected one SignerInfo")
    si = sis[0]
    fields = children(tsr, si[2], si[3])
    if fields[-1][0] == 0xA1:
        raise ValueError("SignerInfo already has unsignedAttrs")
    attr = tlv(0x30, oid_uuid(ATTR_UUID) + tlv(0x31, value))
    new_si = tlv(0x30, tsr[si[2]:si[3]] + tlv(0xA1, attr))
    new_si_set = tlv(0x31, new_si)
    new_sd = tlv(0x30, tsr[sd_cs:si_set[1]] + new_si_set)
    new_ci = tlv(0x30, tsr[ci[0][1]:ci[0][3]] + tlv(0xA0, new_sd))
    return tlv(0x30, tsr[status[1]:status[3]] + new_ci)


def pattern(imprint: bytes, gentime: bytes) -> bytes:
    alg = tlv(0x30, tlv(0x06, SHA256_OID) + b"\x05\x00")
    return tlv(0x30, alg + tlv(0x04, imprint) + tlv(0x18, gentime))


def main() -> int:
    vdir, out = Path(sys.argv[1]), Path(sys.argv[2])
    v31 = json.loads((vdir / "31-tsa-freetsa-verified.json").read_text())
    v50 = json.loads((vdir / "50-criteria-token-imprint-only-in-status-string.json").read_text())
    v51 = json.loads((vdir / "51-record-token-imprint-only-in-status-string.json").read_text())
    crit_tsr = base64.b64decode(v31["inputs"]["criteria_tsr_base64"])
    rec_tsr = base64.b64decode(v31["inputs"]["receipt_tsr_base64"])
    crit_imprint, crit_gentime = tst_info(crit_tsr)
    rec_imprint, rec_gentime = tst_info(rec_tsr)

    # 56: criteria token := the record token (covers the receipt), carrying the criteria's imprint and genTime unsigned.
    f56 = add_unsigned_attr(rec_tsr, pattern(crit_imprint, crit_gentime))
    # 57: record token := the criteria token (covers the criteria), carrying the receipt's imprint and genTime unsigned.
    f57 = add_unsigned_attr(crit_tsr, pattern(rec_imprint, rec_gentime))

    for num, src, forged, key, slug, side in (
        (56, v50, f56, "criteria_tsr_base64", "criteria-token-imprint-only-in-unsigned-attribute", "criteria"),
        (57, v51, f57, "receipt_tsr_base64", "record-token-imprint-only-in-unsigned-attribute", "record"),
    ):
        p = copy.deepcopy(v31)
        p["vector"] = f"{num}-{slug}"
        p["title"] = (
            f"The {side} token's signed TSTInfo covers other bytes; the {side} imprint and time sit only in an "
            "unsigned CMS attribute (grammar-valid variant of vector " + str(num - 6) + ")"
        )
        p["description"] = (__doc__.split("\n\n")[2]).replace("\n", " ")
        p["contributed_by"] = "aos-standard/catalog (CC0), well-formed variant of the probe behind vectors 50 and 51"
        p["inputs"][key] = base64.b64encode(forged).decode()
        p["expected"] = copy.deepcopy(src["expected"])
        p.pop("source", None)
        (out / f"{num}-{slug}.json").write_text(json.dumps(p, indent=1, sort_keys=True) + "\n")
        print(num, len(forged), "bytes; imprint pattern at", forged.find(crit_imprint if num == 56 else rec_imprint))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
