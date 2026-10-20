"""Step 9 of the work-acceptance record profile 1.4: the time-stamp authority's signature on an RFC 3161 token.

Written 2026-10-21 from README.md of maximusrufus/work-acceptance-record at eb0f30b (profile 1.4, step 9) and
RFC 3161 §2.4.2, RFC 5652 §5 (SignedData, SignerInfo, signed attributes), RFC 5035 / RFC 2634 (ESS signing-certificate
v1/v2) and RFC 5280 (chain, extended key usage). The reference verifier (verifier/war_verify.py) was not opened.

Result, one of: verified | failed | untrusted | unsupported | no_signer  (not_evaluated is decided by the caller when
no anchors are supplied). Order of the checks, and the reading of each outcome:
  no_signer    the token carries no certificate matching the SignerInfo's sid (e.g. requested with certReq=false),
               or no SignerInfo at all
  unsupported  the signature algorithm is not RSA PKCS#1 v1.5 or ECDSA with SHA-256/384/512 (RSASSA-PSS included)
  failed       contentType / messageDigest attributes wrong, the signature over the DER signed attributes does not
               verify, the ESS signing-certificate(-v2) hash does not match the signer certificate (or is absent),
               the signer certificate lacks id-kp-timeStamping, or it is not valid at genTime
  untrusted    everything above holds but no chain of CA issuers (each signature verified, each valid at genTime)
               reaches a supplied anchor; a self-signed root carried inside the token is never an anchor
  verified     all of the above hold
Uses `cryptography` for X.509 parsing and the signature arithmetic; the CMS walk is this file's own.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"

DIGESTS = {
    "2.16.840.1.101.3.4.2.1": hashes.SHA256, "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512, "1.3.14.3.2.26": hashes.SHA1,
}
HASHLIB = {"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384",
           "2.16.840.1.101.3.4.2.3": "sha512", "1.3.14.3.2.26": "sha1"}
SIG_ALGS = {  # signatureAlgorithm OID -> (kind, hash) ; rsaEncryption / ecPublicKey use the digestAlgorithm's hash
    "1.2.840.113549.1.1.11": ("rsa", hashes.SHA256), "1.2.840.113549.1.1.12": ("rsa", hashes.SHA384),
    "1.2.840.113549.1.1.13": ("rsa", hashes.SHA512), "1.2.840.113549.1.1.1": ("rsa", None),
    "1.2.840.10045.4.3.2": ("ec", hashes.SHA256), "1.2.840.10045.4.3.3": ("ec", hashes.SHA384),
    "1.2.840.10045.4.3.4": ("ec", hashes.SHA512), "1.2.840.10045.2.1": ("ec", None),
}
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"


class _Bad(Exception):
    pass


# ------------------------------------------------------------------ DER walk with raw spans


def _hdr(b: bytes, i: int):
    tag = b[i]
    ln = b[i + 1]
    j = i + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise _Bad("unsupported length")
        ln = int.from_bytes(b[j:j + n], "big")
        j += n
    if j + ln > len(b):
        raise _Bad("truncated")
    return tag, j, j + ln  # tag, content start, end


def _items(b: bytes, start: int = 0, end: int | None = None):
    """[(tag, content_bytes, raw_bytes_including_header)] for the elements in b[start:end]."""
    end = len(b) if end is None else end
    out, i = [], start
    while i < end:
        tag, cs, ce = _hdr(b, i)
        out.append((tag, b[cs:ce], b[i:ce]))
        i = ce
    return out


def _oid(content: bytes) -> str:
    first = content[0]
    parts = [first // 40, first % 40]
    n = 0
    for byte in content[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def _gen_time(tst: bytes) -> datetime:
    t = _items(tst)
    seq = _items(t[0][1])
    for tag, val, _ in seq[4:]:
        if tag == 0x18:
            s = val.decode("ascii").rstrip("Z").split(".")[0]
            return datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    raise _Bad("no genTime")


# ------------------------------------------------------------------ certificates


def _sig_ok(issuer_pub, cert: x509.Certificate) -> bool:
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            if cert.signature_algorithm_oid.dotted_string == OID_RSASSA_PSS:
                return False
            issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _valid_at(cert: x509.Certificate, t: datetime) -> bool:
    # v14.1 (2026-10-21): `cryptography` < 42 has only the naive-UTC not_valid_before/after; the first scored run of v14
    # stopped here with AttributeError under the system 3.4.8 before producing any result.
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return nb <= t <= na


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _chain_reaches_anchor(leaf: x509.Certificate, pool: list[x509.Certificate], anchors: list[x509.Certificate],
                          t: datetime, depth: int = 0) -> bool:
    """True iff some anchor directly signs `leaf`, or some CA in `pool` (valid at t) signs it and itself chains."""
    if depth > 8:
        return False
    for a in anchors:
        if a.subject == leaf.issuer and _valid_at(a, t) and _sig_ok(a.public_key(), leaf):
            return True
        if a.fingerprint(hashes.SHA256()) == leaf.fingerprint(hashes.SHA256()) and depth > 0:
            return True  # the intermediate IS an anchor
    for c in pool:
        if c is leaf or c.subject != leaf.issuer or not _is_ca(c) or not _valid_at(c, t):
            continue
        if c.subject == c.issuer:
            continue  # a root inside the token is not an anchor (only anchors can terminate the chain)
        if _sig_ok(c.public_key(), leaf) and _chain_reaches_anchor(c, pool, anchors, t, depth + 1):
            return True
    return False


def _ess_matches(attrs: dict, signer_der: bytes) -> bool:
    if OID_SIGNING_CERT_V2 in attrs:
        sc = _items(attrs[OID_SIGNING_CERT_V2])[0][1]          # SigningCertificateV2 SEQUENCE
        certs = _items(_items(sc)[0][1])                         # SEQUENCE OF ESSCertIDv2
        first = _items(certs[0][1])
        alg = "2.16.840.1.101.3.4.2.1"
        k = 0
        if first[0][0] == 0x30:                                  # hashAlgorithm present
            alg = _oid(_items(first[0][1])[0][1])
            k = 1
        h = first[k][1]
        name = HASHLIB.get(alg)
        return name is not None and hashlib.new(name, signer_der).digest() == h
    if OID_SIGNING_CERT in attrs:
        sc = _items(attrs[OID_SIGNING_CERT])[0][1]
        certs = _items(_items(sc)[0][1])
        first = _items(certs[0][1])
        return hashlib.sha1(signer_der).digest() == first[0][1]
    return False


# ------------------------------------------------------------------ the check


def tsa_signature(tsr_der: bytes, anchors_der: list[bytes]) -> str:
    try:
        return _check(tsr_der, anchors_der)
    except (_Bad, IndexError, ValueError, KeyError):
        return "failed"


def _check(tsr_der: bytes, anchors_der: list[bytes]) -> str:
    resp = _items(_items(tsr_der)[0][1])                     # TimeStampResp: status, timeStampToken
    if len(resp) < 2:
        return "no_signer"
    ci = _items(resp[1][1])                                   # ContentInfo
    if _oid(ci[0][1]) != OID_SIGNED_DATA:
        raise _Bad("not SignedData")
    sd = _items(_items(ci[1][1])[0][1])                       # [0] EXPLICIT SignedData
    eci = _items(sd[2][1])
    if _oid(eci[0][1]) != OID_TSTINFO:
        raise _Bad("eContentType is not TSTInfo")
    tst = _items(eci[1][1])[0][1]                             # [0] EXPLICIT OCTET STRING -> TSTInfo DER
    gen = _gen_time(_items(eci[1][1])[0][1])
    certs: list[x509.Certificate] = []
    signer_infos = None
    for tag, val, raw in sd[3:]:
        if tag == 0xA0:                                       # [0] IMPLICIT CertificateSet
            for t2, _v2, raw2 in _items(val):
                if t2 == 0x30:
                    certs.append(x509.load_der_x509_certificate(raw2))
        elif tag == 0x31:
            signer_infos = _items(val)
    if not signer_infos:
        return "no_signer"
    si = _items(signer_infos[0][1])
    # sid: IssuerAndSerialNumber (SEQUENCE) or [0] SubjectKeyIdentifier
    signer = None
    sid_tag, sid_val, _ = si[1]
    for c in certs:
        if sid_tag == 0x30:
            parts = _items(sid_val)
            serial = int.from_bytes(parts[1][1], "big", signed=True)
            if c.serial_number == serial and c.issuer.public_bytes() == parts[0][2]:
                signer = c
        elif sid_tag == 0x80:
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            except x509.ExtensionNotFound:
                ski = None
            if ski == sid_val:
                signer = c
    if signer is None:
        return "no_signer"
    digest_oid = _oid(_items(si[2][1])[0][1])
    k = 3
    signed_attrs_raw = None
    attrs: dict[str, bytes] = {}
    if si[k][0] == 0xA0:
        _tag, content, raw = si[k]
        signed_attrs_raw = b"\x31" + raw[1:]                  # DER of the SET OF, as signed (RFC 5652 §5.4)
        for _t, aval, _r in _items(content):
            a = _items(aval)
            attrs[_oid(a[0][1])] = a[1][1]                    # value: SET content
        k += 1
    sig_alg = _oid(_items(si[k][1])[0][1])
    signature = si[k + 1][1]
    if sig_alg == OID_RSASSA_PSS or sig_alg not in SIG_ALGS:
        return "unsupported"
    if digest_oid not in DIGESTS:
        return "unsupported"
    if signed_attrs_raw is None:
        return "failed"                                       # RFC 3161 tokens carry signed attributes
    # contentType and messageDigest
    if _oid(_items(attrs.get(OID_CONTENT_TYPE, b""))[0][1]) != OID_TSTINFO:
        return "failed"
    md = _items(attrs[OID_MESSAGE_DIGEST])[0][1]
    if hashlib.new(HASHLIB[digest_oid], tst).digest() != md:
        return "failed"
    kind, h = SIG_ALGS[sig_alg]
    h = h or DIGESTS[digest_oid]
    pub = signer.public_key()
    try:
        if kind == "rsa" and isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, signed_attrs_raw, padding.PKCS1v15(), h())
        elif kind == "ec" and isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, signed_attrs_raw, ec.ECDSA(h()))
        else:
            return "failed"
    except InvalidSignature:
        return "failed"
    signer_der = next(raw for t2, _v, raw in _items(next(v for t, v, _ in sd[3:] if t == 0xA0)) if
                      x509.load_der_x509_certificate(raw) == signer)
    if not _ess_matches(attrs, signer_der):
        return "failed"
    try:
        eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if x509.ObjectIdentifier(OID_KP_TIMESTAMPING) not in eku:
            return "failed"
    except x509.ExtensionNotFound:
        return "failed"
    if not _valid_at(signer, gen):
        return "failed"
    anchors = [x509.load_der_x509_certificate(a) for a in anchors_der]
    if not _chain_reaches_anchor(signer, certs, anchors, gen):
        return "untrusted"
    return "verified"
