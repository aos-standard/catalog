"""Step 9 of the work-acceptance record, profile 1.4.1 — the time-stamp authority's signature on an RFC 3161 token.

Written 2026-10-22 from README.md of maximusrufus/work-acceptance-record at d79a737 (profile 1.4.1, step 9 and the 1.4.1
changelog) and RFC 3161, RFC 5652 §5, RFC 5035 / RFC 2634, RFC 4055 (RSASSA-PSS parameters) and RFC 5280 §6.1.1. The
reference verifiers (verifier/war_verify.py, verifier/check_payment.py) were not opened. Replaces tsa_check.py (1.4),
which stays published as recorded.

1.4.1 rules as read here:
  - checks that can run without a signer: contentType attribute == id-ct-TSTInfo (== eContentType), messageDigest
  - checks that need the signer certificate: signature over the DER signed attributes, ESS signing-certificate(-v2),
    id-kp-timeStamping, signer valid at genTime
  - key/algorithm: RSA PKCS#1 v1.5 and ECDSA P-256 / P-384 required, RSASSA-PSS implemented here; any other key or curve
    is `unsupported` (the signature check then cannot run)
  - chain: a path of issuers, each signature verified, from the signer to a supplied anchor matched by subject name and
    public key (not certificate bytes). On a path that reaches the anchor, every issuer other than the anchor must carry
    the CA flag and be valid at genTime, else `failed`. No path reaching an anchor: `untrusted`.
  - several defects: `failed` if any check that can run fails; otherwise `no_signer`, then `unsupported`, then `untrusted`.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"

HASH = {"2.16.840.1.101.3.4.2.1": hashes.SHA256, "2.16.840.1.101.3.4.2.2": hashes.SHA384,
        "2.16.840.1.101.3.4.2.3": hashes.SHA512, "1.3.14.3.2.26": hashes.SHA1}
HASHLIB = {"2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384",
           "2.16.840.1.101.3.4.2.3": "sha512", "1.3.14.3.2.26": "sha1"}
SIG = {  # signatureAlgorithm -> (family, hash or None = the digestAlgorithm's)
    "1.2.840.113549.1.1.11": ("rsa", hashes.SHA256), "1.2.840.113549.1.1.12": ("rsa", hashes.SHA384),
    "1.2.840.113549.1.1.13": ("rsa", hashes.SHA512), "1.2.840.113549.1.1.1": ("rsa", None),
    "1.2.840.10045.4.3.2": ("ec", hashes.SHA256), "1.2.840.10045.4.3.3": ("ec", hashes.SHA384),
    "1.2.840.10045.4.3.4": ("ec", hashes.SHA512), "1.2.840.10045.2.1": ("ec", None),
    OID_RSASSA_PSS: ("pss", None),
}
CURVES = ("secp256r1", "secp384r1")


class _Bad(Exception):
    pass


def _hdr(b: bytes, i: int):
    tag = b[i]
    ln = b[i + 1]
    j = i + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise _Bad("length")
        ln = int.from_bytes(b[j:j + n], "big")
        j += n
    if j + ln > len(b):
        raise _Bad("truncated")
    return tag, j, j + ln


def _items(b: bytes):
    out, i = [], 0
    while i < len(b):
        tag, cs, ce = _hdr(b, i)
        out.append((tag, b[cs:ce], b[i:ce]))
        i = ce
    return out


def _oid(c: bytes) -> str:
    parts = [c[0] // 40, c[0] % 40]
    n = 0
    for byte in c[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def _gen_time(tst: bytes) -> datetime:
    for tag, val, _ in _items(_items(tst)[0][1])[4:]:
        if tag == 0x18:
            s = val.decode("ascii").rstrip("Z").split(".")[0]
            return datetime.strptime(s, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    raise _Bad("no genTime")


def _valid_at(c: x509.Certificate, t: datetime) -> bool:
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=timezone.utc)
    return nb <= t <= na


def _is_ca(c: x509.Certificate) -> bool:
    try:
        return bool(c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        return False


def _spki(c: x509.Certificate) -> bytes:
    return c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _key_supported(pub) -> bool:
    if isinstance(pub, rsa.RSAPublicKey):
        return True
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.curve.name in CURVES
    return False


def _pss_params(params: bytes):
    """RSASSA-PSS-params (RFC 4055): hash [0], mgf [1], saltLength [2]; defaults SHA-1 / MGF1-SHA-1 / 20."""
    h, mgf_h, salt = hashes.SHA1, hashes.SHA1, 20
    # v141.1 (2026-10-22): `params` is the whole RSASSA-PSS-params SEQUENCE; the first scored run iterated it without
    # unwrapping, read no field, fell back to the SHA-1 defaults and reported vector 40 `failed`.
    for tag, val, _ in _items(_items(params)[0][1]) if params else []:
        if tag == 0xA0:
            h = HASH[_oid(_items(_items(val)[0][1])[0][1])]
        elif tag == 0xA1:
            m = _items(_items(val)[0][1])
            if _oid(m[0][1]) != OID_MGF1:
                raise _Bad("mgf")
            mgf_h = HASH[_oid(_items(m[1][1])[0][1])]
        elif tag == 0xA2:
            salt = int.from_bytes(_items(val)[0][1], "big")
    return h, mgf_h, salt


def _verify(pub, family, h, params, sig: bytes, data: bytes) -> bool:
    try:
        if family == "rsa" and isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PKCS1v15(), h())
        elif family == "pss" and isinstance(pub, rsa.RSAPublicKey):
            ph, mh, salt = _pss_params(params)
            pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(mh()), salt_length=salt), ph())
        elif family == "ec" and isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, data, ec.ECDSA(h()))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError, KeyError, _Bad):
        return False


def _cert_sig_ok(issuer: x509.Certificate, c: x509.Certificate) -> bool:
    pub = issuer.public_key()
    try:
        if c.signature_algorithm_oid.dotted_string == OID_RSASSA_PSS:
            p = c.signature_algorithm_parameters
            pub.verify(c.signature, c.tbs_certificate_bytes, p, c.signature_hash_algorithm)  # type: ignore[arg-type]
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(c.signature, c.tbs_certificate_bytes, padding.PKCS1v15(), c.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(c.signature, c.tbs_certificate_bytes, ec.ECDSA(c.signature_hash_algorithm))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError, AttributeError):
        return False


def _paths_to_anchor(cert, pool, anchors, depth=0):
    """Yield lists of issuers [i1, i2, ..., anchor] whose signatures verify, ending at an anchor (subject + key)."""
    if depth > 8:
        return
    for a in anchors:
        if a.subject == cert.issuer and _cert_sig_ok(a, cert):
            yield [a]
    for c in pool:
        if c.subject != cert.issuer or _spki(c) == _spki(cert):
            continue
        if any(c.subject == a.subject and _spki(c) == _spki(a) for a in anchors):
            continue  # a copy of an anchor (e.g. cross-signed) is the anchor; handled above by subject + key
        if not _cert_sig_ok(c, cert):
            continue
        for rest in _paths_to_anchor(c, pool, anchors, depth + 1):
            yield [c] + rest


def tsa_signature(tsr_der: bytes, anchors_der: list[bytes]) -> str:
    try:
        return _check(tsr_der, anchors_der)
    except (_Bad, IndexError, ValueError, KeyError):
        return "failed"


def _check(tsr_der: bytes, anchors_der: list[bytes]) -> str:
    failed = no_signer = unsupported = untrusted = False
    resp = _items(_items(tsr_der)[0][1])
    if len(resp) < 2:
        return "no_signer"
    ci = _items(resp[1][1])
    if _oid(ci[0][1]) != OID_SIGNED_DATA:
        raise _Bad("not SignedData")
    sd = _items(_items(ci[1][1])[0][1])
    eci = _items(sd[2][1])
    econtent_type = _oid(eci[0][1])
    tst = _items(eci[1][1])[0][1]
    gen = _gen_time(tst)
    certs, cert_raw, signer_infos = [], {}, None
    for tag, val, _raw in sd[3:]:
        if tag == 0xA0:
            for t2, _v, raw2 in _items(val):
                if t2 == 0x30:
                    c = x509.load_der_x509_certificate(raw2)
                    certs.append(c)
                    cert_raw[id(c)] = raw2
        elif tag == 0x31:
            signer_infos = _items(val)
    if not signer_infos:
        return "no_signer"
    si = _items(signer_infos[0][1])
    sid_tag, sid_val, _ = si[1]
    signer = None
    for c in certs:
        if sid_tag == 0x30:
            p = _items(sid_val)
            if c.serial_number == int.from_bytes(p[1][1], "big", signed=True) and c.issuer.public_bytes() == p[0][2]:
                signer = c
        elif sid_tag == 0x80:
            try:
                if c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest == sid_val:
                    signer = c
            except x509.ExtensionNotFound:
                pass
    digest_oid = _oid(_items(si[2][1])[0][1])
    k, attrs, signed_raw = 3, {}, None
    if si[k][0] == 0xA0:
        signed_raw = b"\x31" + si[k][2][1:]
        for _t, aval, _r in _items(si[k][1]):
            a = _items(aval)
            attrs[_oid(a[0][1])] = a[1][1]
        k += 1
    alg_items = _items(si[k][1])
    sig_alg = _oid(alg_items[0][1])
    sig_params = alg_items[1][2] if len(alg_items) > 1 else b""
    signature = si[k + 1][1]

    # checks that run without a signer
    if signed_raw is None:
        failed = True
    else:
        ct = attrs.get(OID_CONTENT_TYPE)
        if ct is None or _oid(_items(ct)[0][1]) != OID_TSTINFO or econtent_type != OID_TSTINFO:
            failed = True
        md = attrs.get(OID_MESSAGE_DIGEST)
        if digest_oid not in HASHLIB or md is None or hashlib.new(HASHLIB[digest_oid], tst).digest() != _items(md)[0][1]:
            failed = True

    if signer is None:
        no_signer = True
    else:
        pub = signer.public_key()
        fam = SIG.get(sig_alg)
        if fam is None or not _key_supported(pub) or digest_oid not in HASH:
            unsupported = True
        else:
            family, h = fam
            h = h or HASH[digest_oid]
            if signed_raw is not None and not _verify(pub, family, h, sig_params, signature, signed_raw):
                failed = True
        if not _ess_matches(attrs, cert_raw[id(signer)]):
            failed = True
        try:
            eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if x509.ObjectIdentifier(OID_KP_TIMESTAMPING) not in eku:
                failed = True
        except x509.ExtensionNotFound:
            failed = True
        if not _valid_at(signer, gen):
            failed = True
        anchors = [x509.load_der_x509_certificate(a) for a in anchors_der]
        paths = list(_paths_to_anchor(signer, certs, anchors))
        if not paths:
            untrusted = True
        else:
            def defects(p):
                return any(not _is_ca(c) or not _valid_at(c, gen) for c in p[:-1]) or not _is_ca(p[-1])
            if all(defects(p) for p in paths):
                failed = True

    if failed:
        return "failed"
    if no_signer:
        return "no_signer"
    if unsupported:
        return "unsupported"
    if untrusted:
        return "untrusted"
    return "verified"


def _ess_matches(attrs: dict, signer_der: bytes) -> bool:
    try:
        if OID_SIGNING_CERT_V2 in attrs:
            sc = _items(attrs[OID_SIGNING_CERT_V2])[0][1]
            first = _items(_items(_items(sc)[0][1])[0][1])
            alg, k = "2.16.840.1.101.3.4.2.1", 0
            if first[0][0] == 0x30:
                alg, k = _oid(_items(first[0][1])[0][1]), 1
            return alg in HASHLIB and hashlib.new(HASHLIB[alg], signer_der).digest() == first[k][1]
        if OID_SIGNING_CERT in attrs:
            sc = _items(attrs[OID_SIGNING_CERT])[0][1]
            first = _items(_items(_items(sc)[0][1])[0][1])
            return hashlib.sha1(signer_der).digest() == first[0][1]
    except (IndexError, _Bad):
        return False
    return False
