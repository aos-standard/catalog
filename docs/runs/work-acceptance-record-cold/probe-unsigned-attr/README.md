# Probe — the imprint pattern of vectors 50 and 51 in an unsigned CMS attribute (profile 1.4.1, `6b2f730`)

**Date:** 2026-10-23. **Why:** vectors 50 and 51 of `maximusrufus/work-acceptance-record` (from this catalog's probe
`../probe-status-imprint/`) put `AlgorithmIdentifier(sha-256) || OCTET STRING(imprint) || GeneralizedTime(time)` in
the response's `PKIStatusInfo.statusString`. As robertolocatelli81-dev pointed out on x402-foundation/tsc#4
(issuecomment-6330875448), those bytes are not UTF-8 (byte 0x86 of the OID is not a valid start byte), so the
statusString is outside `PKIFreeText` (RFC 3161 2.4.2, importing RFC 4210 5.1.1). A verifier that checks that grammar
refuses the response before reaching the question the vectors ask, so for such a verifier 50 and 51 test the grammar,
not where the imprint is read from. That was a defect of our probe.

`56-…json` and `57-…json` (CC0), built by `build_vectors_unsigned_attr_imprint.py` from vector 31 at `6b2f730`, put the
same three values, as one `SEQUENCE`, in an unsigned attribute of the token's SignerInfo (`unsignedAttrs`,
RFC 5652 5.3: `SET OF Attribute`, `AttributeValue ::= ANY`). The attribute type is a UUID OID (`2.25.<uuid>`, X.667), so
no registered meaning is claimed. Nothing signed changes; the PKIStatusInfo is the authority's own. 56 is the criteria
side (as 50), 57 the record side (as 51), with the same `expected` as 50 and 51.

| check | 56 | 57 |
|---|---|---|
| `openssl cms -inform DER -cmsout -print` on the token (OpenSSL 3.6.1) | parses; `unsignedAttrs` holds one `2.25.…` attribute | same |
| reference `verifier/war_verify.py` at `6b2f730` (reads the signed TSTInfo only) | agrees: `CRITERIA_TIMESTAMP_MISMATCH`, warning `CRITERIA_COMMITMENT_UNVERIFIED`, `tsa_signature.criteria` `verified` | agrees: `receipt_timestamp` `imprint_mismatch` |
| reference at `d79a737` (before the fix; scans the response) | disagrees: no problem codes — as on 50 | disagrees: `imprint_match` — as on 51 |
| this catalog's `war_cold_verifier_v141.py` (v141.1) | agrees | agrees |

The reference at `6b2f730` gives 57/57 on 01–55 plus these two (`ref_6b2f730_all57.txt`). So the two vectors separate
the same defect as 50 and 51, from a well-formed response. One limit, stated: a verifier that refuses any unknown
unsigned attribute would refuse these too; the 1.4.1 text does not say whether it may.

Found while running: v141.1 cannot run vector 52 (non-integer numbers in the signed body): its JCS serializer raises
on floats instead of writing RFC 8785 numbers. That is recorded separately; it does not touch 56 or 57.

Hashes: `FROZEN.txt`. Reproduce: `python3 -I build_vectors_unsigned_attr_imprint.py <6b2f730>/vectors <out dir>`.
