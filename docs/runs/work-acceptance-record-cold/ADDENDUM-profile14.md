# Addendum — profile 1.4 (`eb0f30b`, 36 vectors): step 9, the time-stamp authority's signature — 36/36

**Date:** 2026-10-21 (JST morning). **Why:** profile 1.4 adds the outcome `tsa_signature` (step 9) and vectors 31–36 with live
FreeTSA (ECDSA P-384) and DigiCert (RSA) tokens and relying-party anchors; Trilatic asked for clean-room runs of 31–36
(tsc#4, 2026-10-20T16:08Z).

| | |
|---|---|
| Written from | README.md at `eb0f30b` (step 9), RFC 3161 §2.4.2, RFC 5652 §5, RFC 5035 / RFC 2634 (ESS signing-certificate v1/v2), RFC 5280. **Not opened:** `verifier/war_verify.py` (the reference, new in this release), and every other verifier. The `expected` objects of 31–36 were read while inspecting the input shape (answer-exposed, as before) |
| Code | `tsa_check.py` (step 9: own CMS walk; `cryptography` only for X.509 parsing and the RSA/ECDSA arithmetic) and `war_cold_verifier_v14.py` (= v13 plus the `tsa_signature` member, one key per token present, `not_evaluated` without anchors; no other member changes) |
| Frozen | `FROZEN_V14.txt` |

## Runs

1. **First scored run of v14: crashed, no score.** Under `python3 -I` the interpreter loads the system `cryptography` 3.4.8,
   which lacks `not_valid_before_utc`; `_valid_at` raised `AttributeError` on the first token. Recorded in `FROZEN_V14.txt`.
2. **v14.1** — the only change is that `_valid_at` falls back to the naive-UTC `not_valid_before/after` of older
   `cryptography` (`tsa_check.py` `ebc44671…6bf9`). **36/36** (`run_v14_eb0f30b.json`), and 36/36 again under `cryptography`
   46.0.3 (`run_v14_eb0f30b_crypto46.json`). Vectors 01–30 unchanged from `2d8fac7`.

Order of the step-9 checks (each a reading of the 1.4 text): `no_signer` if no certificate in the token matches the
SignerInfo's `sid`; `unsupported` for RSASSA-PSS or an unknown algorithm; `failed` for a wrong contentType or
messageDigest, a signature over the DER signed attributes that does not verify, an ESS signing-certificate(-v2) hash that
does not match the signer certificate, a signer without `id-kp-timeStamping`, or a signer not valid at genTime;
`untrusted` when all of that holds but no chain of CA certificates (each signature checked, each valid at genTime)
reaches a supplied anchor — a self-signed root inside the token never terminates the chain; otherwise `verified`.

## Mutation battery — `lax_battery_v14.py`, 12/12

On the criteria tokens of 31 (FreeTSA) and 32 (DigiCert): one bit inside the TSTInfo, inside an embedded certificate's
TBS, and inside the signature each give `failed`; an empty anchor list passed to step 9 gives `untrusted`; the other
authority's root as the only anchor gives `untrusted`. Nothing that should fail verified.

## Not covered

RSASSA-PSS and ECDSA P-256 against live tokens (the release notes say the same); CRL/OCSP revocation (step 9 does not ask
for it); `accuracy`/`ordering` are step 5's and unchanged from v13.
