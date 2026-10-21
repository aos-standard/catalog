# Addendum — profile 1.4.1 (`d79a737`, 49 vectors): step 9 moved to 1.4.1 — first run 48/49, v141.1 49/49; the status-string probe still separates the reference

**Date:** 2026-10-22 (JST morning). **Why:** 1.4.1 (`4daf721`, `06d3b94`, `d79a737`) settled the readings raised on 1.4 —
including two of ours that it did **not** adopt — and added vectors 37–49.

## 1. Unchanged v14.1 on `d79a737` — 44/49

`run_v14_1_latest_unchanged.json`. The five, each a 1.4.1 rule v14.1 predates or read the other way:

| vector | 1.4.1 | v14.1 |
|---|---|---|
| 38 intermediate expired at genTime | `failed` (a chain that reaches the anchor but fails a check) | `untrusted` |
| 40 RSASSA-PSS | `verified`, or `unsupported` (accepted) | `unsupported` — conformant under `tsa_signature_accepted`, but this runner did not read that field |
| 42 ECDSA P-521 | `unsupported` (only P-256/P-384 required) | `verified` |
| 45 no certificates + bad messageDigest | `failed` (any check that can run fails first) | `no_signer` — **our 1.4 reading of the order, which 1.4.1 did not adopt** |
| 49 issuer without the CA flag | `failed` | `untrusted` |

## 2. v141 — `tsa_check_141.py` + `war_cold_verifier_v141.py`

Written from the 1.4.1 README (step 9 and changelog); reference verifiers still not opened. Rules as read: contentType and
messageDigest run without a signer; signature, ESS binding, `id-kp-timeStamping` and signer validity need it; RSA PKCS#1
v1.5 and ECDSA P-256/P-384 required, RSASSA-PSS implemented, anything else `unsupported`; the anchor is matched by subject
name and public key; on a path that reaches it every issuer other than the anchor must be a CA and valid at genTime, else
`failed`; no path is `untrusted`; several defects: `failed` first, then `no_signer`, `unsupported`, `untrusted`. The runner
(`run_vectors_v141.py`) now honours `tsa_signature_accepted`.

- **First scored run (frozen): 48/49.** 40 read `failed`: the RSASSA-PSS parameters were parsed without unwrapping their
  SEQUENCE, so no field was read and the SHA-1 defaults were used. A valid PSS signature reported `failed` — worse than the
  `unsupported` the profile allows.
- **v141.1** (only that unwrap): **49/49** under `cryptography` 3.4.8 and 46.0.3 (`run_v141_1_d79a737.json`,
  `…_crypto46.json`); 36/36 on `eb0f30b` unchanged; battery 12/12 (`lax_battery_v141.json`).

## 3. The status-string probe against 1.4.1

`probe-status-imprint/` (2026-10-21): the reference `verifier/war_verify.py` at `d79a737`, run as a black box, still reports
no problem codes and `tsa_signature.criteria: verified` for a criteria token whose signed TSTInfo covers other bytes
(imprint pattern only in the unsigned PKIStatusInfo). v141.1 reports `CRITERIA_TIMESTAMP_MISMATCH` with the
`CRITERIA_COMMITMENT_UNVERIFIED` fallback. The 1.4.1 changelog does not mention it.

Files: `tsa_check_141.py`, `war_cold_verifier_v141.py`, `run_vectors_v141.py`, `run_v14_1_latest_unchanged.json`,
`run_v141_d79a737.json` (first run), `run_v141_1_d79a737.json`, `run_v141_1_d79a737_crypto46.json`, `lax_battery_v141.py`,
`lax_battery_v141.json`, `FROZEN_V141.txt`.
