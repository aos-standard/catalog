# Addendum — profile 1.3 (`270e9fe`, 28 vectors): the unchanged 1.2.1 verifier scores 24/28; v13 with the four rulings scores 28/28

**Date:** 2026-10-19 (JST morning). **Why:** Trilatic published profile 1.3 (tsc#4, 2026-10-18T14:44Z; vectors 12–27, then 28 at
`270e9fe`) with rulings on the four open questions and vectors 26–28 for the key rule. This verifier had been written for
1.2.1 (`RUN.md`, 1.2.1 at `f7d8984`), so the first thing to record is what the unchanged file does on the new set.

## 1. Unchanged verifier (`war_cold_verifier.py` `897b5648…12e9aa`) on `270e9fe` — 24/28

`run_270e9fe_unchanged.json`. The four disagreements, each a 1.3 ruling this file predates:

| vector | 1.3 ruling | unchanged verifier |
|---|---|---|
| 20 `producer-undeclared` (ours) | stated `independent` with no producer named is `INDEPENDENCE_INCONSISTENT` as well as the `PRODUCER_UNDECLARED` warning | warning only — the expectation we had proposed; Trilatic listed the difference in the file instead of picking quietly. **We take the 1.3 reading**: a record that states independence without naming the other party is claiming something the verifier cannot derive |
| 22 (babyblueviper1) | reference time is the **earlier** of `issued_utc` and a covering token's genTime | used the covering token's genTime alone → `yes` instead of `no` |
| 26 `key-small-order` | canonical, prime-order keys only; otherwise `KEY_REJECTED` and no signature check | accepted the neutral-point key (`R` = neutral, `S` = 0 verifies for any message under `cryptography`/OpenSSL) and reported `signature_valid: true` with no code — the exact failure Trilatic describes as "a verifier that trusts its library alone" |
| 27 `key-non-canonical-encoding` | same rule | same miss |

Vectors 12 (now the former 12b), 23–25 (imprint OID pins, including the two that superseded our SHA-1 vector) and 28 agreed unchanged.

## 2. v13 — `war_cold_verifier_v13.py` `c1e302620e50a906f411f5344b6e71d12bf2accaf9376aa6b067f248b87b5b91`

Frozen before its first scored run (`FROZEN_V13.txt`). Changes, each tied to a ruling: step 2 takes the key named by the
**signed** `receipt.key_id` (an envelope `signature.key_id` that differs is `SIGNATURE_INVALID`, nothing verified) and applies
the key rule first — canonical encoding `y < p` of a prime-order point, by this file's own RFC 8032 decoding and `[8]P`/`[L]P`
checks — with `KEY_REJECTED` and `signature_valid: false` and **no** `SIGNATURE_INVALID`; other entries of the key file are
reported in `key_file_notes`, never in the outcome (vector 28: `spec-test-bad-entry: small-order point (not the signing key;
outcome unaffected)`). Step 5 takes the earlier of `issued_utc` and the covering token's genTime, and reads a token's
`accuracy` (criteria token: later bound; record token: earlier bound; `ordering` ignored) — implemented, **unexercised** by
the 28 vectors, none of which carries `accuracy`. Step 8 derives independence (`undeclared` / `self-checked` / `independent`)
and raises `INDEPENDENCE_INCONSISTENT` on any stated value that differs.

`run_v13_270e9fe.json`: **28/28** on the first scored run of v13 (signature_valid, independence, criteria_hash,
criteria_committed_before_check, receipt_timestamp, verdict_recomputed, verdict_stated, problem_codes and warning_codes as
sets). This is not a cold reading of 1.3: v1 had been scored against these vectors and the four misses were known when v13
was written. The live `selftest-pass.json` of the babyblueviper1 issuer was not run here (this runner takes the vectors'
`inputs` shape; the live record's tokens were verified by the other three parties).

## 3. Files

`war_cold_verifier_v13.py`, `run_vectors_v13.py` (the v1 runner with the import and pin changed), `run_270e9fe_unchanged.json`,
`run_v13_270e9fe.json`, `FROZEN_V13.txt`. v1 files unchanged.
