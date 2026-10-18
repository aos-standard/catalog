# Work-acceptance record (draft profile 1.2.1) — a second clean-room verifier, 11/11, and ten proposed vectors

Answering the invitation in x402-foundation/tsc#4 ("If anyone here wants to write a clean-room
verifier from the README alone…", 2026-10-17). One implementation existed before this one
(babyblueviper1, 5/5 then 11/11, with six contributed vectors). This is the second.

| | |
|---|---|
| Subject | `maximusrufus/work-acceptance-record@f7d898425be6e9a45968019a1b27ffdf36ff4f92` (profile 1.2.1), `README.md` + `vectors/01…11` |
| Run date | 2026-10-18 (UTC 02:20–03:10) |
| Environment | Ubuntu 22.04, CPython 3.10.12 (stdlib; `cryptography` 46.0.3 for Ed25519 verification only) |
| Verifier | `war_cold_verifier.py`, sha256 `897b56489edbaa2095f48e7ee8a6a18739e724891cc243d7c588005f5412e9aa`, frozen 02:45Z before the first scored run (`FROZEN.txt`) |
| Written from | `README.md` at `f7d8984` and the `inputs` shape of the vectors. JCS (RFC 8785) and the RFC 3161 `TimeStampResp` parsing are the file's own |
| Not opened | babyblueviper1's `examples/work-acceptance-record-cold` (checker, `lax_check.py`, proposed vectors); Trilatic's Python/Node/browser verifiers (not published in the repo at this pin) |
| Answer exposure | **Not a blind run.** The vectors' `expected` objects were on screen while the input shape was inspected, before the verifier was written. 11/11 therefore shows the README's procedure is implementable from its text and the eleven are consistent with it; it does not show what a cold reader would get |

## Result: 11 / 11

`run_vectors.py` compares `signature_valid`, `independence`, `criteria_hash`,
`criteria_committed_before_check`, `receipt_timestamp`, `verdict_recomputed`, `verdict_stated`,
and the two code lists as sets. All eleven agree on the first scored run (`run_f7d8984.json`).

## What the eleven do not exercise

`lax_battery.py` edits one check out of the verifier at a time (22 mutations) and re-scores. A
mutation that still passes 11/11 marks a check no vector pins. **11 of 22 survive**
(`lax_battery_f7d8984.json`):

| mutation | README step | still 11/11 |
|---|---|---|
| drop `CHECKER_NOT_SIGNER` | 8 | yes |
| drop `PRODUCER_UNDECLARED` | 8 | yes |
| drop `INDEPENDENCE_INCONSISTENT` | 8 | yes |
| drop `CRITERIA_RESULTS_MISMATCH` | 4 | yes |
| use a mismatching record token's genTime as the reference time | 6 | yes |
| drop the criteria token's imprint check (`CRITERIA_TIMESTAMP_MISMATCH`) | 5 | yes |
| drop `CRITERIA_COMMITMENT_UNVERIFIED` (no-token fallback) | 5 | yes |
| "committed before" with `<=` instead of strictly `<` | 5 | yes |
| drop `RESULT_VOCABULARY` | 7 | yes |
| drop the schema / canonicalization / suite refusal | 1 | yes |
| ignore the imprint algorithm OID (accept any digest algorithm) | 5, 6 | yes |

The other 11 mutations are caught (signature, `KEY_COLLISION`, `SELF_CHECKED`, criteria hash,
record token imprint, `CRITERIA_TIME_MISMATCH`, token time over `committed_at`,
`VERDICT_MISMATCH`, required `fail` wins, `required` flag, canonical form). babyblueviper1's
`lax_check.py` reported five unexercised steps against vectors 01–05; vectors 06–11 closed those
five. This battery is against the eleven and finds the next layer.

## Ten proposed vectors (CC0), `proposed_vectors/12…21`

Built by `build_proposed.py` from vector 01: one change each, re-signed with a fresh **TEST** key
(`TEST_KEY.json`, private seeds published so anyone can regenerate; never trust it). Tokens are
vector 01's token bytes with the 32-byte imprint and 15-byte GeneralizedTime substituted, so the
DER structure is unchanged. `expected` is this verifier's reading of the README; take or edit any.

| vector | pins | expected (this reading) |
|---|---|---|
| 12 signer is not the declared checker | `CHECKER_NOT_SIGNER` | signature valid; problem `CHECKER_NOT_SIGNER` |
| 13 stated independent, producer name = checker name | `INDEPENDENCE_INCONSISTENT` | problem |
| 14 results name a criterion the committed document lacks | `CRITERIA_RESULTS_MISMATCH` | problem |
| 15 criteria token over other bytes | `CRITERIA_TIMESTAMP_MISMATCH` | problem **and** fallback to `committed_at` with `CRITERIA_COMMITMENT_UNVERIFIED` (see choice 1) |
| 16 no criteria token | `CRITERIA_COMMITMENT_UNVERIFIED` | warning only; `criteria_committed_before_check: yes` from `committed_at` |
| 17 criteria token genTime equals `issued_utc` | strictly earlier | `no`, `CRITERIA_COMMITTED_AFTER_CHECK` |
| 18 criteria committed 12:30 after `issued_utc` 12:00; record token over other bytes says 13:00 | step 6: a mismatching token is never evidence of time | `imprint_mismatch`, `no`, `CRITERIA_COMMITTED_AFTER_CHECK`. A verifier that trusts the mismatching token's time says `yes` |
| 19 result `passed` | `RESULT_VOCABULARY` | problem, plus `VERDICT_MISMATCH` (see choice 2) |
| 20 no producer declared | `PRODUCER_UNDECLARED` | warning only; `independence` stays as stated |
| 21 schema `…/9.9` | step 1 refusal | refused before any other output (see choice 3) |

With the ten added, **21 of 22 mutations are caught**; the one that survives is "ignore the
imprint algorithm OID" (a token whose imprint is, say, SHA-1 over the right bytes). Building that
vector needs a token with different DER lengths, so it is left open here.

## Three places where the README left this verifier a choice

1. **A criteria token over other bytes (15).** Step 5 names `CRITERIA_TIMESTAMP_MISMATCH` but does
   not say whether the verifier then falls back to `committed_at`. This verifier does, and warns
   `CRITERIA_COMMITMENT_UNVERIFIED`, so the vector carries a problem and a warning. The other
   reading is "no commitment time at all → `no`".
2. **A result outside the vocabulary (19).** The verdict recompute treats an unknown token on a
   required criterion as "not pass", so `verdict_recomputed` is `incomplete` and `VERDICT_MISMATCH`
   fires beside `RESULT_VOCABULARY`. The other reading is to stop at `RESULT_VOCABULARY`.
3. **Refusal shape (21).** Step 1 says refuse but defines no outcome object. This verifier emits
   `{"refused": …}` and nothing else.

## What this does and does not show

- It is a second implementation of the README's procedure, answer-exposed as stated above, and a
  battery over the eleven; not a review of the shipped verifiers.
- The proposed expectations are one reader's; vectors 15, 19 and 21 encode the choices above.
- Tokens, here as upstream, are structurally valid and unsigned; nothing about a real TSA is tested.

## Files

`war_cold_verifier.py`, `run_vectors.py`, `run_f7d8984.json`, `lax_battery.py`,
`lax_battery_f7d8984.json`, `lax_battery_with_proposed.json`, `build_proposed.py`, `TEST_KEY.json`,
`proposed_vectors/12…21.json`, `FROZEN.txt` (sha256 of each).
