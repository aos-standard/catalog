# x402 `delivery-receipt` v0.2.1 — clean-room verifier, cold run against the PR vectors

**Date:** 2026-10-19 (JST morning). **Target:** `specs/extensions/delivery-receipt.md` and `delivery-receipt.vectors.json` at
x402-foundation/x402 PR #3783, head `737243dc5928db2fe6c202e09490c9deddf3835c` (fork `johnInarti/x402`). The spec text
sha256 `7f95be441bfdf50014c1f7a6fce61de5d0e1bad567b213da7f47e2076d7de1c7`, the vectors file
`ad195d4c6c176ab138d1eb976a91fe3c00ecdf5d1af3e314bf4bacb10c2c4495`.

| | |
|---|---|
| Written from | the specification text (§3–§8, Appendix A–B) and the **input shape** of the vectors file. The `expectedVerdicts` block was on screen while the input shape was inspected, before the verifier was written: this is **answer-exposed**, a third implementation of the text, not a blind read |
| Not opened | the TypeScript reference (`johnInarti/x402` branch `feat/delivery-receipt-extension`, `3cce288`), its tests, the OpenSSL-only check, the JS port |
| Language / deps | Python 3.10, stdlib + `cryptography` 46.0.3 (Ed25519 equation) + the local `openssl` 3.6.1 binary (ML-DSA-65/87 `pkeyutl -verify -rawin`, and `genpkey -pkeyopt hexseed:` to check the published seeds). JCS, the §3 subset check, the SSE parser, the stream digest, the directory root, the Ed25519 canonical/small-order/prime-order point checks and every level are this verifier's own |
| Frozen before the first scored run | `FROZEN_FIRST_RUN.txt`: `dr_cold_verifier.py` `989bf46d…2a8044`, `run_vectors.py` `6ab5858b…ab830` |

## 1. First scored run — 12/14

`first_run_737243d.json` (`da8acb31…1877`). Appendix A: every check true (A.1 JCS text, receipt id and 88-octet message;
A.2–A.4 keys from the published seeds, kid derivation, signature verifies, tampered message and flipped signature
rejected, sizes; A.5 the four stream steps; A.6 root over 5905 preimage octets **and the five wrong-projection digests of
the table, all reproduced**). ML-DSA-65 and ML-DSA-87 were verified, not size-checked (`backend: true`).

Two disagreements, both `endToEnd/stream/*`: the signed payload carries `responseStatus: 200` and the run supplies no
observed status. v1 failed `delivery` closed (`STATUS_UNOBSERVED`); the expectation is `pass`. §8.1 says "`responseStatus`,
when not `null`, equals the observed status" and does not say what an unrecorded status does. The `streamSession` runs give
`responseStatus: 200` explicitly, so the vectors' reading is: compare only when the client recorded one.

## 2. v2 — one reading changed, 14/14

`dr_cold_verifier.py` `006eda9f07d07005ead33980b4adbc2215e86a3d1a0589903c452d2a4ee829a2` (`FROZEN_V2.txt`). The only change:
the status comparison runs when both sides have a value, and the report says whether it ran (`status_compared`).
`run_v2_737243d.json` (`65bac7b5…5c7f`): **14/14 expectedVerdicts agree** on path, all five levels, `valid`,
`longTermEvidence`, `reason.level`, and `reason.code` for the two codes A.7 compares; the informative `outcomes` and
`automaticRepayment` agree on all six runs that carry them. Appendix A unchanged, all true.

Readings fixed before the first run and consistent with the 14:

1. Trust basis `pinned` requires the pinned key **of the path's algorithm** to equal the governance key whose signature was
   verified (§7.3); with no pinned key for that algorithm and no fetch, `trusted` fails.
2. On the session path only `ed25519` is verified and the other algorithms are reported as not checked; on the archival path
   every entry is verified (§6.1, no split verdict). `longTermEvidence` = archival ∧ authentic ∧ trusted.
3. Levels after the first failing level are reported `not-evaluated`; a missing observed body/stream is
   `delivery: not-evaluated` with `DELIVERY_UNCONFIRMED` (§8.4), everything else that stops a level is `fail`.
4. A reference (§5.5) is accepted only when `receiptUrl` is `https`, same-origin with the origin of the request's
   `resourceUrl`, ends with `/<receiptId>`, and the served octets hash to `digest` before parsing, parse without duplicate
   members, equal their own JCS, recompute to `receiptId`, and name that origin as `issuer`; any failure is `integrity` (no receipt).
5. SSE frames are the dispatched events' data buffers after CRLF/CR → LF, comments/`retry:`/empty-data events are not
   frames, a pending event at end of stream is discarded, events after the terminal event are a `delivery` failure.
6. Ed25519 strict: canonical key encoding, not small order, prime order (we also reject mixed-order keys), canonical `R`,
   `S < L`, then the RFC 8032 equation.

## 3. Mutation battery — `lax_battery.py`, 48 mutations, 45 as expected, 3 recorded

`lax_battery_v2.json` (`6cd58d0b…c733`). Each mutation of the `endToEnd` fixtures must fail the level the text names
(or pass where the text says it must still pass: payer case, CRLF stream, inserted comments/`retry:`, reversed directory
arrays). All 45 did. The three "recorded only": a flipped `ml-dsa-65` on the **session** path passes with `ml-dsa-65`
listed as unchecked (by design, §6.1); a `status: revoked` edit fails at the directory root before the lifecycle check
(root covers `keys`); a `resourceUrl` on another origin fails `settlement` before `trusted`'s §8.2 check. No mutation
passed that should have failed: nothing in this verifier was found lax by this battery.

## 4. Proposed negative vectors — `proposed/delivery-receipt.proposed-vectors.json`

7 fixtures, 11 runs, in the A.7 convention, derived from `endToEnd` and **re-signed with the published test seeds**
(`endToEnd.seeds.receiptKeys`, `0202…`; both algorithms — the seeds reproduce the directory's keys byte for byte, and the
Ed25519 re-signature is byte-identical to the published one; ML-DSA-65 re-signatures are hedged, verify them). Shared
inputs are `$ref`s into the upstream file (`/endToEnd/…`), as they would be after a merge; `run_proposed.py` overlays.

| fixture | pins | expected (first failing level · code) |
|---|---|---|
| `keyDirectoryDigestMismatch` | §7.5 step 2 — **the code A.7 compares, with no run in the file that produces it** | `trusted` · `KEY_DIRECTORY_DIGEST_MISMATCH` (both paths) |
| `amountInflatedResigned` | the inflated-amount question of #3758: with the key, everything a third party checks passes; only §8.3 catches it | `settlement` (both paths; archival still `longTermEvidence: true`) |
| `mlDsa65Stripped` | §6.1 malformed on every path | `integrity` (both paths) |
| `splitVerdict` | §6.1 no split verdict | session: `valid: true`, `ml-dsa-65` reported unchecked; archival: `authentic` |
| `issuedInFuture` | §7.4 skew | `trusted` |
| `framingUnregistered` | §5.6 registered framings only, before any digest | `integrity` |
| `eventAfterTerminal` | §5.6 events after the terminal event | `delivery` |

`run_proposed.json` (`9e5b4c32…73de`): 11/11 with this verifier. They are proposals; a second implementation deciding
them is the point.

## 5. For the authors (observations, not findings)

- §8.1 `delivery`: one sentence on an unrecorded `responseStatus` would remove the only reading this run had to choose.
- A.7 compares `reason.code` for `KEY_DIRECTORY_DIGEST_MISMATCH`, but no run exercises it; `keyDirectoryDigestMismatch`
  above would.
- A.6's wrong-projection table is unusually useful; all five digests reproduced here.

## 6. Files and hashes

`FROZEN.txt` (taken after every run): `dr_cold_verifier.py` `006eda9f…29a2`, `run_vectors.py` `6ab5858b…ab830`,
`lax_battery.py` `8ce0b713…0c7e`, `build_proposed.py` `bb7d3f30…b6f`, `run_proposed.py` `b4d0eb25…3bff`,
`proposed/delivery-receipt.proposed-vectors.json` `e376c64b…be8e`, `first_run_737243d.json`, `run_v2_737243d.json`,
`lax_battery_v2.json`, `run_proposed.json`. Reproduce: `python3 run_vectors.py <vectors.json> out.json`;
`python3 run_proposed.py proposed/delivery-receipt.proposed-vectors.json out.json <vectors.json>`.
