# Anchor pointer, draft 1.1 — `earliest_height` is a verified bound; the check order in full

**Date:** 2026-10-28. **Status:** a proposal, not a standard. CC0. Draft 1 ([`anchor-pointer-draft1/`](../anchor-pointer-draft1/))
and its NENRIN addendum stay as published; this directory replaces them for anyone starting now. The pointer form is
unchanged (`anchor_pointer: "1"`); what changes is what the reader reports and what the vectors expect.

## What changed, and why

@aeoess wrote a second reader from the draft 0 and draft 1 READMEs and the vectors, without this catalog's
implementation, and reported 24/24 on `fda940c` with three findings
(aeoess/agent-governance-vocabulary#217, comment 6448170085). Each is taken here.

| finding | draft 1 | draft 1.1 |
|---|---|---|
| `earliest_height` took the smallest height the proof names, verified or not. AP-24 supplied only the header of its claimed block (972145) yet expected 972141. A proof whose unverified earlier attestation is rewritten to 972140 was reported as `earliest_height: 972140` | a named height, not a verified one | **a verified bound.** The reader verifies the claimed block and every other attestation whose header it was given; a supplied header that does not match its attestation is `root_mismatch`. `earliest_height` is the smallest verified height. `proof_heights` lists every height the proof names, for the record. AP-24 now expects 972145; AP-25 supplies both headers and expects 972141; AP-26 supplies a wrong header for 972141; AP-27 is @aeoess's probe, carried as a vector |
| `set_checked` was not defined | implied | **true only when the digest comparison ran**: false when no resource was given, when `anchored_set` is absent, and when the reader stopped at a `select` error |
| the first-failure order was only in the reader's docstring, and the selector checks were not placed in it | — | the order is listed below and in the docstring; AP-28 has two faults at once (a `select` out of range and a wrong `proof.sha256`) and expects the selector result |

## Check order (the first failure is the result)

1. `malformed`  2. `unsupported_mechanism`  3. `unsupported_select`  4. `select_out_of_range`  5. `set_digest_mismatch`
(3–5 only when `anchored_set` is present and the resource was supplied), then

- **opentimestamps:** 6. `proof_sha_mismatch`  7. `proof_unparseable`  8. `proof_for_other_digest`  9. `pending`
  10. `height_not_in_proof`  11. `header_unavailable`  12. `root_mismatch` (the claimed block first, then every other
  attestation with a supplied header, lowest height first; the result names `failed_height`)  13. `anchored`, with
  `earliest_height`, `verified_heights` and `proof_heights`.
- **evm-log:** 6. `unsupported_chain`  7. `tx_not_found`  8. `tx_reverted`  9. `log_not_found`  10. `contract_mismatch`
  11. `event_mismatch`  12. `height_unreachable`  13. `height_mismatch`  14. `digest_mismatch`  15. `not_final`  16. `anchored`.

## Vectors — `vectors.json`, 28, offline

AP-01…AP-22 are draft 1's, unchanged. AP-23 is unchanged from the NENRIN addendum. AP-24 is corrected as above.
AP-25…AP-27 are built from NENRIN entry 120 (carried under CC0 with its owner's permission); AP-27 rewrites one
attestation height inside the proof bytes and pins the rewritten proof. AP-28 is babyblueviper1's slot log (AP-15)
with two faults. Every `expected` was fixed by construction (`build_vectors_d11.py`, frozen before its run).

## Runs

| file | what | result |
|---|---|---|
| `run_output.txt`, `run.json` | the draft 1.1 reader on the 28 vectors | 28/28 |
| `run_nenrin_output.txt`, `run_nenrin.json` | on NENRIN's own 3 vectors at `ea658bd` (their `expected` is the result only) | 3/3 |
| `lax_battery_output.txt` | fourteen lax readers, each dropping or bending one check; the two new ones are "earliest from an unverified attestation" (caught by AP-24, AP-27) and "verify only the claimed block" (caught by AP-25, AP-26) | 14/14 caught |

**Same author, and order.** The reader and the vectors here are by the same author, so 28/28 shows only that they are
consistent. `FROZEN.txt`: the reader was frozen after one run over draft 1's 22 vectors (22/22) and the NENRIN
addendum (where AP-24 differed, as intended), and before every run listed above; the builder and the battery were
frozen before their runs. The independent check of this draft is @aeoess's reader; their record will be linked from
here by commit when it is published, and is not copied into this catalog.

## Open

Inclusion of one member in an anchored batch; other `select` kinds; other mechanisms; a finality vector for
`evm-log`.
