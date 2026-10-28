# Anchor pointer, draft 1.2 — answers to the second reader's four questions

**Date:** 2026-10-28. **Status:** a proposal, not a standard. CC0. Draft 1.1 ([`anchor-pointer-draft1.1/`](../anchor-pointer-draft1.1/))
stays as published; this directory replaces it for anyone starting now. The pointer form is unchanged
(`anchor_pointer: "1"`); what changes is one new result code, two readings of the check order, and three vectors.

## The independent record

@aeoess published a second reader, [aeoess/ots-anchor-reader at `2d721cb`](https://github.com/aeoess/ots-anchor-reader/tree/2d721cbeb7293d115e860ec436df99978c4d5af0),
written from the draft READMEs and the vector files without this catalog's checker (their account, with the
tool-call record for the 1.1 update), standard library only, and reported **28/28 on draft 1.1 at `5294818`** with every
published expected field compared (aeoess/agent-governance-vocabulary#217, comment 6458246337). Their limits, in their
words: supplied block roots are used as given and the chain is not authenticated; the run is author-produced; AP-27
began as their probe; AP-20 to AP-22 are shape checks only. The `vectors.json` they pin (sha256 `0b0b3efb…`) is the
one at `5294818`. That record is theirs and is not copied here.

Their README lists four points where draft 1.1 is silent, each with the choice their reader makes. Draft 1.2 takes a
position on each.

| | question | draft 1.2 | reader change here | vector |
|---|---|---|---|---|
| I1 | two Bitcoin attestations at one height, only one matching the supplied root | **every attestation at a height with a supplied header must match; otherwise `root_mismatch` naming that height** (as their reader does) | yes: `any` became `all` | AP-29 |
| I3 | an `opentimestamps` pointer with no proof bytes supplied | **new code `proof_unavailable`**, step 6, before `proof_sha_mismatch`; `set_checked` reports whether the digest comparison ran, as for every code | yes: draft 1.1's reader answered `proof_sha_mismatch` | AP-30 |
| I4 | a well-formed `evm-log` pointer to a reader that does not read EVM logs | **`unsupported_mechanism`**, at step 2, before the selector checks: the code means "this reader does not read this mechanism", whether or not the draft defines it (AP-05 is the same code for a mechanism the draft does not define) | none (this reader reads `evm-log`) | none possible offline: this reader would query the chain, so no universal `expected` exists; the rule is text only |
| I5 | shape checks for a `select` of an unknown kind | **only `kind` must be a string; the other members are not inspected; `unsupported_select`** (step 3), not `malformed` | yes: draft 1.1's reader checked `index` for every kind | AP-31 |

## Check order (the first failure is the result)

1. `malformed`  2. `unsupported_mechanism`  3. `unsupported_select`  4. `select_out_of_range`  5. `set_digest_mismatch`
(3–5 only when `anchored_set` is present and the resource was supplied), then

- **opentimestamps:** 6. `proof_unavailable`  7. `proof_sha_mismatch`  8. `proof_unparseable`  9. `proof_for_other_digest`
  10. `pending`  11. `height_not_in_proof`  12. `header_unavailable`  13. `root_mismatch` (the claimed block first, then
  every other attestation with a supplied header, lowest height first; every attestation at a height must match; the
  result names `failed_height`)  14. `anchored`, with `earliest_height`, `verified_heights` and `proof_heights`.
- **evm-log:** 6. `unsupported_chain`  7. `tx_not_found`  8. `tx_reverted`  9. `log_not_found`  10. `contract_mismatch`
  11. `event_mismatch`  12. `height_unreachable`  13. `height_mismatch`  14. `digest_mismatch`  15. `not_final`  16. `anchored`.

## Vectors — `vectors.json`, 31, offline (sha256 `00a75863556c158a…`)

AP-01…AP-28 are draft 1.1's, unchanged. AP-29 rewrites the 972145 attestation of NENRIN entry 120's proof to 972141
(proof pinned by `proof.sha256`), so the proof names 972141 twice with two roots; 972141's real header is supplied.
AP-30 is AP-01 with the proof bytes not supplied. AP-31 is AP-15 with `select: {"kind": "byte-range", "index": "x"}`.
Every `expected` was fixed by construction (`build_vectors_d12.py`, frozen before its run).

## Runs

| file | what | result |
|---|---|---|
| `run_output.txt`, `run.json` | the draft 1.2 reader on the 31 vectors | 31/31 |
| `run_nenrin_output.txt`, `run_nenrin.json` | on NENRIN's own 3 vectors at `ea658bd` (`nenrin_ea658bd/vectors.json`, their `expected` is the result only) | 3/3 |
| `lax_battery_output.txt` | draft 1.1's fourteen lax readers plus two: `no-proof-unavailable` (caught by AP-30) and **draft 1.1's reader itself, unchanged** (caught by AP-29, AP-30, AP-31: it answers `anchored`, `proof_sha_mismatch`, `malformed`) | 16/16 caught |

**Same author, post hoc.** The reader (`f2e5c7fca4b3e07d…`) was written after reading the four questions and the choices the
second reader makes, so I1, I3 and I5 are post hoc; the reader and the builder were frozen before any run over these
vectors (`FROZEN.txt`). 31/31 shows that reader and vectors are consistent, not that a stranger's reader would agree;
the independent check of draft 1.1 is the second reader above, and of draft 1.2 it would be that reader after its
author changes it to match, if they choose to.

## Open

Inclusion of one member in an anchored batch; other `select` kinds; other mechanisms; a finality vector for
`evm-log`.
