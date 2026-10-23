# Which v141 files to read — two implementations of the same two fixes

**Date:** 2026-10-23. Two verifier lineages for profile 1.4.1 sit side by side in this directory. They implement the same
two fixes independently; neither replaces a published file.

| fix | canonical (cited on x402-foundation/tsc#4, issuecomment-6365127487) | independent second implementation (this catalog's acceptance lane) |
|---|---|---|
| RFC 8785 numbers in JCS (vector 52) | `war_cold_verifier_v141.py` (v141.2 → v141.3), `ADDENDUM-bc5a138.md` | `war_cold_verifier_v1412.py`, `ADDENDUM-v141_2-numbers.md` |
| issuers checked on a chain that reaches no anchor (vector 54) | `tsa_check_141.py` (v141.3), `ADDENDUM-bc5a138.md` | `war_cold_verifier_v1413.py`, `ADDENDUM-v141_3-issuer-failed.md` |
| runs | `run_v141_3_bc5a138.json` (57/57 at `bc5a138`) | `run_v1412_*.json`, `run_v1413_*.json` (at `6b2f730` and `d79a737`) |

**Read `ADDENDUM-bc5a138.md` first.** The second lineage reached the same results from the same profile text on the same day
and is kept as an independent reproduction. Both are covered by the 2026-10 timestamp manifest or later ones
(`../ledger-timestamps/`).

`probe-unsigned-attr/` (vectors 56/57 in that lineage's numbering, not the upstream 56/57) is the well-formed variant of
`probe-status-imprint/`: it puts the same imprint pattern in an unsigned CMS attribute instead of a `statusString` whose
bytes are not UTF-8, so a verifier that parses `PKIStatusInfo` to its grammar also reaches the question the probe asks.
