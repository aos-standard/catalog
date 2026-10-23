# Addendum — corpus `bc5a138` (57 vectors): two misses of ours, then 57/57

**Date:** 2026-10-23 (JST evening). **Why:** after this catalog's status-string probe, the reference verifiers were changed
to read the imprint, genTime and accuracy only from the signed TSTInfo (`6b2f730`), and the probe became **vector 50** (as
received, credited), with 51 (same construction on the record token), 52 (non-integer numbers in the signed body), 53–55,
56 (a live receipt from another checker) and 57 (integer-valued doubles).

| run | result |
|---|---|
| v141.1 unchanged | **aborted at vector 52**, no score: this verifier's JCS refused floats (`ValueError`) instead of writing them in RFC 8785 form |
| v141.2 — JCS numbers as ECMAScript `Number::toString` (`_es_number`), frozen first | **56/57**: 54 read `untrusted`. Issuer checks ran only on chains that reach an anchor; 1.4.1 says a check that can run and fails takes precedence |
| v141.3 — issuers that sign the chain are checked (CA flag, validity at genTime) even when no anchor is reached | **57/57** (`run_v141_3_bc5a138.json`; also under `cryptography` 46.0.3), 49/49 at `d79a737`, 36/36 at `eb0f30b`, battery 12/12 |

`_es_number` was compared with Node's `JSON.stringify` on 27,048 doubles (20,000 random bit patterns, 5,000 uniform, the
integers −1000…999 and powers of ten 1e−30…1e29): 0 mismatches. It covers the integer-valued doubles of 57 (`1.0` → `1`,
`-0.0` → `0`) as well as the exponent forms of 52.

On vector 50, a point made by robertolocatelli81-dev (tsc#4, 2026-10-22T02:01Z) that this catalog accepts: the probe's
`statusString` holds one `UTF8String` whose bytes (the DER of the three values) are not UTF-8, so the response is outside
RFC 3161's `PKIFreeText` grammar. A verifier that parses `PKIStatusInfo` to its grammar refuses the response as a whole, and
for such a verifier the probe tests the grammar, not where the imprint is read from. The probe still separated a verifier
that scanned the whole response for the pattern; a version whose unsigned bytes are valid UTF-8 would separate both.

Files: `war_cold_verifier_v141.py` and `tsa_check_141.py` (v141.3), the runs above, `FROZEN_V141.txt` (every step recorded).
