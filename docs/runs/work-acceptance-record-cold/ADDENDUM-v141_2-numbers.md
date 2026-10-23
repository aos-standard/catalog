# Addendum — v141.2: RFC 8785 numbers (a defect of ours, found running vector 52 at `6b2f730`)

**Date:** 2026-10-23. **What:** `war_cold_verifier_v141.py` (v141.1) could not run vector 52 of
`maximusrufus/work-acceptance-record` at `6b2f730` (non-integer numbers in the signed body). Its JCS serializer raised
`ValueError("float not expected in these records")` instead of writing numbers as RFC 8785 3.2.2.3 requires
(ECMAScript `Number::toString`). The profile text has required RFC 8785 from the start; the earlier vectors simply held
no non-integers, so the gap did not show. It is the same defect babyblueviper1 reported for their verifier on the same
vector (x402-foundation/tsc#4, issuecomment-6352331928).

**Change (v141.2):** `jcs()` writes every JSON number as an IEEE 754 double through a new `es_number()`; integers up to
2^53 are written as before. Nothing else changed (`tsa_check_141.py` is byte-identical; the verifier's diff is 42 lines, in
the module docstring, `jcs()` and the new function).

**Checks:**

| check | result |
|---|---|
| `es_number()` against Node's `String(x)` on 400,000 doubles (300,000 random finite bit patterns, 100,000 random decimals; seed 20261023; `es_number_check.py`) | 400,000 / 400,000 identical |
| v141.2 on the 49 vectors at `d79a737` | 49/49; output byte-identical to the published v141.1 run (`run_v141_1_d79a737.json`, sha256 `7ab599b5…`) |
| v141.2 on 01–55 at `6b2f730` plus the proposed 56–57 | 56/57 (`run_v1412_6b2f730_plus5657.json`): 52 now agrees; 53 agrees |

The one disagreement is vector 54 (an intermediate expired at genTime, on a chain that reaches no supplied anchor):
v141.2 gives `untrusted`, the text since 2026-10-22 gives `failed` ("a check that can run and fails takes precedence").
That reading was clarified after this verifier was written and is not implemented here; v141.2 is the number fix only.
The runner's `readme_pin` field is a constant carried over from v141 and does not name the tree it ran on.

Hashes: `FROZEN_V1412.txt`.
