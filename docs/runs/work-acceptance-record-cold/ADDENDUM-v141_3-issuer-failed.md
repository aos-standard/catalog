# Addendum — v141.3: an issuer that fails a check is `failed` even when no chain reaches an anchor (vector 54)

**Date:** 2026-10-23. **Why:** profile 1.4.1 was clarified on 2026-10-22 (from robertolocatelli81-dev's reading):
"an issuer that fails a check is `failed` even when no chain reaches an anchor" (vector 54, at `6b2f730`).
`tsa_check_141.py` returned `untrusted` as soon as no path reached a supplied anchor, without checking the issuers the
token itself supplies. v141.2 therefore scored 56/57 on 01–55 plus the proposed 56–57, missing 54
(`ADDENDUM-v141_2-numbers.md`). This is the clarification implemented, not a defect found by a vector we had passed.

**Change (v141.3):** `tsa_check_1413.py`. When no path reaches an anchor, it follows signature-verified links upward
through the token's own certificates (the same link test as the anchor search). If every such chain has an issuer that
is not a CA or not valid at genTime, the outcome is `failed`; otherwise `untrusted`, as before. Nothing else changed:
the diff from `tsa_check_141.py` is 36 lines (one new function, one branch, the docstring); the verifier differs from
v141.2 only in its docstring and the import (8 lines).

| check | result |
|---|---|
| v141.3 on 01–55 at `6b2f730` plus the proposed 56–57 | **57/57** (`run_v1413_6b2f730_plus5657.json`) |
| vector 53 (37's token, the only anchor has root A's name and another key) | `untrusted`, as expected: an intact chain that reaches no anchor is not made `failed` |
| v141.3 on the 49 vectors at `d79a737` | 49/49; output byte-identical to v141.1 and v141.2 (`run_v1413_d79a737.json`) |

Hashes: `FROZEN_V1413.txt`.
