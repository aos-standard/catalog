# Correction, 2026-10-28 — one sentence of `ADDENDUM-profile142.md` was wrong; v142.1 unchanged is 90/90 at `cb7e8f1`

**This file is added beside `ADDENDUM-profile142.md` and changes nothing in it.** It corrects one sentence of that
addendum's reading 3 and records a run on the three vectors added since.

## What was wrong

`ADDENDUM-profile142.md`, reading 3, ends: "An unreadable `committed_at` beside a usable criteria token is not
a problem." That sentence is wrong twice over.

- **As a description of the profile.** Step 5 says a `criteria.committed_at` that disagrees with the token's
  `genTime` is `CRITERIA_TIME_MISMATCH`, and a value that cannot be read cannot agree. @maximusrufus stated this in
  x402-foundation/tsc#4 (comment 6456424622) and pinned it as vector 88 at `cb7e8f1` (`committed_at`
  `2026-13-01T00:00:00Z` beside a valid criteria token: `CRITERIA_TIME_MISMATCH`, `criteria_committed_before_check`
  yes), crediting this catalog as the proposer of the case. Step 10 now states the reading.
- **As a description of our own verifier.** v142.1 (`a0575614…80d22`, frozen 2026-10-28, unchanged since) already
  reports `CRITERIA_TIME_MISMATCH` there: when a usable token supplies the time, it compares `committed_at` with
  `genTime`, and an unreadable `committed_at` is a mismatch. The addendum's sentence described a behaviour the
  verifier never had. The first half of reading 3 (`RECEIPT_TIME_UNREADABLE` is raised only for a stated time step 5
  actually uses) stands, and the reference verifier agrees with it (same comment).

The sentence was written from the rule text, not from the verifier's output on such an input; no vector exercised
the case at `85a310d`, so 87/87 could not catch it. Recorded on our side as a published statement of ours that a
third party refuted with a vector.

## Run: v142.1 unchanged on the 90 vectors at `cb7e8f1`

`run_v1421_cb7e8f1.json` (`run_vectors_v1421.py`, unchanged; it still prints `readme_pin: 85a310d`, which is the
README it was written against, not the one run here): **90/90** on every compared field. The three new vectors:

| vector | sha256 | v142.1 |
|---|---|---|
| 88-committed-at-malformed-with-token | `1247178b8a45f849…` | `CRITERIA_TIME_MISMATCH`; `criteria_committed_before_check` yes |
| 89-criteria-file-base64-noncanonical | `eba45996f18aaf02…` | `CRITERIA_HASH_MISMATCH`, not refused |
| 90-criteria-token-base64-noncanonical | `f63532a8b8a4c127…` | `CRITERIA_TIMESTAMP_MISMATCH` with `CRITERIA_COMMITMENT_UNVERIFIED`, not refused |

README at `cb7e8f1` sha256 `4e07e33e9d9df73a…`. The reference verifier was not opened. 89 and 90 pin the first reading
of the addendum (a non-canonical token or criteria file is a mismatch, never a refusal), which the README's
clarification note attributes to this catalog. Files here are listed in `SHA256SUMS-cb7e8f1`; CC0.
