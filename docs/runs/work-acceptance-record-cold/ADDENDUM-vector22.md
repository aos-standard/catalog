# Addendum — vector 22 closes the last open mutation (imprint algorithm)

`RUN.md` left one mutation of 22 unpinned: a verifier that does not check the imprint's
algorithm. Pinning it needs a token with different DER lengths, so `build_vector22.py` encodes
the `TimeStampResp` itself (minimal DER builder; it reproduces vector 01's criteria token
byte-for-byte when given the same fields, which is the check that the encoder is right).

| | |
|---|---|
| Vector | `proposed_vectors/22-criteria-token-sha1-imprint.json` (CC0, same TEST key as 12–21) |
| Change from vector 01 | the criteria token's `messageImprint` algorithm is SHA-1 (`1.3.14.3.2.26`) and its 20-byte imprint is SHA-1 of the committed criteria document |
| This verifier | `CRITERIA_TIMESTAMP_MISMATCH` and the fallback to `committed_at` with `CRITERIA_COMMITMENT_UNVERIFIED` (reading choice 1 of `RUN.md`); `criteria_committed_before_check: yes` from `committed_at` |

The mutation as first written ("ignore the OID") was not the right lax verifier: comparing a
20-byte imprint to a 64-hex `criteria.sha256` still fails on length. `lax_battery_m22.py` redefines
M22 as the verifier that **recomputes the criteria digest under the token's own algorithm** and
accepts a match. That verifier passes every vector up to 21 and is caught by 22:

| vectors scored | M22 (recompute under the token's algorithm) |
|---|---|
| 01–11 + 12–21 | survives, 21/21 (`lax_battery_m22_without22.json`) |
| 01–11 + 12–22 | caught, 21/22 (`lax_battery_m22_with22.json`) |

With 22, all 22 mutations are caught. Step 5 says the imprint "must equal `criteria.sha256`"; a
SHA-256 value only ever equals a SHA-256 imprint, so the algorithm check is implied by the text.
The vector makes it explicit.

Files: `build_vector22.py`, `proposed_vectors/22-criteria-token-sha1-imprint.json`,
`lax_battery_m22.py`, `lax_battery_m22_without22.json`, `lax_battery_m22_with22.json`,
`FROZEN-22.txt` (sha256 of each; the verifier is unchanged, `897b5648…e9aa`).
