# Probe — an imprint pattern in the unsigned PKIStatusInfo (profile 1.4, `eb0f30b`)

**Date:** 2026-10-21. **Why:** a comment on x402-foundation/tsc#4 (2026-10-21T10:29Z) states that `verifier/war_verify.py`
at `eb0f30b` locates the imprint and genTime by scanning the whole TimeStampResp for byte patterns, so an imprint that
appears only in unsigned bytes could match while step 9 verifies a genuine signature over an unrelated TSTInfo. The
reply asked for reproduction before calling it critical. This is a vector that reproduces it or not, from the outside.

`probe-status-string-imprint.json` (CC0), built by `build_vector_status_imprint.py` from vector 31: the criteria token is
replaced by vector 31's **record** token — a genuine FreeTSA token whose signed TSTInfo covers the canonical receipt —
with a `statusString` added to its unsigned `PKIStatusInfo` holding `AlgorithmIdentifier(sha-256) || OCTET STRING
(criteria.sha256) || GeneralizedTime(criteria.committed_at)`. No signed byte is changed.

Expected by the 1.4 text: the criteria token's imprint is not `criteria.sha256` (step 5) ⇒ `CRITERIA_TIMESTAMP_MISMATCH`,
fallback to `committed_at` with `CRITERIA_COMMITMENT_UNVERIFIED`. `tsa_signature.criteria` is `verified`: the authority's
signature over its own TSTInfo is genuine, which is why the imprint must come from that TSTInfo.

| verifier | problem_codes | warning_codes | tsa_signature.criteria |
|---|---|---|---|
| this catalog's `war_cold_verifier_v14.py` (v14.1) | `CRITERIA_TIMESTAMP_MISMATCH` | `CRITERIA_COMMITMENT_UNVERIFIED` | `verified` |
| `verifier/war_verify.py` at `eb0f30b`, run as a black box (`python -I verifier/war_verify.py <file>` and `--outcome`; **its source was not read**) | `[]` | `[]` | `verified` |

So at `eb0f30b` the reference verifier accepts as committed-before-check a criteria token that does not cover the
criteria, with the authority signature reported verified. The record's own token (step 6) was not probed here; the same
construction applies to it. Other clean-room verifiers were not run here; the file is for them.

Reproduce: `python3 -I build_vector_status_imprint.py <eb0f30b>/vectors probe.json`, then any verifier on `probe.json`.
