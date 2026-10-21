---
url: https://github.com/x402-foundation/tsc/issues/4#issuecomment-6327691458
api: https://api.github.com/repos/x402-foundation/tsc/issues/comments/6327691458
created_at: 2026-10-21T22:12:28Z
fetched_at: 2026-10-21T22:12:48Z
body_sha256: 7519e17a9e0a1922b13e96a166f273d54f6397c301ffe93435b0e77f498d64fb
note: exact copy of the comment body as served by the GitHub API at fetched_at; the row in CONDUCT.jsonl hashes this whole file
---
@maximusrufus — 37–49 at `d79a737`, as asked, and one vector for the step 9 binding claim above, which still separates the reference at `d79a737`.

**1.4.1: 49/49, after one miss of ours.** The unchanged 1.4 verifier gives 44/49: 38, 42 and 49 are the new chain and curve rules, 40 is PSS under a runner that did not read `tsa_signature_accepted`, and 45 is the order between defects, where 1.4.1 took `failed` first rather than the order in my 1.4 report. The step written from the 1.4.1 text was frozen before its first scored run, which gave **48/49**. On 40 it reported `failed` for a valid RSASSA-PSS signature, because it parsed the PSS parameters without unwrapping their SEQUENCE and fell back to SHA-1 with salt 20. That is a worse answer than the `unsupported` the profile allows. With only that unwrap fixed, the result is 49/49 under `cryptography` 3.4.8 and 46.0.3, and 36/36 at `eb0f30b` is unchanged. The reference verifiers are still unopened here.

**The binding claim reproduces, at `eb0f30b` and at `d79a737`.** @magentixai asked for reproduction before anyone calls it critical, so here is a vector: [`probe-status-imprint/`](https://github.com/aos-standard/catalog/tree/8c210d1/docs/runs/work-acceptance-record-cold/probe-status-imprint) (CC0, with its builder). It is vector 31 with the criteria token replaced by 31's *record* token, a genuine FreeTSA token whose signed TSTInfo covers the canonical receipt. Its unsigned `PKIStatusInfo` gets a `statusString` holding `AlgorithmIdentifier(sha-256) || OCTET STRING(criteria.sha256) || GeneralizedTime(committed_at)`, and no signed byte changes. By the text the expected outcome is `CRITERIA_TIMESTAMP_MISMATCH` with the `CRITERIA_COMMITMENT_UNVERIFIED` fallback, while `tsa_signature.criteria` is `verified`, because the authority did sign its own TSTInfo.

- Ours reads the imprint from the signed TSTInfo: `CRITERIA_TIMESTAMP_MISMATCH`.
- `verifier/war_verify.py` at `eb0f30b` and at `d79a737`, run as a black box: `problem_codes: []`, committed before the check `yes`, `tsa_signature.criteria: verified`.

So the reference accepts a criteria commitment the token does not cover, while reporting the authority's signature as verified. I probed only the criteria token; the same construction applies to the record token in step 6.

**Correction.** @robertolocatelli81-dev, my 1.4 report said "an empty anchor list passed to step 9 gives `untrusted`". That was a direct call to the step-9 function inside our battery, not the verifier's outcome: the verifier returned `not_evaluated` for `[]`, the reading 1.4.1 settled with 43. You were right to flag the sentence.

Addendum with both runs, the miss and the hashes: [`ADDENDUM-profile141.md`](https://github.com/aos-standard/catalog/blob/8c210d1/docs/runs/work-acceptance-record-cold/ADDENDUM-profile141.md).

Disclosure: assisted by AI (Claude). I built the probe and ran both verifiers myself and remain responsible for what is claimed here.
