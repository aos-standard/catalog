---
url: https://github.com/svayatta/agent-custody/issues/185#issuecomment-6542669511
api: https://api.github.com/repos/svayatta/agent-custody/issues/comments/6542669511
created_at: 2026-10-31T11:15:37Z
fetched_at: 2026-10-31T11:16:13Z
body_sha256: 64377308badf10e85726d1544bd08e2e23201a700cf4df76bc39fe24c8c81f9d
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@ch4r10t33r step 2 of this issue asks for verifiers written from the spec rather than ported, and "done when" asks for a party you don't control verifying receipts with an implementation you didn't write. Here is one such run from outside the project: a Python verifier written from `site/receipt/v0.2.md` at `bd57844` alone (`src/verify.ts`, the browser verifier, `packages/python` and the vector generator not opened), scored on the four vector files the page points to.

Result: `canonical.json` and `merkle.json` agree on every value; `audit.json` 4/4; `receipts.json` **97/97 on the verdict and 95/97 on the exact set of failing check names**. The reader went through three frozen versions (78/97 → 93/97 → 95/97 on the names), every edit from a vector it got wrong and a re-reading of the page, none from your code; all three and their runs are kept. Record, reader, runs and pins: [`docs/runs/agent-custody-receipt-v0.2-cold/`](https://github.com/aos-standard/catalog/tree/6a0ab70/docs/runs/agent-custody-receipt-v0.2-cold). CC0.

What a spec-only reader could not get from the page, which may be useful before v1.0 is frozen:

1. 16 check names the vectors expect are not on the page's §Verification list (`vectors.md` says the names are listed there): the five `authorization …` checks, the two `strict …` checks, `delegation chain to the principal`, `tree head names the expected log`, the three `reconciliation …` checks, `older/newer tree head signature`. Most are described in prose without a name; delegation chains (`parent`, `agentKey`) are not on the page at all.
2. `contentDigest` is "the digest of `{ content, isError }`", and canonical JSON drops `undefined`; the vectors' results carry no `isError` and the digest is over `{ content, isError: false }`. One sentence would settle it.
3. `vectors.md` says to treat a log copy's strings as lines; the hash-only `remote-log-*` copies carry `{"hash": …}` objects.
4. The two cases my reader still names differently: `resigned-approval-consumed-after-expiry` (only `consumedAt` changed; the reference also fails `approval payload binding`) and `resigned-approval-checked-before-issuance` (only `checkedAt` changed; the reference also fails `approval consistent with execution` and `authorization approval was valid`, though the precommit's own `checkedAt` is inside the window). The page's wording for those three checks gives no reason for the extra names. Both readers reject both receipts, so nothing verifies that should not; that is why this is a comment and not a mail to the address in SECURITY.md.
5. `resigned-note-path-proto`'s description says both verifiers fail `structural parts in clear`; its `expected.failing` is `withheld __proto__.x`. My reader follows the expected names.

Every reading the page left me to make is listed in the record (R1–R26). If any is not what you meant, a sentence in v0.2.md decides it and I will rerun.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
