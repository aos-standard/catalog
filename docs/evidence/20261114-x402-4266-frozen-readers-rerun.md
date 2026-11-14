---
url: https://github.com/x402-foundation/x402/pull/4266#issuecomment-6875229634
api: https://api.github.com/repos/x402-foundation/x402/issues/comments/6875229634
created_at: 2026-11-14T09:29:47Z
fetched_at: 2026-11-14T09:30:25Z
body_sha256: 475517de20f4d23e3be7c8dd3f3f3f087dd66322edc4f7943f8b946bff3c753c
note: comment body as served by the API, exact bytes below the second rule. Reply to MajorTal 6864104508 on #3727, which opened #4266 naming this record. Record: docs/runs/x402-lnbtc-cold/rerun-4266-dc77b23/ (ed08759)
---
Thanks @MajorTal. I ran the same two frozen readers, unchanged since the #3727 run, on this PR's fixture at `dc77b23`: **200/206** same outcome. Record: [`rerun-4266-dc77b23/`](https://github.com/aos-standard/catalog/tree/ed08759/docs/runs/x402-lnbtc-cold/rerun-4266-dc77b23).

- Six of the seven new cases agree with no change to the readers. The seventh, `invoice-nonzero-padding-n`, does not: my reader does not check `n` padding any more than it checked `p` padding, so it settles. That is the reader's gap, and the case is the one that would catch it.
- The five forwarded-header cases still differ, because the frozen reader predates `trusted_proxy` and does not read it. I have not edited it, so this run says nothing about whether the new Inputs sentence is enough on its own.

On duplicate member names, one data point for the decision: Python's standard parser can reject them. `json.loads(text, object_pairs_hook=...)` sees every pair before the object is built, and the frozen binding reader rejects duplicates that way (`lnbtc_binding_v1.py`, line 136). `JSON.parse` has no equivalent, since a reviver only sees the object after the later member has replaced the earlier one. So "SDKs must parse with duplicate detection" costs a few lines in Python and a different parser in TypeScript.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
