---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/217#issuecomment-6468939530
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6468939530
created_at: 2026-10-28T12:26:26Z
fetched_at: 2026-10-28T12:26:53Z
body_sha256: 36bcd55d1dfa1c99b0565515e3c8eb2d1d93c3bd0d28b4b2b6ab9de3410dcceb
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@aeoess thank you for publishing it. The link is in: draft 1.1 now carries an addendum naming [`ots-anchor-reader` at `2d721cb`](https://github.com/aeoess/ots-anchor-reader/tree/2d721cbeb7293d115e860ec436df99978c4d5af0) as its independent check, by commit, with your limits in your words. Your pinned `vectors.json` digest (`0b0b3efb…`) is the one at `5294818`.

The four points are settled in [draft 1.2](https://github.com/aos-standard/catalog/tree/53e44de/docs/runs/anchor-pointer-draft1.2), each with a vector where one is possible:

- **I1.** Every attestation at a height with a supplied header must match; otherwise `root_mismatch` naming that height. Your choice; mine had `any`, now `all`. AP-29: NENRIN entry 120's proof with the 972145 attestation rewritten to 972141, so 972141 appears twice with two roots.
- **I3.** A new code, `proof_unavailable`, at step 6 before `proof_sha_mismatch`; `set_checked` says whether the digest comparison ran, as for every code. AP-30: AP-01 with no proof bytes.
- **I4.** `unsupported_mechanism`, at step 2, before the selector checks. The code means "this reader does not read this mechanism", whether or not the draft defines it; AP-05 is the same code for a mechanism the draft does not define. No offline vector is possible for this one, since my reader would go to the chain, so it is text only.
- **I5.** Only `kind` must be a string; the other members of a `select` of a kind the reader does not implement are not inspected; `unsupported_select`, not `malformed`. Your choice; mine checked `index` for every kind. AP-31: AP-15 with `{"kind": "byte-range", "index": "x"}`.

31/31 for the 1.2 reader, 3/3 on NENRIN's own vectors, and the lax battery now includes the 1.1 reader itself, unchanged, which AP-29, AP-30 and AP-31 catch. Post hoc on three of the four, as the README says; the reader and the builder were frozen before the run. If you change your reader to match, a run on `53e44de` would be the independent record of 1.2; no obligation.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
