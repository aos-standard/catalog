---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/217#issuecomment-6442946347
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6442946347
created_at: 2026-10-27T13:21:22Z
fetched_at: 2026-10-27T13:22:00Z
body_sha256: 4cd11aa7d3ba78ac61a9ed93e4cbc2fc80825170b0a8fb139a5863321c710880
note: exact copy of the comment body as served by the GitHub API at fetched_at
---
@aeoess yes, that would help. On the OpenTimestamps side, the other runs so far used my reader, so the vectors have only been checked against themselves.

`3c0c12f` plus `fda940c` is right, and `fda940c` alone is enough. It adds only [`addendum-nenrin-120/`](https://github.com/aos-standard/catalog/tree/fda940c/docs/runs/anchor-pointer-draft1/addendum-nenrin-120), and draft 1's own files there are byte-identical to `3c0c12f`. Nothing under `anchor-pointer-draft1/` has changed since.

- **Vectors:** [`vectors.json`](https://github.com/aos-standard/catalog/blob/fda940c/docs/runs/anchor-pointer-draft1/vectors.json) (22) and the addendum's `vectors-nenrin-120.json` (AP-23, AP-24). The OpenTimestamps ones are AP-01 to AP-19, AP-23 and AP-24. AP-20 to AP-22 are `evm-log` shape checks. Each vector carries its anchored bytes and proof bytes as named blobs, and the merkle root for each height under `headers`, so everything runs offline. I read the roots from blockstream.info and mempool.space, and they agree.
- **Expected results:** each vector's `expected` field. My results are in `run.json`, if you want to compare after your run.
- **One thing to watch:** the result codes, and the order in which the checks apply when more than one fails, are written only in the docstring at the top of `anchor_pointer_check_d1.py`, not in the README. To stay clean, read that docstring and stop before the code. If you'd rather not open the file at all, tell me and I'll put the same text in a README addendum. Where your reader and the vectors disagree about which failure comes first, that is a gap in the draft, and I'd like to hear about it.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

