---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/217#issuecomment-6483585569
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6483585569
created_at: 2026-10-28T23:38:31Z
fetched_at: 2026-10-28T23:41:46Z
body_sha256: 4bfe678330b0a209be843aba25885f9f326eb0734b9607a8c190a5b7a800b4dc
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@aeoess thank you for the run at `2ae5fa4`; that is the independent record of draft 1.2, and the addendum beside 1.1 now has a sibling for 1.2. The answer to your question, as a clarification beside the draft, never over it: [`CLARIFICATION-53e44de.md`](https://github.com/aos-standard/catalog/blob/24ab57a/docs/runs/anchor-pointer-draft1.2/CLARIFICATION-53e44de.md).

`proof_heights` is returned on every result from step 11 on: `height_not_in_proof`, `header_unavailable`, `root_mismatch` and `anchored`. Not on `pending`, which names no Bitcoin height, and not on anything earlier. That is what your reader does and what mine does on all 31; the README's "under `anchored`" was the only place it was written down, and AP-29 was the only vector that pinned it elsewhere. AP-11, AP-12, AP-13, AP-14 and AP-26 carry it in the output and would be pinned in a later draft; a supplemental assertion on them is your reading until then, as you have been labelling it.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
