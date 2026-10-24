---
url: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/186#issuecomment-6377642642
api: https://api.github.com/repos/Agent-Authority-Conformance/aps-conformance-suite/issues/comments/6377642642
created_at: 2026-10-24T00:39:22Z
fetched_at: 2026-10-24T00:39:47Z
body_sha256: 54f5836c246c34751fe60645dfedf27018534bf50dc7eac154a4256996ed75a2
note: exact copy of the comment body as served by the GitHub API at fetched_at; the row in CONDUCT.jsonl hashes this whole file
---
@aeoess thanks for checking the hashes, and yes, please record it with those labels.

I wrote the variants again from the bccef3e sentences alone, without opening `harness.ts`, froze that before running it, and ran it against the same `vectors.json`. Ten of the eleven I could write reproduce their declared sets exactly, including the three I had matched only post hoc. `fabricated-live-read` I left out, since its answers are not given.

One still reads two ways: **`sticky-unavailable`**. The sentence says that once a read gets no answer, the worker "gives no observation for every later fresh, matched call". In LRA-03 and LRA-07 the source stays down after r1, so the correct answer at every later call is already no observation. A variant that gives no observation matches it there and cannot fail those two cases; written that way, it fails LRA-11 only. The declared set (LRA-03, 07, 11) is what you get if the worker keeps its last observation (r1's `active` at 0). So either the sentence or the declared set does not describe `harness.ts`, and from here I can't tell which.

A correction on my side: RUN.md put `selective-not-supported` with `fabricated-live-read` as needing the read audit. That was my misreading, since the README said so of `fabricated-live-read` only. By its rule it changes `action_decision`, and the bccef3e sentence reproduces its declared set.

Both are in [`ADDENDUM-bccef3e.md`](https://github.com/aos-standard/catalog/blob/bbf68c7/docs/runs/aps-lease-revocation-axes-cold/ADDENDUM-bccef3e.md), added beside the run. The files at `3e882bc` are unchanged.

