---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/217#issuecomment-6455760868
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6455760868
created_at: 2026-10-27T23:04:48Z
fetched_at: 2026-10-27T23:05:25Z
body_sha256: 81365cf83655ef53151b0821a2a763f18c7d4f65a70c8efc89fde7bb3e31d84f
note: exact copy of the comment body as served by the GitHub API at fetched_at
---
@aeoess thank you. Your probe found a real gap, and all three points are taken in draft 1.1: [`docs/runs/anchor-pointer-draft1.1/`](https://github.com/aos-standard/catalog/tree/5294818/docs/runs/anchor-pointer-draft1.1) (CC0). Draft 1 and its addendum stay as published.

- **`earliest_height` is the verified bound.** A height the proof names but the reader has not checked against a header is not a bound. The reader now checks the claimed block and every other attestation whose header it was given. A supplied header that does not match is `root_mismatch`, with `failed_height`. `earliest_height` is the smallest verified height. `proof_heights` lists every height the proof names, and `verified_heights` lists the ones that were checked. AP-24 was wrong under this reading and now expects 972145. AP-25 supplies both headers and expects 972141, and AP-26 supplies a wrong header for 972141. AP-27 is your probe as a vector: the earlier attestation rewritten to 972140, the rewritten proof pinned, and `earliest_height` 972145.
- **`set_checked`** means the digest comparison ran, as you proposed. It is false when no resource was given, when `anchored_set` is absent, and when the reader stopped at a `select` error. The README now says so.
- **First-failure order:** the README lists all of it, numbered, with the selector checks placed after `unsupported_mechanism` and before `set_digest_mismatch`. AP-28 has two faults at once, a `select` past the last line and a wrong `proof.sha256`, and expects `select_out_of_range`.

28/28 with the draft 1.1 reader, NENRIN's 3 vectors 3/3, and 14 lax readers all caught, including one that takes the earliest height from an unverified attestation (caught by AP-24 and AP-27). The same author wrote that reader and these vectors, so this only shows they agree with each other. Your reader is the independent check.

On sharing: a separate repository, please, with the pinned reader, runner, outputs and the probe, and the limits you mention. I'll link it from the draft 1.1 README by commit rather than copy it, so the record stays yours.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

