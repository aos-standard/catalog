# Method — how the runs in this directory are made

Every run under `docs/runs/` follows the four practices below. A run's own `RUN.md` or `README.md` states where it
departs from them. This file describes practice; it is not a certification, and a run here verifies only what its own
page says it verifies.

## 1. The reader is written from the published text

- **The source.** The reader (verifier, model or consumer) is written from the specification text and the published
  vectors' input shape.
- **What stays unopened.** Each run names the files it did not open: the reference implementation, its tests, its
  generators, and any other runner's code.
- **Primitives.** Each run names the cryptography and canonicalization it uses: this catalog's own code (for example
  Ed25519 from RFC 8032, JCS from RFC 8785, an OpenTimestamps proof walker), or a named library with its version.
- **Cross-checks.** Where a second, independent primitive is available (OpenSSL, the `ots` client, a second block
  explorer), the run is cross-checked against it, and the result is published beside the run.
- **Ambiguity is reported, not resolved.** Where the text leaves a choice open, the reader fixes one reading before
  the first scored run and lists it (for example the "R1–R10" readings of `aps-lease-revocation-axes-cold`). A
  disagreement is reported as a question about the text, not as a verdict on anyone.

## 2. What was on screen is stated

Each run carries one of two labels:

- **blind:** no `expected` value was seen before the reader was frozen.
- **answer-exposed:** some were seen. The run says which, for example "each call's `expected` block was on screen
  while the input shape was read", or "the case.json of cases 01, 04, 08, 10 and 12 were opened".

A reading written after a result was seen, or after the author explained it, is labelled **post hoc**. The run
reports it beside the first result and never in its place. The authorship label follows the definitions of the
venue, where it has them (for example `Mode B` / `author-produced` in the APS conformance suite). This catalog writes
its own readers, so its runs are not independent of the reader's author.

## 3. Freezing: reader, inputs, outputs

- **The reader** is frozen by sha256 before its first scored run. `FROZEN*.txt` gives the hash, the UTC time and, for
  later versions, what was written after which result.
- **Inputs** are pinned by commit and sha256: the upstream commit, the sha256 of each vectors file, and the block
  headers or RPC endpoints the reader trusted. Another project's files are copied here only when their licence
  allows it or their owner agreed. Otherwise they are referenced by commit and hash and fetched by whoever reruns.
- **Outputs.** Every file of a run is listed in `SHA256SUMS`. Runs are reproducible from the command lines in the run
  page (`python3 -I`, standard library unless stated).
- **Links** in posts point to a shelf commit, not to `main`. A copy of each public comment is kept under
  `docs/evidence/`, with the body's sha256.
- **Timestamps.** Once a month a manifest of the shelf is stamped with OpenTimestamps
  ([`ledger-timestamps/`](ledger-timestamps/)). Each record therefore has a Bitcoin-attested "no later than" that
  does not depend on GitHub.

## 4. Corrections are added beside, never over

- **No file listed in a run's `SHA256SUMS` changes after publication.** A correction is a new file beside the run:
  `ADDENDUM-<ref>.md`, `CORRECTION-<ref>.md` or `CLARIFICATION-<ref>.md`, with its own `SHA256SUMS-<ref>`. When a
  later file supersedes an earlier one, the later one says so.
- **Each correction gets a row** in the conduct ledger ([`../../CONDUCT.jsonl`](../../CONDUCT.jsonl), guide
  [`../../CONDUCT.md`](../../CONDUCT.md)). The row is `self_found` when we found it, and `externally_refuted` or
  `externally_broken` when someone else did, who is named. The row's digest is the sha256 of the evidence copy.
- **Each correction is also stated publicly** where the run was reported, in the same thread.

Examples on this shelf: `aps-lease-revocation-axes-cold/` (first run, addendum, clarification, correction — the
APS suite recorded all three commits in its interop record) and `work-acceptance-record-cold/` (several versions of
one verifier, each with its addendum and lineage).

## Mutation batteries

Where it is cheap, a run includes lax variants of its own reader, each dropping one check, and reports which vectors
catch each one. A variant no vector catches is reported as a gap in the vectors.
