# Behavior probes

Observation records for registry servers that claim local-only / no-network
behavior. This surface is a measurement archive, not a score and not a product.

## Method

- method_version: `2026-08-16.1`
- census snapshot sha256: `4b69632cc65dde8457ba2723f84394c4d10aa2054d577c1e15529a4e41069ab5`
- batch: `batch_2026-09-28`
- denominator total: **27** (from EXPECTED_BY_REGISTRY; not handwritten)

| registryType | count |
|---|---:|
| `cargo` | 1 |
| `mcpb` | 2 |
| `npm` | 14 |
| `nuget` | 1 |
| `pypi` | 9 |

- measured: **17**
- excluded: **2**
- not measured: **8**

Accounting identity: measured + excluded + not measured = denominator total.

## Verdict vs accounting

1. Judgment `not_measured` **10** = accounting not-measured **8** + exclusion-table **2**.
2. Those 2 exclusion-table rows keep their phase-1 registry exclusion as the row reason. `unreachable-repository` is the exclusion-table class; it is not copied onto the row reason.
3. `cargo` **1** and `nuget` **1** are not on the exclusion table; they sit on the not-measured side of the accounting (same phase-1 exclusion class, different handling).

| verdict | count |
|---|---:|
| `claim_contradicted` | 1 |
| `not_contradicted_within_coverage` | 16 |
| `not_measured` | 10 |

A row is `claim_contradicted` only when unprompted network evidence appears
during the declared launch. Start failures stay `not_measured`.
When `stderr_capture` is not `captured`, the row uses
`start_failed_stderr_unavailable` and could not show a reason
(stderr was empty or could not be read in time).
Tool-invoked network is recorded and does not change the verdict.

## Limits

1. This is one instrumented run of the full denominator. `--only` slices are
   not published.
2. Byte identity is not a reproduce condition. Timestamps, pids, and strace
   line counts move. Compare verdict and the set of unprompted query names.
3. `built_image_digest` is a **local record only**. Third parties cannot pull
   that image; do not treat it as a matching target.
4. Third-party claim text and server stderr are republished verbatim and are
   not vocabulary-filtered.
5. Verdict counts are not a target. Do not treat contradiction rate as a KPI.

## Excluded targets

Unrequested individual judgments follow the published denial classes.
Silence is not an exclusion — only listed classes are excluded.
Unreachable repositories are listed here; they are not dropped in silence.

| Reason class | name |
|---|---|
| `unreachable-repository` | `io.github.CanopyHQ/phloem` |
| `unreachable-repository` | `io.github.JoyTruepath/truepath-office-mcp` |

| Reason class | Scope |
|---|---|
| `unreachable-repository` | repository returns 404; no channel for dispute |
| `self-audit` | *(none observed in this batch)* |
| `competitor` | *(none observed)* |
| `financial-relationship` | *(none observed)* |
| `employer-or-client` | *(none observed — class only)* |

## Reproduce

Three checks, with different jobs:

1. **Output hash** — sha256 every published file and compare to `DIGESTS.json`.
2. **Materials** — pull `base_image_digest`, build the bundled Dockerfile,
   and compare `artifact_sha256` of the installed wheel / sdist / tarball.
3. **Instrument** — the bundled harness keeps the
   `services.behavior_probe` package layout (not flattened). From
   `harness/2026-08-16.1/` run
   `python -m services.behavior_probe --only <name-or-identifier>`
   and compare verdict plus the unprompted query-name set.

`built_image_digest` is recorded from the local build. It is **not** a
third-party matching target (local builds are not bit-reproducible).

## Dispute channel

File a **new** issue on `aos-standard/catalog` if a row or classification is
wrong. Census challenge issue #2 is a different surface; do not mix them.
If we were wrong, we write the correction on `CONDUCT.jsonl` ourselves after
the batch is public. Dated batches are kept.

## Corrections

A published `batch_<date>/` directory is never rewritten.
A correction is a new `batch_<correction-date>/` plus one append-only row on
`RUNS.jsonl` with a `corrects` field naming the earlier batch.
The old batch and its hashes stay.
If an author later edits the registry description, the observed version stays;
the later edit is a new note, not a rewrite of the observation.

