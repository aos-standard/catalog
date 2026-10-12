# Independent run — acceptance-record vectors, 27 at `d750291` / `90b5032`

A fourth reader for the acceptance-record conditions
(x402-foundation/tsc#4, Shodai's table of 2026-10-04, plus
draft-krausz-verification-state-03 §5.4.2), written from the text and run on
the 27-vector corpus. Three implementations preceded it: the reference, actaseal's
(25-vector pin) and robertolocatelli81-dev's `x402-acceptance-check-omega`
(27-vector pin, posted the same morning this was written).

| | |
|---|---|
| Corpus | `babyblueviper1/preaction-governance-conformance`, `examples/acceptance-record-cold/vectors.json`, sha256 `4d01f3e72bdcbcca9e3e2a883ced0a87ae6c969f5cf6de4ef754dc63eb8ced0e`, 27 vectors. Same bytes at `d750291` (first run) and `90b5032` (re-run after the reference's small-order-key fix) |
| Run date | 2026-10-12 (UTC 02:45–03:30 first run; probes re-run 13:40 against `90b5032`) |
| Reader | `acceptance_cold_reader.py`, sha256 in `FROZEN_FIRST_RUN.txt` — Python, standard library, except Ed25519 verification via `cryptography` (not re-derived from RFC 8032) |
| Written from | the tsc#4 condition table; -03 §5.3.2, §5.4.1(h), §5.4.2; the prose of the corpus README at `d750291` (result tokens, evaluation order, readings A1–A8); the vectors' inputs and expectations |
| Not opened | `tools/acceptance_record_check.py`, `tools/_ed25519.py`, `build_vectors.py`, `run_vectors.py`; actaseal's `checker.py`, `ed25519_verify.py`, `run_vectors.py`; omega's `acceptance_check.py` and tests. Declared in `NOT_OPENED.txt` before the first line of code. The reference and omega were later **executed** as black boxes (`case.json` in, JSON out) for the probes below. |

## Result on the corpus

**27 / 27** on the first run (`first_run.json`, hash frozen before anything
else was done; `run.json` is the identical re-run). Compared: `result`,
`conditions` as sets, and `disposition` where the vector pins it. No reading
was changed after the run.

The README's four sentences of 2026-10-12 ("Inputs the vectors do not yet pin")
were adopted after this reader was written. They decide one of the probes
below against this reader (version), and this reader was not changed to match.

## Probes outside the corpus

Not vectors. Each is a fresh verified case (own throwaway keys, so payloads can
be re-signed) with one change, run through this reader, the reference checker
at `90b5032` and omega at `0496d58`, the last two as black boxes. `probe.py`
builds them; `probe_cases.json` holds the inputs; `probes.json` the outputs.
actaseal's checker exposes no command line and was not run.

### One rule enforced by two readers and written nowhere

| Probe | This reader | Reference | Omega |
|---|---|---|---|
| `accepted_at: "2026-10-04T18:05:00Z"` (no fraction) | verified | `acceptance_member_invalid` | `acceptance_member_invalid` |
| `accepted_at` with `+09:00`, same instant | verified | `acceptance_member_invalid` | `acceptance_member_invalid` |
| `accepted_at` with `+09:00`, earlier instant | `acceptance_precedes_outcome` | `acceptance_member_invalid` | `acceptance_member_invalid` |
| `outcome_at` (in the record) without fraction | verified | `acceptance_member_invalid` | `input_error` (exit 3) |

The reference and omega accept exactly one spelling of a timestamp,
`YYYY-MM-DDTHH:MM:SS.mmmZ`. The table says "timestamp"; the README says
nothing; every vector happens to use that form. A reader that parses RFC 3339
verifies records both of them reject, and in the third row never reaches the
ordering rule. That is the finding most worth a sentence in the README, or a
vector — and it is where this reader is probably the one that should change.

### Other disagreements with the reference (3)

| Probe | This reader | Reference | Omega | Note |
|---|---|---|---|---|
| `alg: "ES256"` in the protected header, Ed25519 signature valid | verified | `acceptance_member_invalid` | `acceptance_member_invalid` | §5.4.2 speaks of `kid`; `alg` is not mentioned in the table or README. Two readers check it. |
| Protected header without `kid` | `key_unresolved` | `acceptance_member_invalid` | `acceptance_member_invalid` | §5.4.2(a) is "the `kid` is not in the trust material". An absent `kid` is a case the text does not name. |
| `acceptance_version: "acceptance-record-v1"` | verified | `acceptance_member_invalid` | `acceptance_member_invalid` | **Settled against this reader** by README sentence 3 (2026-10-12). Left as written to show what a reader built from the earlier text did. |

### Where the three agree and the text is silent

| Probe | All three | Note |
|---|---|---|
| `accepted_record_sha256` over the five fields A4 lists (no `record_id`) | `acceptance_record_digest_mismatch` | The digest is over the record **as supplied**; the vectors' records carry `record_id`. A4's list is one field short of what the vectors hash. |
| Record without `record_id`, digest over those five | verified | Consistent: the preimage is whatever record is supplied. |
| `confirming_party: "   "` | `unknown` / `acceptance_authority_unresolved` | Whitespace is not "names no confirming party"; it falls through to authority. |
| Payload JSON with whitespace (non-canonical) | verified | The signature covers the payload bytes as given. |
| Unknown extra payload member | verified | Now README sentence 1. |
| `key_unresolved` together with a digest mismatch | `key_unresolved` only | Key step stops evaluation. |

### Where omega refuses what the other two accept (relying-party input)

| Probe | This reader | Reference | Omega |
|---|---|---|---|
| `trust_material_complete: "true"` (string), key resolves | verified | verified | `input_error` |
| `trust_material_complete: "true"` or `1`, key unresolved | `key_unresolved`, no `policy_refusal` | same | `input_error` |
| Duplicate `kid` in trust material, signer is the second | `signature_invalid` (first wins) | `signature_invalid` | `input_error` |

Omega treats a non-boolean completeness flag and a duplicate `kid` as input
outside the grammar (its exit 3). The reference and this reader silently take
"not complete" and "first key wins". -03 says only that omitting the input is
not a declaration of completeness.

## What this run does not establish

- Nothing about the acceptance-record proposal beyond these files at these commits.
- The probes are one reader's guesses at loose rules, not a suite; the throwaway keys are not test material anyone else should reuse.
- Ed25519 is not independently implemented here.
- No endorsement or integration either way.

## Reproduce

```bash
git clone https://github.com/babyblueviper1/preaction-governance-conformance && cd preaction-governance-conformance
git checkout 90b5032
python3 -I /path/to/run_cold.py examples/acceptance-record-cold/vectors.json        # 27/27, exit 0
python3 -I /path/to/probe.py "$(pwd)" /any/dir [/path/to/x402-acceptance-check-omega]
```

Run assisted by AI (Claude). The maintainer of this repository ran the commands
and is responsible for what is claimed here.
