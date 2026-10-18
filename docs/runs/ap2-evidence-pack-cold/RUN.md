# ap2-evidence-pack/1.0 (SPEC 1.5.x) — an independent clean-room verifier, 26/26

Answering SPEC §7 ("Independent implementations: open a PR to be listed in the README conformance
table") and the exchange on google-agentic-commerce/AP2#338. At `f03abbc` the README lists two
verifiers by the format's author (Python reference, JS). This is a third, by someone else.

| | |
|---|---|
| Subject | `robertolocatelli81-dev/ap2-evidence-pack@f03abbc` (tag `v1.5.3`): `SPEC_AP2_EVIDENCE.md` revision 1.5.x, `spec/vectors/ap2/` 26 vectors (7 ACCEPT, 19 REJECT) with `expected.json` |
| Run date | 2026-10-18 (UTC 02:30–03:20) |
| Environment | Ubuntu 22.04, CPython 3.10.12; `cryptography` 46.0.3 (ES256, Ed25519, P-256 ECDSA); OpenSSL 3.6.1 via the `openssl` binary for ML-DSA-65 (`mldsa_backend: true`) |
| Verifier | `ap2_cold_verifier.py` — first scored run at sha256 `318ac886…` (`FROZEN_FIRST_RUN.txt`), amended once to `638bb3b7…` (`FROZEN_SECOND_RUN.txt`, see below) |
| Written from | `SPEC_AP2_EVIDENCE.md` §1–§9 and the input shape of the vectors. The JSON profile parser, the canonical form, the SD-JWT disclosure resolution, the KB-JWT checks, the RFC 3161 `TimeStampResp` walk, the §9.1 closed-schema checks and the §4 binding search are the file's own |
| Not opened | `ap2_evidence.py`, `verifiers/` (Python, JS, `lax_python_ablation.sh`, `differential_oracle.py`, `schema_mutants.py`), `interop/`, the `test_*.py` files, `spec/vectors/ap2/*.py` (the generators and `run_ap2_conformance.py`) |
| Answer exposure | The `expected.json` blocks were on screen while the vectors' input shape was inspected, before the verifier was written. So: a third implementation of §6 from the text, consistent with the 26; not a blind read |

## Result

| run | agree | the one difference |
|---|---|---|
| first scored run (`318ac886…`) | **25 / 26** | `anchors_unknown_mechanism`: this verifier refused `anchors[0]: unknown key "proof_b64" (SPEC §9.1)`; expected is `anchors[0]: mechanism "bitcoin-ots" is not defined by this revision (SPEC §3.3)` |
| after one change (`638bb3b7…`) | **26 / 26**, 0 SKIP | — |

The change: read `mechanism` before scanning an `anchors[i]` entry for unknown keys. §9.1 lists an
entry's keys *per mechanism* ("for `rfc3161`: `tsr_b64`…"), so for an undefined mechanism there is
no key list to judge against; §3.3 says such an entry "is a refusal naming it". The first run had the
scans in the other order. Twelve normative fields compared on every vector; `report.ignored` on the
three vectors that carry it; `report.refused` text, exactly, on the three that carry it.

All 26 inputs' sha256 are in `run_f03abbc.json`. Refusal and artifact-error texts produced:

| vector | this verifier's text |
|---|---|
| `anchors_empty` | `top level: anchors must be a non-empty list (SPEC §9.1)` |
| `anchors_unknown_key` | `anchors[0]: unknown key "x_unknown_2026" (SPEC §9.1)` |
| `anchors_unknown_mechanism` | `anchors[0]: mechanism "bitcoin-ots" is not defined by this revision (SPEC §3.3)` |
| `unknown_key_anchor_block` | `rfc3161_timestamp: unknown key "additional_anchors" (SPEC §9.1)` |
| `unknown_key_top_level` | `top level: unknown key "retention_profile" (SPEC §9.1)` |
| `unknown_key_artifact` | artifact error `artifacts[0]: unknown key "issuer_verified" (SPEC §9.1)` |
| `header_crit_unknown` | artifact error: `crit` present (RFC 7515 §4.1.11, no extension understood) |
| `kb_jwt_typ_missing` | artifact error: KB-JWT `typ` is not `kb+jwt` (RFC 9901 §4.3) |

## Where the text left this verifier a choice (fixed before the first run unless stated)

1. **`producer_trusted` when the block is not `ok`.** §5 defines it over "every present signature's key"
   when a pinned set is supplied. This verifier reports `null` when the block itself fails
   (`digest_mismatch`, `unknown_key_producer_entry`: `producer_ok: false`, pinned set present or not),
   and a boolean only when the block is `ok`. The 26 agree with that reading; the text could also be
   read as "false whenever any key is unpinned".
2. **`bindings_ok` when an artifact fails.** §6 step 3 recomputes bindings from resolved claims; with an
   artifact that did not verify there is nothing to recompute from. This verifier reports `false`
   (`header_crit_unknown`, `kb_jwt_typ_missing`, `unknown_key_artifact`, all with `bindings: []`).
3. **A KB-JWT that verifies false** is that artifact's error (§6 step 2, "a KB-JWT that verifies FALSE
   does"); a KB-JWT without `cnf.jwk` is recorded `verified: null` and never fails the pack.
4. **Order inside `anchors[i]`** — the one change after the first run, above.
5. **`self_asserted_only`** is always `true` here: this verifier takes no `--trust-anchor` and so never
   validates an x5c chain (§6 step 7, "offline and without an anchor, every class is self-asserted").
   `chain_verified` is `null`. No vector carries an `x5c`.
6. **ML-DSA-65** is checked by wrapping the raw 1952-byte key in a SubjectPublicKeyInfo and calling
   `openssl pkeyutl -verify -rawin` (OpenSSL 3.6). Without that binary the entry would be SKIP and the
   block never `ok`, as §5 requires.

## What this does and does not show

- Agreement on 26 vectors written by the format's author, by a reader who had seen their expected
  blocks. It shows §6 is implementable from the text and the 26 are consistent with it. It is not a
  review of the reference or JS verifiers (not opened) and not a mutation study of the vectors (the
  repository carries its own, `verifiers/lax_python_ablation.sh` and `schema_mutants.py`, not run here).
- `tsa_verified`, `chain_verified`, `x5c_leaf` are not implemented (no `--tsa-cert` / `--trust-anchor`);
  the vectors' policies do not exercise them.
- The real TSA token in `anchor_valid` is checked for binding only (§3.2), as the expected block states.

## Files

`ap2_cold_verifier.py`, `run_conformance.py`, `first_run_f03abbc.json` (25/26, at `318ac886…`),
`run_f03abbc.json` (26/26), `FROZEN_FIRST_RUN.txt`, `FROZEN_SECOND_RUN.txt`, `FROZEN.txt` (sha256 of each).
