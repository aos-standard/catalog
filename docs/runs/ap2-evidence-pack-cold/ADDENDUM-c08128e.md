# Addendum — re-run of the unchanged verifier against ap2-evidence-pack 1.5.4 (`c08128e`, tag v1.5.4)

**Date:** 2026-10-18 (JST evening). **Why:** the format's maintainer (robertolocatelli81-dev) released 1.5.4 the same day, citing the first run (`556b982`, 26/26 at `f03abbc`) in the CHANGELOG. 1.5.4 adds three vectors and a `requires_backend` key to twelve expected files. This addendum records what the **unchanged** verifier does on the new set.

| | |
|---|---|
| Source | `robertolocatelli81-dev/ap2-evidence-pack` tarball of commit `c08128e` (tag `v1.5.4`), fetched 2026-10-18 via the GitHub API; `spec/vectors/ap2`: 29 packs, 29 expected files, 12 carrying `"requires_backend": ["ml-dsa-65"]` |
| Verifier | `ap2_cold_verifier.py` sha256 `638bb3b720745c86ce2f9a9a8799862c8e0652fb51465bef501678fab5a9beb5` — identical to the second run in `RUN.md` (not edited for 1.5.4) |
| Runner | `run_conformance.py` sha256 `baaa481c6b0efecaab0464d37cd90235fe83a030182bb72e49f5af22bc3899bd` — unchanged |
| Environment | Ubuntu 22.04, CPython 3.10.12, `cryptography` 46.0.3, OpenSSL 3.6.1 `openssl` binary for ML-DSA-65 (`mldsa_backend: true`) |
| Result | **29/29 AGREE, 0 SKIP** on the twelve normative fields, `report.ignored` and `report.refused` where carried. Output `run_c08128e.json` sha256 `35ffc5956a8d591402e0868192336291d636b8511985ddf37517c999ac626137` |

## What this does and does not show

- The three new vectors (`producer_classical_fails_pinned`, `producer_classical_fails_unpinned`, `producer_mldsa_fails_pinned`) agree without any change to the verifier. Per the 1.5.4 CHANGELOG, points 4 and 5 (`producer_trusted` null and `pq_protected` false on a producer block that is not `ok`) were written down from this verifier's behaviour. So on those three vectors this is **not** an independent reading of 1.5.4: the text was aligned to the code, then the code was re-run. The 26 vectors carried over from 1.5.3 keep the status of `RUN.md` (answer-exposed, SPEC-only, 25/26 then 26/26).
- `run_conformance.py` does **not** read `requires_backend`. It compares the normative block regardless. On this host the ML-DSA-65 backend is present, so the twelve marked vectors are scored and agree. On a host without the backend the unchanged runner would report those twelve as disagreements, not SKIP — the maintainer measured exactly that (14/26 on 1.5.3, 17/29 on 1.5.4 under OpenSSL 3.0.22). A runner honouring §7 should count them SKIP; this one was not changed for this addendum so that the numbers stay comparable with `RUN.md`.
- Nothing else was opened: `ap2_evidence.py`, `verifiers/`, `interop/`, the tests and `make_vectors_154.py` remain unread.

## Files

- `run_c08128e.json` — per-vector rows (`vector`, `input_sha256`, `status`, `diffs`, `refused`, `artifact_errors`)
- `FROZEN_C08128E.txt` — sha256 of the verifier, the runner and the output, taken after this run
