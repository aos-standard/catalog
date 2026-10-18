# Addendum — ap2-evidence-pack 1.6.0 (`a01867e`, tag v1.6.0): one defect in this verifier, found by the maintainer; v2 with the fix

**Date:** 2026-10-19 (JST morning). **Trigger:** the maintainer (robertolocatelli81-dev) ran this verifier, unchanged, against the 42 vectors of 1.6.0 and reported 37/42, naming one disagreement as a defect of this verifier (AP2 #338, 2026-10-18T18:44Z). This addendum reproduces that run, records the defect, and freezes a v2 whose only change is the fix.

## 1. Unchanged verifier on 1.6.0 — reproduced

| | |
|---|---|
| Source | tarball of commit `a01867e` (tag `v1.6.0`), fetched 2026-10-19; `spec/vectors/ap2`: 42 packs / 42 expected files |
| Verifier / runner | `ap2_cold_verifier.py` `638bb3b7…a9beb5`, `run_conformance.py` `baaa481c…3899bd` — both unchanged since `RUN.md` |
| Environment | Ubuntu 22.04, CPython 3.10.12, `cryptography` 46.0.3, OpenSSL 3.6.1 (`mldsa_backend: true`) |
| Result | **37/42 AGREE, 0 SKIP** — the same five disagreements the maintainer listed. Output `run_v160_unchanged.json` sha256 `ebe61e69…f787d` |

The five, sorted by cause:

| vector | cause | whose |
|---|---|---|
| `holder_sd_hash_mismatch` | **defect of this verifier.** A KB-JWT whose ES256 signature verifies under `cnf.jwk` but whose `sd_hash` does not match `issuer-JWT~disclosure*~` was recorded (`sd_hash_ok: false`, `verified: false`) but did not fail the artifact; only a false signature raised. RFC 9901 §7.3 step 5.g makes the `sd_hash` check part of verifying the KB-JWT, and SPEC §6 step 2 fails the pack on a KB-JWT that verifies false. The 1.5.x text read "ES256 over `issuer-JWT~disclosure*~`"; 1.6.0 spells the rule out. The reading was available from the RFC the SPEC cites; this verifier did not take it | ours |
| `unknown_key_artifact`, `unknown_key_producer_entry` | 1.6.0 changes §9.1: an unknown key inside an artifact or a producer signature entry now refuses the pack. Under 1.5.x it was that artifact's error, which is what this verifier does | intended change of 1.6.0 |
| `issuer_x5c_ca_certified`, `time_tsa_invalid` | need the new policy keys `trust_anchor` / `tsa_cert` (X.509 chain validation to a given anchor; TSA signature under a given certificate). Not implemented here, as `RUN.md` already states | not implemented |

## 2. v2 — the fix and nothing else

`ap2_cold_verifier_v2.py` sha256 `187b0dd21634ca90ce836e196d65adc336a2deccc3cbfbb25334728cdbe1cd45`. Diff against v1 is two lines after the signature check in the KB-JWT branch:

```
                if not sd_hash_ok:  # v2 (2026-10-19): RFC 9901 §7.3 step 5.g — the sd_hash check is part of verifying the KB-JWT
                    raise ValueError("KB-JWT sd_hash does not match issuer-JWT~disclosure*~ (RFC 9901 §7.3)")
```

`run_conformance_v2.py` (`b400f8c6…a052e`) differs from `run_conformance.py` only in the import. Neither reads `requires_backend` (§7); on this host the ML-DSA-65 backend is present, so that does not affect the scores below.

| vector set | v1 (unchanged) | v2 |
|---|---|---|
| 1.5.3 `f03abbc` (26) | 26/26 | **26/26** (`run_v2_f03abbc.json`, byte-identical to the v1 output) |
| 1.5.4 `c08128e` (29) | 29/29 | **29/29** (`run_v2_c08128e.json`, byte-identical to the v1 output) |
| 1.6.0 `a01867e` (42) | 37/42 | **38/42** (`run_v2_a01867e.json` `5149782d…72a1a5`) — remaining four as in §1 |

The fix was made after reading the maintainer's description of the failing case and the expected file. v2 is therefore not a cold reading of that vector; it is a correction of a verifier that had already been scored against it.

## 3. Files

`ap2_cold_verifier_v2.py`, `run_conformance_v2.py`, `run_v160_unchanged.json`, `run_v2_f03abbc.json`, `run_v2_c08128e.json`, `run_v2_a01867e.json`, `FROZEN_V2.txt` (sha256 of all of the above, taken after the runs). v1 files are unchanged.
