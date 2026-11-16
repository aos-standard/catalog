# did:atp: an independent reader of the identifier rules on the published vectors, 11/11

An independent reader for the did:atp DID method (W3C Agent Trust Protocol CG draft), written from
`specs/did-atp/index.html` at `w3c-cg/atp` `8e4f7ac` and nothing else from the CG. The vector generator, `/proof`,
the ATP SDK and PR #10's runner were not opened. Python standard library, plus `cryptography` for Ed25519. ML-DSA-65
keys are generated from their seeds with OpenSSL 3.6.1 (`genpkey -pkeyopt hexseed`), not with `@noble/post-quantum`.
Run on 2026-11-16 (UTC) on `test-vectors.json`, git blob `c42a2d50`, the same bytes PR #10 uses.

**Scope:** identifier syntax, the `e1_` and `pq1_` fingerprints, and pairwise derivation. It does not cover DID
resolution, the DID Document, either required signature, or request binding. This is not a result for the complete
selected profile.

| Group | Cases | Same as the file |
| --- | ---: | ---: |
| `rootIdentifiers` | 1 | 1 |
| `pathIdentifiers` (both JWKs, `e1`, `pq1`, `did`) | 2 | 2 |
| `pairwiseIdentifiers` (`peerSegment`, `did`) | 3 | 3 |
| `invalidIdentifiers` (refused) | 5 | 5 |
| **Total** | **11** | **11** |

## v1 10/11, v2 11/11

The reader was frozen before any expected value was compared (`FROZEN_V1.txt`). v1 missed `pairwiseIdentifiers[2]`,
because my input split filed that vector's `saltHex` with the answers, so v1 never received it. v2 changes one line:
`run()` passes `saltHex` to the derivation (`FROZEN_V2.txt`, `atp_did_reader_v1.py` kept beside it). The derivation
itself is unchanged. Between the two runs I saw that the field exists and that the vector's `did` and `peerSegment`
differed. I did not see their expected values.

The two pairwise derivations reproduce the file's `did` exactly. Each did is built from an Ed25519 key and an
ML-DSA-65 key that two different libraries generated from HKDF-SHA256 seeds. So the "deterministic function of a
32-byte seed" that "Recommended Derivation" relies on holds across implementations.

## Which rules the vectors exercise

`mutation_battery.py` loosens one rule of the v2 reader at a time (`runs/mutation_battery_v2.json`).

| Loosened rule | Caught by |
| --- | --- |
| uppercase domain accepted | `invalidIdentifiers[0]` |
| fingerprint length not checked | `invalidIdentifiers[3]` |
| `pq1_` segment optional | `invalidIdentifiers[1]` |
| salt ignored | `pairwiseIdentifiers[2]` |
| method name compared case-insensitively | none |
| fingerprint alphabet not checked | none |
| path-type DID with no path segment accepted | none |
| master secret shorter than 32 bytes accepted | none |
| domain port form not checked | none |

## Four proposed additions

`proposed/test-vectors-additions.json` holds three invalid identifiers and one refused pairwise input. Each one tests
a rule the text states in so many words:

- `did:ATP:agents.example.com`. Method Name: the prefix "MUST be lowercase".
- An `e1_` fingerprint of the right length with one character outside base64url (`base64url-char`).
- `did:atp:agents.example.com:e1_…:pq1_…` with no path segment (`1*(":" path-segment)`).
- A 31-byte master secret. Recommended Derivation: "MUST be at least 32 bytes".

`check_proposed.py` shows that the frozen reader refuses each one, and that the mutant loosening exactly that rule
accepts it (`runs/check_proposed.txt`).

## Two questions on the text

- `invalidIdentifiers[0]` expects `did:atp:Agents.Example.com` to be refused. This document makes only the method
  name lowercase, and `domain-name` is not defined here. If the rule comes from did:wba, one sentence here would let
  the vector be read from this text alone.
- `path-segment` allows a segment that itself looks like a binding, such as `…:billing:e1_<43>:e1_<43>:pq1_<43>`. My
  reader refuses `e1_` and `pq1_` prefixes inside the path. The ABNF accepts them, and no vector decides.

## Reproduce

Put the repository's `specs/did-atp/test-vectors.json` at `upstream/specs/did-atp/` next to `reader/`.

```
python -I split_inputs.py && python -I atp_did_reader.py ../inputs/given.json > run_v2.json && python -I score.py run_v2.json
python -I mutation_battery.py && python -I build_proposed.py && python -I check_proposed.py
```

Needs OpenSSL 3.5 or later on `PATH` for ML-DSA-65. Files: `reader/`, `runs/`, `proposed/`, `FROZEN_V1.txt`,
`FROZEN_V2.txt`, `upstream_pins_8e4f7ac.txt`, `SHA256SUMS`. Under the catalog's MIT license.
