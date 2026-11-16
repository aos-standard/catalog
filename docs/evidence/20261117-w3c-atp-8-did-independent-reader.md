---
url: https://github.com/w3c-cg/atp/issues/8#issuecomment-6931778426
api: https://api.github.com/repos/w3c-cg/atp/issues/comments/6931778426
created_at: 2026-11-16T22:51:28Z
fetched_at: 2026-11-16T22:51:58Z
body_sha256: 44025173c3175fcf3e6457ab9696ea1b8465ada9811dcf819da066b2b40144a6
note: comment body as served by the API, exact bytes below the second rule. Comment on w3c-cg/atp #8 (completion tracker, item 1): independent reader of the did:atp identifier rules, 11/11 (v1 10/11) on test-vectors.json blob c42a2d50, four proposed additions, two questions on the text. First contact with this repository. Record: docs/runs/w3c-atp-did-cold/ (fedc713)
---
An independent result for part of item 1, with its pins, scope and limits, as the 13 November update asks.

**Source pins:** `specs/did-atp/index.html` at `8e4f7ac`, and `test-vectors.json` git blob `c42a2d50` (the bytes PR #10 uses). **Implementation:** a reader written from the specification text only. It is Python, with `cryptography` for Ed25519 and OpenSSL 3.6.1 for ML-DSA-65 key generation from a seed. The vector generator, `/proof`, the SDK and PR #10's runner were not opened. **Scope:** identifier syntax, the `e1_`/`pq1_` fingerprints and pairwise derivation only. It does not cover resolution, the DID Document, either required signature or request binding, so it is not a complete-profile result.

**Result: 11/11 on v2, 10/11 on v1.** v1 was frozen before any comparison. It missed `pairwiseIdentifiers[2]` because my input split filed that vector's `saltHex` with the answers. v2 changes one line, which passes the salt through. Both pairwise dids match exactly. Each did is built from keys that OpenSSL generated from the HKDF seeds, not `@noble`, so the seed-determinism that "Recommended Derivation" relies on holds across two ML-DSA-65 implementations. Record: [`docs/runs/w3c-atp-did-cold/`](https://github.com/aos-standard/catalog/tree/fedc713/docs/runs/w3c-atp-did-cold).

**Negative controls.** I loosened one rule of the reader at a time. Four mutants are caught by the file and five are not. Four of the five are rules the text states outright, so I wrote one case for each in the file's format ([`proposed/`](https://github.com/aos-standard/catalog/tree/fedc713/docs/runs/w3c-atp-did-cold/proposed)):

- `did:ATP:agents.example.com`. Method Name: the prefix MUST be lowercase.
- an `e1_` of the right length with one non-base64url character.
- `did:atp:agents.example.com:e1_…:pq1_…`, which has no path segment (`1*(":" path-segment)`).
- a 31-byte master secret, which the derivation MUST refuse (at least 32 bytes).

I am not a CG participant. Treat these as review input. If the CG wants them as test-suite contributions, I understand that needs membership first.

**Two questions on the text.**
1. `invalidIdentifiers[0]` refuses `did:atp:Agents.Example.com`, but this document makes only the method name lowercase and does not define `domain-name`. If the rule comes from did:wba, one sentence here would let the vector be read from this text alone.
2. `path-segment` admits a segment that looks like a binding (`…:billing:e1_<43>:e1_<43>:pq1_<43>`). Is that intended? My reader refuses it, but the ABNF accepts it and no vector decides.

Disclosure: assisted by AI (Claude). I ran the reader myself and remain responsible for what is claimed here.
