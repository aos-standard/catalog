---
url: https://github.com/FG-TIDA/themes/issues/66#issuecomment-7080721382
api: https://api.github.com/repos/FG-TIDA/themes/issues/comments/7080721382
created_at: 2026-11-22T14:40:37Z
fetched_at: 2026-11-22T14:40:51Z
body_sha256: 52ea1713ab72f9f3703975cdfba368fd28aff5c5c2432a9478a0cfecf0c1e65d
note: comment body as served by the API, exact bytes below the second rule. Reply to zhaoxinghua09-cell (7063572126) on the Ed25519/EdDSA spelling: the text-only reader accepts both and agrees 26/26; no vector uses EdDSA, so the corpus does not pin the choice; one vector each way suggested. Record: docs/runs/wimse-http-signature-cold/ (ef1cbb4)
---
@zhaoxinghua09-cell I posted my run without having read yours, which landed a few minutes earlier. Sorry for talking past it. Two data points for your transition question:

- **The text-only reader takes both spellings.** I wrote it from -08 and workload-creds alone. It accepts `Ed25519` (RFC 9864, as -08's examples write it) and `EdDSA` (RFC 8037) for an OKP/Ed25519 key, and with that it agrees on all 26 verifier-decidable cases. It imports no WIMSE implementation, so it may serve as one data point for the independent-implementation tier while wimsey's release catches up. Record: [`wimse-http-signature-cold/`](https://github.com/aos-standard/catalog/tree/ef1cbb4/docs/runs/wimse-http-signature-cold).
- **The corpus does not pin the choice either way.** No vector uses the `EdDSA` spelling: the WIT headers and every Ed25519 `cnf.jwk` say `Ed25519`, and the one other workload key is ES256. So a verifier that accepts only `Ed25519` and one that accepts both get the same 29 results, while one that accepts only `EdDSA` fails closed, as wimsey 0.9.0 does. If -09 states what a verifier should do, one vector each way would make it checkable: the same message with the WIT and `cnf.jwk` re-issued under `alg: "EdDSA"`, with the expected outcome the text chooses.

Disclosure: assisted by AI (Claude).
