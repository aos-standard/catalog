---
url: https://github.com/FG-TIDA/themes/issues/66#issuecomment-7063898429
api: https://api.github.com/repos/FG-TIDA/themes/issues/comments/7063898429
created_at: 2026-11-21T14:11:55Z
fetched_at: 2026-11-21T14:13:01Z
body_sha256: 79d91d5e74f2b6eb6730c1a2ebe692cd9fc571b41f4d0142e0f8de35b731a51c
note: comment body as served by the API, exact bytes below the second rule. First contact with ITU-T FG-TIDA: clean-room reader on the 29 WIMSE HTTP signature vectors (draft-miao-wimse-http-signature-test-vectors-00), 26/26 applicable agree; three text points; 39-mutant battery, 25 survive; 10 proposed negatives isolate 10/10. Record: docs/runs/wimse-http-signature-cold/ (ef1cbb4)
---
@HUIIIM An independent run of the seed corpus, from the text only. I wrote a reader from draft-ietf-wimse-http-signature-08 §3, workload-creds §5.1 and RFC 9421/8941/9530, without opening any implementation. I froze it before reading any vector body or expected outcome, and ran it on the 29 vectors as printed in draft-miao-wimse-http-signature-test-vectors-00. Zenodo refused this network, so the I-D text was the source. Record: [`wimse-http-signature-cold/`](https://github.com/aos-standard/catalog/tree/ef1cbb4/docs/runs/wimse-http-signature-cold).

**Result: 26 of the 26 cases a verifier can show agree.** That is all 6 positives (each given signature base equals the reader's byte for byte), all 17 message negatives, and N-17, N-20 and N-22 as verifier behavior. N-16, N-18 and N-19 are about senders and servers, so a reader cannot show them.

Three things in the text:

1. **P-06 folding.** The `Signature-Input` fold falls between `"@query"` and `"workload-identity-token"`. RFC 8792's single-backslash rule strips all leading whitespace from the continuation line, so the strict unfold is `"@query""workload-identity-token"`, which is not a valid inner list. With the one space restored, P-06 verifies.
2. **The WIT placeholder.** §2 defines `[WIT-x, full text in the Test Key Material section]` and says it is "retained verbatim in the signed material". The messages print `[WIT-A，§2 全文]` (12 times), and the signatures are over the full token: they all verify with it substituted and none verify with the placeholder kept.
3. **Against -09** (published 2026-11-20):
   - O-2 can close (#420).
   - N-20's "Section 5.1.4" now reads Section 5.1.3 of workload-creds-03 (#422).
   - P-04 already matches the clarified CONNECT `@authority` (#419).
   - The new server-nonce MAY (#369) has no vector yet.

On question 2 (what a vector is, as a record), one result may be useful. I turned off one check of the frozen reader at a time (39 mutants) and reran the set. 25 mutants pass every vector:

- **No WIT-only negative.** Nothing catches a missing check on the WIT issuer signature, `typ`, `exp`, `cnf.jwk.alg` or `sub`.
- **No missing-coverage negative for most components.** Request: `@method`, `@path`, Workload-Identity-Token, Content-Type, Content-Digest and Authorization. Response: `@status`, the `;req` components and Workload-Identity-Token.
- **No future `created`.**
- **N-01, N-03 and N-05 carry the old signature over.** A verifier without that coverage, digest or `expires` check still rejects them, on the signature.
- **N-08 does not say which key re-signs `sig1`.**

So a vector can have the right expected outcome without isolating the requirement it points to. A record field such as "signature regenerated: yes/no" or "isolates: <requirement>" would make that checkable.

The record has ten proposed negatives, one per gap (`proposed/proposed_vectors.json`), with the draft's keys, WITs and clock. For each one, the frozen reader rejects it and the mutant that drops the named rule accepts it (10/10). They are yours to take, reshape or drop.

Disclosure: assisted by AI (Claude). I ran the reader and the battery myself and remain responsible for what is claimed here.
