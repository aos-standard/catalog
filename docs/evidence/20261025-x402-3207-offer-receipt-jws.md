---
url: https://github.com/x402-foundation/x402/pull/3207#issuecomment-6391891972
api: https://api.github.com/repos/x402-foundation/x402/issues/comments/6391891972
created_at: 2026-10-25T01:22:05Z
fetched_at: 2026-10-25T01:22:51Z
body_sha256: baa6308dac42d676f351ad76095a4fe18ad1d1841b946ebfa81e11783dd56a72
note: exact copy of the comment body as served by the GitHub API at fetched_at; the row in CONDUCT.jsonl hashes this whole file
---
@cv-scvd a run of these 13 vectors outside `@x402/extensions`. I wrote a verifier from `specs/extensions/extension-offer-and-receipt.md` (`4241d56`, v0.6) and the input shape of `offer-receipt-vectors.json` at this PR's head `96f7a71` (sha256 `e10fd6b7…acf7c`), without opening `@x402/extensions` or `offer-receipt-vectors.test.ts`.

**13/13 under the file's rule.** All three valid ones are accepted and decode to exactly the vector's `payload`. Every invalid one is rejected at the layer `reject_at` names (parse, alg, kid, signature, schema). `offer_expired_but_wellformed` is accepted and reported as expired.

- Ed25519 is RFC 8032 code of my own, and OpenSSL 3.6.1 re-verified the same 12 signing inputs with no disagreement.
- `alg` is taken from the configured key for the `kid`, never from the header. Of the lax variants I ran against the set, "alg from the header" is caught by `offer_alg_none` and `offer_alg_confusion_hs256`, "kid optional" by `offer_no_kid`, and "no receipt schema" by `receipt_missing_payer`.
- Not exercised by the set: a `kid` the verifier does not know, a payload `version` other than 1, unknown payload fields, and ES256K, the spec's other example `alg`.

The limit on independence: the `expect` and `reject_at` fields were on screen while I read the input shape. Verifier, outputs and hashes: [`docs/runs/x402-offer-receipt-cold/`](https://github.com/aos-standard/catalog/tree/89e7a98/docs/runs/x402-offer-receipt-cold) (CC0). The same verifier also ran the EIP-712 set from #3533, and that result is reported there.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

