# Addendum, 2026-10-25 — two proposed JWS vectors for #3207

**This file is added beside `RUN.md` and changes nothing in it.** The files in `SHA256SUMS` (at `89e7a98`) are unchanged.

The author of the JWS set answered on x402-foundation/x402#3207 (2026-10-25T01:38:57Z). Their verifier and this one
disagree on two cases the set does not exercise, and in both the spec leaves the outcome open. `proposed/` builds one
vector for each, under the set's published test key (seed `0x42 * 32`):

| vector | what | this catalog's verifier | the set author's verifier (as reported) |
|---|---|---|---|
| `offer_unknown_kid` | correctly signed, header names a `kid` the verifier holds no key for | reject at `kid` (R3) | inconclusive, `key_unavailable` |
| `offer_extra_field` | correctly signed, the payload carries one member outside §4.2 (`note`) | reject at `schema` (R5) | accept |

`expect` is left empty for the set's author to choose.

- **Signatures:** `build_proposed.py` writes the Ed25519 signatures (RFC 8032 §5.1.6, its own code). It checks that the
  seed gives the published public key, and OpenSSL 3.6.1 verifies both signatures.
- **Verifier:** the verifier run on them is the frozen `x402_offer_receipt.py` (`4cafed70…af5`).

Files: `proposed/build_proposed.py`, `proposed/proposed-jws-vectors.json`, `SHA256SUMS-proposed-3207`. CC0.
