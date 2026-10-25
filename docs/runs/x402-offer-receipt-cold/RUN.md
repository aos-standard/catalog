# x402 Offer and Receipt extension — a clean-room verifier, on the JWS vectors (#3207) and the EIP-712 vectors (#3533)

**Date:** 2026-10-25 (run 01:03Z). **Spec:** `specs/extensions/extension-offer-and-receipt.md` at
x402-foundation/x402 `4241d56` (version 0.6), sha256 `51151bd2b7dd174bc4a44b712234c074e45ca6c752c44ce077a94a4d97596ae9`.
**Vectors:**
- JWS: `typescript/packages/extensions/test/vectors/offer-receipt-vectors.json` of PR #3207, head `96f7a71`
  (`cv-scvd/x402`), document version 2, sha256 `e10fd6b71395b4175ffb8695c27a738884b49b6c904f20683c39e27a364acf7c`.
- EIP-712: `https://pay.neuronto.com/.well-known/conformance/offer-receipt-eip712-vectors.json` (issue #3533),
  document version 2, sha256 `b21170d81a093e0ba1735b7821910187f64b78b4a4376bf7b786cacb7afd86fd`.

Neither vector file is copied here; fetch them and check the hashes.

| | |
|---|---|
| Written from | the specification text above, and the input shape of the two vector files |
| Not opened | `@x402/extensions` (the reference implementation), the PR's `offer-receipt-vectors.test.ts`, any generator script |
| What was on screen | **answer-exposed.** Both files carry `expect` and `reject_at` next to each input, and they were read while the input shape was learnt. Two readings, R7 and R9, were fixed after that (see below) |
| Language / deps | Python 3.10.12, standard library only. Keccak-256 and Ed25519 (RFC 8032) are this catalog's own code, from its evm-log and E6 runs. secp256k1 recovery, ES256K, the EIP-712 encoding and EIP-55 are written in `x402_offer_receipt.py`. Cross-check: OpenSSL 3.6.1 |
| Frozen before the first scored run | `FROZEN_FIRST_RUN.txt`: `x402_offer_receipt.py` `4cafed70…af5` and `run_offer_receipt.py` `9841ad1f…02b` (01:03:41Z). Neither changed after. The cross-check and the battery were edited after their first runs, and each edit is recorded there |
| Mode / authorship | an alternate implementation from the text. This catalog wrote the verifier and none of the vectors, keys or the reference |

## 1. Result — 26/26

`first_run_output.txt`, `first_run.json` (`c6bddedc…8997`). The agreement rule is the files' own: accept every `valid`
entry and reject every `invalid` one. A rejection at a different layer from `reject_at` is still conformant.

- **JWS (EdDSA over Ed25519): 13/13.** The three valid ones decode to exactly the vector's `payload`. Every
  rejection lands at the vector's own `reject_at` (parse, alg, kid, signature, schema).
- **EIP-712 (secp256k1): 13/13.**
  - The struct hash of each of the four valid artifacts equals the vector's `structHash`.
  - The domain separators and type hashes, computed from the spec's types alone, equal the file's `constants`.
  - The domain `chainId` 8453 trap, the altered amount and the wrong-case domain name are rejected as "recovered
    signer is not a configured signer". The file puts these at `signature` (see R9).

The run's clock was 1792890221 (2026-10-25T01:03:41Z). Both `offer_expired_but_wellformed` vectors are accepted
and reported `expired: true` (R10).

## 2. Cross-check — 20/20 signature decisions, `xcheck_openssl_output.txt`

- **JWS:** OpenSSL re-verified each Ed25519 signature over the same signing input, and agrees on all 12 that
  decode.
- **EIP-712:** for each of the 8 artifacts that reach recovery, OpenSSL verified (r, s) over the same digest with
  the key this verifier recovered. The authorized address, re-derived by OpenSSL from the published test seed,
  matches the file's `signing.address`. The unauthorized vector recovers to the file's `unauthorized_address`.

## 3. Lax variants — 11/11 caught, `lax_battery_output.txt`

Each variant breaks one rule. In this battery a crash counts as not accepting.

- **JWS:**
  - alg taken from the header (`none`, and HS256 keyed with the public key)
  - kid optional
  - no signature check
- **Both formats:**
  - no payload schema
  - no receipt schema
  - expired offers rejected
- **EIP-712:**
  - chainId taken from the payment network
  - types taken from the artifact
  - an omitted optional field signed as empty
  - signature without authorization
  - any v byte

All are caught. One is caught narrowly, as noted below.

## 4. Readings and findings

- **R7: an omitted optional EIP-712 field is a schema failure.** §4.3 and §5.3 say signers MUST set unused fields to
  `0` / `""`, and §4.5 step 3 says the payload is used exactly as transmitted. But §6's JSON schemas leave
  `validUntil` and `transaction` out of `required`, so a payload without them is schema-valid there. The vectors
  (both `*_omitted_*` cases) take the first reading. This reader was set to it after seeing them. The §6 schemas and
  the §4.3/§5.3 rule would agree if §6 listed both fields as required for `eip712`.
- **The omission vectors catch a lax reader unevenly.** A reader that fills an omitted field with its empty value
  and then checks the signature accepts `receipt_optional_field_omitted_not_empty`, whose signature is over
  `transaction: ""`. It still rejects `offer_optional_field_omitted_not_zeroed`, because that signature does not
  verify with `validUntil: 0`. So only the receipt vector separates the two readings. An offer counterpart signed
  over `validUntil: 0` would catch it for offers too.
- **R9: signature versus authorization (EIP-712).** With recovery, an altered payload and an unauthorized key both
  come out as a signer the verifier did not configure. The file's `recovery_note` says this. This reader reports
  both at `authorization`. Telling them apart would take a list of known keys, which the spec does not define.
- **Not exercised by either file:**
  - ES256K, which the spec gives as an example and which is implemented here but untested.
  - A JWS `kid` the verifier does not know.
  - A payload `version` other than 1.
  - Unknown payload fields (rejected here, R5).
  - An EIP-712 `network` that is not `eip155:<id>`, and an EIP-55 checksum failure.
  - Receipt `issuedAt` policy.

## Files

`x402_offer_receipt.py` (the verifier; its docstring lists R1–R11), `run_offer_receipt.py`, `xcheck_openssl.py`,
`lax_battery.py`, the four outputs, `FROZEN_FIRST_RUN.txt`, `SHA256SUMS`. Rerun:

```
python3 -I -B run_offer_receipt.py offer-receipt-vectors.json offer-receipt-eip712-vectors.json 1792890221 first_run.json
```

CC0 for the files here.
