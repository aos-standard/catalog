---
url: https://github.com/eclipse-biscuit/biscuit/issues/202
api: https://api.github.com/repos/eclipse-biscuit/biscuit/issues/202
created_at: 2026-11-24T23:54:45Z
fetched_at: 2026-11-24T23:55:02Z
body_sha256: 209779dd6a1c7cc3066e85a82ba6013c7ff7fe8bab8ee398c5d804cc52fb90a7
note: issue body as served by the API (title: An independent reader of samples/current: 45/50, four text points, and 15 rules no sample reaches), exact bytes below the second rule. First contact with Eclipse Biscuit: verifier from SPECIFICATIONS.md and schema.proto, 45/50 on samples/current at b3d3fe2 and 50/50 revocation ids; four text points; 15 rules no sample reaches; 6 proposed samples isolate 6/6. Record: docs/runs/biscuit-samples-cold/ (7cc63df)
---
I wrote a verifier and authorizer from `SPECIFICATIONS.md` and `schema.proto` alone, and ran it on `samples/current` at `b3d3fe2`. I did not open any implementation or `samples/current/README.md`. It covers the protobuf format, Ed25519 and secp256r1 signatures (v0 and v1 payloads, third-party, sealed), symbol and key tables, the Datalog engine with origins and scopes, closures, and a parser for the authorizer code. I froze it before reading any expected value, then scored it once. Record: [`biscuit-samples-cold/`](https://github.com/aos-standard/catalog/tree/7cc63df/docs/runs/biscuit-samples-cold).

**Result: 45/50 on the outcome (allow and its policy, or the failed checks and policy, or the error kind), and 50/50 on revocation ids.** The five differences come from three places where the text leaves room:

1. **Expression errors** (`test027` overflow, `test032` shadowing, `test038` an uncaught error on the right of `try_or`). The text says "If it overflows, the expression fails" and that strict equality "fails with a type error". I read a failing expression as a rule that doesn't match, but the samples expect authorization to stop with an execution error. Both readings reject, but the error class differs. One sentence saying that an expression error aborts authorization would settle it.
2. **Unsafe rules** (`test018`). The text defines a safe rule, but not what an unsafe rule in a token leads to. The samples expect `FailedLogic/InvalidBlockRule`.
3. **`test035`** expects `true.extern::test()` to succeed and `"a".extern::test("a") == "equal strings"`. The spec leaves external calls to the implementation and doesn't name `test`, so this case can't be passed from the text. It would help to say what host function the sample assumes.

A fourth point came up while reading: **the v0 signature payload order.** The v0 list in "Signed payload generation" gives data, then `pk`, then `alg`. The sealing formula (`data_n + alg_n+1 + pk_n+1 + sig_n`) puts `alg` first, and the v0 sample tokens' signatures only verify with `alg` before `pk`. I took that order, and the record says so. The byte width of "the little endian representation" is also not stated. 32 bits works for every sample.

I then changed one rule of the frozen reader at a time and reran the 50 cases. **15 rules are not reached by any sample:**

- a matching `deny` policy treated as `allow`
- `nextSecret` not checked against the last public key
- a sealed token's `finalSignature` not checked
- third-party external signatures not checked
- datalog versions outside v3.0–v3.3 accepted
- third-party blocks below v3.2 accepted
- a symbol defined in two blocks accepted
- `previous` read as only the previous block
- `previous` honoured in the authorizer
- block-level `trusting` ignored
- a generated fact's origin not including the facts it came from
- `set.contains(set)` read as overlap instead of superset
- mixed-type sets accepted
- dates compared with integers
- floor instead of truncating division (the text doesn't say which)

Six proposed samples cover the first group. Each is built from a `samples/current` token with the samples' own root key, is byte-reproducible, and gives the expected result under my reader but not under the reader without that rule (6/6):

- **`deny if true;`** before `test012`'s authorizer: expect `Unauthorized` with policy `Deny(0)`.
- **`test012` with `check if !{1, 2}.contains({1, 3});`:** expect `Ok(0)`.
- **`test012` with an unrelated `nextSecret`:** expect a format error.
- **`test020` with one bit of `finalSignature` flipped:** expect a format error.
- **`test012`'s authority block at versions 7 and 2, re-signed:** expect format errors.

The files are in `proposed/` (CC0). The scope, external-signature and symbol gaps would need new multi-block tokens, so I haven't proposed those.

Disclosure: assisted by AI (Claude). I ran the reader, the battery and the proposals myself, and I remain responsible for what is claimed here.
