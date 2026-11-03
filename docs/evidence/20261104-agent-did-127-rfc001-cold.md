---
url: https://github.com/edisonduran/agent-did/issues/127
api: https://api.github.com/repos/edisonduran/agent-did/issues/127
created_at: 2026-11-03T23:14:35Z
fetched_at: 2026-11-03T23:14:55Z
body_sha256: 6b89c2408722b22f0a37fef14a3d75da78607f6c36e6619c298bcadc6b148783
note: issue body as served by the API, exact bytes below the second rule; title "[RFC] Third-party reader of the RFC-001 fixtures: blind 46/46, and none of the §6.5 HTTP verification rules is pinned"
---
### Change type

Interoperability concern

### RFC section or subsection

§6.5 HTTP Signing (items 2–6), §7.2 Interoperability Fixtures; also §4.3, §6.1, §6.2.1

### What is the problem or ambiguity?

The compliance checklist (SHOULD-03) asks to "add third-party vectors as external implementations mature". Here is an outside reader of the RFC-001 fixtures at `37a3190`, written from RFC-001, the anti-replay guide and the referenced RFCs only (no `sdk/`, `sdk-python/`, `integrations/` or test file opened or run), and scored once:

| Fixture | Agreement |
| --- | --- |
| `jcs-vectors.json` (6 documents, 26 numbers) | 32/32 |
| `canonical-document-reference.json` | 1/1 |
| `metadata-commitment-vectors.json` | 5/5 |
| `interop-vectors.json` (message signature, `Content-Digest`, rebuilt signature base byte for byte, HTTP verdict; legacy and `did:webvh`) | 8/8 |

The expected values were sealed until the reader was frozen. Record, reader, runs and pins: [`docs/runs/agent-did-rfc001-cold/`](https://github.com/aos-standard/catalog/tree/38720e6/docs/runs/agent-did-rfc001-cold). CC0.

I then changed one rule of the reader at a time and reran the fixtures. JCS, `documentRef`, the commitments and the message-signing bytes are pinned well. **The §6.5 verification rules are not pinned at all.** Both HTTP vectors are valid signatures, so a verifier that accepts too much still passes. Each of these keeps 46/46:

1. `tag="agent-did"` not checked
2. `alg="ed25519"` not checked
3. `now <= expires` not checked
4. `created` skew not checked
5. `expires >= created` not checked
6. `keyid` not required to be a method of the `Signature-Agent` DID
7. `Content-Digest` not checked against the body
8. The seven components accepted in any order
9. `signature-agent` dropped from the required components
10. `nonce` not required
11. A repeated `(keyid, nonce)` accepted
12. A missing `Date` header accepted

The two requests also leave `@query` without a query, an explicit default port in `@authority`, and re-serialization of `@signature-params` (item 4) unreached. No vector reaches `key_purpose_violation` or a `keyAgreement`-only key (§6.2.1).

Two places where the text left a choice and the vectors settled it:

- §4.3: the fixture's `salt` is a hex string. Read as hex, it is the 32-byte key; read as UTF-8, it would be 64 bytes.
- §7: `signMessage` does not say which bytes are signed. The vectors show the UTF-8 payload with a hex signature.

### Proposed change

Add rejecting HTTP vectors to `interop-vectors.json`, one per rule in §6.5 items 2, 3, 5 and 6, each a single change from the valid request, with the reason a verifier should report. For example: `tag="web-bot-auth"`, `now` after `expires`, a body that does not match `Content-Digest`, a `keyid` under another DID, components reordered, and the same request verified twice. Add one request with no query and one with an explicit `:443`.

Optionally, one sentence each in §4.3 (how a salt is written when carried as text) and §7 (the bytes `signMessage` signs).

### Compatibility or implementation impact

Fixture-only. No SDK change unless an SDK fails a new vector. The `tag` case matters most: the anti-replay guide relies on `tag` to keep a web-bot-auth signature from being accepted as an Agent-DID one, and nothing tests that today.

### Related references

RFC 9421 §2.2.7 and §2.5, RFC 9530, `docs/Anti-Replay-HTTP-Signatures.md`, `docs/RFC-001-Compliance-Checklist.md` SHOULD-03.

Also small: the document in `canonical-document-reference.json` has `publicKeyMultibase: "z678cd8…"`, which is hex after the `z` and contains `0`, so it is not base58btc. It does not change `documentRef`, but a reader that validates the document before hashing it rejects it.

### Confirmations

- [x] I checked whether this topic is already covered in the RFC, README, or existing issues.
- [x] I understand that normative RFC changes may require coordinated updates across TS, Python, tests, fixtures, and docs.
