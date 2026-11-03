# Agent-DID RFC-001 fixtures at `37a3190`: an independent reader from the spec text, blind 46/46

RFC-001 §7.2 asks implementations to share versioned vectors, and the compliance checklist (SHOULD-03) asks to "add
third-party vectors as external implementations mature". This record is an outside reader of the four fixture files
that RFC-001 itself lists or that carry its §4.3 and §6.1 rules. It was written from the text without opening either
SDK and then scored once.

Text used: `docs/RFC-001-Agent-DID-Specification.md` (§4.3, §6.1, §6.2, §6.5), `docs/Anti-Replay-HTTP-Signatures.md`,
RFC 8785, RFC 9421 §2, RFC 8941, RFC 9530, RFC 2104, and the multibase/multicodec form of an Ed25519 key.

## First blind run (reader v1, frozen before scoring)

| Fixture | What is checked | Agreement |
| --- | --- | --- |
| `jcs-vectors.json` | canonical output of 6 documents, 26 numbers (2 must be rejected) | **32/32** |
| `canonical-document-reference.json` | `documentRef` (§6.1) | **1/1** |
| `metadata-commitment-vectors.json` | `hash://hmac-sha256/` (4) and legacy `hash://sha256/` (1) (§4.3) | **5/5** |
| `interop-vectors.json` | per vector (legacy, `did:webvh`): message signature, `Content-Digest`, rebuilt HTTP signature base, HTTP verdict | **8/8** |

The mismatch list is empty. The reader rebuilds the signature base from the request and compares it with the
fixture's `signatureBase` byte for byte. Answer exposure: the inputs of every vector were read before the freeze
(documents, values, salts, keys, signatures, request headers). No expected value, `signatureBase` or `contentDigest`
was read. `reader/split_inputs.py` sealed them, and the freeze hashes are in `FROZEN.txt`. The only expected-side
fact seen was that 2 of the 26 number vectors carry an `error` key. `webvh-log-vectors.json` and
`didwebvh-test-suite.json` are not scored: they test `did:webvh` log processing, which RFC-001 delegates to the
`did:webvh` specification.

Readings the text leaves open, as the reader took them:

- **A2:** the commitment `salt` in the fixture is a hex string. Read as hex, it is the 32-byte key §4.3 asks for. Read as
  UTF-8 text, it would be 64 bytes. Hex agrees with the vectors. §4.3 could say how a salt is written when it is
  carried as text.
- **A3:** §7 names `signMessage(payload, privateKey)` and `verifySignature(did, payload, signature)` but does not say
  which bytes are signed. Ed25519 over the UTF-8 bytes of the payload string, with a hex signature, agrees with the
  vectors.
- **A5/A6:** an HTTP vector carries a verification method but no DID document. So "an active key listed under
  `assertionMethod`" (§6.5 item 5) cannot be checked from the vector. The reader takes the given method as that key.

## What the vectors do not pin: one rule changed at a time

`reader/mutants.py` changes one rule of the frozen reader and reruns the vectors (`runs/mutants_37a3190_v1.json`).
12 of 29 mutants are caught. JCS is pinned well: every serialization mutant but one is caught. Key order, escaping,
the number formatting thresholds, `-0` and the `+` in exponents are all caught. So are the salt encoding, HMAC
argument order, timestamp normalization in `documentRef`, and the message-signing bytes.

**The HTTP verification rules are not pinned at all.** Both HTTP vectors are valid signatures, so a verifier that
accepts too much passes them. Each of these mutants keeps 46/46:

1. `tag="agent-did"` not checked (§6.5 item 3; the anti-replay guide says the tag keeps a web-bot-auth signature
   from being accepted as an Agent-DID one).
2. `alg="ed25519"` not checked.
3. `now <= expires` not checked.
4. `created` skew not checked.
5. `expires >= created` not checked.
6. `keyid` not required to be a method of the `Signature-Agent` DID.
7. `Content-Digest` not checked against the body.
8. The seven components accepted in any order (§6.5 item 2 says "in this order").
9. `signature-agent` dropped from the required components.
10. `nonce` not required.
11. A repeated `(keyid, nonce)` accepted (§6.5 item 6).
12. A missing `Date` header accepted.

Three signature-base rules are not reached by the two requests: `@query` when the URL has no query (RFC 9421 §2.2.7
gives `?`), an explicit default port in `@authority`, and re-serializing `@signature-params` from the parsed
`Signature-Input` (§6.5 item 4), since the fixture's header is already in canonical form. Two more survive:
`documentRef` computed with plain sorted compact JSON instead of JCS (the fixture document has only ASCII keys and no
numbers, so both give the same bytes), and duplicate member names accepted by JCS input parsing.

No vector reaches `key_purpose_violation` (§6.2.1), a `keyAgreement`-only key, the error shape of §6.2.1.1, or the
`documentRef` checks a resolver makes (§6.2 step 2: `id` mismatch, hash mismatch, no fallback after a failed check).

One small note: the document in `canonical-document-reference.json` has
`publicKeyMultibase: "z678cd8…"`, which is hex after the `z`. It contains `0`, which is not in the base58btc
alphabet, so it is not a decodable Ed25519 key. It does not affect `documentRef`, but a reader that validates the
document before hashing it rejects it.

## Reproduce

Fetch `fixtures/` at `37a3190` into `upstream/fixtures/` and check the hashes in `upstream_pins_37a3190.txt`. Then:

```
python3 -I -B reader/split_inputs.py upstream/fixtures blind
python3 -I -B reader/run_blind.py reader/agent_did_check_v1.py blind/inputs.json run.json <now>
python3 -I -B reader/score.py run.json blind/expected_SEALED.json
python3 -I -B reader/mutants.py reader/agent_did_check_v1.py blind/inputs.json blind/expected_SEALED.json <now>
```

`<now>` is a Unix time between `created` (1704067200) and `expires` (2704067199). The blind run used 1793746419.
`inputs.json` must hash to the value in `FROZEN.txt`. Needs Python 3 and `cryptography`.

## Files

| File | What |
| --- | --- |
| `reader/agent_did_check_v1.py` | the reader, frozen before scoring (readings A1–A6 in comments) |
| `reader/split_inputs.py` | separates the inputs from the expected values |
| `reader/run_blind.py` | runs a reader on the inputs only |
| `reader/score.py` | scores a run against the sealed expected values |
| `reader/mutants.py` | the one-rule-changed battery |
| `runs/run_37a3190_v1.json` | the blind run, with the wall-clock `now` used for the HTTP time checks |
| `runs/score_37a3190_v1.json` | every scored value, expected and got |
| `runs/mutants_37a3190_v1.json` | the battery |
| `FROZEN.txt` | hashes of the reader and inputs at the freeze |
| `upstream_pins_37a3190.txt` | what was fetched, opened and not opened |

The same author wrote the reader and the readings. No SDK code was opened or run, so nothing here says what either
SDK does beyond the values the fixtures publish. CC0.
