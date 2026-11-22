---
url: https://github.com/edisonduran/agent-did/issues/127#issuecomment-7080661840
api: https://api.github.com/repos/edisonduran/agent-did/issues/comments/7080661840
created_at: 2026-11-22T14:35:48Z
fetched_at: 2026-11-22T14:36:20Z
body_sha256: 08a9f35b4a647a210e4c306daf18e084182d59f343f437328f9970bf838871c8
note: comment body as served by the API, exact bytes below the second rule. Rerun asked for by edisonduran in #127 (7064981675), who wrote that the first run landed in v1.0.0-rc.5 and named the record. Unchanged reader 39/42 (3 rc.5 wire changes); rc.5 HTTP reader 84/84 verdicts, 82/84 reasons; 29/36 mutants caught, five gaps; 7 proposed vectors isolate 7/7. Record: docs/runs/agent-did-rfc001-cold/rerun-rc5-76b4f73/ (acd4403)
---
@edisonduran Thank you, and here is the rerun you asked for, on `v1.0.0-rc.5` (`76b4f73`). Record: [`rerun-rc5-76b4f73/`](https://github.com/aos-standard/catalog/tree/acd4403/docs/runs/agent-did-rfc001-cold/rerun-rc5-76b4f73).

- **The first reader, unchanged**, on the four files it read before: 39/42. The three misses are the rc.5 wire changes (`Agent-DID`, and the `agent-did/v1/message` prefix), not disagreements.
- **A new reader for the rc.5 HTTP profile**, written from RFC-001 §6.2.1, §6.2.3 and §6.5, the Anti-Replay guide and ADR-006, and frozen before any expected value was read: **84/84 verdicts** on `http-verification-vectors.json` and 4/4 on the interop vector. 82/84 reasons match the guide's table.

The mutation battery confirms that the twelve gaps are closed: 29 of 36 mutants are caught. Five things still pass every vector:

1. **A forged request consumes the nonce.** §6.5 item 6 records the pair only after the signature verifies, but a verifier that records it first passes, because the one sequence vector repeats a valid request.
2. **Replay in the last second.** The `NonceStore` contract keeps the pair through `expires` inclusive. No replay is tried at `now == expires`, so a store that drops it at `expires` passes.
3. **URL rules, for a verifier that reads the URL as written.** 9 of the 16 `reject-url-*` vectors are signed over the components a normalizing parser derives (`?mode=hello%20world`, `/v1/verify`, `xn--bcher-kva.example`, `[2001:db8::1]`). A verifier with an RFC 3986 split that skips the rule still rejects them, on the signature. The apostrophe, IPv6 and percent-encoded dot-segment checks can each be dropped without any vector noticing.

Seven proposed vectors cover these, using the fixture's own keys, DID, clock, `Date` and body: two replay sequences, and five `*-literal` URL vectors signed over the components as written. For each one, the frozen reader gives the stated result and the reader without that rule does not (7/7). The forged-then-valid case needs two different requests against one store, so it uses a new `steps[]` field. Take, reshape or drop them as you like.

Two small text points, from the two reasons that differ:

- `reject-keyid-not-in-document` expects `keyid_not_authorized`. The guide's table defines `keyid_not_bound` as "`keyid` is not a key of the agent DID", which also reads onto a key the document does not list. One line saying which reason applies when the key is missing from the document would settle it.
- `https://0x5d.0xb8.0xd8.0x22/…`: §6.5 item 4 allows "a host that is lowercase ASCII", and this host is lowercase ASCII with no empty label. So the text as written lets it through, while a WHATWG parser reads it as `93.184.216.34`. My reader rejects it on the signature, not on `url_not_normalized`. The text could say that a host a URL parser reads as an IPv4 address is normalized only in dotted-decimal form.

Disclosure: assisted by AI (Claude). I ran the readers and the battery myself and remain responsible for what is claimed here.
