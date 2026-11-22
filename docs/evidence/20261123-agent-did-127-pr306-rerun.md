---
url: https://github.com/edisonduran/agent-did/issues/127#issuecomment-7087960331
api: https://api.github.com/repos/edisonduran/agent-did/issues/comments/7087960331
created_at: 2026-11-22T23:57:55Z
fetched_at: 2026-11-22T23:58:42Z
body_sha256: e78d252ecd38ae4f5dd35bc36713ac375d73604f204d850192783970ae6fb3e2
note: comment body as served by the API, exact bytes below the second rule. Rerun on #306 (d09ca9f) asked for in #127 (7084711440): same frozen reader, 94/95 verdicts as predicted (the difference is the reader's), all five rc.5 gaps caught, 32/35 mutants; one remaining gap (no accepted IPv6 host) with one proposed vector; my rc.5 IPv6 literal proposal withdrawn. Record: docs/runs/agent-did-rfc001-cold/rerun-pr306-d09ca9f/ (0ef1899)
---
@edisonduran Rerun on #306 (`d09ca9f`), with the same frozen reader and the same mutant definitions. Only the runner is new, and it runs `steps[]` as `usage` defines them. Record: [`rerun-pr306-d09ca9f/`](https://github.com/aos-standard/catalog/tree/0ef1899/docs/runs/agent-did-rfc001-cold/rerun-pr306-d09ca9f).

- **94/95 verdicts, as predicted before scoring.** The one difference is `reject-url-non-canonical-ipv4-literal`, which this reader accepts. That is the reader's fault, not the fixture's: it was written from the rc.5 text, and #306's new §6.5 item 4 sentence settles that case, as it does the `keyid_not_authorized` reason.
- **All five gaps are caught now.** Record-first by `accept-valid-after-forged-same-nonce`, the last second by `reject-replayed-at-expires`, and the apostrophe, encoded-dot and IPv6 mutants by their `-literal` twins. That makes 32 of 35 mutants. Two of the survivors only show how this reader is built.

The third survivor came from a defect in my own reader. It builds `@authority` from the parsed host name, so it drops the brackets of an IPv6 literal. It still passes all 95 vectors, because every IPv6 vector is a rejection. No vector accepts a request to an IPv6 host, so a verifier that mishandles the brackets only ever sees requests it should reject anyway. One proposed vector, `proposed-accept-ipv6-host`, covers it: an accepted request to `https://[2001:db8::1]/…`, signed over `"@authority": [2001:db8::1]` with the fixture's keys. My frozen reader rejects it and the same reader with the brackets kept accepts it. Take it or leave it.

On your question about my five literal vectors, I compared their `@authority`, `@path` and `@query` lines with yours. Four match exactly: space, dot segment, encoded dot segment and apostrophe. The IPv6 one does not. Mine was signed over `2001:db8:0:0::1` without brackets, which is the same defect again, and yours (`[2001:db8:0:0::1]`) is the right one. Please disregard my IPv6 literal.

Disclosure: assisted by AI (Claude).
