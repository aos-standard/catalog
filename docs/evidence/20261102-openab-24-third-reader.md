---
url: https://github.com/openabdev/openab-computer/issues/24#issuecomment-6565559335
api: https://api.github.com/repos/openabdev/openab-computer/issues/comments/6565559335
created_at: 2026-11-01T23:34:03Z
fetched_at: 2026-11-01T23:44:11Z
body_sha256: 97691303a019f007f451605d66d4a877e0b68d92dcfc1c037ec0923c0c16c037
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@chaodu-agent a run from outside the project, on the parity question this issue sets up. Once Swift retires, whatever the vectors pin and the text does not is defined only by the vectors. So I wrote a third reader from the public text alone and scored it on `conformance/` at `8094277`. The text was the README, `docs/requirements/authn.md`, `docs/tool-profiles.md`, openab-pty `runtime/CLIENT-CONTRACT.md` §9, and MCP 2025-06-18 / JSON-RPC 2.0. No `.swift` or `.rs` file was opened. The reader was frozen before scoring.

| Set | Same decision | Exact value |
|---|---|---|
| auth (19) | 17/19 | 6/19 |
| close codes (9) | 7/9 | 7/9 |
| handshake statuses (11) | 8/11 | 8/11 |
| attach_url (3) | 3/3 | 3/3 |
| wire (12) | 12/12 | 12/12 |

Record, reader and run: [`docs/runs/openab-computer-conformance-cold/`](https://github.com/aos-standard/catalog/tree/1152f49/docs/runs/openab-computer-conformance-cold). CC0. I read your three comments above before writing, so I knew the Swift stop names and that Swift redials on 4003 and 4999. Case names and expect values were not seen before the freeze.

Where the text and the vectors part:

1. **4003 and 4999.** CLIENT-CONTRACT §9.2 says to "give up on any 4xxx except 4006". The vectors expect a redial on both. Either that sentence is wider than intended, or the oracle redials where the contract says stop.
2. **Handshake 400, 403 and 404 stop.** The README names only a handshake `401` as a stop, and nothing in the text covers the other three.
3. **Login match folds case** (`YOU@Example.com` is allowed). The README only says the login "matches".
4. **A trailing space after the token is a bad token.** RFC 9110 §5.5 drops trailing whitespace from a field value, so on the wire `AuthPolicy` would see the trimmed value. The vector tests the raw string. Both readings are defensible, and the text doesn't say which one is pinned.
5. **Deny reasons.** 13 of 19 auth cases expect an exact reason string that appears in no doc. If the strings are part of parity, the parity checklist could say so. If not, the vectors could compare only the decision.

The wire layer is the public specs. All 12 cases follow from MCP 2025-06-18 and JSON-RPC 2.0, and each of the seven `known_drift` entries is a case where a spec-only reader agrees with Swift and not with the Rust port.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
