# openab-computer conformance vectors at `8094277`: a third reader from the public text

`conformance/` holds language-neutral vectors that the Swift daemon (the oracle) and the Rust port must both pass
(#24). This record asks a different question: how much of what the vectors pin can a third implementation get from the
**public text**, with no Swift or Rust source opened? The parity gate retires Swift. After that, whatever the vectors
pin and the text does not is defined only by the vectors.

Text used: `README.md` (Auth; Lending this Mac), `docs/requirements/authn.md`, `docs/tool-profiles.md`,
`docs/adr/reverse-attach.md`, openab-pty `runtime/CLIENT-CONTRACT.md` §9, MCP 2025-06-18, JSON-RPC 2.0, RFC 9110.

## First blind run (reader v1, frozen before scoring)

| Set | Same kind of decision (allow/deny, stop/redial) | Exact expected value |
| --- | --- | --- |
| `auth_vectors.json` (19) | 17/19 | 6/19 |
| `reverse_attach_vectors.json` close codes (9) | 7/9 | 7/9 |
| handshake statuses (11) | 8/11 | 8/11 |
| `attach_url` (3) | 3/3 | 3/3 |
| `mcp_wire_vectors.json` (12) | **12/12** | **12/12** |

Answer exposure: issue #24's comments were read before writing. They name the Swift stop reasons, say Swift redials on
4003 and 4999, and list the Linux drift fixed in #41. Case names, expect values and `known_drift` were not seen before
the freeze. The vector inputs and the types of the expect values were.

## Where the text and the vectors part

1. **Close codes 4003 and 4999.** CLIENT-CONTRACT §9.2 says "redial for the remainder of the grant, with backoff, and
   give up on any 4xxx except 4006." The vectors expect redial for both. Either the contract sentence is wider than
   intended (it may mean the four codes in its table), or the oracle redials where the contract says stop. The reader
   follows the text here on purpose, knowing from #24 what Swift does.
2. **Handshake 400, 403 and 404 stop.** The README's redial policy names only a handshake `401` as a stop. §9.2 says a
   missing session, a wrong secret, an expired grant and a disabled plane are all `401`. Nothing in the text says
   400, 403 or 404 stop. The reader redials on them.
3. **The login comparison folds case.** `YOU@Example.com` is allowed for `you@example.com`. The README says
   `--allow-login` "matches" `Tailscale-User-Login`. Nothing says the match is case-insensitive.
4. **A trailing space after the token is a bad token.** The reader trimmed it. RFC 9110 §5.5 excludes leading and
   trailing whitespace from a field value, so on the wire an HTTP stack hands `AuthPolicy` the trimmed value. The vector
   tests `AuthPolicy` with the raw string. Both are defensible, and the text does not say which one the vectors pin.
5. **Deny reasons.** 13 of the 19 auth cases expect an exact reason string (`bad token`, `Authorization must be Bearer`,
   `login evil@example.com not allowed`, `no Tailscale identity on request`, `unauthenticated`, `missing Authorization
   header`). None of them is in the text. The same holds for the stop names (`grantExpired` and the rest), which this
   reader took from #24. If reasons are part of the parity contract, the parity checklist could say so. If they are not,
   the vectors could compare the decision and leave the string out.

## The wire layer is the public specs

All 12 wire cases follow from MCP 2025-06-18 and JSON-RPC 2.0 alone: version negotiation, `-32700`, `-32600` for a
`jsonrpc` other than 2.0 and for a batch, `-32601`, `-32602` for an unknown tool and for a missing name, and no response
to a notification. Each of the seven entries in `known_drift` (what the Rust port returns today) is a case where a
reader of the MCP spec agrees with Swift and not with the Rust port.

## Files

| File | What |
| --- | --- |
| `reader/openab_check_v1.py` | the reader, frozen before scoring (readings O1–O10 in comments) |
| `reader/score.py` | scores a reader on the three files, by kind of decision and by exact value |
| `runs/run_8094277_v1.json` | the blind run, every case with expected and got |
| `upstream_pins_8094277.txt` | what was fetched, opened and not opened |

The same author wrote the reader and the readings. No Swift or Rust code was run, so nothing here says what either does
beyond the expected values the vectors publish. CC0.
