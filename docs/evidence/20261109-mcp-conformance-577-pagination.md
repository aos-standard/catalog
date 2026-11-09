---
url: https://github.com/modelcontextprotocol/conformance/issues/577
api: https://api.github.com/repos/modelcontextprotocol/conformance/issues/577
created_at: 2026-11-09T10:53:19Z
fetched_at: 2026-11-09T10:53:37Z
body_sha256: ab237d5696989b2b0200b2830bddd9de092b1b056976da6110d4b93455545258
note: issue body as served by the API, exact bytes below the second rule. Title: Client scenario: an empty-string `nextCursor` is not the end of results (pagination MUST NOT)
---
**The MUST.** `server/utilities/pagination` (2026-07-28): "Clients **MUST** treat cursors as opaque tokens … an empty string is a valid cursor and thus **MUST NOT** be treated as the end of results." Clients also "**MUST NOT** assume a fixed page size".

**What checks it today.** Nothing that I can find at `c37eec8`. No client scenario under `src/scenarios/client/` sends a paginated list. Among the server scenarios, cursors appear only in the skills and tasks extensions. The core `tools/list`, `resources/list` and `prompts/list` pagination is not exercised, and `requirements/2026-07-28.yaml` lists no pagination scenario. I searched the issues for "pagination" and "cursor" and found none on this.

**Why it is worth one scenario.** The mistake is a one-character one, and it appears in an official example. The library code of both SDKs walks pages until `nextCursor` is absent, which is right: TypeScript `_walkPages` loops `while (cursor !== undefined)` (`packages/client/src/client/client.ts` at `1e608ca`), and the Python client stops on `is None` (`src/mcp/client/client.py` at `77001c9`). But the Python SDK's `examples/snippets/clients/pagination_client.py` continues with `if result.next_cursor:`, which stops on `""`. The same SDK's `examples/stories/pagination/client.py` says the opposite in a comment: "terminate on absent, NOT on falsy: "" is a valid cursor". Code that copies the snippet passes every current scenario.

**A possible shape, one scenario with several checks:**

- The test server's `tools/list` returns page 1 with one tool and `nextCursor: ""`, and page 2 with the tool the client is asked to call and no `nextCursor`.
- The everything-client is told to call the page-2 tool.
- Checks: (1) a second `tools/list` is sent with `cursor: ""`; (2) the cursor sent is byte-identical to the one received, so it is treated as opaque; (3) the page-2 tool is called; (4) no third `tools/list` is sent after a page without `nextCursor`.
- Failing case: the same client with the stop condition changed to a truthiness check fails (1) and (3).

I have not written or run this. `npm install` is not available where I work, so I cannot yet show the pass and fail runs that CONTRIBUTING asks for. Opening this first, as CONTRIBUTING asks, to check whether a scenario like this is wanted and whether it belongs under `core` before anyone writes it.

Disclosure: assisted by AI (Claude). I read the files cited above myself and remain responsible for what is claimed here.
