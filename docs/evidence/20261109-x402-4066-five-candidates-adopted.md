---
url: https://github.com/x402-foundation/x402/pull/4066#issuecomment-6727425653
api: https://api.github.com/repos/x402-foundation/x402/issues/comments/6727425653
created_at: 2026-11-08T21:33:54Z
fetched_at: 2026-11-09T10:51:38Z
body_sha256: aa0c4acfb4ff26eb4518d6dbe58918b8ea85d123be9406fa9fffc98b789e4eed
note: comment body as served by the API, exact bytes below the second rule. Commit 8046ff97e8ea693b37891742542cbab10960ee74 (2026-11-08T21:33:40Z) on the PR branch modifies specs/transports-v2/vectors/http_headers.json (+45) and README.md (+5 -1); its message reads 'Five reject cases from the candidates Tetsuroh Hori posted on the PR (CC0)'. PR #4066 not merged as of fetched_at.
---
@Tetsurohhori thanks, these were useful. 8046ff97 adds five of them as reject cases, built from the http.md examples like the existing ones:

| your candidate | case id |
|---|---|
| pad-extra | `padding-extra` |
| pad-inside | `padding-inside` |
| line-break | `alphabet-line-break` |
| json-nan | `json-nan` |
| json-trailing | `json-trailing` |

The TypeScript decoder already rejects all five, so this stays test-only and `fixture_version` stays 1 (adding a case doesn't bump it). Going by your run, Python on main accepts `padding-extra`, `alphabet-line-break` and `json-nan`.

I left out two:

- utf16-json: the README already puts bytes that aren't valid UTF-8, or that start with a BOM, under Not covered. Adding it would widen the file's scope, so I'd rather leave that to a separate decision.
- pad-bits-nonzero: as you say, it's a choice for the spec. It's now listed under Not covered, citing RFC 4648 section 3.5, which lets a decoder reject it and leaves the choice to the referring specification.

@erkancamli thanks as well for running Go and Python against the file.
