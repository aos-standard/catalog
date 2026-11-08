---
url: https://github.com/x402-foundation/x402/pull/4066#issuecomment-6717333958
api: https://api.github.com/repos/x402-foundation/x402/issues/comments/6717333958
created_at: 2026-11-08T04:40:44Z
fetched_at: 2026-11-08T04:40:57Z
body_sha256: a7a9eeb8c05368ce25be73a309e224dd107563144c83a4e7c7e496b7abe88934
note: comment body as served by the API, exact bytes below the second rule. The Python decode-step runs it reports are in docs/runs/x402-http-headers-cold/sdk-python-513dd66/
---
@erkancamli thanks for running the SDKs. That matches the first observation in my earlier comment: only `alphabet-space` pins the strict alphabet, and a decoder that drops characters gets the other two alphabet cases rejected for a different reason.

I had also posted one candidate case for each of seven rules that no current case reaches ([`runs/candidates_c3e23c9.json`](https://github.com/aos-standard/catalog/blob/c3db1ad/docs/runs/x402-http-headers-cold/runs/candidates_c3e23c9.json), each one change from an `http.md` example). Through the decode step of Python on `main` (`513dd66`), `base64.b64decode` without `validate`, then `.decode("utf-8")`, then `json.loads`, without the model step:

| candidate | proposed | Python decode step |
| --- | --- | --- |
| `pad-extra` (`==` after a full quantum) | reject | accepted |
| `pad-inside` (`=` inside the value) | reject | rejected, by `json.loads` |
| `line-break` (CR LF inside the value) | reject | accepted |
| `utf16-json` (UTF-16 with a BOM) | reject | rejected |
| `json-nan` (`NaN` as a member value) | reject | accepted |
| `json-trailing` (data after the value) | reject | rejected |
| `pad-bits-nonzero` | no expectation (a choice for the spec) | accepted |

With `validate=True` (Python 3.10), `line-break` is rejected, but `pad-extra` is still accepted: the extra `==` after a full quantum passes. `json-nan` needs `parse_constant` or the model step to refuse it. I did not run Go: no toolchain here. The Go `encoding/base64` documentation says `\r` and `\n` are ignored, so `line-break` may be accepted there too.

The proposed expectations are my reading of RFC 4648 and RFC 8259, not agreed. If any are useful for this file or a follow-up, they are CC0.

Disclosure: assisted by AI (Claude). I ran the Python check above myself and remain responsible for what is claimed here.
