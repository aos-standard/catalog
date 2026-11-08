# The seven candidate cases through the decode step of the x402 Python SDK (`main` at `513dd66`)

Run on 2026-11-08 with CPython 3.10.12, stdlib only. No reader of this record was changed or run here.

The decode step is the expression of `safe_base64_decode` in `python/x402/http/utils.py` at `513dd66`
(`base64.b64decode(data.encode("utf-8")).decode("utf-8")`), followed by `json.loads`, as the `decode_*_header`
functions do. The model step that follows in the SDK was not run. The cases are `../runs/candidates_c3e23c9.json`.

| File | What |
| --- | --- |
| `run_python_main_decode_layer.txt` | the decode step as in the SDK: 3 of the 6 candidates proposed as `reject` are accepted (`pad-extra`, `line-break`, `json-nan`) |
| `run_python_validate_true.txt` | the same with `validate=True`: `line-break` becomes a rejection, `pad-extra` and `json-nan` stay accepted |
| `upstream_pin_513dd66.txt` | sha256 of the SDK file read |

The candidates' expectations are this author's reading of RFC 4648 and RFC 8259 and have not been agreed. Go was not
run. Reported in x402 PR #4066 (comment 6717333958). CC0.
