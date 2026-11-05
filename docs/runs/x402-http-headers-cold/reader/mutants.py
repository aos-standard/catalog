#!/usr/bin/env python3
"""One rule of the frozen reader changed at a time, rerun on the blind inputs and scored.
Usage: mutants.py <reader.py> <inputs.json> <expected_SEALED.json> <out.json>"""
import json, os, subprocess, sys, tempfile
reader, inputs, sealed, outp = sys.argv[1:5]
here = os.path.dirname(os.path.abspath(__file__))
src = open(reader).read()
LENIENT = '''def b64decode_strict(s: str) -> bytes:
    import base64 as _b
    return _b.b64decode(s + "===", validate=False)
def _unused(s: str) -> bytes:'''
M = [
 ("A1 lenient base64: characters outside the alphabet discarded (Python default)", "def b64decode_strict(s: str) -> bytes:", LENIENT),
 ("A2 URL-safe alphabet accepted as well ('-' read as '+', '_' as '/')", "    body = s.rstrip(\"=\")", "    s = s.replace('-', '+').replace('_', '/')\n    body = s.rstrip(\"=\")"),
 ("A1b lenient like Node Buffer.from(s, 'base64'): non-alphabet characters and '=' dropped, length not checked", "def b64decode_strict(s: str) -> bytes:", "def b64decode_strict(s: str) -> bytes:\n    import re as _re\n    s = _re.sub(r'[^A-Za-z0-9+/]', '', s)\n    s = s + '=' * (-len(s) % 4) if len(s) % 4 != 1 else s[:-1]"),
 ("A9 value percent-decoded before base64 (as if it were a URL component)", "    raw = b64decode_strict(value)", "    import urllib.parse as _u\n    raw = b64decode_strict(_u.unquote(value))"),
 ("A3 missing padding accepted", '    if len(s) % 4 != 0:\n        raise Reject("length not a multiple of 4")', '    if len(body) % 4 == 1:\n        raise Reject("length not a multiple of 4")\n    s = body + "=" * (-len(body) % 4)'),
 ("A4 non-zero pad bits rejected", "    return bytes(out)", "    if nbits and (bits & ((1 << nbits) - 1)):\n        raise Reject(\"pad bits\")\n    return bytes(out)"),
 ("A5 value trimmed of spaces and tabs before decoding", "    raw = b64decode_strict(value)", "    raw = b64decode_strict(value.strip(' \\t'))"),
 ("A6 CR and LF ignored (MIME-style line breaks)", "    raw = b64decode_strict(value)", "    raw = b64decode_strict(value.replace('\\r', '').replace('\\n', ''))"),
 ("A7 '=' inside the value accepted (concatenated quanta)", "    body = s.rstrip(\"=\")", "    s = s[:-2].replace('=', '') + s[-2:] if len(s) > 2 else s\n    body = s.rstrip(\"=\")"),
 ("A8 padding after a full quantum accepted", '    if pad and len(body) % 4 == 0:\n        raise Reject("padding after a full quantum")', ""),
 ("U1 invalid UTF-8 replaced, not rejected", 'text = raw.decode("utf-8")', 'text = raw.decode("utf-8", errors="replace")'),
 ("U2 latin-1 instead of UTF-8", 'text = raw.decode("utf-8")', 'text = raw.decode("latin-1")'),
 ("U3 leading BOM stripped", "    try:\n        v = json.loads(text", "    text = text.lstrip('\\ufeff')\n    try:\n        v = json.loads(text"),
 ("U4 bytes handed to the JSON parser (UTF-16/32 auto-detected)", "        v = json.loads(text, parse_constant=_no_constants)", "        v = json.loads(raw, parse_constant=_no_constants)"),
 ("J1 NaN and Infinity accepted", "        v = json.loads(text, parse_constant=_no_constants)", "        v = json.loads(text)"),
 ("J2 any JSON value accepted (no object check)", "    if not isinstance(v, dict):", "    if False:"),
 ("J3 arrays accepted as well as objects", "    if not isinstance(v, dict):", "    if not isinstance(v, (dict, list)):"),
 ("J4 duplicate member names rejected", "        v = json.loads(text, parse_constant=_no_constants)", "        v = json.loads(text, parse_constant=_no_constants, object_pairs_hook=_dupes)"),
 ("J5 trailing data after the JSON value accepted", "        v = json.loads(text, parse_constant=_no_constants)", "        v = json.JSONDecoder(parse_constant=_no_constants).raw_decode(text.lstrip())[0]"),
]
results = []
for name, a, b in M:
    assert a in src, name
    s = src.replace(a, b, 1)
    if name.startswith("J4"):
        s = s.replace("def decode_header(", "def _dupes(pairs):\n    keys = [k for k, _ in pairs]\n    if len(keys) != len(set(keys)):\n        raise Reject('duplicate')\n    return dict(pairs)\n\n\ndef decode_header(", 1)
    with tempfile.TemporaryDirectory() as td:
        s += "\n\n_inner = decode_header\n\ndef decode_header(value):\n    try:\n        return _inner(value)\n    except Reject:\n        raise\n    except Exception as e:  # a lax decoder that raises is counted as rejecting\n        raise Reject(type(e).__name__)\n"
        rp = os.path.join(td, "m.py"); open(rp, "w").write(s); run = os.path.join(td, "run.json")
        subprocess.run([sys.executable, "-I", "-B", os.path.join(here, "run_blind.py"), rp, inputs, run], check=True, capture_output=True)
        sc = json.loads(subprocess.run([sys.executable, "-I", "-B", os.path.join(here, "score.py"), run, sealed], check=True, capture_output=True, text=True).stdout)
    caught = sorted({m["run"].split("|")[0] for m in sc["mismatches"]})
    results.append({"mutant": name, "caught": bool(caught), "by": caught})
    print(("CAUGHT  " if caught else "SURVIVES") + "  " + name + ("  <- " + ", ".join(caught[:4]) if caught else ""))
json.dump(results, open(outp, "w"), indent=1, ensure_ascii=False)
print("caught %d of %d" % (sum(r["caught"] for r in results), len(results)))
