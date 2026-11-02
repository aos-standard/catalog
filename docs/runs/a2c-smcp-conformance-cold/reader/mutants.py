#!/usr/bin/env python3
"""One rule removed or changed at a time from the frozen v1 reader; a survivor keeps full agreement, so no vector pins that rule.
Usage: mutants.py <a2c_check_v1.py> <fixtures dir> <out.json>"""
import json, subprocess, sys, tempfile, hashlib
from pathlib import Path
src = Path(sys.argv[1]).read_text(); F = sys.argv[2]; score = Path(__file__).with_name("score.py")
MUT = [
 ("B1 no fold of '_' runs", 's = re.sub(r"_{2,}", "_", s)', 's = s'),
 ("B2 '-' folded too", 's = re.sub(r"_{2,}", "_", s)', 's = re.sub(r"_{2,}", "_", re.sub(r"-{2,}", "-", s))'),
 ("B3 no trim", 'return s.strip("_-")', 'return s'),
 ("B4 trim '_' only", 'return s.strip("_-")', 'return s.strip("_")'),
 ("B5 lower-cased", 'return s.strip("_-")', 'return s.strip("_-").lower()'),
 ("B6 Unicode \\w kept", 'c if c in ASCII_BID else "_" for c in name', 'c if (c in ASCII_BID or c.isalnum()) else "_" for c in name'),
 ("B7 iterate UTF-8 bytes", 'c if c in ASCII_BID else "_" for c in name', 'chr(c) if chr(c) in ASCII_BID else "_" for c in name.encode()'),
 ("T1 map keys unsorted", 'keys = sorted(m)', 'keys = list(m)'),
 ("T2 list without count", 'b.append(struct.pack(">I", len(args)))', 'pass'),
 ("T3 map without count", 'b.append(struct.pack(">I", len(keys)))', 'pass'),
 ("T4 little-endian lengths", 'b.append(struct.pack(">I", len(raw)) + raw)', 'b.append(struct.pack("<I", len(raw)) + raw)'),
 ("T5 hash first 4 bytes", '.digest()[:8].hex()', '.digest()[:4].hex()'),
 ("T6 type omitted", '    _str(b, t)\n', '    pass\n'),
 ("T7 args sorted", 'for a in args:', 'for a in sorted(args):'),
 ("T8 explicit bundle_id normalized", 'return cfg["bundle_id"]', 'return normalize_name(cfg["bundle_id"])'),
 ("E1 env folds '_' runs", 'return "".join(c if c in ASCII_ENV else "_" for c in s)', 'return re.sub(r"_{2,}", "_", "".join(c if c in ASCII_ENV else "_" for c in s))'),
 ("E2 env trims", 'return "".join(c if c in ASCII_ENV else "_" for c in s)', 'return "".join(c if c in ASCII_ENV else "_" for c in s).strip("_")'),
 ("E3 env upper-cases", 'return "".join(c if c in ASCII_ENV else "_" for c in s)', 'return "".join(c if c in ASCII_ENV else "_" for c in s).upper()'),
 ("E4 env keeps '-'", 'c if c in ASCII_ENV else "_" for c in s', 'c if (c in ASCII_ENV or c == "-") else "_" for c in s'),
 ("E5 env per UTF-8 byte", 'c if c in ASCII_ENV else "_" for c in s', 'chr(c) if chr(c) in ASCII_ENV else "_" for c in s.encode()'),
 ("E6 env per UTF-16 unit", 'c if c in ASCII_ENV else "_" for c in s', 'c if c in ASCII_ENV else "_" for c in s.encode("utf-16-le").decode("latin-1")[::2]'),
 ("E7 tool segment dropped", '    if tool_name is not None:\n        out += "_" + env_segment(tool_name)\n', ''),
 ("E8 old prefix", 'out = "A2C_SMCP_" + env_segment(input_id)', 'out = "A2C_INPUT_" + env_segment(input_id)'),
 ("P1 NUL accepted", 'if inp == "" or "\\x00" in inp:', 'if inp == "":'),
 ("P2 '..' at root not clamped (error)", '            if out:\n                out.pop()\n            continue', '            if not out:\n                raise InvalidPath\n            out.pop()\n            continue'),
 ("P3 trailing '/' kept", 'return "/" + "/".join(segs)\n    # windows', 'return "/" + "/".join(segs) + ("/" if inp.endswith("/") and segs else "")\n    # windows'),
 ("P4 drive letter kept as given", 'drive = s[0].upper()', 'drive = s[0]'),
 ("P5 \\\\.\\ accepted", '    if inp.startswith("\\\\\\\\.\\\\"):\n        raise InvalidPath', '    if False:\n        raise InvalidPath'),
 ("P6 UNC after \\\\?\\ accepted", '        if s[:4].upper() == "UNC\\\\":\n            raise InvalidPath', '        pass'),
 ("P7 UNC check case-sensitive", 'if s[:4].upper() == "UNC\\\\":', 'if s[:4] == "UNC\\\\":'),
 ("P8 '/X:' canonical form not stripped", '    if re.match(r"^/[A-Za-z]:(/|$)", s):', '    if False:'),
 ("P9 bare '/X:' not completed", '        if len(s) == 2:\n            s += "/"', '        pass'),
 ("P10 component ':' allowed", 'WIN_BAD = set(\'<>:"|?*\')', 'WIN_BAD = set(\'<>"|?*\')'),
 ("P11 control chars allowed", '| {chr(c) for c in range(1, 0x20)}', '| set()'),
 ("P12 trailing '.' allowed", 'or seg.endswith(".") or', 'or'),
 ("P13 trailing space allowed", 'or seg.endswith(" "):', ':'),
 ("P14 component check after '..' pop (skips '..'-adjacent)", 'if windows and seg != "..":', 'if windows and seg != ".." and not seg.startswith(".."):'),
 ("P15 '?' allowed", 'WIN_BAD = set(\'<>:"|?*\')', 'WIN_BAD = set(\'<>:"|*\')'),
 ("P16 '<' '>' '|' '\"' '*' allowed", 'WIN_BAD = set(\'<>:"|?*\')', 'WIN_BAD = set(\':?\')'),
 ("P17 posix backslash as separator", 'segs = _segments(inp, windows=False)', 'segs = _segments(inp.replace("\\\\", "/"), windows=False)'),
 ("P18 posix relative accepted", '        if not inp.startswith("/"):\n            raise InvalidPath', '        pass'),
 ("P19 percent-decoding", 'segs = _segments(inp, windows=False)', 'import urllib.parse\n        segs = _segments(urllib.parse.unquote(inp), windows=False)'),
]
rows = []
for name, old, new in MUT:
    assert src.count(old) == 1, (name, src.count(old))
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "m.py"; p.write_text(src.replace(old, new)); o = Path(td) / "o.json"
        subprocess.run([sys.executable, "-I", "-B", str(score), str(p), F, str(o)], capture_output=True, text=True)
        d = json.loads(o.read_text()); caught = [r["set"] + ":" + str(r["id"]) for r in d["rows"] if not r["agree"]]
        rows.append({"mutant": name, "survives": not caught, "caught_by": caught})
        print(("SURVIVES " if not caught else "caught   ") + name, caught[:3])
Path(sys.argv[3]).write_text(json.dumps({"reader_sha256": hashlib.sha256(src.encode()).hexdigest(), "mutants": rows}, indent=1, ensure_ascii=False) + "\n")
print(sum(r["survives"] for r in rows), "of", len(rows), "survive")
