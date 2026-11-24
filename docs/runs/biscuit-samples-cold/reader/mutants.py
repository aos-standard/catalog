#!/usr/bin/env python3
"""One rule of the frozen reader changed at a time (source replacement); rerun the 50 cases.
A mutant is caught when a case the frozen reader agrees on (class and detail) stops agreeing.
usage: mutants.py READER inputs.json samples_dir expected_SEALED.json out.json"""
import json, sys, types, os, subprocess, tempfile
rd, inp, sd, exp, out = sys.argv[1:6]
SRC = open(rd).read(); here = os.path.dirname(os.path.abspath(__file__))
def score(src):
    with tempfile.TemporaryDirectory() as t:
        open(t + "/r.py", "w").write(src)
        subprocess.run([sys.executable, "-I", "-B", here + "/run_blind.py", t + "/r.py", inp, sd, t + "/run.json"], check=True, capture_output=True)
        s = json.loads(subprocess.run([sys.executable, "-I", "-B", here + "/score.py", t + "/run.json", exp], check=True, capture_output=True).stdout)
    return {r["n"]: (r["class_agree"] and r["detail_agree"] and r["revocation_ids_agree"], r["filename"]) for r in s["rows"]}
base = score(SRC)
M = [
 ("default scope trusts every block (no scoping)", "        sc = scopes or default_scopes or [(\"authority\",)]\n        t = {block_id, AUTHORIZER}",
  "        sc = scopes or default_scopes or [(\"authority\",)]\n        t = {block_id, AUTHORIZER} | set(range(len(self.token.blocks)))"),
 ("authority not trusted by default", "            if s[0] == \"authority\":\n                t.add(0)", "            if s[0] == \"authority\":\n                pass"),
 ("`previous` trusts only the previous block", "                    t.update(range(0, block_id + 1))", "                    t.update({block_id - 1, block_id})"),
 ("`previous` honoured in the authorizer", "                if block_id != AUTHORIZER:\n                    t.update(range(0, block_id + 1))", "                t.update(range(0, len(self.token.blocks)))"),
 ("public-key scope ignored", "                    if bl.external_key == s[1]:\n                        t.add(i)", "                    pass"),
 ("rule-level scope ignored (block default used)", "        sc = scopes or default_scopes or", "        sc = default_scopes or"),
 ("block-level scope ignored", "        sc = scopes or default_scopes or", "        sc = scopes or"),
 ("fact origin not checked (any fact usable)", "if o <= trusted]", "]"),
 ("generated fact origin omits the matched facts", "                new.append((fact, origin | {bid}))", "                new.append((fact, frozenset({bid})))"),
 ("`check all` passes when nothing matches", "        return any_match", "        return True"),
 ("`check all` treated as `check if`", "    if kind == \"all\":", "    if False:"),
 ("`reject if` treated as `check if`", "    return (not found) if kind == \"reject\" else found", "    return found"),
 ("authorizer checks skipped", "    for ci, (kind, qs) in enumerate(auth[\"checks\"]):", "    for ci, (kind, qs) in enumerate([]):"),
 ("deny policy treated as allow", "    if policy[0] == \"deny\":", "    if False:"),
 ("checks only of the authority block", "    for bid, bl in enumerate(tok.blocks):\n        for ci, (kind, qs) in enumerate(bl.checks):", "    for bid, bl in enumerate(tok.blocks[:1]):\n        for ci, (kind, qs) in enumerate(bl.checks):"),
 ("block signatures not verified", "        if not verify_sig(prev_pk, sig, msg):\n            raise FormatError(\"invalid block signature", "        if False:\n            raise FormatError(\"invalid block signature"),
 ("external signatures not verified", "            if not verify_sig(ext_pk, ext_sig, external_payload_v1(data, prev_sig, 1)):", "            if False:"),
 ("proof secret not checked against the last key", "        if public_from_secret(prev_pk[0], secret) != prev_pk[1]:", "        if False:"),
 ("sealed final signature not checked", "        if not verify_sig(prev_pk, bytes(proof[2][-1]), msg):", "        if False:"),
 ("v1 payload without PREVSIG", "    if prev_sig is not None:\n        p += b\"\\0PREVSIG\\0\" + prev_sig", "    if False:\n        p += b\"\\0PREVSIG\\0\" + prev_sig"),
 ("duplicate symbols across blocks accepted", "                raise FormatError(\"symbol defined twice\")", "                pass"),
 ("third-party block uses the token symbol table", "            dec = Decoder(syms, keys)                      # third-party", "            dec = Decoder(token_syms + syms, token_keys + keys)                      # third-party"),
 ("third-party symbols leak into following blocks", "        if ext_pk is None:\n            if set(syms)", "        if True:\n            if set(syms)"),
 ("datalog version not checked", "        if bl.version is None or not (MIN_VERSION <= bl.version <= MAX_VERSION):", "        if False:"),
 ("third-party block version not checked", "        if ext_pk is not None and bl.version < 5:", "        if False:"),
 ("unsafe rules accepted", "            if not rule_vars_safe(r[0], r[1]):\n                return {\"result\": (\"err\", \"format\", \"unsafe rule", "            if False:\n                return {\"result\": (\"err\", \"format\", \"unsafe rule"),
 ("strict equality across types is false, not an error", "        raise ExecError(\"strict equality between different types\")", "        return False"),
 ("lenient equality as strict", "    if name == \"heq\":\n        return (\"bool\", a == b)", "    if name == \"heq\":\n        return (\"bool\", _strict_eq(a, b))"),
 ("regex anchored (fullmatch)", "re.search(b[1], a[1]) is not None", "re.fullmatch(b[1], a[1]) is not None"),
 ("string length in characters", "            return (\"int\", len(a[1].encode(\"utf-8\")))", "            return (\"int\", len(a[1]))"),
 ("floor division", "            q = q if (x >= 0) == (y >= 0) else -q", "            q = x // y"),
 ("integer overflow wraps", "    if not (I64_MIN <= n <= I64_MAX):\n        raise ExecError(\"integer overflow\")\n    return (\"int\", n)", "    return (\"int\", ((n - I64_MIN) % (1 << 64)) + I64_MIN)"),
 ("set contains set = intersection non-empty", "                return (\"bool\", b[1] <= a[1])", "                return (\"bool\", bool(b[1] & a[1]))"),
 ("string contains not supported", "        if a[0] == \"str\" and b[0] == \"str\":\n            return (\"bool\", b[1] in a[1])", "        if False:\n            return (\"bool\", b[1] in a[1])"),
 ("&& evaluated eagerly", "        if name == \"lazyand\" and not a[1]:\n            return (\"bool\", False)", "        if False:\n            return (\"bool\", False)"),
 ("shadowing allowed", "                if p in env:\n                    raise ExecError(\"shadowing\")", "                if False:\n                    raise ExecError(\"shadowing\")"),
 ("array get out of bounds is an error", "            return a[1][i] if 0 <= i < len(a[1]) else (\"null\", None)", "            return a[1][i]"),
 ("map contains on values", "            return (\"bool\", any(k == b for k, _ in a[1]))", "            return (\"bool\", any(v == b for _, v in a[1]))"),
 ("typeof integer named int", "TYPE_NAMES = {\"int\": \"integer\"", "TYPE_NAMES = {\"int\": \"int\""),
 ("set homogeneity not checked", "                raise FormatError(\"set elements must have the same type\")", "                pass"),
 ("date compared with integer", "        if a[0] != b[0] or a[0] not in (\"int\", \"date\"):", "        if a[0] not in (\"int\", \"date\") or b[0] not in (\"int\", \"date\"):"),
]
rows = []
for name, a, b in M:
    assert SRC.count(a) >= 1, name
    try:
        got = score(SRC.replace(a, b, 1))
    except subprocess.CalledProcessError as e:
        rows.append({"mutant": name, "caught_by": [], "caught": None, "error": e.stderr.decode()[-300:]})
        continue
    caught = [got[n][1] for n in base if base[n][0] and not got[n][0]]
    rows.append({"mutant": name, "caught_by": sorted(set(caught)), "caught": bool(caught)})
json.dump({"baseline_agree": sum(v[0] for v in base.values()), "mutants": rows}, open(out, "w"), indent=1)
for r in rows: print("ERROR  " if r["caught"] is None else "CAUGHT " if r["caught"] else "SURVIVE", r["mutant"], ("<- " + ", ".join(r["caught_by"][:2])) if r["caught"] else "")
print(sum(1 for r in rows if r["caught"]), "of", len([r for r in rows if r["caught"] is not None]), "caught")
