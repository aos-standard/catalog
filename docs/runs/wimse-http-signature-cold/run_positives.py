"""Extract P-01..P-06 messages from draft-miao-...-00 text and run the frozen reader."""
import os as _os_, tempfile as _tf_
_HERE = _os_.path.dirname(_os_.path.abspath(__file__))
_SCR = _os_.environ.get("WIMSE_TMP", _tf_.gettempdir())
import sys, re, json, hashlib
import os
sys.path.insert(0, os.environ.get("READER_DIR", (_HERE + "/reader")))
import wimse_cold_reader as R
V = open((_HERE + "/upstream/vectors_clean.txt"), encoding="utf-8").read()

def unfold(block):
    lines = block.split("\n")
    out = []
    for l in lines:
        l = l[3:] if l.startswith("   ") else l
        if out and out[-1].endswith("\\"):
            out[-1] = out[-1][:-1] + l.lstrip()
        else:
            out.append(l)
    return out

def section(vid):
    s = V.index(f"{vid} - ", V.index("\n4.  Positive Test Vectors\n"))
    e = V.index("\n4.", s + 10) if vid != "P-06" else V.index("\n5.  Negative", s)
    return V[s:e]

def wit(name):
    s = V.index(f"*WIT-{name}*")
    blk = V[s:].split("\n\n")[1]
    return "".join(x.strip().rstrip("\\") for x in blk.split("\n"))

WITS = {k: wit(k) for k in "ABC"}
def jwk_line(label):
    s = V.index(label); seg = V[s:s+600]
    m = re.search(r"Public JWK: (.*?)\n   Private", seg, re.S)
    return json.loads("".join(x.strip().rstrip("\\") for x in m.group(1).split("\n")))
ISSUER = jwk_line("*Issuer (WIT issuer)")
AUD = {"https://svcb.example.com/gimme-ice-cream", "https://svcb.example.com/inventory/cones",
       "https://svcb.example.com/status", "https://svcb.example.com"}
T0 = 1795000000; NOW = T0 + 60
PH = re.compile(r"\[WIT-([ABC])[^\]]*\]")

def message(vid, expand=True):
    sec = section(vid)
    body = sec.split("   Message:\n\n", 1)[1].split("\n\n   Signature base:", 1)[0]
    lines = unfold(body)
    txt = "\n".join(lines)
    if expand:
        txt = PH.sub(lambda m: WITS[m.group(1)], txt)
    if vid == "P-06" and os.environ.get("P06_RESTORE") == "1":  # author's evident intent: one space at the fold
        txt = txt.replace('"@query""workload-identity-token"', '"@query" "workload-identity-token"')
    if vid == "P-02":  # body is 'No ice cream today.\n' (20 bytes) per the entry text
        head, _, b = txt.partition("\n\n")
        txt = head + "\n\n" + b.strip("\n") + "\n"
    if vid == "P-03":  # body stated in prose, not in the artwork
        txt = txt.rstrip("\n") + "\n\n" + '{"flavor":"vanilla","amount":1}'
    return txt

def given_base(vid, which=0):
    sec = section(vid)
    parts = sec.split("   Signature base")[1:]
    blk = parts[which].split(":\n\n", 1)[1].split("\n\n   ")[0]
    return "\n".join(unfold(blk)).strip("\n")

if __name__ == "__main__":
    expand = "--literal" not in sys.argv
    print("issuer kid", ISSUER["kid"], "| placeholders expanded:", expand)
    results = {}
    p01 = message("P-01", expand)
    for vid in ["P-01", "P-02", "P-03", "P-04", "P-05", "P-06"]:
        m = message(vid, expand)
        if vid == "P-02":
            out = R.verify_response(m, request=p01, now=NOW, issuer_jwk=ISSUER)
        else:
            out = R.verify_request(m, now=NOW, trusted_aud=AUD, issuer_jwk=ISSUER)
        gb = given_base(vid)
        gb_exp = PH.sub(lambda mm: WITS[mm.group(1)], gb)
        mine = out[2].get("base")
        same = None if mine is None else (mine == gb_exp)
        results[vid] = {"outcome": out[0], "reason": out[1], "base_equals_given_expanded": same}
        print(vid, out[0], out[1] or "", "| base==given(expanded):", same)
    json.dump(results, open(os.environ.get("POS_PREFIX", "runs/positives_") + f"{'expanded' if expand else 'literal'}.json", "w"), indent=1)
