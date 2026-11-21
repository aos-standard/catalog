import os as _os_, tempfile as _tf_
_HERE = _os_.path.dirname(_os_.path.dirname(_os_.path.abspath(__file__)))
_SCR = _os_.environ.get("WIMSE_TMP", _tf_.gettempdir())
import sys,re
sys.path.insert(0,(_HERE + "/reader"))
import wimse_cold_reader as R
src=open((_HERE + "/upstream/draft-ietf-wimse-http-signature-08.txt")).read()
src="\n".join(l for l in src.split("\n") if not re.match(r"^(Salowey & Sheffer|Internet-Draft  |\f)",l))
def art(start,end):
    s=src.index(start); e=src.index(end,s)
    t=src[s:e]
    t=re.sub(r"\\\n\s*","",t)
    return "\n".join(l[3:] if l.startswith("   ") else l for l in t.strip("\n").split("\n")).strip()+"\n"
req=art("GET /gimme-ice-cream","\n\n                  Figure 2")
resp=art("HTTP/1.1 404 Not Found","\n\n                  Figure 4")
# undo blank-line between headers and body: response has "\n\n   No ice cream today."
req_m=R.parse_http(req.rstrip("\n"))
resp_m=R.parse_http(resp.rstrip("\n").replace("\n\nNo ice cream today.","\n\nNo ice cream today.\n"))
for m,r in ((req_m,None),(resp_m,req_m)):
    lab,items,ps,sig=R.find_wimse_signature(m)
    base=R.signature_base(items,ps,m,r)
    tok=R.header(m,"workload-identity-token"); import json
    jwk=json.loads(R.b64u_dec(tok.split(".")[1]))["cnf"]["jwk"]
    print(base[-200:]); print("sig ok:",R.verify_with_jwk(jwk,jwk["alg"],base.encode(),sig))
    try: R.check_digest(m); print("digest ok")
    except R.Reject as e: print("digest",e.code, len(m["body"]))
