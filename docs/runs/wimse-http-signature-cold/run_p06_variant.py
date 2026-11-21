import os as _os_, tempfile as _tf_
_HERE = _os_.path.dirname(_os_.path.abspath(__file__))
_SCR = _os_.environ.get("WIMSE_TMP", _tf_.gettempdir())
import sys,re
sys.path.insert(0,_HERE)
sys.path.insert(0,(_HERE + "/reader"))
import run_positives as P, wimse_cold_reader as R
m=P.message("P-06")
fixed=m.replace('"@query""workload-identity-token"','"@query" "workload-identity-token"')
print("strict RFC 8792 unfold has no space:", '"@query""workload' in m)
out=R.verify_request(fixed,now=P.NOW,trusted_aud=P.AUD,issuer_jwk=P.ISSUER)
gb=P.PH.sub(lambda mm:P.WITS[mm.group(1)],P.given_base("P-06"))
print("with one space restored:",out[0],out[1],"label",out[2].get("label"),"base==given:",out[2].get("base")==gb)
# decoy sig1 check with other-key (information only)
oth=P.jwk_line("*other (decoy signer")
msg=R.parse_http(fixed); si=dict(R.SFParser(R.header(msg,"signature-input")).dictionary()); sg=dict(R.SFParser(R.header(msg,"signature")).dictionary())
items,ps=si["sig1"][1],si["sig1"][2]
b=R.signature_base(items,ps,msg,None)
print("decoy sig1 verifies with other-key:",R.verify_with_jwk(oth,"Ed25519",b.encode(),sg["sig1"][1][1]), "| decoy base==given:", b==P.given_base("P-06",1))
