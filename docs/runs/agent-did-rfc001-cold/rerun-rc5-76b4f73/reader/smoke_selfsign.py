"""Self-signed smoke test of reader v2 (own key, own request; no fixture involved)."""
import importlib.util, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
spec = importlib.util.spec_from_file_location("r", sys.argv[1]); r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
sk = Ed25519PrivateKey.generate(); from cryptography.hazmat.primitives import serialization as S; pub = sk.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
B="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; n=int.from_bytes(b"\xed\x01"+pub,"big"); s=""
while n: n,m=divmod(n,58); s=B[m]+s
mb="z"+s; did="did:webvh:QmX:ex.example:a"; kid=did+"#key-1"
body='{"a":1}'; url="https://api.example.com/v1/x?mode=t"
items=[(x,[]) for x in ["@method","@authority","@path","@query","content-digest","date"]]+[("agent-did",[("key","sig1")])]
params=[("created",1000),("expires",1030),("nonce","abc123"),("keyid",kid),("alg","ed25519"),("tag","agent-did")]
h={"Agent-DID":'sig1="%s"'%did,"Date":"Mon, 01 Jan 2024 00:00:00 GMT","Content-Digest":r.content_digest(body)}
ad=r.parse_dictionary(h["Agent-DID"])
base=r.signature_base("POST",url,h,items,params,ad)
import base64
h["Signature-Input"]="sig1="+r.ser_inner(items,params); h["Signature"]="sig1=:"+base64.b64encode(sk.sign(base.encode())).decode()+":"
res=r.Resolver({did:{"vms":{kid:(mb,["assertionMethod"])}}}); st={}
print(base); print(r.verify_request("POST",url,body,h,res,1010,store=st)); print(r.verify_request("POST",url,body,h,res,1010,store=st)["reason"])
print(r.verify_request("POST",url,body+" ",h,res,1010)["reason"], r.verify_request("POST",url,body,h,res,1031)["reason"])
print(r.url_normalized("https://API.example.com/x"), r.url_normalized("https://a.example/x/%2e%2e/y"), r.url_normalized("https://a.example:443/x?"))
