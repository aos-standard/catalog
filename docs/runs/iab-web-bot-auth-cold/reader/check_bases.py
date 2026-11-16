#!/usr/bin/env python3
"""Compare the verifier's signature base with each expected_signature_base, and re-sign it with the published seed."""
import json,sys,base64,hashlib,glob,os
sys.path.insert(0,'/home/tetsuroh/.claude/work/iab_wba_cold/reader')
import wba_cold_verifier as V
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
W='/home/tetsuroh/.claude/work/iab_wba_cold'
keys=json.load(open(W+'/upstream/src/iab_agentic_primitives/web_bot_auth/vectors/keys.json'))['keys']
priv={k['kid']:Ed25519PrivateKey.from_private_bytes(V.b64url_decode(k['_private_d_for_test_only'])) for k in keys}
for k in keys:
    d=hashlib.sha256(('aamp-wba-test/'+k['seed_name']).encode()).digest()
    pub=Ed25519PrivateKey.from_private_bytes(d).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    print('seed',k['seed_name'],'d_matches',V.b64url(d)==k['_private_d_for_test_only'],'x_matches',V.b64url(pub)==k['x'],'kid_is_thumbprint',V.thumbprint(k)==k['kid'])
tot=same=resig=0
for f in sorted(glob.glob(W+'/inputs/[pn][oe][sg]-*.json')):
    c=os.path.basename(f)[:-5]; op=json.load(open(f))['operation']; ans=json.load(open(f'{W}/answers/{c}.json'))
    eb=ans.get('expected_signature_base') or {}
    msgs=[]
    if op['op']=='verify_request': msgs=[('req',op['request'],None)]
    elif op['op']=='verify_response': msgs=[('resp',op['response'],V.prepare_request(op['request'],None))]
    for kind,m,reqp in msgs:
        try: si,sg,sa=V.parse_signature_fields(m['headers'])
        except V.Refusal as r: print(c,'parse refusal',r.rule,'labels in expected base:',list(eb)); continue
        for lab,mm in si:
            if lab not in eb: continue
            items,plist=mm[1],mm[2]
            if kind=='req': base=V.signature_base(items,plist,V.prepare_request(m,op['authority']),None,None)
            else: base=V.signature_base(items,plist,{'headers':m['headers'],'status':m['status']},reqp,None)
            tot+=1; ok=base.decode()==eb[lab]; same+=ok
            sig=[x for l,x in sg if l==lab]; kid=dict(plist).get('keyid'); rs=None
            if kid in priv and sig: rs=priv[kid].sign(base)==sig[0][1]; resig+=bool(rs)
            print(c,lab,'base_equal',ok,'resign_equal',rs)
    if op['op']=='verify_directory': print(c,'directory op; expected base labels',list(eb))
print('bases',same,'/',tot,'re-signed byte-equal',resig)
