"""Hypothesis probe on VALID fixtures only (js-signed, rust-signed, js-default-emitter, intact-dsse-3, intact-3)."""
import json,hashlib,base64,sys
U=sys.argv[1]
def canon_sorted(o): return json.dumps(o,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def canon_utf16(o):
    def enc(x):
        if isinstance(x,dict): return "{"+",".join(json.dumps(k,ensure_ascii=False)+":"+enc(x[k]) for k in sorted(x,key=lambda k:k.encode("utf-16-be")))+"}"
        if isinstance(x,list): return "["+",".join(enc(i) for i in x)+"]"
        return json.dumps(x,ensure_ascii=False)
    return enc(o).encode()
def ins(o): return json.dumps(o,separators=(",",":"),ensure_ascii=False).encode()
STRIP=[(),("signature",),("dsse_envelope",),("signature","dsse_envelope")]
def variants(rec):
    for s in STRIP:
        r={k:v for k,v in rec.items() if k not in s}
        for cn,f in (("sorted",canon_sorted),("utf16",canon_utf16),("insertion",ins)):
            yield "strip=%s/%s"%("+".join(s) or "none",cn), hashlib.sha256(f(r)).hexdigest()
def load(p):
    t=open(U+"/"+p).read()
    return [json.loads(l) for l in t.splitlines() if l.strip()] if p.endswith(".jsonl") else [json.loads(t)]
for p in ["dsse/js-signed-v05.json","dsse/rust-signed-v05.json","dsse/js-default-emitter-v05.json","chain/intact-dsse-3.jsonl"]:
    for i,rec in enumerate(load(p)):
        st=json.loads(base64.b64decode(rec["dsse_envelope"]["payload"]))
        want=st["subject"][0]["digest"]["sha256"]; pred=st["predicate"]
        hits=[n for n,h in variants(rec) if h==want]+["pred/"+n for n,h in variants(pred) if h==want]
        same={k for k in set(rec)|set(pred) if rec.get(k)!=pred.get(k)}
        print(p,i,"subject.name",st["subject"][0]["name"],"run_id",rec["run_id"],"| digest hits:",hits,"| record-vs-predicate differing keys:",sorted(same))
for p in ["chain/intact-3.jsonl","chain/intact-dsse-3.jsonl"]:
    recs=load(p)
    for i in range(1,len(recs)):
        want=recs[i].get("prev_record_hash")
        print(p,i,"prev hits:",[n for n,h in variants(recs[i-1]) if h==want])
