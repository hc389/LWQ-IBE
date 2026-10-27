"""Small preregistered controls while awaiting the independent code interface."""
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
import round2_search_frozen_highproof as s
HERE=Path(__file__).resolve().parent
doc=s.metadata();doc['control_orchestrator_sha256']=s.sha(__file__);doc['rows']=[];doc['gates']=[]
configs=[('old',4,5,'512',1),('exact',64,5,'512',1),('exact',4,1,'512',1)]
for profile,b,k,r,kp in configs:
    lo,hi=6000,15000;cache={}
    def ev(n):
        if n not in cache:
            c=s.candidate(n,r,b,k,profile,kp);c['usvp']=s.old.attack(c,'usvp')
            cache[n]=c;doc['rows'].append(c)
        return cache[n]
    while hi-lo>8:
        mid=((hi+lo)//16)*8
        if mid<=lo:mid=lo+1
        c=ev(mid)
        if c['usvp']['status']=='ok' and c['usvp']['bits']>=128:hi=mid
        else:lo=mid
    near=[ev(n) for n in range(lo-8,hi+9,2)]
    best=min([c for c in near if c['usvp']['status']=='ok' and c['usvp']['bits']>=128],key=lambda c:c['MPK_bytes'])
    doc['gates'].append(best)
    print(json.dumps({k:best[k] for k in ['n','r','gadget_b','honest_entropy_k','proof_entropy_profile','q_bits','m','MPK_TiB']}),flush=True)
(HERE/'small-controls.json').write_text(json.dumps(doc,indent=2)+'\n')
