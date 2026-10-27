"""Bounded n screening AFTER common-bound a minimization; no global optimum claim."""
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
SEARCH=HERE/'baselines/search_baselines_column.py'
spec=importlib.util.spec_from_file_location('common_baselines',SEARCH)
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
EST=Path('/Users/Admin/Desktop/IBE/Revision_20261012/experiments/A3_lattice-estimator')
sys.path.insert(0,str(EST))
from estimator import LWE,ND
from estimator.reduction import RC
from sage.all import ZZ,RR,pi,sqrt,log

def usvp(c):
    p=LWE.Parameters(n=c['n'],q=ZZ(c['q']),Xs=ND.UniformMod(ZZ(c['q'])),
                     Xe=ND.DiscreteGaussian(RR(c['r'])/sqrt(2*pi)),m=c['m']+1)
    cost=LWE.primal_usvp(p,red_cost_model=RC.ADPS16,red_shape_model='gsa')
    return dict(bits=float(log(cost['rop'],2)),raw=repr(cost),input=repr(p))

def main():
    dest=HERE/'dimension_screen.json'
    if dest.exists():raise SystemExit('Refusing to overwrite existing dimension screen')
    allrows=[];selected=[];summary=[]
    for scheme,start in [('jkn',5168),('ablaI',8336),('ablaII',9504)]:
        seen={};ledgers={}
        def test(n):
            if n in seen:return seen[n]
            r=base.cs(9*n) if scheme!='ablaII' else 512
            result=base.scan(dict(id=f'{scheme}_n{n}',scheme=scheme,n=n,r=r),column=True)
            c=result['selected'];res=usvp(c)
            row=dict(scheme=scheme,parameters=c,usvp=res)
            seen[n]=row;ledgers[n]=result
            allrows.append(row)
            dest.write_text(json.dumps(dict(status='screen_running',rows=allrows,selected=selected),indent=2)+'\n')
            print(json.dumps(dict(scheme=scheme,n=n,a=c['q_bits'],r=r,bits=res['bits'],
                                  MPK_TiB=c['MPK_TiB'],CT_MiB=c['CT_MiB'])),flush=True)
            return row
        top=test(start)
        assert top['usvp']['bits']>=128
        n=start
        while test(n)['usvp']['bits']>=128:
            n-=128
            if n<512:raise RuntimeError('Screen left predefined practical domain')
        # Enumerate a 16-grid across the bracket, plus both neighboring grid points.
        for nn in range(n-16,n+128+17,16):test(nn)
        good=[row for row in seen.values() if row['usvp']['bits']>=128]
        best=min(good,key=lambda row:row['parameters']['MPK_bytes'])
        nn=best['parameters']['n']
        best['parameters']['profile_id']=f'{scheme}_retuned_common'
        selected.append(best['parameters'])
        ld=ledgers[nn];ld['selected']['profile_id']=best['parameters']['profile_id']
        (HERE/'baselines'/f'{scheme}_retuned_common-ledger.json').write_text(json.dumps(ld,indent=2)+'\n')
        summary.append(dict(scheme=scheme,search_dimensions=sorted(seen),selected_n=nn,
                            selected_usvp_bits=best['usvp']['bits'],
                            status='uSVP_SCREEN_ONLY_pending_six_attacks'))
    out=dict(status='screen_complete',scope='bounded 16-grid n screen; exhaustive a search per n; not global n optimization',
             selection='minimum MPK among explicitly screened n with uSVP>=128',
             script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             search_sha256=hashlib.sha256(SEARCH.read_bytes()).hexdigest(),
             rows=allrows,selected=selected,summary=summary)
    dest.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(dict(selected=[{k:c[k] for k in ['profile_id','n','r','q_bits','m','CT_MiB','MPK_TiB']} for c in selected])),flush=True)

if __name__=='__main__':main()
