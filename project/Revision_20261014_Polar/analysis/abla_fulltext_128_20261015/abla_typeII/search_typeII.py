"""Claude-Scholar bounded Type-II Abla24 parameter screening.

ARS finite arithmetic retains original public evaluation, prime q, ReRand,
uniform [-rho,rho] hidden masks, and no ciphertext compression.
Not a published Table-2 numerical parameter set; uSVP screening only.
"""
from __future__ import annotations
import functools
import hashlib
import itertools
import json
import math
from pathlib import Path
import platform
import subprocess
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
from search_abla import code_parameters, csqrt, clog, radix_length, attack, prime, EST


@functools.lru_cache(maxsize=None)
def candidate(n,p,L,eta,b,r_policy='floor'):
    if b not in (2,4,8,16):raise ValueError('This branch freezes b=rho in 2,4,8,16')
    code=code_parameters(p,L)
    xi=radix_length(L,eta);t=code['t'];count=t*(xi+1);matrices=count+1
    blog=b.bit_length()-1;rho_mask=b;entropy_floor=blog+1
    r=csqrt(9*n) if r_policy=='floor' else int(r_policy)
    if r*r<9*n or eta**eta>n:raise ValueError('Source floor or chosen eta class unmet')
    T,qlog,tail=232,16,200
    for a in range(max(32,clog(r)+1),401):
        q=prime(a)
        if q<=max(eta,t*p*p,4*n*rho_mask*rho_mask):continue
        s=(a+blog-1)//blog
        assert b**(s-1)<q<=b**s
        k=s+2;w=n*k
        entropy_target=n*a+2*(T+8)+2*clog(w)
        bar=(entropy_target+entropy_floor-1)//entropy_floor
        m=((w+bar+127)//128)*128;bar=m-w
        # Deterministic canonical radix bounds, with at most w active rows.
        B=(b-1)*csqrt(w*m);J=k*(b-1)
        # Original simulation masks, not binary-difference masks.
        nu=T+clog(count)+4
        x=(3045*m+694*nu+999)//1000
        K0=rho_mask*csqrt((100*(m+2*csqrt(m*x)+2*x)+80)//81)
        # For eta=2, D(G)D(-G)=D(-G): the image of D(-G) is in
        # the first s radix rows P and D(G)P=P. No special inverse is added.
        E0=J if eta==2 else eta**eta*B*J
        Eeq=E0*(1+(xi-1)*B)
        Esel=L*J*Eeq
        delta=t*(B+p-1)*(Esel+1)
        rho_eval=K0*delta
        D=2*m
        theta=T+qlog+2+clog(D)+4
        h=csqrt((theta+5)//4)
        GS2=(b*b+1)*max(1+rho_eval*rho_eval,1+rho_mask*rho_mask*bar*w)
        sigma=h*csqrt(GS2)
        S=csqrt(4*r*r*(rho_eval*rho_eval+1))+1
        keyK=(D+2*csqrt(D*(tail+2))+2*(tail+2)+5)//6
        W2=r*r+S*S*sigma*sigma*keyK
        if (q-8)*(q-8)<4*163*W2:continue
        checks=dict(prime_modulus=True,source_floor=r*r>=9*n,
                    eta_range=q>eta,no_wrap=q>t*p*p,
                    mask_range=q>4*n*rho_mask*rho_mask,
                    honest_entropy=entropy_floor*bar>=entropy_target,
                    joint_LHL=entropy_floor*m>=(n+1)*a+2*(T+8)+2*clog(count*m),
                    sigma_coverage=sigma*sigma>=h*h*GS2,
                    h_smoothing=3140*h*h>694*(theta+2),
                    strict_rerand=S*S>4*r*r*(rho_eval*rho_eval+1),
                    rerand_smoothing=2*r*r>=T+clog(D)+8,
                    common_DFR=(q-8)*(q-8)>=4*163*W2,
                    partition=12*(1<<16)*(code['dimension']-1)**t<=L**t)
        assert all(checks.values()),checks
        mpk=(a*(matrices*n*m+n)+7)//8
        return dict(scheme='Abla24-TypeII-original-algorithms-finite-reanalysis',
                    n=n,q=str(q),q_bits=a,m=m,D=D,r=str(r),r_policy=r_policy,
                    **code,eta=eta,xi=xi,matrix_count=matrices,b=b,
                    rho_mask=rho_mask,mask_law=f'uniform integer [-{rho_mask},{rho_mask}]',
                    entropy_log2_lower_integer=entropy_floor,
                    gadget_k=k,gadget_s=s,w=w,bar=bar,B=str(B),J=J,
                    initial_K0=str(K0),norm_x=x,norm_nu=nu,
                    E0=str(E0),Eeq=str(Eeq),Esel=str(Esel),delta=str(delta),
                    rho=str(rho_eval),sigma=str(sigma),S=str(S),h=h,
                    theta=theta,T=T,keynorm_tail_bits=tail,
                    MPK_bytes=mpk,MPK_TiB=mpk/2**40,
                    raw_ciphertext_bytes=((D+1)*a+7)//8,
                    raw_MiB=(((D+1)*a+7)//8)/2**20,
                    phase_DFR_bits=(q-8)*(q-8)//(4*W2)-1,
                    finite_checks=checks,
                    source_pdf_sha256='ab60c527fc043d5088da36aa624d64226f905aa5a0cc1467df9cbb1f855fa846',
                    scope='uSVP-screening only; canonical reference and finite bounds, no full IBE runtime')
    raise RuntimeError('No finite q within a<=400')


def main():
    configs=list(itertools.product((2,4,8,16),((65537,128),(257,256)),(2,4),('floor','512','4096','65536')))
    dest=HERE/'screen-typeII.json'
    meta=dict(scope='finite grid uSVP screening; selected candidates require six attacks',
              skill='Claude-Scholar results-analysis, deterministic screening; ARS derivation',
              date='2026-10-15',command=sys.argv,
              script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              source_script_sha256=hashlib.sha256((HERE.parent/'search_abla.py').read_bytes()).hexdigest(),
              estimator_commit=subprocess.check_output(['git','-C',str(EST),'rev-parse','HEAD'],text=True).strip(),
              python=platform.python_version(),platform=platform.platform(),
              randomness='none',configs=len(configs),rows=[],best_by_config=[])
    start=time.time()
    for ix,(b,(p,L),eta,rp) in enumerate(configs):
        cache={}
        def check(n):
            if n in cache:return cache[n]
            began=time.time()
            try:
                c=candidate(n,p,L,eta,b,rp)
                a=attack(c,'usvp')
                row=dict(config_index=ix,status='ok',parameters=c,usvp=a,seconds=time.time()-began)
            except Exception as e:
                row=dict(config_index=ix,status='error',n=n,b=b,p=p,L=L,eta=eta,r_policy=rp,error=repr(e),seconds=time.time()-began)
            cache[n]=row;meta['rows'].append(row)
            return row
        lo,hi=512,16000
        upper=check(hi)
        if upper['status']!='ok' or upper['usvp']['bits']<128:
            meta['best_by_config'].append(dict(config_index=ix,status='no_passing_upper',config=[b,p,L,eta,rp]))
        else:
            while hi-lo>32:
                mid=((hi+lo)//2//16)*16
                row=check(mid)
                if row['status']=='ok' and row['usvp']['bits']>=128:hi=mid
                else:lo=mid
            for n in range(max(512,hi-32),hi+65,16):check(n)
            good=[row for row in cache.values() if row['status']=='ok' and row['usvp']['bits']>=128]
            best=min(good,key=lambda z:z['parameters']['MPK_bytes'])
            meta['best_by_config'].append(best)
        meta['seconds']=time.time()-start
        passing=[z for z in meta['best_by_config'] if z['status']=='ok']
        meta['best_screened']=sorted(passing,key=lambda z:z['parameters']['MPK_bytes'])[:12]
        dest.write_text(json.dumps(meta,indent=2)+'\n')
        best=meta['best_screened'][0] if meta['best_screened'] else None
        print(json.dumps(dict(config=ix+1,total=len(configs),b=b,p=p,L=L,eta=eta,r=rp,
              seconds=meta['seconds'],current_best=(dict(n=best['parameters']['n'],b=best['parameters']['b'],
              p=best['parameters']['p'],L=best['parameters']['L'],eta=best['parameters']['eta'],
              r=best['parameters']['r'],a=best['parameters']['q_bits'],MPK_TiB=best['parameters']['MPK_TiB'],
              usvp_bits=best['usvp']['bits']) if best else None))),flush=True)


if __name__=='__main__':main()
