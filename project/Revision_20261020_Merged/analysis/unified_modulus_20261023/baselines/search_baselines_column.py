"""Deterministic common-bound baseline audit; no manuscript or old-data writes.

Original JKN21 and Abla24 algorithms/formats are retained.  Common Gaussian
MGF, finite smoothing, and exact integer GS rounding are analysis changes.
No ciphertext compression is attached to either baseline.
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import math
from pathlib import Path
import platform
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PROJECT = Path('/Users/Admin/Desktop/IBE')
OLD = PROJECT / 'Revision_20261014_Polar/analysis'
T, QLOG, TTAIL, TG = 232, 16, 200, 162


def cs(x):
    return math.isqrt(x - 1) + 1 if x else 0


def cl(x):
    return (x - 1).bit_length()


def align(x, modulus):
    return ((x + modulus - 1) // modulus) * modulus


@functools.lru_cache(None)
def prime(a):
    from sage.all import previous_prime, ZZ
    return int(previous_prime(ZZ(2)**a))


def common(n, r, a, m, rho, gs2, S):
    q, D = prime(a), 2*m
    theta = T + QLOG + 2 + cl(D) + 4
    h = 1
    while 3140*h*h <= 694*(theta+2):
        h += 1
    sigma = h*cs(gs2)
    K = (D + 2*cs(D*(TTAIL+2)) + 2*(TTAIL+2) + 5)//6
    W2 = r*r + S*S*sigma*sigma*K
    left, right = (q-8)**2, 4*(TG+1)*W2
    # q > 8 is required before squaring the conservative odd-q threshold.
    checks = dict(modulus_positive_threshold=q>8,
                  source_floor=r*r>=9*n,
                  strict_source_floor=r*r>8*n,
                  smoothing=3140*h*h>694*(theta+2),
                  GS_coverage=sigma*sigma>=h*h*gs2,
                  rerand_smoothing=2*r*r>=T+cl(D)+8,
                  common_MGF=q>8 and left>=right)
    return dict(n=n,r=str(r),q=str(q),q_bits=a,m=m,D=D,rho=str(rho),
                S=str(S),sigma=str(sigma),key_h=h,key_theta_bits=theta,
                GS_squared_bound=str(gs2),key_norm_K=str(K),W2=str(W2),
                MGF_lhs=str(left),MGF_rhs=str(right),
                MGF_ratio=left/right if q>8 else 0,
                phase_DFR_bits=(left//(4*W2)-1) if q>8 else None,
                stat_budget_bits=T,query_log2=QLOG,keynorm_tail_bits=TTAIL,
                phase_target_bits=TG,reference_DFR_target_bits=160,
                source_samples=m+1,finite_checks=checks)


def jkn(n, r, a, alignment=128, legacy=False, column=False,tight_rerand=True):
    m=align(6*n*a+1,alignment)
    beta=1+9*m
    rho=m*(beta+1)
    # The original paper's sqrt(2)*rho is a loose certificate for [I|R].
    # Its same ReRand lemma allows the exact sqrt(1+rho^2) sufficient norm.
    aux_s=cs(2*rho*rho)+1
    S=(math.isqrt(4*r*r*(1+rho*rho))+1 if tight_rerand else 2*r*aux_s)
    w=n*a
    bar=m-w
    Gsim2=5*(rho*rho+1)
    Ghon2=5*(1+bar*w)
    C=(beta+1)*cs(m)
    CH=cs(bar)
    if column:
        Gsim2=min(Gsim2,9*C*C+5)
        Ghon2=min(Ghon2,9*CH*CH+5)
    gs2=max(Gsim2,Ghon2)
    c=common(n,r,a,m,rho,gs2,S)
    c['finite_checks'].update(
        source_dimension=n>=259,
        strict_m_gt_6na=m>6*n*a,
        strict_ReRand=S*S>4*r*r*(1+rho*rho),
        honest_entropy=bar>=n*a+2*(T+8)+2*cl(w),
        joint_LHL=m>=(n+1)*a+2*T+2*cl(m))
    c.update(scheme='JKN21',variant='original blockwise, common finite analysis',
             lambda_hash=128,hash_output_bits=259,ell=8,matrix_count=12,
             beta=str(beta),w=w,bar=bar,auxiliary_s=str(aux_s),
             rerand_policy=('exact [I|R] norm; original factor 2' if tight_rerand else
                            'legacy sqrt(2)*rho sufficient norm'),
             original_loose_rerand_satisfied=S*S>8*r*r*rho*rho,
             GS_policy=('min(full-matrix, prime sparse-column)' if column else
                        'sqrt(5) full-evaluator norm, honest binary trapdoor'),
             column_policy=column,simulated_column_bound=str(C),
             honest_column_bound=str(CH),simulated_GS2=str(Gsim2),
             honest_GS2=str(Ghon2),
             hash_description_bytes='excluded: unspecified wNCR family',
             mask_policy='original, no entropy redesign')
    if legacy:
        theta=c['key_theta_bits']
        h=cs((theta+5)//4)
        sigma=3*h*(rho+1)
        rhs=5*(r*cs(m)+2*m*S*sigma)
        c.update(key_h=h,sigma=str(sigma),legacy_Cauchy_rhs=str(rhs))
        c['finite_checks']['common_MGF']=True
        c['finite_checks']['legacy_Cauchy']=int(c['q'])>=rhs
    return finish(c,alignment)


def abla(n,r,a,type_ii=False,alignment=128,legacy=False,column=False,tight_rerand=True):
    # Same original code and original masks as the latest paper rows.
    p,L,eta,t,xi,count=65537,128,2,5,7,40
    b=16 if type_ii else 2
    if type_ii:
        g=4
        s=(a+g-1)//g
        k=s+2
        w=n*k
        target=n*a+2*(T+8)+2*cl(w)
        bar=(target+4)//5
        m=align(w+bar,alignment)
        bar=m-w
        B=(b-1)*cs(w*m)
        J=k*(b-1)
        mask=b
    else:
        k=a+2
        w=n*k
        target=n*a+2*(T+8)+2*cl(w)
        bar=(50*target+78)//79
        m=align(w+bar,alignment)
        bar=m-w
        B=cs(w*m)
        J=k
        mask=1
    nu=T+cl(count)+4
    x=(3045*m+694*nu+999)//1000
    K0=mask*cs((100*(m+2*cs(m*x)+2*x)+80)//81)
    E0=J
    Eeq=E0*(1+(xi-1)*B)
    Esel=L*J*Eeq
    delta=t*(B+p-1)*(Esel+1)
    rho=K0*delta
    Gsim2=(b*b+1)*(1+rho*rho)
    Ghon2=(b*b+1)*(1+mask*mask*bar*w)
    d=(b-1)*cs(w)
    C0=mask*cs(m)
    Ceq=K0*E0*(1+(xi-1)*d)
    Csel=L*J*Ceq
    CR=t*(K0*(Esel+1)*d+(p-1)*(Csel+C0))
    C=min(rho,CR)
    CH=mask*cs(bar)
    if column:
        Gsim2=min(Gsim2,(b+1)**2*C*C+b*b+1)
        Ghon2=min(Ghon2,(b+1)**2*CH*CH+b*b+1)
    gs2=max(Gsim2,Ghon2)
    S=(math.isqrt(4*r*r*(rho*rho+1))+1 if tight_rerand else
       cs(4*r*r*(rho*rho+1))+1)
    c=common(n,r,a,m,rho,gs2,S)
    q=int(c['q'])
    c['finite_checks'].update(
        eta_range=q>eta,
        no_wrap_partition=q>t*p*p,
        strict_ReRand=S*S>4*r*r*(rho*rho+1),
        partition_balance=12*(1<<QLOG)*7**t<=L**t)
    if type_ii:
        c['finite_checks'].update(
            mask_range=q>4*n*mask*mask,
            gadget_digit_range=b**(s-1)<q<=b**s,
            honest_entropy=5*bar>=target,
            joint_LHL=5*m>=(n+1)*a+2*(T+8)+2*cl(count*m))
    else:
        c['finite_checks'].update(
            honest_entropy=79*bar>=50*target,
            joint_LHL=79*m>=50*((n+1)*a+2*(T+8)+2*cl(count*m)))
    c.update(scheme='Abla24',variant='Type II' if type_ii else 'Type I',
             p=p,L=L,eta=eta,t=t,xi=xi,matrix_count=41,b=b,
             gadget_k=k,w=w,bar=bar,mask_amplitude=mask,
             mask_policy=f'original uniform integers [-{mask},{mask}]',
             entropy_target=target,B=str(B),J=J,initial_K0=str(K0),
             initial_x=x,initial_nu=nu,E0=str(E0),Eeq=str(Eeq),
             Esel=str(Esel),delta=str(delta),
             GS_policy=('min(full-matrix, prime sparse-column)' if column else
                        f'sqrt({b*b+1}) full-evaluator norm, original masks'),
             column_policy=column,digit_column_bound=str(d),
             starting_column_bound=str(C0),equality_column_bound=str(Ceq),
             selector_column_bound=str(Csel),derived_column_bound=str(CR),
             simulated_column_bound=str(C),honest_column_bound=str(CH),
             simulated_GS2=str(Gsim2),honest_GS2=str(Ghon2))
    if legacy:
        h=cs((c['key_theta_bits']+5)//4)
        sigma=(h*cs(gs2) if type_ii else 3*h*max(rho+1,cs(1+bar*w)))
        K=int(c['key_norm_K'])
        W2=r*r+S*S*sigma*sigma*K
        c.update(key_h=h,sigma=str(sigma),W2=str(W2),
                 MGF_rhs=str(652*W2),MGF_ratio=(q-8)**2/(652*W2),
                 phase_DFR_bits=(q-8)**2//(4*W2)-1)
        c['finite_checks']['common_MGF']=q>8 and (q-8)**2>=652*W2
    return finish(c,alignment)


def finish(c,alignment):
    a,m,n=c['q_bits'],c['m'],c['n']
    c['alignment']=alignment
    c['raw_ciphertext_bytes']=((2*m+1)*a+7)//8
    c['complete_ciphertext_bytes']=c['raw_ciphertext_bytes']
    c['MPK_bytes']=(a*(c['matrix_count']*n*m+n)+7)//8
    c['MPK_TiB']=c['MPK_bytes']/2**40
    c['CT_MiB']=c['raw_ciphertext_bytes']/2**20
    c['failures']=[k for k,v in c['finite_checks'].items() if not v]
    c['status']='CONDITIONS_PASS_ATTACKS_PENDING' if not c['failures'] else 'REJECT'
    return c


PROFILES=[dict(id='jkn_fixed_n',scheme='jkn',n=5712,r=227),
          dict(id='jkn_retuned_prior',scheme='jkn',n=5168,r=216),
          dict(id='abla_I_fixed_n',scheme='ablaI',n=8336,r=274),
          dict(id='abla_II_fixed_n',scheme='ablaII',n=9504,r=512)]


def scan(profile,alignment=128,legacy=False,column=False,tight_rerand=True):
    rows=[]
    for a in range(2,401):
        kind,n,r=profile['scheme'],profile['n'],profile['r']
        c=(jkn(n,r,a,alignment,legacy,column,tight_rerand) if kind=='jkn' else
           abla(n,r,a,kind=='ablaII',alignment,legacy,column,tight_rerand))
        c['profile_id']=profile['id']
        rows.append(c)
        if not c['failures']:
            return dict(profile=profile,alignment=alignment,legacy=legacy,column=column,
                        search_min_a=2,search_max_a=400,
                        candidate_family='q=previous_prime(2^a)',
                        rows=rows,selected=c,
                        all_smaller_bitlength_candidates_rejected=all(
                            z['failures'] for z in rows[:-1]),
                        previous=rows[-2] if len(rows)>1 else None)
    raise RuntimeError(f'No finite candidate for {profile}')


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--single',nargs=4,metavar=('ID','SCHEME','N','R'))
    ap.add_argument('--column',action='store_true')
    ap.add_argument('--loose-rerand',action='store_true')
    args=ap.parse_args()
    profiles=(PROFILES if not args.single else [dict(id=args.single[0],
              scheme=args.single[1],n=int(args.single[2]),r=int(args.single[3]))])
    started=time.time()
    selected=[]
    for profile in profiles:
        result=scan(profile,column=args.column,tight_rerand=not args.loose_rerand)
        suffix=('-column' if args.column else '')+('-loose-rerand' if args.loose_rerand else '')
        path=HERE/f"{profile['id']}{suffix}-ledger.json"
        path.write_text(json.dumps(result,indent=2)+'\n')
        c=result['selected']
        selected.append(c)
        if not args.column:
            control=scan(profile,legacy=True,tight_rerand=False)
            (HERE/f"{profile['id']}-legacy-replay.json").write_text(json.dumps(control,indent=2)+'\n')
        sensitivity=scan(profile,alignment=1,column=args.column,tight_rerand=not args.loose_rerand)
        (HERE/f"{profile['id']}{suffix}-alignment1.json").write_text(json.dumps(sensitivity,indent=2)+'\n')
        print(json.dumps({k:c[k] for k in ['profile_id','n','r','q_bits','m','key_h','MPK_TiB','CT_MiB','MGF_ratio']},ensure_ascii=False),flush=True)
    metadata=dict(date='2026-10-23',skill='Claude-Scholar/results-analysis',
                  command=sys.argv,randomness='none; exact deterministic integer calculations',
                  scope='Finite conditions only; six base-LWE attacks run separately by root',
                  python=sys.version,platform=platform.platform(),
                  script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  elapsed_seconds=time.time()-started,
                  common_budgets=dict(T=T,Qlog=QLOG,Ttail=TTAIL,TG=TG),
                  source_scripts=[str(OLD/'baseline_mpk_128_20261015/jkn/search.py'),
                                  str(OLD/'abla_fulltext_128_20261015/search_abla.py'),
                                  str(OLD/'abla_fulltext_128_20261015/abla_typeII/search_typeII.py')],
                  selected=selected)
    for path in metadata['source_scripts']:
        metadata.setdefault('source_sha256',{})[path]=hashlib.sha256(Path(path).read_bytes()).hexdigest()
    dest=(('shared_column_loose_rerand.json' if args.loose_rerand else 'shared_column.json') if args.column else 'selected.json') if not args.single else f"{args.single[0]}{suffix}-selected.json"
    (HERE/dest).write_text(json.dumps(metadata,indent=2)+'\n')


if __name__=='__main__':
    main()
