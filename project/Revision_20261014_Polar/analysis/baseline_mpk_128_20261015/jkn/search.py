"""JKN21 blockwise IB-KEM: finite source-faithful parameter exploration.

Author exposition: Niehues thesis PDF pp.144--146, 167--169. This is our
finite instantiation of asymptotic sufficient conditions, not a published
128-bit parameter table. Manuscripts and prior results are read-only.
"""
from __future__ import annotations
import argparse
import functools
import hashlib
import json
import math
import platform
import subprocess
import sys
from pathlib import Path
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
EST = Path('/Users/Admin/Desktop/IBE/Revision_20261012/experiments/A3_lattice-estimator')

def csqrt(x):
    return math.isqrt(x - 1) + 1 if x else 0

def clog(x):
    return (x - 1).bit_length()

@functools.lru_cache(maxsize=None)
def prime(a):
    from sage.all import previous_prime, ZZ
    return int(previous_prime(ZZ(2)**a))

def candidate(n, mode='original', r=None):
    """Keep original m>6na, beta and ReRand; only finite constants specified.

    mode=mgf replaces the original Cauchy correctness inequality by the
    independently derived common integer-Gaussian MGF bound, and is labelled
    as a new analysis, never attributed to JKN21.
    """
    r = csqrt(9*n) if r is None else int(r)
    if r*r <= 8*n:
        raise ValueError('Source requires r > 2 sqrt(2 n)')
    lam, T, qlog, tail = 128, 232, 16, 200
    ell = (2*lam+3).bit_length()-1
    for a in range(max(16,clog(r)+1),400):
        q = prime(a)
        m = ((6*n*a+1+127)//128)*128
        D = 2*m
        beta = 1+(ell+1)*m
        rho = m*(beta+1)
        theta = T+qlog+2+clog(D)+4
        h = csqrt((theta+2+3)//4)
        sigma = 3*h*(rho+1)
        s = csqrt(2*rho*rho)+1
        S = 2*r*s
        K = (D+2*csqrt(D*(tail+2))+2*(tail+2)+5)//6
        W2 = r*r+S*S*sigma*sigma*K
        source_correctness_rhs = 5*(r*csqrt(m)+2*m*S*sigma)
        if mode == 'original':
            ok = q >= source_correctness_rhs
        elif mode == 'mgf':
            # Tphase=162 leaves margin below the common total 2^-160 target.
            # Conservative common threshold for odd-q decision rounding.
            ok = (q-8)*(q-8) >= 4*163*W2
        else:
            raise ValueError(mode)
        if not ok:
            continue
        # 12 matrices at lambda=128. Hash description length is family-specific.
        matrices = ell+4
        mpk_bits = (matrices*n*m+n)*a
        return dict(scheme='JKN21-blockwise-original',mode=mode,n=n,q=str(q),
            q_bits=a,m=m,D=D,lambda_hash=lam,hash_output_bits=2*lam+3,
            ell=ell,matrix_count=matrices,beta=str(beta),rho=str(rho),
            r=str(r),r_bits=math.log2(r),sigma=str(sigma),S=str(S),
            sigma_bits=math.log2(sigma),S_bits=math.log2(S),
            key_h=h,key_theta_bits=theta,stat_budget_bits=T,query_log2=qlog,
            keynorm_tail_bits=tail,
            MPK_matrix_vector_bytes=(mpk_bits+7)//8,
            MPK_TiB=((mpk_bits+7)//8)/2**40,
            MPK_TB=((mpk_bits+7)//8)/10**12,
            hash_description_bytes='not included: requires explicit wNCR hash family',
            raw_ciphertext_bytes=((D+1)*a+7)//8,
            original_Cauchy_sufficient=(q>=source_correctness_rhs),
            reference_phase_DFR_bits=(q-8)*(q-8)//(4*W2)-1,
            finite_checks=dict(prime_modulus=True,strict_m_gt_6na=m>6*n*a,
                dimension=n>=2*lam+3,
                LHL_budget=m>=(n+1)*a+2*T+2*clog(m),
                rerand_strict=s*s>2*rho*rho,
                rerand_smoothing=2*r*r>=T+clog(D)+8,
                private_GS_coverage=sigma*sigma>5*h*h*(rho*rho+1)))
    raise RuntimeError('No modulus found')

def attack(c, name):
    sys.path.insert(0,str(EST))
    from estimator import LWE, ND
    from estimator.reduction import RC
    from sage.all import ZZ, RR, pi, sqrt, log
    q=ZZ(c['q']);r=ZZ(c['r'])
    p=LWE.Parameters(n=c['n'],q=q,Xs=ND.UniformMod(q),
        Xe=ND.DiscreteGaussian(RR(r)/sqrt(2*pi)),m=c['m']+1)
    kw=dict(red_cost_model=RC.ADPS16,red_shape_model='gsa')
    fs={'usvp':lambda:LWE.primal_usvp(p,**kw),
        'bdd':lambda:LWE.primal_bdd(p,**kw),
        'dual':lambda:LWE.dual(p,red_cost_model=RC.ADPS16),
        'dual_hybrid':lambda:LWE.dual_hybrid(p,red_cost_model=RC.ADPS16),
        'bdd_hybrid':lambda:LWE.primal_hybrid(p,mitm=False,babai=False,**kw),
        'mitm':lambda:LWE.primal_hybrid(p,mitm=True,babai=True,**kw)}
    cost=fs[name]()
    return dict(attack=name,bits=float(log(cost['rop'],2)),cost=repr(cost),input=repr(p))

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--worker',nargs=3,metavar=('N','MODE','ATTACK'))
    ap.add_argument('--screen',action='store_true')
    args=ap.parse_args()
    if args.worker:
        n,mode,name=args.worker
        c=candidate(int(n),mode)
        print(json.dumps(dict(candidate=c,result=attack(c,name))))
    elif args.screen:
        rows=[]
        # 16-coordinate lattice dimension precision; this is a finite search,
        # not a proof of global optimality or a monotonocity theorem.
        for mode in ['original','mgf']:
            low,high=259,8960
            while high-low>16:
                mid=((low+high)//2//16)*16
                if mid<=low: mid=low+1
                c=candidate(mid,mode);c['usvp']=attack(c,'usvp');rows.append(c)
                print(json.dumps(c),flush=True)
                if c['usvp']['bits']>=128: high=mid
                else: low=mid
            c=candidate(high,mode);c['usvp']=attack(c,'usvp');rows.append(c)
            print(json.dumps(c),flush=True)
        meta=dict(estimator_commit=subprocess.check_output(['git','-C',str(EST),'rev-parse','HEAD'],text=True).strip(),
            python=platform.python_version(),platform=platform.platform(),
            script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            search='uSVP bisection, <=16 dimension interval; heuristic screening only',rows=rows)
        (HERE/'screen.json').write_text(json.dumps(meta,indent=2))
