"""Finite parameters for the original Abla24 algorithms, with explicit safe bounds.

Not published Abla numerical parameters. Repairs omitted skip branches and
includes the selector-sum factors missing from the printed norm proof.
No compression is added to this baseline. See accompanying ARS derivations.
"""
from __future__ import annotations
import argparse
import functools
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
EST = Path('/Users/Admin/Desktop/IBE/Revision_20261012/experiments/A3_lattice-estimator')
BASE = HERE.parent/'baseline_mpk_128_20261015'
sys.path.insert(0, str(BASE/'jkn'))
from search import attack, prime


def csqrt(x):
    return math.isqrt(x-1)+1 if x else 0


def clog(x):
    return (x-1).bit_length()


def radix_length(size, base):
    k, power = 0, 1
    while power < size:
        k += 1
        power *= base
    return k


def code_parameters(p, length):
    k = radix_length(1 << 128, p)
    if not k <= length <= p:
        raise ValueError('RS code requires dimension <= length <= prime alphabet')
    # 3Q(1-d)^t <= epsilon, epsilon=1/4; exact integers only.
    t = 1
    while 12*(1 << 16)*(k-1)**t > length**t:
        t += 1
    return dict(p=p,L=length,dimension=k,distance_numerator=length-k+1,
                distance_denominator=length,t=t,identity_bits=128,
                partition_epsilon='1/4',query_log2=16,
                gamma_max_denominator=str(p**t),
                tau_lower_denominator=str(12*p**t))


@functools.lru_cache(maxsize=None)
def widths(n, a, count):
    T = 232
    # Literal conservative gadget [1,2,...,2^a,0], k=a+2.
    k = a+2
    w = n*k
    # log2(3)>79/50, certified by 3^50 > 2^79.
    assert 3**50 > 2**79
    entropy_target = n*a + 2*(T+8) + 2*clog(w)
    bar = (50*entropy_target+78)//79
    m = ((w+bar+127)//128)*128
    bar = m-w
    B = csqrt(w*m)  # canonical binary G^-1 has at most w*m entries in {0,1}.
    # Uniform {-1,0,1}, NOT the binary-difference ternary law of our scheme.
    # Hoeffding proxy variance 1; one-sided 1/10-net cardinality <=21^m.
    nu = T+clog(count)+4
    x = (3045*m+694*nu+999)//1000
    K0 = csqrt((100*(m+2*csqrt(m*x)+2*x)+80)//81)
    return k,w,bar,m,B,K0,x,nu,entropy_target


@functools.lru_cache(maxsize=None)
def candidate(n, p, length, eta, r_policy='floor', equality_policy='tight_binary'):
    code = code_parameters(p,length)
    xi = radix_length(length,eta)
    t = code['t']
    count = t*(xi+1)
    matrices = count+1
    r = csqrt(9*n) if r_policy=='floor' else int(r_policy)
    if r*r < 9*n or eta**eta > n:
        raise ValueError('source floor or chosen conservative eta class not met')
    T, qlog, tail = 232,16,200
    for a in range(max(32,clog(r)+1),401):
        q = prime(a)
        if q <= max(eta,t*p*p):
            continue
        k,w,bar,m,B,K0,x,nu,entropy_target = widths(n,a,count)
        if eta==2 and equality_policy=='tight_binary':
            # One nontrivial interpolation factor; canonical projection identity.
            E0 = k
        else:
            E0 = eta**eta * B*k
        Eeq = E0*(1+(xi-1)*B)
        Esel = length*k*Eeq
        delta = t*(B+p-1)*(Esel+1)
        rho = K0*delta
        D = 2*m
        theta = T+qlog+2+clog(D)+4
        h = csqrt((theta+2+3)//4)
        honest = csqrt(1+bar*w)
        sigma = 3*h*max(rho+1,honest)
        # Strict sigma1/(2r) > sqrt(1+rho^2) as required by ReRand.
        S = csqrt(4*r*r*(rho*rho+1))+1
        keyK = (D+2*csqrt(D*(tail+2))+2*(tail+2)+5)//6
        W2 = r*r+S*S*sigma*sigma*keyK
        # Common integer-Gaussian linear-form MGF; conservative odd-q threshold.
        if (q-8)*(q-8) < 4*163*W2:
            continue
        finite = dict(prime_modulus=True,eta_range=q>eta,
            no_wrap_partition=q>t*p*p,source_floor=r*r>=9*n,
            trapgen_entropy=79*bar>=50*entropy_target,
            programmed_joint_LHL=79*m>=50*((n+1)*a+2*(T+8)+2*clog(count*m)),
            initial_matrix_budget=nu>=T+clog(count)+4,
            strict_rerand=S*S>4*r*r*(rho*rho+1),
            rerand_smoothing=2*r*r>=T+clog(D)+8,
            private_GS=sigma*sigma>5*h*h*max(rho*rho+1,1+bar*w),
            common_mgf=(q-8)*(q-8)>=4*163*W2,
            partition_balance=12*(1<<16)*(code['dimension']-1)**t<=length**t)
        assert all(finite.values()),finite
        mpk_bytes=(a*(matrices*n*m+n)+7)//8
        return dict(scheme='Abla24-original-algorithms-finite-analysis',
            source_pdf_sha256='ab60c527fc043d5088da36aa624d64226f905aa5a0cc1467df9cbb1f855fa846',
            n=n,r=str(r),q=str(q),q_bits=a,m=m,D=D,**code,
            eta=eta,xi=xi,gadget_base=2,mask_range=1,mask_law='uniform {-1,0,1}',
            gadget_k=k,w=w,bar=bar,gadget_inverse_bound=str(B),
            scalar_gadget_bound=k,initial_mask_spectral_bound=str(K0),
            initial_mask_x=x,initial_mask_nu=nu,
            equality_policy=equality_policy,small_equality_factor=str(E0),
            digit_equality_factor=str(Eeq),selector_factor=str(Esel),delta=str(delta),
            rho=str(rho),S=str(S),sigma=str(sigma),key_h=h,key_theta_bits=theta,
            stat_budget_bits=T,keynorm_tail_bits=tail,finite_checks=finite,
            matrix_count=matrices,MPK_bytes=mpk_bytes,MPK_TiB=mpk_bytes/2**40,
            raw_ciphertext_bytes=((D+1)*a+7)//8,
            complete_MiB=(((D+1)*a+7)//8)/2**20,
            phase_DFR_bits=(q-8)*(q-8)//(4*W2)-1,
            sampler_implementation_error='not measured; canonical reference only',
            note='Algorithm-faithful finite reanalysis, not printed Table2 numerical parameters')
    raise RuntimeError('No finite modulus found')


def scan():
    from sage.all import is_prime
    configs=[]
    for p in [37,67,127,257,521,1031,4099,65537]:
        assert is_prime(p)
        dim=radix_length(1<<128,p)
        lengths=sorted({p,*[min(p,j*dim) for j in [2,4,8,16]]})
        for length in lengths:
            for eta in [2,3,4,5]:
                for r in ['floor','512','4096','65536','16777216']:
                    configs.append((p,length,eta,r))
    log=[];best=[];start=time.time()
    for idx,(p,length,eta,r) in enumerate(configs):
        low,high=512,16000
        seen={}
        def test(n):
            if n in seen:return seen[n]
            try:
                c=candidate(n,p,length,eta,r)
                u=attack(c,'usvp')
                seen[n]=(c,u)
                log.append(dict(config_index=idx,parameters=c,usvp=u))
            except (ValueError,RuntimeError) as e:
                seen[n]=(None,dict(bits=-1,error=str(e)))
            return seen[n]
        while high-low>16:
            mid=((low+high)//2//16)*16
            if mid<=low:mid=low+1
            _,u=test(mid)
            if u['bits']>=128:high=mid
            else:low=mid
        for n in range(max(512,high-32),high+49,16):test(n)
        good=[(c,u) for c,u in seen.values() if c and u['bits']>=128]
        if good:
            c,u=min(good,key=lambda z:z[0]['MPK_bytes'])
            best.append(dict(parameters=c,usvp=u))
        if idx%25==0:
            print(json.dumps(dict(progress=idx,total=len(configs),seconds=time.time()-start,
                best_MPK_TiB=min((r['parameters']['MPK_TiB'] for r in best),default=None))),flush=True)
    best.sort(key=lambda z:z['parameters']['MPK_bytes'])
    data=dict(date='2026-10-15',script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        estimator_commit=subprocess.check_output(['git','-C',str(EST),'rev-parse','HEAD'],text=True).strip(),
        python=platform.python_version(),platform=platform.platform(),seconds=time.time()-start,
        command='sage -python search_abla.py --scan',configs=len(configs),
        source_pdf=str('/Users/Admin/Zotero/storage/8K72TIQ8/978-3-031-58868-6_13.pdf'),
        scope='finite-grid uSVP screening only; selected candidates need six attacks',
        best_by_config=best,rows=log)
    (HERE/'screen.json').write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps(dict(top=best[:5],config_count=len(configs),seconds=time.time()-start),indent=2))


if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--scan',action='store_true')
    ap.add_argument('--worker',nargs=6,metavar=('N','P','L','ETA','R','ATTACK'))
    a=ap.parse_args()
    if a.scan:scan()
    elif a.worker:
        n,p,L,eta,r,name=a.worker
        c=candidate(int(n),int(p),int(L),int(eta),r)
        print(json.dumps(dict(candidate=c,result=attack(c,name))))
