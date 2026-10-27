"""Bounded quantum-cost parameter comparison. No manuscript or source writes."""
import sys
sys.dont_write_bytecode = True
import importlib.util, json, math, time, signal, hashlib, subprocess
from pathlib import Path
from functools import partial

BASE = Path('/Users/Admin/Desktop/IBE')
SRC = BASE/'Revision_20261014_Polar/analysis/abla_borrowing_round2_20261016/experiments/round2_search_frozen_mixed.py'
EST = BASE/'Revision_20261012/experiments/A3_lattice-estimator'
spec = importlib.util.spec_from_file_location('frozen_parameters', SRC)
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
sys.path.insert(0, str(EST))
from sage.all import RR, ZZ, sqrt, pi, log
from sage.env import SAGE_VERSION
from estimator import LWE, ND
from estimator.reduction import ADPS16
from estimator.lwe_dual import DH
from estimator.lwe_guess import exhaustive_search

QM = ADPS16(mode='quantum')
def emit(kind, value): print(json.dumps({'kind':kind, 'data':value},ensure_ascii=False),flush=True)
def ontimeout(*args): raise TimeoutError('45-second bounded attack check')
signal.signal(signal.SIGALRM, ontimeout)

def lwe(c):
    q=ZZ(2)**c['q_bits']
    return LWE.Parameters(n=c['n'],q=q,Xs=ND.UniformMod(q),
                          Xe=ND.DiscreteGaussian(RR(c['r'])/sqrt(2*pi)),m=c['m']+1)

def attack(c, name):
    p=lwe(c); kw={'red_cost_model':QM,'red_shape_model':'gsa'}
    f={
        'usvp':lambda:LWE.primal_usvp(p,**kw),
        'bdd':lambda:LWE.primal_bdd(p,**kw),
        'dual':lambda:LWE.dual(p,red_cost_model=QM),
        'dual_hybrid_reduction_only':lambda:LWE.dual_hybrid(p,red_cost_model=QM),
        'bdd_hybrid_reduction_only':lambda:LWE.primal_hybrid(p,mitm=False,babai=False,**kw),
        'mitm_reduction_only':lambda:LWE.primal_hybrid(p,mitm=True,babai=True,**kw),
        'dual_hybrid_grover':lambda:DH(solver=partial(exhaustive_search,quantum=True),
                                     params=p,red_cost_model=QM,opt_step=8),
    }
    t=time.monotonic(); signal.alarm(45)
    try:
        out=f[name]()
        bits=float(log(out['rop'],2))
        return {'attack':name,'status':'finite' if math.isfinite(bits) else 'nonfinite',
                'bits':bits,'raw':repr(out),'seconds':time.monotonic()-t,'input':repr(p)}
    except Exception as e:
        return {'attack':name,'status':'timeout' if isinstance(e,TimeoutError) else 'error',
                'error':repr(e),'seconds':time.monotonic()-t,'input':repr(p)}
    finally: signal.alarm(0)

def params(n, r, b, kp):
    return mod.candidate(n,str(r),b,80,'higher',kp,'folded_rs8192',mixed=True)

def compact_cert(c):
    t=time.monotonic(); p=mod.old.certify(c,256)
    # Keep all numeric summaries and exact per-level counts, omit large index lists.
    return {k:v for k,v in p.items() if k not in ['frozen_sets','base_deficit_upper']} | {'seconds':time.monotonic()-t}

if '--summaries' in sys.argv:
    for name,n,r,b,kp in [('old_mpk',10072,8192,64,6),('new_mpk',10848,8192,64,6),('old_ct',11600,4096,1024,9),('new_ct',12480,4096,1024,9)]:
        c=params(n,r,b,kp); p=compact_cert(c)
        emit('compact',{'name':name,'parameters':{k:c[k] for k in ['n','r','q_bits','m','D','w','bar','gadget_digit_length','gadget_last_radix','rho','sigma','S','S_log2','sigma_log2','MPK_bytes','MPK_TiB','checks','alternative_gate_diagnostics','exact_reference_DFR_bits']}, 'certificate':{k:p[k] for k in ['block_repetitions','frozen_bits_per_block','information_bits_per_block','raw_bytes','compressed_bytes','complete_byte_saving_fraction','global_tv_upper','matching_TV_upper','finite_grid_TV_upper','combined_DFR_upper','DFR_pass','savings_pass','lattice_layout_pass','actual_GPV_sampler_TV_excluded','full_dim_execution']}, 'partial_freezes':{i+1:v for i,v in enumerate(p['per_level_frozen']) if 0<v<256}})
    sys.exit(0)

meta={'sage':SAGE_VERSION,'estimator_commit':subprocess.check_output(['git','-C',str(EST),'rev-parse','HEAD'],text=True).strip(),
      'source':str(SRC),'source_sha256':hashlib.sha256(SRC.read_bytes()).hexdigest(),
      'scope':'ADPS16 quantum-sieving model, bounded checks; not all quantum attacks or full IBE quantum security',
      'fixed':{'N':256,'seed_bits':256,'Q_E':65536,'stat_bits':232,'key_tail_bits':200,'DFR_target_bits':160},
      'timeout_seconds_per_attack':45}
emit('metadata',meta)
names=['usvp','bdd','dual','dual_hybrid_reduction_only','bdd_hybrid_reduction_only','mitm_reduction_only','dual_hybrid_grover']
selected=[]
for family,n0,r,b,kp in [('MPK-priority',10072,8192,64,6),('CT-priority',11600,4096,1024,9)]:
    old=params(n0,r,b,kp)
    oldatt=[attack(old,'usvp'),attack(old,'dual_hybrid_grover')]
    emit('old_quantum_checks',{'family':family,'attacks':oldatt})
    cache={}
    def screen(n):
        if n not in cache:
            c=params(n,r,b,kp); a=attack(c,'usvp'); cache[n]=(c,a)
            emit('screen',{'family':family,'n':n,'a':c['q_bits'],'m':c['m'],'attack':a})
        return cache[n]
    lo=(n0//16)*16; hi=math.ceil(n0*1.30/16)*16
    assert screen(hi)[1].get('bits',0)>=128
    while hi-lo>16:
        mid=((lo+hi)//32)*16
        if screen(mid)[1].get('bits',0)>=128: hi=mid
        else: lo=mid
    chosen=None
    for n in range(hi,hi+65,16):
        c,a=screen(n); checks=[a]+[attack(c,k) for k in names[1:]]
        emit('candidate_attack_checks',{'family':family,'n':n,'attacks':checks})
        finite=[x['bits'] for x in checks if x['status']=='finite']
        if finite and min(finite)>=128:
            chosen=(c,checks); break
    if chosen is None:
        emit('family_failed',family); continue
    c,checks=chosen; certificate=compact_cert(c)
    row={'family':family,'old_quantum_checks':oldatt,'parameters':c,'attacks':checks,
         'minimum_completed_bits':min(x['bits'] for x in checks if x['status']=='finite'),
         'all_seven_checks_finite':all(x['status']=='finite' for x in checks),
         'polar':certificate,'search_dimensions':sorted(cache),
         'previous_grid_point':cache.get(hi-16,[None,None])[1]}
    selected.append(row); emit('selected',row)
emit('complete',{'selected_count':len(selected),'metadata':meta,'selected':selected})
