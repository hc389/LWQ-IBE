"""Re-run only the previously timed-out branch, preserving attack settings."""
import sys
sys.dont_write_bytecode = True
import json, math, os, time, signal, resource, hashlib, subprocess
from pathlib import Path

EST = Path('/Users/Admin/Desktop/IBE/Revision_20261012/experiments/A3_lattice-estimator')
sys.path.insert(0, str(EST))
from sage.all import RR, ZZ, sqrt, pi, log
from sage.env import SAGE_VERSION
from estimator import LWE, ND
from estimator.reduction import ADPS16

family = sys.argv[1]
n,a,r,M = {'mpk':(10848,240,8192,466561), 'ct':(12480,271,4096,391809)}[family]
q = ZZ(2)**a
p = LWE.Parameters(n=n,q=q,Xs=ND.UniformMod(q),Xe=ND.DiscreteGaussian(RR(r)/sqrt(2*pi)),m=M)
def emit(kind, data):
    print(json.dumps({'kind':kind,'data':data},ensure_ascii=False),flush=True)
def timeout(*args):
    raise TimeoutError('1800-second MITM re-run limit')
signal.signal(signal.SIGALRM, timeout)
meta = {'family':family,'n':n,'q_log2':a,'r':r,'samples':M,
        'input':repr(p),'sage':SAGE_VERSION,'pid':os.getpid(),
        'estimator_commit':subprocess.check_output(['git','-C',str(EST),'rev-parse','HEAD'],text=True).strip(),
        'primal_source_sha256':hashlib.sha256((EST/'estimator/lwe_primal.py').read_bytes()).hexdigest(),
        'call':"LWE.primal_hybrid(p,mitm=True,babai=True,red_cost_model=ADPS16(mode='quantum'),red_shape_model='gsa')",
        'timeout_seconds':1800,'initial_maxrss':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
emit('start',meta)
start=time.monotonic(); cpu_start=time.process_time(); signal.alarm(1800)
try:
    result=LWE.primal_hybrid(p,mitm=True,babai=True,red_cost_model=ADPS16(mode='quantum'),red_shape_model='gsa')
    bits=float(log(result['rop'],2))
    record={'family':family,'status':'finite' if math.isfinite(bits) else 'nonfinite','bits':bits,
            'raw':repr(result),'fields':{str(k):str(v) for k,v in result.items()},
            'seconds':time.monotonic()-start,'cpu_seconds':time.process_time()-cpu_start,
            'maxrss':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'metadata':meta}
    emit('result',record)
    if not math.isfinite(bits): sys.exit(3)
except Exception as exc:
    emit('failure',{'family':family,'status':'timeout' if isinstance(exc,TimeoutError) else 'error',
                    'error':repr(exc),'seconds':time.monotonic()-start,
                    'maxrss':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'metadata':meta})
    sys.exit(2)
finally:
    signal.alarm(0)
