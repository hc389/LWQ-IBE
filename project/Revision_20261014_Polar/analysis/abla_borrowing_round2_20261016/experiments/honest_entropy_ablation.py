"""Fixed n/r/radix/proof/code controls; only honest entropy kh varies.

These are deterministic constraint/formula evaluations, not new attack-verified
parameter recommendations. q, m, S and sigma are re-selected by the same rules.
"""
import hashlib,json
from pathlib import Path
import round2_search_frozen_mixed as R
P=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
targets=[dict(name='MPK-priority',n=10072,r='8192',b=64,kp=6,mixed=True),
         dict(name='CT-priority',n=11600,r='4096',b=1024,kp=9,mixed=False)]
d=dict(scope=__doc__,script_sha256=sha(__file__),candidate_dependency_sha256=sha(R.__file__),rows=[])
lines=['# 诚实源熵的固定结构消融','',
'仅固定 n、r、b、proof_k、身份编码与 mixed 选项，重新满足约束选择 q、m、S、sigma；不是固定所有参数的单变量运行时间实验，也不是新安全推荐。', '',
'| 目标 | kh | n | a | m | w | bar | log2 S | log2 sigma | 诚实GS支配 | MPK (TiB) |',
'|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|']
for t in targets:
    for kh in [8,16,32,64,80,96]:
        c=R.candidate(t['n'],t['r'],t['b'],kh,'higher',t['kp'],'folded_rs8192',mixed=t['mixed'])
        d['rows'].append(dict(target=t,parameters=c))
        lines.append(f"|{t['name']}|{kh}|{c['n']}|{c['q_bits']}|{c['m']}|{c['w']}|{c['bar']}|{c['S_log2']:.3f}|{c['sigma_log2']:.3f}|{c['honest_GS_dominates']}|{c['MPK_TiB']:.6f}|")
lines += ['', '增大 kh 首先降低熵所需的 bar，但诚实GS界显式支付 2^(kh-1)；较大 kh 使诚实GS支配后，sigma 和 q 会反升。所有行仅采用同一充分条件，不能称全局最优。']
(P/'honest-entropy-ablation.json').write_text(json.dumps(d,indent=2)+'\n')
(P/'honest-entropy-ablation.md').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines),flush=True)
