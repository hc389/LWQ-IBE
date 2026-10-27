"""Record finite-search results, selected points and complete provenance.

All scientific values are read from frozen JSON outputs. This script does not
run the estimator, change candidates, or write a manuscript.
"""
from pathlib import Path
import hashlib,json,csv,math
P=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(name):return json.loads((P/name).read_text())
verified=['quick-verified.json','higher-quick-verified.json','rs8192-small-verified.json',
          'rs1024-small-verified.json','folded-rs8192-large-verified.json',
          'folded-rs8192-refine-verified.json','folded-rs8192-final-verified.json',
          'folded-rs8192-mixed-verified.json','folded-rs8192-size-verified.json']
selected_names={'MPK-priority':'folded-rs8192-mixed-verified.json','CT-priority':'folded-rs8192-size-verified.json'}
qnames={'MPK-priority':'folded-rs8192-mpk-quantizers.json','CT-priority':'folded-rs8192-size-quantizers.json'}
allfiles=list(P.glob('*.py'))+list(P.glob('*.json'))
filehash={str(f.relative_to(P)):sha(f) for f in allfiles if f.name not in ['provenance.json','selected-results.json']}
pyhash={sha(f):str(f.relative_to(P)) for f in P.glob('*.py')}
jsonhash={sha(f):str(f.relative_to(P)) for f in P.glob('*.json')}
checks=[]
def ck(name,ok,**detail):
    checks.append(dict(name=name,pass_=bool(ok),**detail))
for fname in verified:
    d=read(fname)
    ck(fname+':script_hash_exists',d['script_sha256'] in pyhash)
    ck(fname+':screen_hash_exists',d['source_screen_sha256'] in jsonhash)
    ck(fname+':readonly_dependency_hash',sha(d['readonly_dependency'])==d['dependency_sha256'])
    for i,row in enumerate(d['rows']):
        c=row['parameters'];attacks=row['attacks']
        ck(f'{fname}:{i}:six_finite',row['six_attack_status']=='PASS' and len(attacks)==6 and
           all(a['status']=='ok' and math.isfinite(a['bits']) and a['bits']>=128 for a in attacks))
        ck(f'{fname}:{i}:polar',row['polar']['DFR_pass'] and row['polar']['savings_pass'] and row['polar']['lattice_layout_pass'])
        for a in attacks:
            sf,ef=Path(a['stdout_path']),Path(a['stderr_path'])
            cf=sf.parent/'candidate.json'
            ck(f'{fname}:{i}:{a["attack"]}:binding',sha(sf)==a['stdout_sha256'] and sha(ef)==a['stderr_sha256'] and
               sha(cf)==a['candidate_sha256']==row['frozen_candidate_sha256'] and json.loads(cf.read_text())==c)
            filehash[str(sf.relative_to(P))]=sha(sf);filehash[str(ef.relative_to(P))]=sha(ef);filehash[str(cf.relative_to(P))]=sha(cf)
selected={}
for label,fname in selected_names.items():
    row=read(fname)['rows'][0];q=read(qnames[label]);c=row['parameters']
    ck(label+':Ngrid_source',q['source_verified_sha256']==sha(P/fname))
    ck(label+':150decimal',q['precision150']['frozen_and_bytes_identical'] and
       q['precision150']['certificate']['frozen_sets']==row['polar']['frozen_sets'] and
       q['precision150']['certificate']['compressed_bytes']==row['polar']['compressed_bytes'])
    ck(label+':Ngrid',all(x['status']=='UNALIGNED' or x['status']=='PASS' for x in q['rows']))
    selected[label]=dict(source=fname,source_sha256=sha(P/fname),quantizers=qnames[label],
                         quantizers_sha256=sha(P/qnames[label]),**row)
selection=dict(scope='Finite searched recommendations, not a claim of global optimality or deployment',
               script_sha256=sha(__file__),selected=selected)
(P/'selected-results.json').write_text(json.dumps(selection,indent=2)+'\n')
lines=['# 第二轮 MPK 收紧实验结果','',
'本轮只写分析/实验目录，不改论文与既有快照。采用 Claude-Scholar results-analysis 与可复现性规则；理论门槛由同目录 ARS 推导和独立审计提供。', '',
'## 1. 范围与边界','',
'保留 Yamada17 FMAH 集合谓词、原 ReRand 因子 2、q=2^a、源高斯宽度 r、极化量化。变化明确包括：诚实/证明掩码熵、gadget 基数、RS 身份编码、公开常量 slot 折叠以及可选混合末 radix；不是把原 BCH 参数简单改名。', '',
'基础 LWE 估计固定 estimator commit 53da5982597709ba0fdf94ea37a84d822310fd84、ADPS16 classical Core-SVP、GSA、UniformMod(q) secret、DiscreteGaussian(r/sqrt(2pi)) error、m+1 samples。S 和 sigma 从未作为攻击输入的 r。六个有限攻击最低均不少于 128。此处不把基础 LWE 128 估计自动称为扣除分区损失后的完整 IBE 128 位结论。', '',
'RS8192 保留分区 gamma loss 26.262965 bits / effective loss 26.999653 bits；常量折叠不新增损失。RS1024 对照为 30.262661 / 30.998134 bits。所有数据为确定性充分条件与证书计算，不是大维实际 IBE 运行、内存分配或可部署声明；p值、重复种子和置信区间不适用。', '',
'## 2. 两个终选点','',
'| 指标 | MPK优先 | 完整CT优先 |','|---|---:|---:|']
cs={label:row['parameters'] for label,row in selected.items()}
for key,title in [('n','n'),('r','源宽度 r'),('q_bits','a (q=2^a)'),('m','m'),('w','有效 gadget 列数/宽度 w'),('bar','诚实源列数 bar'),('gadget_b','基数 b'),('gadget_digit_length','digit长度'),('gadget_last_radix','末radix'),('honest_entropy_k','kh'),('proof_entropy_k','kp'),('u','公开FMAH矩阵数 u')]:
    vals=[cs[x].get(key,cs[x]['q_bits']//cs[x]['gadget_t'] if key=='gadget_digit_length' else cs[x]['gadget_b'] if key=='gadget_last_radix' else '') for x in selected]
    lines.append(f'|{title}|{vals[0]}|{vals[1]}|')
for key,title in [('MPK_TiB','MPK (TiB)'),('S_log2','log2 S'),('sigma_log2','log2 sigma')]:
    vals=[f'{cs[x][key]:.9f}' for x in selected];lines.append(f'|{title}|{vals[0]}|{vals[1]}|')
for key,title in [('raw_bytes','完整原始CT (B)'),('compressed_bytes','完整polar CT (B)'),('combined_DFR_upper','合计DFR上界')]:
    vals=[selected[x]['polar'][key] for x in selected];lines.append(f'|{title}|{vals[0]}|{vals[1]}|')
vals=[f'{100*selected[x]["polar"]["complete_byte_saving_fraction"]:.6f}%' for x in selected]
lines += [f'|相对自身原始完整CT节省|{vals[0]}|{vals[1]}|','',
'完整CT已计入标量、全向量和256位seed；不是只统计vector，也不是相对更大参考格式人为放大压缩率。主N=256；DFR目标2^-160。极化匹配、有限精度与参考解密项合并核验，实际GPV采样器误差依约定边界单列，不假称测得。', '',
'### 六攻击值 (log2 rop)','',
'| 攻击 | MPK优先 | 完整CT优先 |','|---|---:|---:|']
for attack in ['usvp','bdd','dual','dual_hybrid','bdd_hybrid','mitm']:
    vals=[next(a['bits'] for a in selected[x]['attacks'] if a['attack']==attack) for x in selected]
    lines.append(f'|{attack}|{vals[0]:.9f}|{vals[1]:.9f}|')
lines += ['', '## 3. 量化格参数敏感性','',
'保持终选 IBE 参数不变，只改极化块长度 N；不为1024整除而修改m。110位与150位十进制计算在N256的冻结集合和字节数逐一一致。', '',
'| 终选点 | N | 状态 | 完整CT (B) | 节省 | 合计DFR上界 |','|---|---:|---|---:|---:|---|']
for label in selected:
    for r in read(qnames[label])['rows']:
        if r['status']=='UNALIGNED':lines.append(f'|{label}|{r["N"]}|UNALIGNED|—|—|—|')
        else:
            p=r['polar'];lines.append(f'|{label}|{r["N"]}|{r["status"]}|{p["compressed_bytes"]}|{100*p["complete_byte_saving_fraction"]:.6f}%|{p["combined_DFR_upper"]}|')
lines += ['', '## 4. 历史节点与可归因范围','',
'以下各点均通过各自冻结版本的六攻击和N256证书，但相邻行通常同时改变了结构/参数，不是固定n消融，也不能将全部改善归因于一个因素。', '',
'| 输出 | code | u | b | kh/kp | n | a | MPK (TiB) | 完整polar CT (B) |','|---|---|---:|---:|---|---:|---:|---:|---:|']
for f in verified:
    row=read(f)['rows'][0];c=row['parameters'];p=row['polar']
    lines.append(f'|{f}|{c.get("code_profile","origBCH")}|{c["u"]}|{c["gadget_b"]}|{c["honest_entropy_k"]}/{c.get("proof_entropy_k",1)}|{c["n"]}|{c["q_bits"]}|{c["MPK_TiB"]:.6f}|{p["compressed_bytes"]}|')
lines += ['', '## 5. 有趣现象与解释边界','',
'1. 增加诚实源熵最初减少bar，从而降低m；到kh96诚实GS支配后，sigma和q反而增大。固定结构数据见 honest-entropy-ablation.md/json，未把这些控制行冒充新安全推荐。',
'2. 大基数不是免费压缩：gadget列数随g减少，但digit范数、隐藏矩阵谱界、sigma/S与模数共同上升；4096基数在此次网格劣于64/256/1024。',
'3. MPK最小与完整CT最小不是同一个点：MPK含n*m*a和公开矩阵数，CT含2m*a并受极化冻结率影响。因此同时保留两项取舍，不以MPK排名代替CT排名。',
'4. g整除a是额外表示约束，混合末radix可去掉舍入台阶；已显式检查gadget乘积等于q，旧保守GS/CR界未降低。',
'5. 某些整除q点参考DFR指数达数百万。最终驱动只把极小参考上界保守放宽为2^-2048以避免巨大Decimal分母，记录原指数与实际使用指数；不改变几何参数、冻结集和字节数。', '',
'## 6. 复现入口与冻结绑定','',
'- round2_search_frozen_binarydiff.py：首轮 exact binary-proof 点验证。',
'- round2_search_frozen_highproof.py：原BCH higher-proof 历史点。',
'- round2_search_frozen_rs_small.py：80/82矩阵 RS 对照点。',
'- round2_search_frozen_folded_large.py / _refine.py / _final.py：逐批有限扫描历史。',
'- round2_search_frozen_mixed.py：最终混合radix及两终选六攻击/Ngrid，逐项独立进程300秒，最多2workers。',
'- candidate_polar_screen.py 与 mixed_polar_screen.py：已uSVP通过有限gate点的完整极化CT对照。',
'- selected-results.json：最终参数、六攻击与N256完整证书。',
'- provenance.json：输入、脚本、输出、候选和所有stdout/stderr SHA256逐项绑定。', '',
'扫描为分阶段、有界网格加n二分/8步邻域，不声称全局最优；screen中未做六攻击的行仍只是初筛。']
(P/'experiment-results.md').write_text('\n'.join(lines)+'\n')
with (P/'selected-summary.csv').open('w',newline='') as fp:
    fields=['label','n','r','a','m','b','kh','kp','MPK_TiB','raw_bytes','polar_bytes','saving_fraction','minimum_finite_bits']
    wr=csv.DictWriter(fp,fieldnames=fields);wr.writeheader()
    for label,row in selected.items():
        c=row['parameters'];p=row['polar']
        wr.writerow(dict(label=label,n=c['n'],r=c['r'],a=c['q_bits'],m=c['m'],b=c['gadget_b'],kh=c['honest_entropy_k'],kp=c['proof_entropy_k'],MPK_TiB=c['MPK_TiB'],raw_bytes=p['raw_bytes'],polar_bytes=p['compressed_bytes'],saving_fraction=p['complete_byte_saving_fraction'],minimum_finite_bits=row['minimum_finite_bits']))
for name in ['selected-results.json','experiment-results.md','selected-summary.csv','honest-entropy-ablation.md']:
    filehash[name]=sha(P/name)
proof=dict(scope='SHA256 binding of frozen sources, candidates, all finite attack logs and selected certificates',
           script_sha256=sha(__file__),status='PASS' if all(x['pass_'] for x in checks) else 'FAIL',
           checks=checks,files=filehash,verified_points=len(verified),finite_attack_logs=sum(len(read(f)['rows'][0]['attacks']) for f in verified))
(P/'provenance.json').write_text(json.dumps(proof,indent=2)+'\n')
print(json.dumps(dict(status=proof['status'],checks=len(checks),points=proof['verified_points'],finite_attack_logs=proof['finite_attack_logs'],selected={k:dict(MPK_TiB=v['parameters']['MPK_TiB'],polar_bytes=v['polar']['compressed_bytes']) for k,v in selected.items()})),flush=True)
assert proof['status']=='PASS'
