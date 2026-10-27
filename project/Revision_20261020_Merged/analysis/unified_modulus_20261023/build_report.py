"""Join exact certificates, bound input-matched estimates, and render analysis artifacts."""
from pathlib import Path
import csv
import hashlib
import json
import math

HERE=Path(__file__).resolve().parent
OLD=HERE.parents[2]/'Revision_20261014_Polar/analysis'

def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def mdtable(headers,rows):
    return '\n'.join(['| '+' | '.join(headers)+' |','|'+'|'.join(['---']*len(headers))+'|']+
                     ['| '+' | '.join(map(str,row))+' |' for row in rows])
def findparams(obj,n):
    if isinstance(obj,dict):
        if obj.get('n')==n and all(k in obj for k in ['q','m','r']) and any(k in obj for k in ['MPK_bytes','MPK_matrix_vector_bytes']):return obj
        for v in obj.values():
            found=findparams(v,n)
            if found:return found
    elif isinstance(obj,list):
        for v in obj:
            found=findparams(v,n)
            if found:return found

def main():
    sec=read(HERE/'security/verified.json')
    assert len(sec['attacks'])==18 and all(x['status']=='completed' for x in sec['attacks'])
    assert all(x['status']=='PASS' for x in sec['candidate_status'])
    dim=read(HERE/'dimension_screen.json')
    ours=read(HERE/'ours/ours_shared_column_audit.json')
    reuse=read(HERE/'ours/security-reuse.json')
    rows=[]
    names=['JKN21','Abla24 Type I','Abla24 Type II']
    for i,c in enumerate(dim['selected']):
        attacks=[x for x in sec['attacks'] if x['candidate_index']==i]
        assert all(int(x[k])==int(c[k]) for x in attacks for k in ['n','q','r','m'])
        rows.append(dict(name=names[i],id=c['profile_id'],n=c['n'],r=int(c['r']),a=c['q_bits'],m=c['m'],
                         q=c['q'],CT_bytes=c['raw_ciphertext_bytes'],raw_bytes=c['raw_ciphertext_bytes'],
                         MPK_bytes=c['MPK_bytes'],minimum_bits=min(x['bits'] for x in attacks),
                         security_evidence='18 new attack calls, six per baseline',
                         attack_bits={x['attack']:x['bits'] for x in attacks},compression_percent=0))
    for ob,ev in zip(ours['rows'],reuse['rows']):
        c=ob['selected'];p=ob['polar'];rr=ev['evidence']
        assert ob['name']==ev['name'] and all(rr['identical_input_fields'].values())
        rows.append(dict(name='Ours '+ob['name'],id=ob['name'],n=c['n'],r=c['r'],a=c['q_bits'],m=c['m'],
                         q=c['q'],CT_bytes=p['compressed_bytes'],raw_bytes=c['raw_complete_ciphertext_bytes'],
                         MPK_bytes=c['MPK_bytes'],minimum_bits=rr['minimum_finite_bits'],
                         security_evidence='Reused six exact-input-matched saved attacks; not rerun',
                         attack_bits={x['attack']:x['bits'] for x in rr['attacks']},
                         compression_percent=100*(1-p['compressed_bytes']/c['raw_complete_ciphertext_bytes'])))
    for r in rows:
        r['CT_MiB']=r['CT_bytes']/2**20;r['MPK_TiB']=r['MPK_bytes']/2**40
    oldsources=[(OLD/'baseline_mpk_128_20261015/jkn/verified.json',5712),
                (OLD/'abla_fulltext_128_20261015/verified.json',8336),
                (OLD/'abla_fulltext_128_20261015/abla_typeII/verified-typeII.json',9504)]
    oldrows=[]
    for name,(p,n) in zip(names,oldsources):
        c=findparams(read(p),n);assert c
        oldrows.append(dict(name=name,n=n,r=int(c['r']),a=c['q_bits'],m=c['m'],
                            CT_bytes=c['raw_ciphertext_bytes'],
                            MPK_bytes=c.get('MPK_bytes',c.get('MPK_matrix_vector_bytes')),
                            source=str(p),sha256=sha(p)))
    boundary=[]
    for i,c in enumerate(dim['selected']):
        ld=read(HERE/'baselines'/f"{c['profile_id']}-ledger.json")
        assert all(x['failures'] for x in ld['rows'][:-1]) and not ld['selected']['failures']
        boundary.append(dict(name=names[i],a=c['q_bits'],previous_ratio=ld['previous']['MGF_ratio'],
                             selected_ratio=c['MGF_ratio'],examined=len(ld['rows']),domain='a=2..selected; prime family'))
    for ob in ours['rows']:
        c=ob['selected'];previous=next(x for x in ob['ledger'] if x['q_bits']==c['q_bits']-1)
        boundary.append(dict(name='Ours '+ob['name'],a=c['q_bits'],previous_ratio=previous['decryption_ratio'],
                             selected_ratio=c['decryption_ratio'],examined=len(ob['ledger']),
                             domain='a<80 excluded by fixed kH=80; every a=80..selected checked'))
    # Extend the existing narrow, fixed-source BKW/Arora model audits by checking their predicates.
    bounds=[]
    for r in rows:
        q=int(r['q']);n=r['n'];width=r['r']
        assert r['m']+1>=2*n and width>=203 and n-159>4096
        # pi<4: sd=r/sqrt(2pi)>r/3>16; therefore all Gaussian equation degrees>16.
        assert width>48
        bounds.append(dict(name=r['name'],original_modulus_BKW_log2_lower_bound=2*(q.bit_length()-1),
                           Arora_GB_dense_log2_lower_bound=160,
                           status='COVERED_BY_FIXED_MODEL_BOUND_NOT_NUMERIC_EXECUTION'))
    data=dict(scope='classical narrow-source LWE target only; no complete IBE security equivalence',
              new_attacks=18,reused_attacks=18,rows=rows,old_baselines=oldrows,boundaries=boundary,
              additional_fixed_model_bounds=bounds,dimension_screen_points=len(dim['rows']),
              source_hashes={str(p.relative_to(HERE)):sha(p) for p in [HERE/'security/verified.json',HERE/'dimension_screen.json',
                             HERE/'ours/ours_shared_column_audit.json',HERE/'ours/security-reuse.json']})
    (HERE/'comparison.json').write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
    with (HERE/'comparison.csv').open('w') as f:
        keys=['name','n','r','a','m','CT_bytes','CT_MiB','MPK_bytes','MPK_TiB','minimum_bits','compression_percent']
        wr=csv.DictWriter(f,fieldnames=keys,extrasaction='ignore');wr.writeheader();wr.writerows(rows)
    table=mdtable(['方案','n','r','a','m','完整 CT / MiB','MPK 主体 / TiB','六攻击最低 / bit'],
                  [[r['name'],r['n'],r['r'],r['a'],r['m'],f"{r['CT_MiB']:.6f}",f"{r['MPK_TiB']:.6f}",f"{r['minimum_bits']:.6f}"] for r in rows])
    oldtable=mdtable(['方案','旧→新 a','旧→新 n','旧→新 CT / MiB','旧→新 MPK / TiB'],
                    [[old['name'],f"{old['a']} → {new['a']}",f"{old['n']} → {new['n']}",
                      f"{old['CT_bytes']/2**20:.6f} → {new['CT_MiB']:.6f}",
                      f"{old['MPK_bytes']/2**40:.6f} → {new['MPK_TiB']:.6f}"] for old,new in zip(oldrows,rows)])
    btable=mdtable(['方案','最小通过 a','a−1 的正确性比值','a 的正确性比值'],
                   [[b['name'],b['a'],f"{b['previous_ratio']:.6f}",f"{b['selected_ratio']:.6f}"] for b in boundary])
    atable=mdtable(['攻击']+[r['name'] for r in rows],
                  [[a]+[f"{r['attack_bits'][a]:.6f}" for r in rows] for a in ['usvp','bdd','dual','dual_hybrid','bdd_hybrid','mitm']])
    exacttable=mdtable(['方案','q（精确整数）','完整 CT / bytes','MPK 主体 / bytes'],
                      [[r['name'],r['q'],r['CT_bytes'],r['MPK_bytes']] for r in rows])
    jkn,ablaI,ablaII,mpk,mid,ct=rows
    report=f'''# 三方案统一参数分析、独立最小可认证模数与尺寸重比较

日期：2026-10-23。论文未修改。Claude-Scholar（本地 results-analysis）负责可复现实验；ARS 辅助审计可迁移界。来源：[Claude-Scholar 可复现性规范](https://github.com/Galaxy-Dawn/claude-scholar/blob/main/rules/experiment-reproducibility.md)。

## Material Passport

- 类型：确定性参数搜索、有限证书重算与固定版本攻击估计；无完整 IBE 执行。
- 对象：Revision_20261020_Merged 最新稿的三方案比较；基线不加任何压缩。
- 证据状态：基线 18 项攻击新运行；本文 18 项攻击精确输入绑定复用；量化证书重新计算。
- 修改权限：仅本分析目录，论文只读。完整脚本、候选、拒绝记录、环境与源哈希随报告保存。

## 1. 结论先行

**统一共享分析之后，基线可以明显缩小；本文三个经典配置的最小通过模数和尺寸不变。** 因此旧表的基线偏保守，原来对基线的优势幅度需要下调，但原生量化的约49%自身压缩收益不变。

{table}

主比较均为**相同经典底层 LWE 128 位估计目标**，不是相同完整 IBE 安全强度。Abla Type I/II 是同一文献的两种原始变体；本文 C-Mid 仅是原有折中配置。JKN 另有 wNCR 假设且这里的 MPK 未包括未实例化的哈希描述。密文为单 bit 完整格式，MPK 为展开系数主体，并不是实测文件或已执行 TB 级 Setup。

具体含义：

- 本文 C-CT 完整密文为 {ct['CT_MiB']:.6f} MiB，比重新校准后的 Abla Type II 短 **{100*(1-ct['CT_bytes']/ablaII['CT_bytes']):.2f}%**，比 JKN21 短 **{100*(1-ct['CT_bytes']/jkn['CT_bytes']):.2f}%**。
- 本文 C-MPK 公钥主体为 {mpk['MPK_TiB']:.6f} TiB，比 Abla Type II 小 **{100*(1-mpk['MPK_bytes']/ablaII['MPK_bytes']):.2f}%**，但为 JKN21 主体的 **{mpk['MPK_bytes']/jkn['MPK_bytes']:.3f} 倍**。不能声称公钥全面最小。
- 本文 C-MPK / C-Mid / C-CT 相对各自未压缩格式节省 **{mpk['compression_percent']:.4f}% / {mid['compression_percent']:.4f}% / {ct['compression_percent']:.4f}%**，仍超过30%。跨方案大小差不是纯粹的量化压缩率，还包含各方案结构和参数差异。

## 2. 这次真正统一了什么

完整推导见 [共享分析审计](audit.md)。保留各自原始身份求值、掩码分布、安全模型和密文格式，不把本文高熵掩码或压缩器移植给基线。

1. **正确性统一为 Gaussian 线性型 MGF 尾界**，不再让 JKN 独自承担更松的 Cauchy 范数界。
2. **有限平滑系数统一**：取满足 `3140h²>694(theta+2)` 的最小整数 h，当前均为8。
3. **诚实与模拟陷门都采用可验证的逐列 GS 界，并与旧谱范数界取小者**。素数 gadget 最后一列虽然通常不稀疏，但 GS 可以减去前列的实线性组合；其残差有短的一范数界，所以方法也适用于两个素数模数基线。
4. **ReRand 统一保留原因子2**，按 `[I|R]` 的精确范数关系计算严格整数宽度 `S=isqrt(4r²(1+rho²))+1`。去掉 JKN 额外的 sqrt(2) 粗界不是降低 ReRand 的因子2，也不是给它加量化。
5. **预算统一**：T=232、Q_E=2^16、T_tail=200、T_G=162、参考总 DFR 目标2^-160。本文另支付量化匹配误差；不存在量化器的基线不强行添加该项。
6. **估计与计数统一**：窄源误差的定义及标准差换算、攻击模型、样本口径、位打包和单位统一；r的数值分别选择。依赖方案的 rho、身份代码、矩阵数和熵门槛不强制相等。

本轮的基线数值是原抽象算法接口下的新有限参数分析，不是原作者公布的具体参数；它使用明确核基实现相同 Gaussian 采样接口，不声称原作者的软件已采用这些基或完成运行。

## 3. 搜索过程：先消除分析不对称，再回到同一安全门槛

第一阶段固定旧 n/r，只换共享分析。固定维数结果完整保留在 `baselines/shared_column.json`；只做这一步会使某些基线的底层 LWE 估计明显超过128，进而不必要地保留较大维数。

第二阶段按原来的基线结构做有界维数重校准：JKN、Abla I 取 `r=ceil(3 sqrt(n))`，Abla II 保持r=512；从原点向下按128维寻找门槛区间，再在边界及相邻区间枚举16维网格。共保存 {len(dim['rows'])} 个 uSVP 筛选点。**这些筛选点不是全攻击通过结果**；只对主表三个选中基线完成六攻击复核。

{oldtable}

旧 JKN 行是最新稿的低r原 Cauchy 条件行（n5712），不是其另一个高r对照。所有中间分析和失败点保留；主表并非对全部 n/r/gadget/身份代码做全局优化。

## 4. “最小可认证模数”具体认证到哪里

固定每一行的 n/r、身份结构、gadget/熵配置及列数规则，逐一枚举 a。本文 `q=2^a` 且每个允许位长都检查（含混合末radix）；基线 `q=previous_prime(2^a)`。每次都重算 w、m、范数、sigma、S 和正确性条件，不能把旧噪声固定后只将q除以2。

定义正确性比值：本文 `q²/(652W²)`，奇素数基线 `(q−8)²/(652W²)`。小于1表示该充分正确性条件不通过。

{btable}

这张表只是最邻近失败点的摘要，完整账本证明声明域内**所有更小位长候选**均未通过。本文a<80是固定80-bit诚实掩码配置的声明域外，不是证明其不安全。基线a=1没有可选素数，a=2起全查。维数策略中列数保留128对齐；另保存alignment1敏感性，不宣称其必要。

结论严格限于**所列充分条件、固定设计及声明模数族内最小通过位长**；不宣称更小模数真实不安全，也不宣称素数位长区间内的最小数值素数或所有参数的全局最优。

## 5. LWE 安全估计：新运行与复用明确分开

固定 lattice-estimator `53da5982597709ba0fdf94ea37a84d822310fd84`，Sage10.9，ADPS16 classical Core-SVP，primal GSA。输入 `Xs=UniformMod(q), Xe=DiscreteGaussian(r/sqrt(2pi)), M=m+1`；绝不把输出S或私钥sigma当作源误差。基线18项新运行全部有限完成；本文源输入(n,q,r,m+1)完全相同，18项历史记录逐项绑定原日志和哈希后复用。

{atable}

另将原有两个**受限源码模型下界**按新参数检查：原模数 coded-BKW 至少q²，所有点最低保守位数为 {min(x['original_modulus_BKW_log2_lower_bound'] for x in bounds)}；默认 Gaussian Arora–GB+dense猜测至少2^160，推导见 [附加模型覆盖](additional-model-bounds.md)。这是解析覆盖，不是两项优化器成功运行；不覆盖模数切换等其他攻击变体，也不构成对未知攻击的保证。

没有从这些位数扣除规约优势损失来声称完整 IBE 位安全。本文量子配置另外做了模数算术复核（a240/271不变），不混入本次经典三方案主表，也没有给两个基线补做量子校准。

## 6. 量化证书与正确性边界

本文采用现有N=256、公开种子256bit、总SC匹配预算2^-170。重新计算了110与150位小数精度证书，冻结集合和完整字节一致。三个经典点的S、sigma、m、q均未改变，故完整CT仍为13019115、12419313、12189318 bytes。

诚实TrapGen列界虽然变紧，但本文三个边界点都是模拟端GS界主导，因此sigma和可认证q不变。先前“C-CT只搜10倍数可能错过更小q”的疑虑，本轮通过补查全部位长排除：在固定设计下a261–269等候选也失败。

这是理想参考采样和已声明有限证书下的正确性界；实际私钥/标量采样器误差、实现终止误差仍需按原边界单独支付。不是完整 IBE 实测成功率，不作可部署声明。

## 7. 有趣现象及其设计含义

**现象一：较紧GS界主要改善了基线，而非本文。** 原基线用整个矩阵谱界估计私钥宽度，列结构被浪费；本文原模拟界已利用列结构。因而这项方法不应再作为仅属于本文的参数优势。

**现象二：收紧私钥宽度可以降低模数，但仍不能把本方案的模数压到基线以下。** 本文的求值器、radix和证明掩码宽度仍决定较大rho/S；当前密文优势来自较少的列与原生量化表示，并非小模数。

**现象三：基线变强后，本文压缩功能仍然成立，但MPK的相对优势变弱。** 对AblaII的MPK优势从旧比较约31%变成约{100*(1-mpk['MPK_bytes']/ablaII['MPK_bytes']):.2f}%；对JKN没有MPK优势。尺寸比较必须同时给出这种代价。

上述解释来自对应公式与单因素中间记录，不是根据几个点推断所有同类IBE。进一步改结构或搜索更多radix/熵/身份码需要另立实验，不属于本轮结论。

## 8. 能说什么、不能说什么

- **允许**：在相同底层经典LWE目标、列明攻击模型和共同有限分析工具下，本文完整密文更短，且相对自身未压缩格式仍节省约49%。证据：`comparison.json`、攻击日志和量化证书。
- **允许**：本轮为每个固定设计找到声明模数族内的最小可认证位长。证据：完整拒绝账本。局限：有限条件可能仍保守、其他设计未全搜。
- **禁止**：完整IBE安全完全相同、所有攻击均已运行、全局最优、可部署、无显式采样、JKN/Abla原作者给出了这些参数，或本文MPK全面最小。
- **下一步**：作者确认后再决定是否更新正文与R4-4回复；本轮不执行改稿。

## 9. 精确计数与复现入口

{exacttable}

- [参数审计推导](audit.md)、[预先固定口径及执行补充](protocol.md)。
- [精确总表JSON](comparison.json)、[CSV](comparison.csv)、[六攻击新日志](security/verified.json)。
- [本文模数及量化证书](ours/analysis-report.md)、[基线方法与中间结果](baselines/方法与中间结果.md)。
- [统计适用性与验证](stats-appendix.md)、[图说明](figure-catalog.md)。
- `retune_baselines.py`：有界维数重校准；`baselines/search_baselines_column.py`：基线逐位枚举；`ours/search_shared_column.py`：本文统一列界后的重算。
- `check_column_lemma.py`：42组小矩阵的精确有理数一致性测试，全部通过；不能替代audit.md中的数学证明。
- `paper-before.json` 与 `paper-after.json`：论文目录运行前后逐文件哈希；最终状态见 `final-qa.json`。
'''
    (HERE/'analysis-report.md').write_text(report)
    (HERE/'additional-model-bounds.md').write_text('''# 附加固定源码模型覆盖（非新数值运行）

同一estimator提交与原有审计：`Revision_20261014_Polar/analysis/experiment_guidance_20261014/bkw_cost_bound_review.md`、`arora_cost_bound_review.md`。只沿用这些明确模型，不扩展到模数切换或其他代数预处理。

1. 原模数coded-BKW默认b>=2，非负成本中包含 q^b(b log2 q+1)，故 C>=q²，至少2 floor(log2 q)位。normalize和扩样不改变q；不把程序异常记成无穷成本。
2. 所有新旧主表点r>=203，sigma=r/sqrt(2pi)>r/3>16，因此Gaussian噪声/秘密方程最低度大于16，有限d_reg>=16。秘密密度>1/2，按原默认dense乘法猜测模型，每个猜测坐标的代价保守下界2。若zeta>=160，总成本>=2^160；若zeta<160，剩余n'>4096，基础GB成本>=binom(n'+16,16)^2 >=(n'/16)^32 >2^256，因此仍>=2^160。这里不把秘密换成二元分布，只放松猜测乘法代价；默认Gaussian分布的degree与normalize条件保持。
3. 已逐点检查m+1>=2n、n−159>4096、r>=203。原始秘密仍是UniformMod(q)；此处是estimator的normalize在样本充足时将秘密换成与误差同宽的Gaussian，之后才应用上述方程度论证。因而输入与上述界匹配。六项有限结果的最小值和这两个解析界分开列，不假装八项数值成功，更不推导完整IBE位安全。

逐点结果见comparison.json的additional_fixed_model_bounds。
''')
    make_figures(rows,oldrows,boundary)
    print(json.dumps({'rows':len(rows),'new_attacks':18,'reused_attacks':18,'report':str(HERE/'analysis-report.md')}))

def make_figures(rows,oldrows,boundary):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    figdir=HERE/'figures';figdir.mkdir(exist_ok=True)
    plt.rcParams.update({'font.size':10,'axes.spines.top':False,'axes.spines.right':False,'pdf.fonttype':42})
    chosen=[rows[i] for i in [0,1,2,3,5]]
    fig,axs=plt.subplots(1,2,figsize=(10.5,4.6),layout='constrained')
    colors=['#0072B2','#56B4E9','#009E73','#D55E00','#E69F00']
    for ax,key,label in [(axs[0],'CT_MiB','Complete ciphertext (MiB)'),(axs[1],'MPK_TiB','Expanded MPK core (TiB)')]:
        bars=ax.barh(range(len(chosen)),[r[key] for r in chosen],color=colors)
        ax.set_yticks(range(len(chosen)),[r['name'] for r in chosen]);ax.invert_yaxis();ax.set_xlabel(label)
        ax.set_xlim(0,max(r[key] for r in chosen)*1.2);ax.grid(axis='x',alpha=.2);ax.set_axisbelow(True)
        for bar,r in zip(bars,chosen):ax.text(r[key]+max(x[key] for x in chosen)*.015,bar.get_y()+bar.get_height()/2,f'{r[key]:.2f}',va='center')
    fig.savefig(figdir/'01-common-comparison.pdf');fig.savefig(figdir/'01-common-comparison.png',dpi=180);plt.close(fig)
    fig,axs=plt.subplots(1,2,figsize=(10.5,4.4),layout='constrained');x=np.arange(3)
    for ax,key,den,label in [(axs[0],'CT_bytes',2**20,'Complete ciphertext (MiB)'),(axs[1],'MPK_bytes',2**40,'Expanded MPK core (TiB)')]:
        ax.bar(x-.18,[r[key]/den for r in oldrows],.36,label='Previous finite analysis',color='#999999')
        ax.bar(x+.18,[r[key]/den for r in rows[:3]],.36,label='Shared bounds + n recalibration',color='#0072B2')
        ax.set_xticks(x,['JKN21','Abla24 I','Abla24 II']);ax.set_ylabel(label);ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True)
    axs[0].legend(fontsize=8)
    fig.savefig(figdir/'02-baseline-reanalysis.pdf');fig.savefig(figdir/'02-baseline-reanalysis.png',dpi=180);plt.close(fig)
    (HERE/'figure-catalog.md').write_text('''# 图与解读

## 01-common-comparison.pdf

- 目的：比较统一分析、同经典底层LWE128目标后的完整密文与展开MPK主体。
- 数据：comparison.json，确定性有限参数与位打包；没有随机重复、误差条或显著性检验。
- 观察：本文密文短；JKN公钥主体更小；本文相对AblaII的公钥优势有限。
- 含义：不能把密文优势扩张成全面效率优势。
- 图注必须注明：JKN未包含未实例化wNCR哈希描述；原基线无压缩；不等于同完整IBE安全，不是全维实测。

## 02-baseline-reanalysis.pdf

- 目的：显示旧比较中基线保守性对尺寸的影响。
- 数据：comparison.json中的old_baselines和新主表前三行；源文件哈希随JSON保存。
- 观察：共享MGF、平滑/逐列GS和ReRand分析，再回调n后，基线变小。
- 含义：旧优势百分比应下调；基线算法格式并未被添加压缩。
- 边界：此图合并了理论界收紧和维数重选，不把总变化全部归因于单个界。固定n中间点在baselines/中可拆解。
''')

if __name__=='__main__':main()
