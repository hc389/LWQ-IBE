# 三方案共同有限参数分析：独立理论与公式审计

日期：2026-10-23。范围：本文、JKN21、Abla24 的有限参数分析与最小可认证模数搜索；不修改稿件，不给基线添加压缩，不执行原论文的完整 IBE 实现。

本记录将可迁移的分析工具共同用于三个方案，保留各自的公开求值电路、掩码分布、模数类别与密文格式。JKN21/Abla24 数值是对原抽象算法接口的有限重分析，不是作者发表的推荐参数，也不是原作者实现的性能测量。基础 LWE 的估计目标、完整方案规约、正确性和统计距离是不同的证据，不能相互替代。

## 1. 统一规则和不统一的内容

共同使用：

- 源噪声参数化 `rho_r(x)=exp(-pi x^2/r^2)`，估计器的标准差为 `r/sqrt(2pi)`；秘密为 `UniformMod(q)`，样本数为 `m+1`。
- `T=232`、`Q_E=2^16`、私钥范数尾预算 `T_tail=200`、Gaussian 相位尾预算 `T_G=162`、参考总 DFR 目标 `2^-160`。
- 有限 GPV 平滑系数、私钥范数 MGF、Gaussian 线性型 MGF、逐列 gadget 核基 GS 分析和原 ReRand 的因子 2。
- 同一底层 LWE 攻击成本模型与攻击覆盖；参数改变后不能直接沿用旧参数的攻击输出。

保留差异：求值电路、矩阵数量、身份编码/分区假设、公开编程的熵条件、原掩码分布、素数与二次幂模数类别、本文的原生量化。特别是 JKN 的 wNCR 假设和 IND-ID-CPA IB-KEM 并不等于本文的匿名 IBE 安全模型。本文量化误差必须另外记账，不能因为参考 Gaussian 相位尾相同而删除。

## 2. 通用逐列 Gram–Schmidt 引理

### 2.1 主 gadget 核基

设整数 radix `b>=2`，取 `s` 使 `b^(s-1)<q<=b^s`，主 gadget 为

\[
g=(1,b,\ldots,b^{s-1}),\qquad Jz=(\pm Rz,z).
\]

`R` 可以是矩形；假设它的每一列二范数不超过 `C`。取主核基前 `s-1` 列

\[
v_j=b e_j-e_{j+1}.
\]

最后一列取 `q` 的 radix 数字向量 `d`，满足 `g^T d=q`。当 `q=b^s` 时取 `d=b e_s`；当 `s=1` 时前面没有列，取 `d=(q)`。该整数矩阵的行列式绝对值为 `q`，各列都在 `ker_q(g)` 中，因此是整个主核格的基。

对于前 `s-1` 列，

\[
\|Jv_j\|_2^2
 =\|bR_j-R_{j+1}\|_2^2+b^2+1
 \le(b+1)^2C^2+b^2+1.
\]

GS 长度不超过原列长度。对于最后一列，不需要直接以 `q` 的非零数字数目界住 `Rd`：前 `s-1` 列的实张成空间为 `g` 的正交补。存在前面列的实线性组合，将 `d` 化为

\[
v=\frac{qg}{\|g\|_2^2}.
\]

GS 是到已张成空间的最短距离，故提升后的最后 GS 长度不超过 `||Jv||_2`。几何级数给出（包括 `s=1`）

\[
\|v\|_1
 =\frac{q\sum_{j=0}^{s-1}b^j}{\sum_{j=0}^{s-1}b^{2j}}
 =\frac{q(b+1)}{b^s+1}\le b+1.
\]

又因 `q<=b^s`、`||g||_2>=b^(s-1)`，有 `||v||_2<=b`。于是

\[
\|Jv\|_2^2\le C^2\|v\|_1^2+\|v\|_2^2
 \le(b+1)^2C^2+b^2.
\]

因此主 gadget 图空间核基的 GS 最大长度满足

\[
L_{\rm col}\le
\left\lceil\sqrt{(b+1)^2C^2+b^2+1}\right\rceil.\tag{1}
\]

这适用于素数 `q`，也适用于二次幂及末位混合 radix 的 `q`。推导使用的是实投影，不要求 `v` 为整数；整数性只要求原始基列为整数。

### 2.2 多块、冗余幂、补零列和排列顺序

先依次放置所有 `n` 个主 gadget 块的完整核基。此前其他块已张成的空间只会缩短 GS 残差，因此逐块使用上述界仍然成立。

然后处理额外的 gadget 幂与零列。对每个新增列，取核向量 `e_extra-z_digits`，其中 `z_digits` 支持在已经处理的主 gadget 坐标上，且其 gadget 像等于新增列。主核基在实数域张成全部主坐标空间，故提升后可减去整个 `J z_digits`，以 `J e_extra` 为残差候选，长度至多 `sqrt(C^2+1)`。局部零列以及全局补零列是该步骤的特例。

该排序不可省略：先放主核基，再放冗余/零列。如果任意改变基列顺序，不能不加验证地宣称同一 GS 界。

### 2.3 完成诚实与模拟私钥核格的基

模拟端矩阵为 `[A | AR+HG]`，`H` 可逆，图空间提升为 `Jz=(-Rz,z)`。因为 `ker_q(HG)=ker_q(G)`，前面的基向量属于私钥矩阵的核。对每个 `A_i` 选择整数 `z_i` 满足 `HGz_i=-A_i mod q`，再附加

\[
(e_i-Rz_i,z_i).
\]

它与 `(e_i,0)` 的差位于已张成图空间，因此新增 GS 长度至多 1。整数生成性可由映射 `(x,z) -> x+Rz` 验证：先用补向量消掉该整数坐标，剩余向量由 gadget 核基生成。

诚实端 `A=[Abar | G-Abar R_A]` 用 `Jz=(R_Az,z)`，同样先放 gadget 图空间核基，再附加 `(e_i+R_Az_i,z_i)`；证明完全相同。进一步把 `A` 扩展为 `[A|B]` 时，先保留 `A` 的核基，再放解 `Ay_j=-B_j` 得到的 `(y_j,e_j)`；新增 GS 长度为 1。

所以式 (1) 对诚实矩形 `R_A` 和模拟方形 `R` 均合法。该论证提供显式核基与多项式时间的基转换/采样接口；没有说明这些巨大维数下的转换或 GPV 实现具有实用运行时间，更没有计时证据。

### 2.4 与已有全矩阵界取最小

标准主 radix gadget 的 GS 不超过 `sqrt(b^2+1)`；补列不会增大该界。若已有谱范数上界 `rho`，则另一合法界为

\[
L_{\rm full}^2\le(b^2+1)(1+\rho^2).
\]

因此程序可以先取两种平方上界的最小值，再作整数平方根向上舍入。此处没有将用于 ReRand 的谱界替换成列界。

## 3. JKN21：源证明直接支持的两个收紧

首要原始来源为作者 David Niehues 博士论文 `More Efficient Techniques for Adaptively-Secure Cryptography` 中 JKN21 的完整重述；不是声称已经逐式核对会议版本。

本地来源：[niehues_thesis.pdf](/Users/Admin/Desktop/IBE/Revision_20261014_Polar/analysis/baseline_mpk_128_20261014/jkn/sources/niehues_thesis.pdf)。下列页码是 PDF 页序／印刷页码；已有结构预检记录的源哈希与本次读取一致。

| 来源位置 | 直接支持的事实 |
|---|---|
| PDF166／156，Lemma25 | 对任意整数 `V`，`s>||V||_2` 的 ReRand 输出宽度为 `2rs` |
| PDF167／157，Construction8 | 单 bit IB-KEM；向量密文维数 `2m`，标量密文维数 1 |
| PDF168／158，Remark12 | 原 `m>6n ceil(log2 q)`、源宽度及原渐近参数要求 |
| PDF172／162，Eq. (5.15) | 最大条目绝对值 `||R_C+R_id||_infty<=1+beta` |
| PDF173／163，Eq. (5.17) | 证明中的 ReRand 输入矩阵 `V=[I|R_C+R_id]` |
| PDF174／164 | 原 `sqrt(2)m(beta+1)` 是通用范数不等式产生的充分上界 |

保留 blockwise 构造的 `beta=1+9m`、`rho=m(beta+1)`，得到确定性列界

\[
C_J=(\beta+1)\lceil\sqrt m\rceil.
\]

二进制 gadget `b=2` 的模拟 GS 平方上界可取

\[
\min\{5(1+\rho^2),\;9C_J^2+5\}.
\]

此前有限实例所用的诚实二元 TrapGen 有 `w=na`、`bar=m-w`，其每列范数不超过 `ceil(sqrt(bar))`；诚实 GS 也适用同一引理。这里具体化的是原文抽象 GenTrap/预像采样接口，不是声称原作者已经实现或公布这个有限核基。

原 Cauchy 正确性充分条件可以改用第 6 节共同 MGF 界。原 `m>6na`、原分区/wNCR 假设、原掩码、原密文格式均不改。由新的充分证明选出较窄的 `sigma`、`S`，不等于这些参数仍满足原文那组较松的充分公式；应明确称“同一算法模板的有限重分析”。

JKN 的原始完整密文计数为 `ceil((2m+1)a/8)`，不用另外把输出的明文/会话比特计入密文。MPK 计 12 个 `n x m` 矩阵与一个 `n` 维向量，另须加未实例化的 wNCR 哈希描述；该描述不能假称为 0 字节。

## 4. Abla24：保留原电路的逐列递推

原文：[978-3-031-58868-6_13.pdf](/Users/Admin/Zotero/storage/8K72TIQ8/978-3-031-58868-6_13.pdf)。Construction3.6 在 PDF15／印刷333，Construction4.4 在 PDF17–18／印刷335–336。对应既有提取文本为 [fulltext.txt](/Users/Admin/Desktop/IBE/Revision_20261014_Polar/analysis/baseline_mpk_128_20261015/abla/fulltext.txt)，相关行990–1022、1122–1161。

沿用此前有限重分析明确补全的 skip 分支、规范 gadget 右逆以及原 selector 求和项，不引入压缩步骤。所有初始掩码谱范数在同一个好事件上不超过 `K0`；原掩码最大条目绝对值为 `rho_mask`。Type I 保持均匀 `{-1,0,1}`，Type II 保持均匀 `[-b,b]`，不是本文的二元差分布。

定义

\[
B=(b-1)\lceil\sqrt{wm}\rceil,\quad
d=(b-1)\lceil\sqrt w\rceil,\quad
J=k(b-1),\quad C_0=\rho_{\rm mask}\lceil\sqrt m\rceil.
\]

任意规范右逆 `D(M)` 只有前 `w` 行活动，每个数字大小不超过 `b-1`，所以其谱范数不超过 `B`，每列二范数不超过 `d`。对于标量右逆 `D(cG)`，每列仅位于一个大小 `k` 的块内，每列一范数不超过 `J`。

令原小范围等式测试的谱放大为 `E0`；本轮固定 `eta=2` 时 `E0=J`。共同事件上其初始列界可以保守地直接取 `K0 E0`，不假设不同求值项独立。

Construction3.6 的真实递推为

\[
R_i''=R_i'D(B_{i-1}'')+\mathrm{Equal}_{j_i}(x_i)R_{i-1}''.
\]

布尔系数绝对值不超过 1，且每个 `R_i'` 的谱界不超过 `K0 E0`，因此

\[
C_{\rm eq}=K_0E_0[1+(\xi-1)d].\tag{2}
\]

原谱界仍为 `K0 Eeq`，其中 `Eeq=E0[1+(xi-1)B]`。随后 Construction4.4 的 `L` 项 selector 求和右乘 `D(ECC_j G)`，由其每列一范数得到

\[
C_{\rm sel}=LJ C_{\rm eq},\qquad E_{\rm sel}=LJ E_{\rm eq}.\tag{3}
\]

最后令 `T_i=R_i-R_i^B`，原式为

\[
R_x=\sum_{i=1}^{t}\left[T_iD(A_i-B_i)+z_iT_i\right],
\qquad |z_i|\le p-1.
\]

第一项用 `||T_i||_2<=K0(Esel+1)` 与右逆单列二范数 `d`；第二项用 `C(T_i)<=Csel+C0`，得到

\[
C_R=t\left[K_0(E_{\rm sel}+1)d+(p-1)(C_{\rm sel}+C_0)\right].\tag{4}
\]

所有步骤都是逐个身份的确定性矩阵不等式；同一初始谱事件保证其同时对全部身份成立。`D(M)` 可以依赖隐藏矩阵，不需额外独立性。

ReRand 仍用原谱界

\[
\rho=K_0t(B+p-1)(E_{\rm sel}+1).
\]

将 `min(rho,C_R)` 用于式 (1) 的模拟 GS；诚实 TrapGen 则用 `C_H=rho_mask ceil(sqrt(bar))`。原求值电路、掩码和公开矩阵数量不变。

## 5. 本文与基线共同收紧诚实 GS、ReRand

本文诚实 TrapGen 的最大条目为 `H_H=2^(k_H-1)`，故

\[
C_H=H_H\lceil\sqrt{\bar m}\rceil.
\]

式 (1) 与旧诚实 full-matrix GS 上界取最小；本文原有的模拟端列界继续使用。这避免只给基线应用共同技巧、却遗漏本文诚实侧的同类收紧。

三个方案的 ReRand 都是作用于 `V=[I|R]` 的原算法，其精确谱恒等式为

\[
\|V\|_2^2=1+\|R\|_2^2\le1+\rho^2.
\]

因此统一取最小严格整数输出宽度

\[
S=\left\lfloor\sqrt{4r^2(1+\rho^2)}\right\rfloor+1.\tag{5}
\]

这样仍然是原 `2rs` 的输出宽度，原始因子 2 没有被取消。JKN 的额外 `sqrt(2)rho` 上界可收紧到 `sqrt(1+rho^2)`；这不是量化专属收益，也不是改变 Gaussian 误差族。

## 6. 共同平滑与正确性证书

令 `D=2m`，`theta=T+16+2+ceil_log2(D)+4`，取最小正整数 `h` 满足

\[
3140h^2>694(\theta+2).\tag{6}
\]

由于 `pi>3.140`、`ln2<0.694`，该整数检查保证所有中心的一维 Gaussian 归一化误差满足所列预算。当前搜索范围得到 `h=8`，不能把旧 JKN/Abla 的较粗 `h=9` 当作其算法固有限制。取

\[
\sigma=h\max\{L_{\rm hon},L_{\rm sim}\}.
\]

在 canonical coset Gaussian 与已列平滑条件下，私钥范数尾可取

\[
K=\left\lceil\frac{D+2\lceil\sqrt{202D}\rceil+404}{6}\right\rceil,
\qquad L_e^2=\sigma^2K,
\]

范数坏事件小于 `2^-200`。固定合法私钥 `e` 后，独立中心整数 Gaussian 的解密相位有

\[
\Pr[|e_0-\langle e,E\rangle|\ge u\mid e]
\le2\exp\!\left(-\frac{\pi u^2}{r^2+S^2\|e\|_2^2}\right).
\]

这来自配方后 `rho_s(Z-mu)<=rho_s(Z)` 的 MGF，不需要在加密误差与私钥范数之间做 Cauchy 最坏乘积估计。令 `W^2=r^2+S^2 sigma^2 K`，统一整数判据为

\[
\begin{cases}
q^2\ge652W^2,&q=2^a,\\
(q-8)^2\ge652W^2\text{ 且 }q>8,&q\text{ 为奇素数}.
\end{cases}\tag{7}
\]

奇素数的 `q-8` 留出了原最近整数判决的取整余量。式 (7) 给出相位错误项低于 `2^-162`；再加入私钥范数坏事件、参考采样误差及本文已有量化误差，才是各自的总 DFR 账本。实际有限精度采样器尚未验证的误差不能自动置零。

详细既有推导：[sampler_rerand_conditions.md](/Users/Admin/Desktop/IBE/Revision_20261013_Native/analysis/yamada_tightening_20261014/sampler_rerand_conditions.md)，第4–6节。这里采用其更精细的有理常数形式，不改变证明原理。

## 7. 源码独立审计与证据边界

已逐项审查本轮主脚本：

| 文件 | 审查结论 |
|---|---|
| `baselines/search_baselines_column.py` 的 `column=True, tight_rerand=True` 路径 | 正确实现式 (1)–(7)、JKN 条目列界、Abla 逐列递推、诚实列界及 full/column 最小值；未发现主结果公式错误 |
| `ours/search_shared_column.py` | 正确在原固定设计搜索之上收紧诚实 GS，重算 `sigma,W2`、正确性判据与逐模数拒绝记录；没有改变掩码分布 |
| `ours/search_ours.py` | 重新计算依赖 `a` 的 gadget、熵列数、求值/谱界、ReRand 和尺寸，不是把旧参数固定后仅将 `q` 减半 |
| `check_column_lemma.py` | 42 个有理数精确 GS 一致性测试覆盖矩形提升、素数与二次幂 `q`、`s=1`；只用于排查实现错误，不替代第2节证明 |

在本次审查所读版本中有两点需要保留说明：

1. `search_baselines_column.py` 的历史 `legacy=True` JKN 回放分支重写 `sigma` 后没有同步改写所有 `W2/MGF_ratio` 诊断字段。该分支以 `legacy_Cauchy` 判断，不影响本轮主 column 结果；不能拿它残留的 MGF 诊断字段解释原参数的正确性余量。
2. JKN 保留旧 `m>6na` 的列数，使编程 LHL 有巨大余量；其简写 gate 没有显式写出所有公开矩阵的并集因子。对本轮选中点可以另外直接核查更强的多矩阵条件，不应把源码中简写的式子描述成已经完整记录全部 hybrid 常数。该问题不授权改变原分区或哈希假设。

对当前 `baselines/shared_column.json` 的两个 JKN 点，另行代入更强的
`m >= (n+1)a+2(T+8)+2 ceil_log2(12m)`：固定旧维数点的左右值为 `3,838,592 >= 640,388`，先前重调维数点为 `3,441,920 >= 574,291`，均通过。这补核的是公开编程的列数裕度，不代表 wNCR 假设或完整规约损失已由该不等式认证。

审查时文件 SHA256（脚本随后若变化，需要重新核对）：

```text
3ba99635ecdd83e74e364a658213ad2bbb8f9e41a2b5e4b054303a7954e124bb  baselines/search_baselines_column.py
b58b09771ac99d0010c7a3fb612819dca1da4ae811546789cd5b8968687f64f5  ours/search_shared_column.py
5ee91ed004367f5dcd778adae434c844836393dce148439a7ea26f1e86037791  ours/search_ours.py
00825a57a12be2574a1390b2c4dadc1b4dd38185a55de49ed84ff0885f71dd58  check_column_lemma.py
bf4904c3f62aa75829c38d05d957729091396251961631624fbe4beea47abd43  niehues_thesis.pdf
ab60c527fc043d5088da36aa624d64226f905aa5a0cc1467df9cbb1f855fa846  Abla24 原文 PDF
```

“最小可认证模数”只指固定设计、所列充分条件和声明的模数候选族内的最小值。素数族使用 `previous_prime(2^a)` 时，结果是该候选族内最小合格位长，不是同一位宽内数值最小的素数；固定 `n,r` 的模数搜索也不是跨所有设计的全局最优。更小候选不能通过这些充分条件，不等于它必然不安全。

本报告为本轮独立理论和公式核查。没有外部模型上传、原作者实现计时、完整维数 IBE 执行、形式化证明或完整 IBE 128 位认证。实验与估计器完成状态以本目录后续结果文件为准，不由本审计预先宣告。
