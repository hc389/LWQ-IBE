# 量化优化图表目录

两图均由严格验证后的原始数据生成。原始文件 SHA、数值与逐次观测见 comparison.json；数据与图表来自同一次分析。

## Figure 1 — figures/quant_before_after.svg

目的：观察量化实现修改前后每个真实参数集的量化耗时及试验间波动。

图注：每版本 5 次试验、每次 4 个实际执行的 256 维块。柱为每块平均毫秒，误差线为试验平均值的样本标准差，点为全部试验。横向点位偏移仅避免重叠，不表示数值或配对关系。输入与随机带在版本间不同。

解读检查：先看绝对差再看比例；检查所有点和 SD。减少仅表示本次记录中的量化时间下降，不是安全性证明，也不推出完整密文时间。无显著性标记或配对连线。

## Figure 2 — figures/phase_before_after.svg

目的：辨别量化加速怎样反映在被测计算核总耗时中，并同时观察未修改的矩阵阶段。

图注：共享零起点毫秒坐标；M/Q/O 分段分别为矩阵、量化、其余阶段的样本均值，其和等于总均值。末端误差线是总耗时的样本 SD，并非三个 SD 相加；下方后版本占比采用累计阶段/累计总时间。其余项包括随机数、标量、序列化、分配与计时管理开销。

解读检查：量化下降不保证总时间按同一比例下降；量化不到 50% 也可能仍是最大阶段。供给与验证单列、不计入这些条形。检查矩阵控制项漂移，避免把固定执行顺序造成的变化全部归因于算法。

## 数据直接支持的观察

- ours_mpk: quant 76.640 ± 0.468 → 37.539 ± 0.303 ms/块；total 137.571 ± 0.644 → 98.696 ± 0.341 ms/块；量化相对降低 51.019%。
- ours_mid: quant 79.561 ± 2.631 → 39.231 ± 0.140 ms/块；total 153.222 ± 4.400 → 110.959 ± 0.386 ms/块；量化相对降低 50.691%。
- ours_ct: quant 77.318 ± 0.412 → 39.884 ± 0.209 ms/块；total 153.410 ± 0.468 → 116.476 ± 0.806 ms/块；量化相对降低 48.416%。

## 已知局限

- Descriptive only: repeated trials on one host are not independent machines or benchmark sessions. No p-values, confidence intervals, or inferential multiple-comparison claims.
- Inputs and random tapes differ across runs; identical trial indices do not form pairs. Speedup is the ratio of two sample means, not the mean of per-trial ratios.
- The planned fixed order is baseline then optimized, not an interleaved/counterbalanced design. Thermal state, scheduling and cache conditions may drift; a difference is not isolated causal evidence.
- Sample SD describes variation between trial averages, not between individual blocks. Median/IQR use linear interpolation at (n-1)p; no observations are removed.
- Total means matrix + quantization + other measured compute. Data feed and codec verification are excluded and separately reported; this is not end-to-end encryption time.
- Real full n/q/S and frozen layouts are retained, but only a prefix of blocks is executed. No complete-ciphertext, full-IBE, decryption, deployment or Windows-cycle extrapolation is supported.
- Recorded source hashes agree except sampler.cpp and recorded compiler/library versions match. Metadata alone does not attest compiled binary provenance, identical compiler flags, or unchanged physical host; consult the separately archived build/run manifests.
- Maximum reported memory is cumulative process-lifetime peak RSS, not an independent per-profile allocation measurement or an OS-enforced limit on non-Windows hosts.
- Same-tape correctness/distribution-preserving tests belong to a separate validation artifact; these timings do not establish output-distribution equivalence.
