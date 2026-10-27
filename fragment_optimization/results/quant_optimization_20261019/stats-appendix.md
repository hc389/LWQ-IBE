# 量化实现优化：描述性统计附录

## 范围与可比性

每组参数在同一记录平台进行 5 次测量，每次实际执行 4 个 256 维块；每组/每版本预热 1 次，不进入统计。
矩阵维数、模数、量化宽度及冻结集合保留真实参数。仅执行前缀块，不产生完整密文；不存在完整加密或解密时间的外推。

已逐项核对平台、编译器/库版本、块数、重复数、预热数、内存/tile/核绑定设置、参数与配置 SHA。六个源文件的记录 SHA 中仅 sampler.cpp 不同。随机种子与参数执行次序允许不同；未忽略其他元数据差异。

平台：Darwin 25.6.0 arm64; native wall-time / correctness measurements; no Windows cycle counts or OS-enforced memory-cap claim; compiler=Apple LLVM 21.0.0 (clang-2100.1.1.101)

版本：compiler=Apple LLVM 21.0.0 (clang-2100.1.1.101); gmp=6.3.0; mpfr=4.2.2; flint=3.4.0; openssl=OpenSSL 3.4.0 22 Oct 2024

## 核心观察（ms / 实际执行的 256 维块）

均值 ± 样本 SD 来自试验的每块均值；并非单块 SD。下表正数表示降低，负数表示变慢。

| 参数 | 指标 | 优化前 mean ± SD | 优化后 mean ± SD | 绝对降低 ms | 相对降低 % | 均值比 speedup |
|---|---|---:|---:|---:|---:|---:|
| ours_mpk | quant | 76.640 ± 0.468 | 37.539 ± 0.303 | 39.101 | 51.019 | 2.042× |
| ours_mpk | total | 137.571 ± 0.644 | 98.696 ± 0.341 | 38.876 | 28.259 | 1.394× |
| ours_mid | quant | 79.561 ± 2.631 | 39.231 ± 0.140 | 40.330 | 50.691 | 2.028× |
| ours_mid | total | 153.222 ± 4.400 | 110.959 ± 0.386 | 42.263 | 27.583 | 1.381× |
| ours_ct | quant | 77.318 ± 0.412 | 39.884 ± 0.209 | 37.434 | 48.416 | 1.939× |
| ours_ct | total | 153.410 ± 0.468 | 116.476 ± 0.806 | 36.934 | 24.075 | 1.317× |

## 阶段组成与未修改控制项

占比采用累计阶段时间 / 累计总时间，M+Q+O=100%，不是逐次占比的简单平均。

| 参数 | 前 M/Q/O % | 后 M/Q/O % | 后 Q<50% | 后 Q>M | 后 Q 最大 | 矩阵均值变化 % |
|---|---:|---:|---|---|---|---:|
| ours_mpk | 43.124 / 55.709 / 1.168 | 60.339 / 38.035 / 1.626 | True | False | False | 0.382 |
| ours_mid | 46.755 / 51.926 / 1.319 | 63.033 / 35.356 / 1.610 | True | False | False | -2.369 |
| ours_ct | 48.340 / 50.400 / 1.260 | 64.077 / 34.242 / 1.681 | True | False | False | 0.641 |

## 单列的输入供给、验证与内存

供给与验证未包含在 total 中。RSS 为进程历史峰值；参数组执行次序可能不同，不能把组间峰值差解释成精确的缓存增量。

| 参数 | 前供给 ms/块 | 后供给 ms/块 | 前验证 ms/块 | 后验证 ms/块 | 前 peak RSS MiB | 后 peak RSS MiB |
|---|---:|---:|---:|---:|---:|---:|
| ours_mpk | 964.301 ± 15.742 | 962.621 ± 4.165 | 0.822 ± 0.033 | 0.815 ± 0.029 | 40.234 | 70.922 |
| ours_mid | 1138.994 ± 53.112 | 1085.684 ± 1.197 | 0.899 ± 0.032 | 0.909 ± 0.052 | 40.234 | 71.266 |
| ours_ct | 1232.721 ± 3.362 | 1244.481 ± 9.447 | 0.867 ± 0.021 | 0.926 ± 0.014 | 40.234 | 40.438 |

## 完整分布描述

包含全部试验，不做异常点删除。中位数和 IQR 的分位数位置为 (n−1)p 线性插值。

| 参数 | 版本 | 指标 | mean ± SD | median | Q1 | Q3 | IQR | min | max |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|
| ours_mpk | baseline | matrix_ms_per_256_block | 59.326 ± 0.337 | 59.304 | 59.213 | 59.533 | 0.320 | 58.844 | 59.734 |
| ours_mpk | optimized | matrix_ms_per_256_block | 59.552 ± 0.315 | 59.426 | 59.335 | 59.834 | 0.499 | 59.229 | 59.938 |
| ours_mpk | baseline | quant_ms_per_256_block | 76.640 ± 0.468 | 76.387 | 76.379 | 76.731 | 0.352 | 76.282 | 77.418 |
| ours_mpk | optimized | quant_ms_per_256_block | 37.539 ± 0.303 | 37.609 | 37.306 | 37.730 | 0.424 | 37.156 | 37.893 |
| ours_mpk | baseline | other_ms_per_256_block | 1.606 ± 0.031 | 1.598 | 1.583 | 1.615 | 0.032 | 1.579 | 1.655 |
| ours_mpk | optimized | other_ms_per_256_block | 1.605 ± 0.040 | 1.587 | 1.584 | 1.611 | 0.028 | 1.569 | 1.671 |
| ours_mpk | baseline | total_ms_per_256_block | 137.571 ± 0.644 | 137.600 | 137.172 | 137.690 | 0.518 | 136.846 | 138.550 |
| ours_mpk | optimized | total_ms_per_256_block | 98.696 ± 0.341 | 98.664 | 98.532 | 98.733 | 0.201 | 98.315 | 99.235 |
| ours_mpk | baseline | feed_ms_per_256_block | 964.301 ± 15.742 | 955.738 | 954.652 | 965.335 | 10.683 | 954.502 | 991.276 |
| ours_mpk | optimized | feed_ms_per_256_block | 962.621 ± 4.165 | 960.054 | 959.836 | 964.232 | 4.396 | 959.725 | 969.258 |
| ours_mpk | baseline | validation_ms_per_256_block | 0.822 ± 0.033 | 0.817 | 0.796 | 0.840 | 0.044 | 0.789 | 0.868 |
| ours_mpk | optimized | validation_ms_per_256_block | 0.815 ± 0.029 | 0.806 | 0.799 | 0.842 | 0.043 | 0.779 | 0.846 |
| ours_mid | baseline | matrix_ms_per_256_block | 71.639 ± 1.795 | 71.895 | 70.172 | 72.269 | 2.097 | 69.680 | 74.175 |
| ours_mid | optimized | matrix_ms_per_256_block | 69.941 ± 0.319 | 69.788 | 69.699 | 70.177 | 0.478 | 69.662 | 70.380 |
| ours_mid | baseline | quant_ms_per_256_block | 79.561 ± 2.631 | 78.988 | 77.512 | 80.340 | 2.829 | 77.255 | 83.712 |
| ours_mid | optimized | quant_ms_per_256_block | 39.231 ± 0.140 | 39.286 | 39.242 | 39.316 | 0.075 | 38.987 | 39.323 |
| ours_mid | baseline | other_ms_per_256_block | 2.022 ± 0.443 | 1.855 | 1.785 | 1.894 | 0.109 | 1.766 | 2.809 |
| ours_mid | optimized | other_ms_per_256_block | 1.787 ± 0.046 | 1.773 | 1.749 | 1.825 | 0.077 | 1.742 | 1.846 |
| ours_mid | baseline | total_ms_per_256_block | 153.222 ± 4.400 | 153.692 | 149.193 | 154.395 | 5.202 | 149.086 | 159.742 |
| ours_mid | optimized | total_ms_per_256_block | 110.959 ± 0.386 | 110.734 | 110.721 | 111.265 | 0.544 | 110.600 | 111.476 |
| ours_mid | baseline | feed_ms_per_256_block | 1138.994 ± 53.112 | 1122.206 | 1105.181 | 1164.580 | 59.400 | 1084.828 | 1218.176 |
| ours_mid | optimized | feed_ms_per_256_block | 1085.684 ± 1.197 | 1086.318 | 1084.956 | 1086.608 | 1.652 | 1083.926 | 1086.611 |
| ours_mid | baseline | validation_ms_per_256_block | 0.899 ± 0.032 | 0.891 | 0.882 | 0.902 | 0.021 | 0.868 | 0.952 |
| ours_mid | optimized | validation_ms_per_256_block | 0.909 ± 0.052 | 0.903 | 0.870 | 0.924 | 0.054 | 0.860 | 0.991 |
| ours_ct | baseline | matrix_ms_per_256_block | 74.158 ± 0.153 | 74.153 | 74.082 | 74.248 | 0.166 | 73.955 | 74.353 |
| ours_ct | optimized | matrix_ms_per_256_block | 74.634 ± 0.608 | 74.440 | 74.298 | 74.821 | 0.522 | 74.019 | 75.592 |
| ours_ct | baseline | quant_ms_per_256_block | 77.318 ± 0.412 | 77.260 | 76.970 | 77.678 | 0.708 | 76.882 | 77.801 |
| ours_ct | optimized | quant_ms_per_256_block | 39.884 ± 0.209 | 39.890 | 39.767 | 39.933 | 0.166 | 39.634 | 40.195 |
| ours_ct | baseline | other_ms_per_256_block | 1.933 ± 0.029 | 1.936 | 1.909 | 1.942 | 0.034 | 1.904 | 1.975 |
| ours_ct | optimized | other_ms_per_256_block | 1.958 ± 0.044 | 1.966 | 1.941 | 1.975 | 0.034 | 1.894 | 2.013 |
| ours_ct | baseline | total_ms_per_256_block | 153.410 ± 0.468 | 153.517 | 153.059 | 153.703 | 0.643 | 152.812 | 153.957 |
| ours_ct | optimized | total_ms_per_256_block | 116.476 ± 0.806 | 116.201 | 116.040 | 116.695 | 0.655 | 115.680 | 117.762 |
| ours_ct | baseline | feed_ms_per_256_block | 1232.721 ± 3.362 | 1232.564 | 1231.532 | 1234.085 | 2.553 | 1228.133 | 1237.289 |
| ours_ct | optimized | feed_ms_per_256_block | 1244.481 ± 9.447 | 1240.678 | 1240.075 | 1244.414 | 4.339 | 1236.603 | 1260.638 |
| ours_ct | baseline | validation_ms_per_256_block | 0.867 ± 0.021 | 0.858 | 0.856 | 0.863 | 0.007 | 0.855 | 0.905 |
| ours_ct | optimized | validation_ms_per_256_block | 0.926 ± 0.014 | 0.928 | 0.920 | 0.935 | 0.015 | 0.905 | 0.940 |

## 统计方法与不可作出的推论

绝对降低 = 前均值 − 后均值；相对降低 = 100×(1−后均值/前均值)；speedup = 前均值/后均值。分母为零时报告 NA。没有把 trial 编号对应成配对。

使用不同测试种子与矩阵 fixture 的两批运行；实际种子覆盖与不重复已核验。固定先 baseline 后 optimized 的设计可能受热漂移、调度和缓存状态影响。小样本单机重复不支持分布假设检查、置信区间、p 值或多重比较显著性声明，因此本报告不做这些推断。

- Descriptive only: repeated trials on one host are not independent machines or benchmark sessions. No p-values, confidence intervals, or inferential multiple-comparison claims.
- Inputs and random tapes differ across runs; identical trial indices do not form pairs. Speedup is the ratio of two sample means, not the mean of per-trial ratios.
- The planned fixed order is baseline then optimized, not an interleaved/counterbalanced design. Thermal state, scheduling and cache conditions may drift; a difference is not isolated causal evidence.
- Sample SD describes variation between trial averages, not between individual blocks. Median/IQR use linear interpolation at (n-1)p; no observations are removed.
- Total means matrix + quantization + other measured compute. Data feed and codec verification are excluded and separately reported; this is not end-to-end encryption time.
- Real full n/q/S and frozen layouts are retained, but only a prefix of blocks is executed. No complete-ciphertext, full-IBE, decryption, deployment or Windows-cycle extrapolation is supported.
- Recorded source hashes agree except sampler.cpp and recorded compiler/library versions match. Metadata alone does not attest compiled binary provenance, identical compiler flags, or unchanged physical host; consult the separately archived build/run manifests.
- Maximum reported memory is cumulative process-lifetime peak RSS, not an independent per-profile allocation measurement or an OS-enforced limit on non-Windows hosts.
- Same-tape correctness/distribution-preserving tests belong to a separate validation artifact; these timings do not establish output-distribution equivalence.

## 敏感性提示

- 矩阵与供给均值的变化未超过预设的 5% 描述性提示线；这不证明不存在漂移。

## 数据来源与可追溯性

原始文件只读。完整原始行、版本、源码 SHA、诊断及文件 SHA 见 comparison.json；comparison.csv 提供可复用的数值表。

### baseline: blocks_quantopt_baseline_20261019

- raw.csv: `9e53d30fc9b734c857e7c9a3a3cc5f9191296ac3ec870c4413d554019a5e994a`
- metadata.json: `0184beed160e938fab63ad3e288d8691c1c7968f712748af3cc8395b272b8d7d`
- warmup.csv: `95e1809f13a6d5c10e012e0050293049f5d01083f49e9c9e2be76761f2d6c65f`
- COMPLETED.txt: `04b2788dfba30633fa07e437153a5eb3463206c8384db4a382bdc27ed38b9817`
- diagnostics.txt: `eb60c94dbce6c9549cc755d186ea552d04fb0cda5f1603f183c165373f47bd83`

### optimized: blocks_quantopt_optimized_20261019

- raw.csv: `0336807bea0208b95ff1023f7b8d990fd302933744230b79d615821c77f2749d`
- metadata.json: `5608c43d9a8ca5c3743971b312f1d87c4f271efe03dd7dc745a744cdcb981d6f`
- warmup.csv: `8fa8adfc3c10890f201cf87246abec47b876506cdc910a69d8d9c0940473c8d0`
- COMPLETED.txt: `04b2788dfba30633fa07e437153a5eb3463206c8384db4a382bdc27ed38b9817`
- diagnostics.txt: `e50e236b2a3260901d39f0852d97b27c981f0ee18581815ee79f014b10cd9d32`
