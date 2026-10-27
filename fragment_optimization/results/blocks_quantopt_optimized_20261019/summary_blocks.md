# 分块加密计时汇总

Real frozen n/q/S and partial 256-coordinate blocks only; no complete ciphertext, decryption, or full-IBE claim

平台：Darwin 25.6.0 arm64; native wall-time / correctness measurements; no Windows cycle counts or OS-enforced memory-cap claim; compiler=Apple LLVM 21.0.0 (clang-2100.1.1.101)

以下为实际执行块的平均每 256 维耗时；均值 ± 样本 SD 来自重复试验的每块均值，不是单块观测的 SD。

| 参数 | 重复次数 | 每次块数 | 矩阵乘法 ms/块 | 量化 ms/块 | 其余 ms/块 | 合计 ms/块 |
|---|---:|---:|---:|---:|---:|---:|
| ours_ct | 5 | 4 | 74.6339 ± 0.608365 | 39.8838 ± 0.20931 | 1.95803 ± 0.0441173 | 116.476 ± 0.806251 |
| ours_mpk | 5 | 4 | 59.5524 ± 0.314684 | 37.5388 ± 0.302984 | 1.60455 ± 0.0399794 | 98.6957 ± 0.340872 |
| ours_mid | 5 | 4 | 69.9412 ± 0.319337 | 39.2309 ± 0.139994 | 1.78697 ± 0.0463919 | 110.959 ± 0.386232 |

## 时间占比

汇总占比为各阶段总耗时除以所有试验总耗时，不是逐次占比的简单平均。三阶段之和为 100%。

| 参数 | 矩阵汇总占比 | 量化汇总占比 | 其余汇总占比 | 量化逐次占比均值 ± SD |
|---|---:|---:|---:|---:|
| ours_ct | 64.077% | 34.242% | 1.681% | 34.243% ± 0.106535 个百分点 |
| ours_mpk | 60.339% | 38.035% | 1.626% | 38.035% ± 0.267193 个百分点 |
| ours_mid | 63.033% | 35.356% | 1.610% | 35.356% ± 0.126223 个百分点 |

## 结果边界与判断

Descriptive repeated trials on one machine; sample SD across trial means, not across individual blocks. No p-values, confidence intervals, or cross-platform inference. Median/IQR use linear interpolation at (n-1)p.

Wall-time pooled share = sum(phase seconds)/sum(total seconds). This is distinct from mean trial share. Matrix+quantization+other exhaust measured compute time; other includes fresh randomness, scalar generation, serialization, allocation, bookkeeping and timing instrumentation. Data feed, codec validation and progress checks are excluded; feed and validation are reported separately.

Small repeated-run samples (including five trials) do not justify distributional inference. Per-block values divide measured trial totals by the number of actually executed blocks; never multiply them to claim full-ciphertext time. Peak memory is cumulative process-lifetime RSS. Quantization below 50% does not imply that it is not the largest phase.

- ours_ct: Quantization accounts for 34.242% of pooled measured wall time. It is below 50% (not a majority). It does not exceed the matrix phase. It is not strictly the largest measured phase. These are descriptions of these trials only, not an extrapolation to complete ciphertext encryption.
- ours_mpk: Quantization accounts for 38.035% of pooled measured wall time. It is below 50% (not a majority). It does not exceed the matrix phase. It is not strictly the largest measured phase. These are descriptions of these trials only, not an extrapolation to complete ciphertext encryption.
- ours_mid: Quantization accounts for 35.356% of pooled measured wall time. It is below 50% (not a majority). It does not exceed the matrix phase. It is not strictly the largest measured phase. These are descriptions of these trials only, not an extrapolation to complete ciphertext encryption.

各阶段中位数、IQR、最小值、最大值、数据供给与验证耗时见 summary_blocks.csv/json。Windows 周期数独立于墙钟时间统计；非 Windows 运行不补造周期数。
