# 极化量化缓存的精确区间审计

日期：2026-10-19。本项是正确性审计，不是性能测试，也没有修改论文。

## 审计对象

- 旧实现：`baseline/src/sampler.cpp`，SHA-256 `7ab80db243daa57d308dd2c0f7e9ca4fe47ede9410fb38e7505e871c4c734215`。
- 最终优化实现：`../../src/sampler.cpp`，SHA-256 `4b2b52b8474b65c45bd1cb0fafec2dde7bd04282f395378c1b4ad1922b46e79d`。
- 最终实现包含 H1 按层高精度缓存，以及 H2 相邻层整数变换复用。编译后再次核对优化源文件哈希，未变化。

## 源码审查

1. `WrappedLayer` 的模数、Gaussian 宽度、精度、`pi`、`goal`、比值和 `c` 的运算顺序与旧实现相同；保存的是完整 Arb 区间，而非浮点近似。
2. Fourier 系数和级数尾项仅依赖公共层参数、精度和项号。spatial 分支只缓存尾项，仍逐坐标按 `tail < goal*leading(z)` 停止，没有复用其他坐标的截止项。
3. spatial 的 `target=goal*leading` 由循环内移到循环外，其操作数在循环中均不变化。
4. 缓存仅存在于一层的一次精度尝试；384、768、1536 位精度之间不复用。
5. 缓存项按需生成。引用只在当前循环迭代内使用，使用期间没有再次扩容，不存在缓存向量扩容后的悬空引用。
6. H2 将上一层结束已经校验的 `integer_transform(w_low)` 保留至下一层开始。`w_low` 在两处之间未改变；层末刷新、所有 carry 及冻结位检查均保留。因此此复用是精确整数恒等替换。
7. 未修改 SC、随机硬币、随机带推进、冻结集合、高位提升、精度重试或数值失败门槛。

结论：未发现使数学分布、参数、数值区间或随机带消费发生变化的逻辑改动。有限测试不是覆盖所有输入的形式化证明；逐项代码依赖检查与后续随机带回放提供互补证据。

## 内部后验区间逐项对照

可复现测试文件（相对 WindowsNative 根目录）：

- `tests/wrapped_enclosure_old.cpp`：包含快照源码，重命名其公开采样符号，导出旧内部后验。
- `tests/wrapped_enclosure_new.cpp`：包含当前源码，重命名其公开采样符号，在相同层内复用缓存。
- `tests/wrapped_enclosure_check.cpp`：逐项调用 `arb_equal`，比较 Arb 中心和半径的精确相等，不仅比较区间相交或采样结果。

覆盖13个宽度：1、2、3、7、8、17、257、`2^120`、`2^120-1`、`2^120+1`以及三个真实参数组的精确大整数宽度。层数覆盖固定小层、宽度位数附近、以及宽度之上6层；余数包括正负值、四分之一/二分之一周期及其相邻点、跨周期点和确定性非对称点。每组先顺序遍历再倒序遍历，检查缓存已有更多项时的行为。精度分别为384、768、1536位。

实际输出：

```text
EXACT_ENCLOSURE_PASS exact=15042 same_exception=0
```

即15,042个后验区间中心和半径完全一致，无异常。该测试未触发精度不足异常，不能声称测试覆盖了此失败分支；异常路径另由代码审查及采样级回放检查。

## 本机复现命令

从 WindowsNative 根目录运行；依赖为现有 Sage 10.9 本机动态库，生成的测试二进制留在 `/tmp`。这不是 Windows 二进制或 Windows 性能结果。

```sh
clang++ -std=c++17 -O2 \
  -I/Applications/SageMath-10-9.app/Contents/Frameworks/Sage.framework/Versions/10.9/local/include \
  tests/wrapped_enclosure_old.cpp tests/wrapped_enclosure_new.cpp \
  tests/wrapped_enclosure_check.cpp src/core_arithmetic.cpp \
  -L/Applications/SageMath-10-9.app/Contents/Frameworks/Sage.framework/Versions/10.9/local/lib \
  -Wl,-rpath,/Applications/SageMath-10-9.app/Contents/Frameworks/Sage.framework/Versions/10.9/local/lib \
  -lflint -lgmpxx -lgmp -lcrypto -o /tmp/lwq_ibe_quant_exact_enclosure_final
/tmp/lwq_ibe_quant_exact_enclosure_final
```

Windows UCRT64 具备同样依赖时，可用 `g++ -std=c++17 -O2` 编译同样四个文件，链接 `-lflint -lgmpxx -lgmp -lcrypto`；该平台命令尚未在目标机执行，不以本机通过代替目标机验证。

测试源码 SHA-256：

```text
91a6fc98f3fd492f533e4ab341cbe47d5ae8615e3e7612c5d6301cc1c9650a33  tests/wrapped_enclosure_old.cpp
fc26be206d6175fba0ac6a7e7d4e46aeb7166205cee34e2e76dfebde4fcaf3f5  tests/wrapped_enclosure_new.cpp
ea3be8df25a9a6f24de266912d21edf930e84f2d1cb1e893eb055608a2520601  tests/wrapped_enclosure_check.cpp
```
