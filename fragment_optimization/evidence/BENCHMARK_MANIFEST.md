# 前后对照的实现绑定与命令

平台：Apple M2，macOS/Darwin ARM64。相同原生依赖、Clang、C++17、O3、DNDEBUG。正式测试串行，先baseline后optimized；各自随机参数组顺序、各次新随机数，不是逐次配对的相同密文。

旧程序：baseline/build/lwq_ibe_bench，SHA-256 3eda58d6cbd78dcd40cd4e724a3b539195526898beb57b39e6f40e35098619b7。

新程序：../../build/local/lwq_ibe_bench，SHA-256 75eccb03ea8da5c8fd7c841f0fcc233f6e8d1d2627c972cf53d1e8fff37f6f39。

仅sampler.cpp源码变化：旧7ab80db243daa57d308dd2c0f7e9ca4fe47ede9410fb38e7505e871c4c734215，新4b2b52b8474b65c45bd1cb0fafec2dde7bd04282f395378c1b4ad1922b46e79d。其余五个源码/头文件与全部参数文件逐文件相同。计时边界、矩阵实现、统计脚本及参数不因优化改变。

C++程序在运行时从data的相邻src目录记录源码哈希。为了保证对应正确，旧程序显式使用快照data，优化程序使用项目data；只凭运行时哈希并不能证明任意外来二进制的构建来源，本清单额外绑定实际测试二进制。量化回放测试的源码到二进制构建校验另见build/local/quant_replay_*.build_manifest.txt及replay/manifest.json。

从WindowsNative根目录执行；统一设置OMP_NUM_THREADS、OPENBLAS_NUM_THREADS、MKL_NUM_THREADS、FLINT_NUM_THREADS为1。未绑定CPU核心。

旧版：

    validation/quant_opt_20261019/baseline/build/lwq_ibe_bench --mode blocks --data validation/quant_opt_20261019/baseline/data --profiles ours --blocks 4 --repetitions 5 --warmup 1 --tile-mib 32 --memory-limit-mb 1400 --output results/blocks_quantopt_baseline_20261019

新版：

    build/local/lwq_ibe_bench --mode blocks --data data --profiles ours --blocks 4 --repetitions 5 --warmup 1 --tile-mib 32 --memory-limit-mb 1400 --output results/blocks_quantopt_optimized_20261019

实际执行时data传绝对路径以明确来源。复现请选新的输出目录，原结果不覆盖。两次均不使用旧mainrun数据代替本轮baseline。性能进程运行时不并发编译、回放或sanitizer测试。
