# 附加固定源码模型覆盖（非新数值运行）

同一estimator提交与原有审计：`Revision_20261014_Polar/analysis/experiment_guidance_20261014/bkw_cost_bound_review.md`、`arora_cost_bound_review.md`。只沿用这些明确模型，不扩展到模数切换或其他代数预处理。

1. 原模数coded-BKW默认b>=2，非负成本中包含 q^b(b log2 q+1)，故 C>=q²，至少2 floor(log2 q)位。normalize和扩样不改变q；不把程序异常记成无穷成本。
2. 所有新旧主表点r>=203，sigma=r/sqrt(2pi)>r/3>16，因此Gaussian噪声/秘密方程最低度大于16，有限d_reg>=16。秘密密度>1/2，按原默认dense乘法猜测模型，每个猜测坐标的代价保守下界2。若zeta>=160，总成本>=2^160；若zeta<160，剩余n'>4096，基础GB成本>=binom(n'+16,16)^2 >=(n'/16)^32 >2^256，因此仍>=2^160。这里不把秘密换成二元分布，只放松猜测乘法代价；默认Gaussian分布的degree与normalize条件保持。
3. 已逐点检查m+1>=2n、n−159>4096、r>=203。原始秘密仍是UniformMod(q)；此处是estimator的normalize在样本充足时将秘密换成与误差同宽的Gaussian，之后才应用上述方程度论证。因而输入与上述界匹配。六项有限结果的最小值和这两个解析界分开列，不假装八项数值成功，更不推导完整IBE位安全。

逐点结果见comparison.json的additional_fixed_model_bounds。
