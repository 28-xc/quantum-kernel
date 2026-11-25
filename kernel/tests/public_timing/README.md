# 输入分组时序实验的复算

`tools/recompute_timing.py` 从原始 CSV 重新计算输入分组的时序统计量。输入清单采用 `lattice.timing_observations.v1`，统计结果采用 `lattice.timing_statistics.v2`。每个实验明确记录二进制身份、参数、输入组、种子、计时单位、检查点及阳性对照。

Windows 数据的单位为 TSC tick，Linux/AArch64 数据的单位为 `CLOCK_MONOTONIC_RAW` 纳秒。两平台分别分析。完整解封装记录包含上下文初始化与解封装调用；NTT、点乘及 Keccak 记录覆盖各自指定的算术入口。输入组的公共量、秘密量和合法性条件见清单的 `families` 字段。

每个检查点分别对原始时间和中心化平方偏差计算 Welch t 统计量，样本方差采用 `ddof=1`。t 统计量方向为 class0 减 class1；效应字段 `final_class1_minus_class0` 表示 class1 减 class0。阈值比较覆盖全部预先指定的检查点与两类统计量。慢样本保留在原始文件和复算中。多输入族的阈值检查属于有限软件时序检测，物理侧信道评估采用独立实验。

```powershell
py -3.13 -B tools/recompute_timing.py --manifest data/timing/observations.xml --output D:/时序复算/summary.xml
```

输出使用新文件名。工具逐文件核验相对路径、SHA-256、字节数、完整行数、类平衡、返回值及每个原始检查点。所有数值从 CSV 重新计算，统计清单与输入清单通过摘要关联。

界面加载时核验已发布清单与统计文件的摘要和结构；上述命令执行完整数值复算。输入因素对照与解封装主实验使用同一实际密码库，并保留各自的输入定义、结果检查和原始记录。

合成数据回归检查：

```powershell
py -3.13 -B tests/public_timing/test_timing.py
```

合成数据检查覆盖统计复算、缺失记录、身份变更和重复字段。密码算法实验数据按其实际二进制身份单独归档。
