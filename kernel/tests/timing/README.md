# 本地库的软件时序检查

本工具检查明确指定的本机项目 DLL。`prepare` 构建驱动、核对实际入口并固定输入计划，`validate` 执行数学和接口预检，`collect` 采集已登记的固定/随机输入观察。原始样本、阳性控制和统计结果分别保存，由具体记录说明覆盖范围。

每个构建在全新目录执行 prepare；计划绑定 DLL、驱动、源码和私有 ABI 地址。每个进程按绝对路径装载 DLL并核对实际模块路径。函数地址取自同一文件的符号表并检查可执行段。缺失符号或 LTO 删除入口时停止并记录缺口。

```powershell
py -3.13 -B tests/timing/run.py prepare --dll <实际DLL> --output <新的D盘主组目录> --keccak-family kem
py -3.13 -B tests/timing/run.py validate --output <同一主组目录>
py -3.13 -B tests/timing/run.py prepare --dll <实际DLL> --output <新的D盘DSA组目录> --keccak-family dsa --only-keccak
py -3.13 -B tests/timing/run.py validate --output <同一DSA组目录>
```

`collect --output ... --token <采集窗口标识> --final-build-reviewed` 在源码/ABI核对和功能预检后使用。采集期间保持 CPU 独占；标识用于记录采集窗口。

Windows `throughput / speed` 另有真实的小模 NTT 与 CRT 路径，主组 prepare 加 `--speed-helpers`，随后使用同目录 validate/collect。它要求实际库保留相应入口，将 small-update、small-subtract 与 CRT-product 纳入数学预检、目标族和对应阳性控制。该选项与 `--only-keccak` 或 DSA-only 组不能组合。可移植和原生 `hosted` 紧凑配置采用常规算术路径，各自单独绑定；不登记实际库没有的辅助函数。

## 预登记范围与解释

- 常规主组：69 个目标任务及9个阳性任务。每任务100000次，3个固定种子；每1000次块内固定/随机各500，顺序独立打乱；1000次预热。检查10000/25000/50000/75000/100000前缀的均值及中心化二阶矩 Welch t，阈值为绝对值4.5。全部样本保留，不因结果提前停止，不自动重试或换种子。
- 合法 ML-KEM 密钥族是一把固定生成密钥与另外256把实际生成密钥的有限池，同一公开密文。嵌入公钥与公开矩阵种子一起改变，显著结果不能直接归为秘密泄漏。保留隔离秘密 z、公开密文诊断和固定公开部分的 dk_PKE 算术域诊断，分别按对应输入域统计。
- ML-DSA 的 eta 与 gamma1 NTT 族比较零与均匀合法系数，覆盖小秘密系数及签名掩码的算术域。逐点乘固定第二操作数，核对 Montgomery 域关系。完整签名保留标准规定的自然重试。
- KEM 与 DSA 的 Keccak 符号分别绑定。附加 DSA-only 计划有6个目标任务及3个阳性任务，避免将一个家族的原语检测外推给另一个独立代码副本。均检测24轮、规范四连续状态的接口。
- 不带 `--speed-helpers` 的主组覆盖常规入口，小模/CRT 路径由该选项单独登记。每组准确任务、入口地址、输入域和阳性包装器以生成的计划为准。
- 阳性包装器读取秘密派生比特并执行明确敏感分支；只有实际采集后确认检出，检测流程才有效。prepare/validate 和合成数据不能替代此阳性运行。

显著结果保留 `INVESTIGATE`，结合公开输入、准备过程和环境因素分析；追加实验另行登记。阈值用于所列输入族的软件时序筛查。

当前驱动为 Windows PE/Win64 ABI 与固定 P 核的 LFENCE/RDTSC，输出 TSC ticks，不能直接称核心周期。Linux/AArch64 的 ELF入口与单调时钟工具单独说明于 `README_linux.md`，不以本工具结果替代。
