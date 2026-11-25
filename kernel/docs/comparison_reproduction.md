# 完整操作比较的独立复算与重新采集

当前可直接使用的复算任务见[实验复算说明](../../../02_测试代码与数据/复算数据/README.md)。下文命令使用复现工作区中的 `source/`、`bin/` 和 `data/comparison-replay.xml`；执行前按上述说明准备工作区、输入清单和运行环境。

`tools/reproduce_comparison.py` 默认读取随附的全部原始 CSV，重新计算均值、中位数、P95、P99 和置信区间，并核对已有摘要。两平台主比较各含十三配置；Windows表示消融包含最终紧凑配置和五种表示控制，统一保存为`data/layout-contribution-windows`。每批使用自己的输入、随机顺序和区组重采样种子。

```text
python source/tools/reproduce_comparison.py --input data/comparison-replay.xml --output ../results/comparison
```

输入清单中的 `observations`、`summary`、`design` 和 `resources` 均由相对路径与 SHA-256 标识。输出包括逐研究派生统计、`resource_points.json`、逐操作统计表 `operation_cells.csv` 和配对时间比表 `paired_operation_ratios.csv`。输出目录须为新目录，并位于源码树以外。此命令使用能够直接导入 NumPy 2.2.5 的 Python 环境。Windows随包Python可通过下面的`comparison`入口加载离线NumPy，对同样完整数据进行全部复算，无需另行安装Python依赖：

```text
bin\python\python.exe -B source\tools\offline_analysis.py --entry comparison -- --mode replay --input data/comparison-replay.xml --output ../results/comparison-offline
```

该入口覆盖同批低内存比较、编译策略和消融数据。其他离线入口与源码重建见[复现说明](reproduction.md)。

每个区组包含全部参数、操作和实现。区间按完整区组共同重采样，同一抽样同时用于各实现与各统计量。所有慢样本均进入统计；预热记录也保留在原始数据中，仅按事先指定的标记从统计量中排除。均值时间比为分子实现除以分母实现，小于 1 表示分子更快。逐格区间是点态区间，不构成多重比较同时置信保证。

复算精确核对原始CSV、源码、样本数量、抽样种子和区组抽样摘要。不同指令集的二进制浮点运算可能相差少量末位，派生浮点字段按相对`3e-13`或绝对`1e-9`的容差逐项比较。输出的`numerical_validation`记录差异数、最大误差及两端浮点数组摘要；`*.recomputed-summary.json`保留本次完整重算值，原归档摘要保持不变。

编译策略对照比较同一目标架构下的 `Os + LTO`与`O3 + LTO`，保留相同算法配置及LTO设置。`lattice-separated32-control`采用独立保存的32位矩阵及独立掩码工作区实现，其实际测量映像、构建命令和源码位于随包参考资料中；这一比较反映联合存储与调度方案的完整效果。秘密表示对照主要报告三项签名操作；保留向量宽度对照主要报告六项签名算法密钥生成和验签操作；矩阵采样对照主要报告九项密钥封装操作。其他操作完整保留。六配置表示消融保留九个配对区组，每格1000次正式调用与20次预热。

`data/windows-mechanism-confirmation-v1`另存七配置、二十个配对区组的机制确认实验，完整保留2520批、1310400条记录。其三组比较分别检验自然掩码留存、44参数的低位检查顺序及联合计算组织，绑定各自实际测量映像，与裁剪库主比较分开统计，报告联合机制的整体效果。该包的`README.md`给出独立消费与复算命令。

资源按每个实际映像分别绑定。`R = W + S + C + G + H`，依次为工作区、预留栈、外部上下文、可写全局区与额外堆；共同资源取六组参数的分项最大值，家族资源另列。计时配置中的统一工作区容量仅为调用许可，不代替实际资源值。资源检查覆盖固定正常输入，并保留栈余量，未外推为所有输入的栈上界证明。核心资源不包含调用者持有的序列化输入输出；完整应用的数据另行核算。

## 在本机重新采集

重新采集先从当前归档导出独立配方，再显式选择`collect`。导出器逐项核对十三个部署映像与原测量像的执行等价收据，复制所需映像和本机OpenSSL依赖，保留区组、样本、种子及比较关系。采集工具随后构建并核对OpenSSL 3.6.4配对驱动，测量六组参数的十八项完整操作，最后投影原始数据并计算统计量。时钟边界包含新鲜序列化密钥的完整公共接口调用及其实际校验、编码和逐次清理。输入准备位于时钟外。

```text
python source/tools/export_collection_plan.py --bundle . --platform windows --crypto-prefix <OpenSSL安装目录> --crypto-library <该目录下的libcrypto-3-x64.dll> --output ../results/windows-plan
python source/tools/reproduce_comparison.py --mode check --input ../results/windows-plan/plan.xml --output ../results/windows-plan-check
python source/tools/reproduce_comparison.py --mode collect --input ../results/windows-plan/plan.xml --output ../results/new-windows-study
```

尖括号处替换为本机实际OpenSSL 3.6.4安装路径。安装应包含头文件、共享库和GCC所需的链接库；`--crypto-library`须位于指定安装目录内。Linux AArch64在本机将导出参数改为`--platform arm`，指定该安装下的`libcrypto.so.3`，使用`python3`执行。导出器默认沿用归档CPU编号，可用`--cpu`指定本机可用核心。平台检查在加载密码库之前执行；Windows 机器的采集不能代替 AArch64 实测。所选 CPU 还须支持库编译时要求的指令集，Windows 原生实现包含 AVX2 和 AVX-VNNI，不能用仅支持 AVX2 的机器代替。

配置采用 `lattice.comparison_acquisition.v1`，包含：

- `platform`、`dataset_id`、`compiler`、`cpu`；
- `crypto_library: {path, sha256}`、`crypto_prefix`，以及用作驱动预检的 `preparation_library` 标识；
- `blocks`、`samples`、`warmups`、`seed`、`bootstrap_seed`、`resamples`；
- `message_bytes`、`context_bytes`；
- `configurations`：每项为 `{id, library: {path, sha256}, workspace}`；
- `comparisons`：每项为 `{id, candidate, reference}`。

文件和 OpenSSL 安装前缀均相对于配置文件目录。安装前缀需要包含 `include/openssl/evp.h`；Windows 还需要其 `lib` 中的导入库。编译器可通过 `PATH` 提供。比较库必须为相应架构实际构建的库，散列不同须显式更新配置。新采集结果保存到独立目录。

只检查配置、文件身份和规模而不加载密码库，可使用 `--mode check`。采集期间应保持该机器无其他编译、测试或重负载任务。工具按固定区组顺序执行，逐步保留命令、标准输出、错误输出、退出状态和原始记录；失败停止，原目录不重用。重新采集会产生新实验身份，新实验记录本机硬件、工具链和运行条件。
