# 构建、验证与实验复现

复算：[实验复算说明](../../../02_测试代码与数据/复算数据/README.md)。构建：[源码说明](../README.md)、[平台与构建](../support-notes.md)。

下文命令使用复现工作区的 `source/`、`bin/` 和 `data/signing-pipeline-*` 等路径；执行前按上述说明准备工作区，并核对输入清单与源码版本。

`../results/` 是下文示例输出位置，可换成有写权限且尚不存在的新目录，输出须位于支撑材料之外。

## 只读取随附数据

Windows随包提供CPython 3.13和NumPy 2.2.5。单批统计可通过离线入口复算，无需安装额外软件：

```text
bin\python\python.exe -B source\tools\offline_analysis.py --entry mean-tail -- recompute --observations data/signing-pipeline-windows/observations.xml --summary data/signing-pipeline-windows/mean-tail-summary.xml
```

将目录替换为`layout-contribution-windows`可核对六配置表示消融的完整操作数据。跨平台复算使用下列入口，例如在Windows读取AArch64结果：

```text
bin\python\python.exe -B source\tools\offline_analysis.py --entry operation-statistics -- --kind mean-tail --observations data/signing-pipeline-arm/observations.xml --summary data/signing-pipeline-arm/mean-tail-summary.xml --output ../results/arm-mean-tail
bin\python\python.exe -B source\tools\offline_analysis.py --entry operation-statistics -- --kind equal-frequency --observations data/signing-pipeline-arm/observations.xml --summary data/signing-pipeline-arm/equal-frequency-summary.xml --output ../results/arm-equal-frequency
```

该入口逐项核对原始样本、源码摘要、抽样种子和区组安排，记录跨架构浮点差异及两次统计数组摘要。此过程读取全部CSV，不加载密码库。统计使用实际样本及完整区组重采样，保留全部正式样本。

完整报告复算使用独立的Python 3.13环境、NumPy 2.2.5、SciPy 1.18.1、Matplotlib 3.10.9、GNU objdump及中文字体；这些版本已用于随附数据的完整复算。依赖版本见`source/docs/analysis_requirements.txt`，可用`python -m pip install -r source/docs/analysis_requirements.txt`安装。随包离线环境提供NumPy统计；完整分析环境另行准备。以下命令复算两平台应用、原语、完整操作与消融、安全和验证记录，并重新生成图表与补充表格：

```text
python -B source/tools/reproduce_scientific.py --bundle . --mode full --output ../results/science-full
```

`--mode quick`只运行应用、原语、指令观察和验证记录的复算；`full`再执行两平台十三配置完整操作、六配置表示消融、同条件原生与低内存比较，以及当前安全数据的复算和绘图。机器代码对应检查默认从PATH查找GNU objdump，也可添加`--objdump <可执行文件路径>`。每项实际退出码、源摘要、日志摘要保存在输出`result.xml`。该入口读取随附原始测量记录，重新采集使用后文的独立入口。

只需要完整操作、编译策略比较、资源点和消融派生表时，可使用NumPy环境运行：

```text
python -B source/tools/reproduce_comparison.py --input data/comparison-replay.xml --output ../results/comparisons
```

统计方向、资源统计及派生表字段见[完整操作比较说明](comparison_reproduction.md)。应用计时的初始化与关闭边界见[完整应用说明](enrollment_owner.md)。

## Windows源码重建与验证

使用支持目标指令集的Windows x86-64主机、Python 3.10以上，以及同一套MinGW GCC、gcc-ar、nm、objdump和size。将工具目录加入PATH，或用`--toolchain-directory`指定目录。包含科学数据和图表的完整复现使用上述Python 3.13、NumPy、SciPy与Matplotlib环境，并配置中文字体。

```text
python -B source/tools/reproduce.py --mode quick --configuration native-x86-sign-pipeline --bundle . --output ../results/windows-quick
python -B source/tools/reproduce.py --mode full --configuration native-x86-sign-pipeline --bundle . --output ../results/windows-full
```

两个命令使用不同的新输出目录。入口按公开配方构建所选实现，并通过`tools/build_reference.py`从随包`reference-source/current`独立构建当前成熟低内存对照，采用所选配方的优化策略：速度配置为`O3 + LTO`，其余四种部署配置为`Os + LTO`；重建对照采用相同优化级别，随后执行功能、公开私钥编码边界和正常资源检查。`full`增加固定Wycheproof向量，并执行完整科学复算。报告中的独立原生对照采用O3编译，同条件低内存比较分别采用Os+LTO与O3+LTO；各数据集记录对应的源码、程序和编译选项。

Windows原生库的部署重链接由该入口自动执行：先核对实际链接引用，再生成独立部署库和同代码重链接记录。功能与资源检查使用该部署库。

同一入口也支持以下资源配置。将命令中的`--configuration`替换为对应名称，即可完成构建、验证和资源测量。紧凑、两种矩阵缓存与32位矩阵缓存配置裁掉七个无引用归档成员；速度配置保留验签哈希所需的四路Keccak成员，裁掉六个成员。每个配置均核对实际符号引用。

|配置|Windows x86-64|Linux AArch64|
|---|---|---|
|紧凑配置|`native-x86`|`native-arm`|
|48项矩阵缓存|`native-x86-cache48-gamma`|`native-arm-cache48-yall`|
|40项缓存对照|`native-x86-cache40-gamma`|`native-arm-cache40-yall`|
|完整矩阵缓存|`native-x86-cache56-gamma`|`native-arm-cache56-yall`|
|32位矩阵缓存配置|`native-x86-speed32`|`native-arm-speed32`|
|速度配置|`native-x86-sign-pipeline`|`native-arm-sign-pipeline`|

主比较数据保存在`data/signing-pipeline-windows`和`data/signing-pipeline-arm`。每个平台以同批十三种配置测量六组参数的十八项操作，保留20个配对区组、每格500次正式调用与20次预热。`mean-tail-summary.xml`给出均值、中位数、P95、P99及区间，`equal-frequency-summary.xml`给出十八项操作各执行一次的均值总和。两项统计从同目录的`observations.xml`及原始样本复算。`resources.xml`逐项关联实际库、工作区、栈、上下文、全局区与程序空间。六配置表示消融的计算路径和构建记录由相应数据记录，独立复算核对其源码与执行代码。

只检查源码构建与功能而不读取随附科学数据时，可显式添加`--source-only`。结果会记录`EXPLICIT_SOURCE_ONLY`。输出根的`result.xml`和`logs/`保留成功、失败或未完成状态；构建、功能与资源结果分目录保存。驱动传入的262144字节是测试容量许可，实际资源值由`resources/`单独测量。

## Linux AArch64和Docker

AArch64本机使用该平台GCC及二进制工具：

```text
python3 -B source/tools/reproduce.py --mode full --configuration native-arm-sign-pipeline --bundle . --output ../results/arm-full
```

该命令构建本机NEON路径。Windows与AArch64分别记录各自工具链、库文件与结果。

`source/Dockerfile`固定Ubuntu基础映像、GCC 11.4.0与Python 3.10，提供源码构建和功能检查环境。默认容器入口构建并检查可移植`compact-rate`，不采集正式性能。首次构建映像需要网络取得锁定的系统包与Python依赖。在Linux或兼容Docker的终端中：

```sh
docker build -t lattice-reproduction source
mkdir -p ../docker-results
docker run --rm --network=none -v "$(pwd)/../docker-results:/results" lattice-reproduction --mode quick --configuration compact-rate --source-only --output /results/quick
```

完整源码检查增加固定测试向量，继续使用`--source-only`并选择新的输出目录：

```sh
docker run --rm --network=none -v "$(pwd)/../docker-results:/results" lattice-reproduction --mode full --configuration compact-rate --source-only --output /results/full
```

在AArch64主机上，将上述命令的`--configuration compact-rate`改为`--configuration native-arm`即可构建原生NEON路径。容器执行记录保存实际配置、源码摘要、映像和工具链身份；运行阶段使用`--network=none`。容器命令执行源码检查；全部科学数据及图表由前述Python 3.13环境运行`reproduce_scientific.py`复算。原生平台性能来自对应主机的实际测量。

跨平台复算对原始样本、整数计数、区组抽样及其SHA-256保持精确核验。统计结果的二进制浮点运算允许相对误差`3e-13`或绝对误差`1e-9`；每份结果记录实际最大差异，并同时保留归档与本次重算的浮点数组摘要。此规则适用于统计派生值，原始数据和抽样方案仍须逐项一致。

## 在本机重新采集完整18项操作

重新采集先核验随附部署映像并导出独立配方，再选择`collect`。准备本机OpenSSL 3.6.4安装（头文件、共享库及GCC链接库），将下列尖括号替换为实际路径：

```text
python -B source/tools/export_collection_plan.py --bundle . --platform windows --crypto-prefix <OpenSSL安装目录> --crypto-library <该目录下的libcrypto-3-x64.dll> --output ../results/windows-plan
python -B source/tools/reproduce_comparison.py --mode check --input ../results/windows-plan/plan.xml --output ../results/windows-plan-check
python -B source/tools/reproduce_comparison.py --mode collect --input ../results/windows-plan/plan.xml --output ../results/windows-new-measurement
```

AArch64本机将导出参数改为`--platform arm`，指定相应安装下的`libcrypto.so.3`，并使用`python3`。导出器从`data/signing-pipeline-{windows,arm}`读取当前实验协议，按`data/comparison-images.xml`逐一验证十三份部署像及其执行等价收据；随后把库、OpenSSL头文件及链接依赖复制到新的配方目录。该步骤只准备文件，不调用密码接口。

导出的`plan.xml`记录相对路径、SHA-256、CPU编号、消息长度及全部比较关系。协议保持20个随机区组、每格500次正式调用与20次预热，覆盖六组参数的十八项完整操作。默认沿用归档CPU编号，`--cpu`可选择本机可用核心。正式采集入口构建驱动并验证OpenSSL实际版本，所有输出均写入新的目录。

使用自己的重建库时，在独立配置副本中同时更新路径与SHA-256，并根据本机核对CPU编号和指令集。配置的`compiler`可设为本机编译器名称或路径。工具先检查平台与所有文件身份；`--mode check`可只做这些检查，不执行目标库。

采集期间应保持该机器无其他重负载任务。工具按固定随机区组保留全部任务、标准输出、错误输出和原始样本，失败后停止；新结果留在新目录，不覆盖附件。重新采集受硬件、编译器和操作系统影响，不要求时间数值与附件逐一相等。普通数据复算则应按已记录方法重建原统计结果。

## 来源与使用条件

标准格式、接口范围、错误处理和平台要求见[源码说明](../README.md)。参数与操作裁剪见[部署说明](deployment.md)。上游实现、独立基线、运行库与许可索引见[来源与许可](sources_and_licenses.md)。各向量文件和数据结构保留其实际来源版本、输入与映像摘要；第三方声明适用于各自文件。

## 部署映像与测量映像

随包算法库删除调试信息后部署。每份库旁的`derivation.xml`同时记录原测量像和部署像的SHA-256，并逐段核对执行代码、只读常数、入口及装载属性。演示先验证该收据，再将实际加载库与原测量结果关联；功能导出同时给出两种身份。重新采集使用随包部署像，生成新的测量身份。完整原始样本始终保留原测量像的SHA-256。
