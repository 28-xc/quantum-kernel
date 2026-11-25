# 源码构建与复现

正式部署先使用 `tools/kernel.py`，选择平台和 `low-memory` / `performance` 两种策略，示例见[源码说明](../README.md)。它调用底层构建器生成源码清单，编译共享库与静态库，运行功能探针，并记录编译依赖、选项和文件摘要。本文以下 `tools/build.py`、CMake 及详细配方用于复建和研究比较。

## 默认构建

需要 Python 3.10 以上、GCC 及匹配的归档器、GNU nm、objdump、size；可选 CMake 3.24 以上。Windows 使用 MinGW 工具链。Windows 构建入口要求输出位于 D 盘，临时目录随新构建目录保存；Linux 使用本机匹配工具链，构建后实际执行功能检查。

```text
cmake -S . -B build/local-compact -DLC_CONFIGURATION=compact-rate -DLC_BACKEND=portable -DLC_OPT=Os -DLC_LTO=ON
cmake --build build/local-compact
```

默认紧凑实现支持两类算法的六组参数，采用固定位宽编码、谓词位图、单块采样和缓冲区复用。输出包括共享库、静态库、两种链接方式的功能探针及构建记录。CMake 显示输出目录，`result.xml` 记录实际产物与检查结果。

直接调用 Python 入口时，先生成记录配置与源码摘要的构建清单，再执行该清单：

```text
python -B tools/build.py plan --mode hosted --configuration compact-rate --backend portable --opt Os --lto --output build/compact-plan.xml
python -B tools/build.py build --plan build/compact-plan.xml --output build/compact-output
```

输出目录应为新目录；源码或选项改变后重新生成清单。

## 可移植与通用缓存配方

|实现|`LC_CONFIGURATION`|后端|优化选项|
|---|---|---|---|
|紧凑|`compact-rate`|`portable`|`Os`，LTO 开启|
|逐行重算|`compact-recompute`|`portable`|`Os`，LTO 开启|
|共享 Keccak|`compact-rate-shared`|`portable`|`Os`，LTO 开启|
|大缓存|`native-cache-large`|`x86_64` 或 `aarch64`|`O3`，LTO 关闭|
|小缓存|`native-cache-small`|`x86_64` 或 `aarch64`|`O3`，LTO 关闭|

五种实现采用 `LC_BUILD_MODE=hosted`，具有相同的标准字节格式和公共接口。大缓存为 ML-DSA 三参数分别保留16、30、56项矩阵，小缓存保留16、30、28项；矩阵与秘密变换均在单次调用内复用。

```text
cmake -S . -B build/native-balanced -DLC_CONFIGURATION=native-cache-small -DLC_BACKEND=aarch64 -DLC_OPT=O3 -DLC_LTO=OFF
cmake --build build/native-balanced
```

原生 x86 配方使用 `-march=native`，AArch64 使用 `-mcpu=neoverse-n1`。选择与运行机器相容的目标选项。完整测量记录同时登记实际编译器、库文件摘要、工作区与栈容量；配置名称表示实现方法，资源表给出部署用量。

## 原生紧凑配方与完整配置目录

`configs/recipes.xml` 是算法配方的唯一目录。`python -B tools/build.py recipes` 列出全部配方、支持平台及默认构建选项。两个底层构建器与参数裁剪入口均读取该目录。

|配方|用途|默认平台|默认选项|
|---|---|---|---|
|`native-x86`|AVX2 / AVX-VNNI 原生紧凑实现|`x86_64`|`Os`，LTO 开启|
|`native-arm`|NEON 原生紧凑实现|`aarch64`|`Os`，LTO 开启，目录中登记的 NEON 选项|
|`reference-full`|成熟实现完整缓存对照|`portable`|`O3`，LTO 关闭|
|`reference-lowram`|成熟实现按需生成对照|`portable`|`O3`，LTO 关闭|
|`compact-fixed`|固定位宽表示与共享置换的机制比较|`portable`|`Os`，LTO 开启|

例如，`python -B tools/build.py plan --configuration native-arm --output build/arm-plan.xml` 自动填入该配方登记的全部AArch64选项。命令行显式选项优先；布尔选项使用 `--选项` 或 `--no-选项`。生成的清单完整记录每个实际值，构建时逐项回放。对照配方支持 `portable`、`x86_64` 和 `aarch64`，通过 `--backend` 显式选择同平台比较。

`native-x86` 含 VEX 编码的 AVX-VNNI 指令，部署检查须同时满足 AVX2、AVX-VNNI 与操作系统 YMM 状态保存要求。构建使用本机目标选项，实际所需指令特性登记在部署清单中。

资源实验数据保留测量时的配置标识和库摘要；重新构建生成新的产物摘要。资源选择器按数据中的实际库身份连接时间与内存记录。

<a id="Windows原生紧凑部署"></a>
## Windows 原生紧凑部署

在支持配方所需指令的 Windows x86-64 主机上，使用 MinGW GCC 及匹配的 `gcc-ar`、`nm`、`objdump`、`size`。已验证构建使用 GCC 15.2；各实验的精确版本和选项保存在构建记录中。`native-x86` 默认选择 `Os` 和 LTO，使用本机指令目标选项。

```text
python -B tools/build.py plan --configuration native-x86 --cc gcc --ar gcc-ar --nm nm --objdump objdump --size size --output out/windows-plan.xml
python -B tools/build.py build --plan out/windows-plan.xml --output out/windows-full
```

上述完整构建保存 `out/windows-full/artifacts/build.xml`、`commands.xml`、`latticecore.dll`、`liblatticecore.a`、映射文件和原生汇编归档。紧凑部署继续使用 `tools/relink_pe.py`。下表是该六参数配方的七个归档成员；名称同时用于源归档和闭包检查。

|归档成员|对应实现|
|---|---|
|`09_keccak_f1600_x4_avx2_asm.o`|原转置式四路 Keccak 入口|
|`25_mlkem_polyvec_basemul_acc_montgomery_cached_k3_avx2_asm.o`|原 K=3 缓存基乘入口|
|`26_mlkem_polyvec_basemul_acc_montgomery_cached_k4_avx2_asm.o`|原 K=4 缓存基乘入口|
|`28_mlkem_rej_uniform_avx2_asm.o`|原 ML-KEM 拒绝采样入口|
|`40_mldsa_poly_decompose_32_avx2_asm.o`|原 ML-DSA 分解入口之一|
|`41_mldsa_poly_decompose_88_avx2_asm.o`|原 ML-DSA 分解入口之二|
|`46_mldsa_rej_uniform_avx2_asm.o`|原 ML-DSA 拒绝采样入口|

以下为一条完整命令；`--parent` 指向上一步的 `artifacts` 目录。工具链与该构建保持一致，两个新输出目录各自保存完整对照和部署结果。

```text
python -B tools/relink_pe.py --parent out/windows-full/artifacts --control out/windows-link-control --output out/windows-native --cc gcc --ar gcc-ar --nm nm --objdump objdump --omit-member 09_keccak_f1600_x4_avx2_asm.o --omit-member 25_mlkem_polyvec_basemul_acc_montgomery_cached_k3_avx2_asm.o --omit-member 26_mlkem_polyvec_basemul_acc_montgomery_cached_k4_avx2_asm.o --omit-member 28_mlkem_rej_uniform_avx2_asm.o --omit-member 40_mldsa_poly_decompose_32_avx2_asm.o --omit-member 41_mldsa_poly_decompose_88_avx2_asm.o --omit-member 46_mldsa_rej_uniform_avx2_asm.o
```

工具以实际全节重定位和未定义符号确认省略成员未被使用，保留共同常数及所有仍在使用的函数。完整对照重链接的代码与 Windows 展开节须与父构建一致，部署库继续检查导入、导出、展开记录及动态和静态接口。产物 `out/windows-native/latticecore.dll` 与同目录 `build.xml`、`closure.json`、`paired-link-record.xml` 一起保存。若成员仍有引用，工具返回错误并保留日志。

`relink_pe.py` 用于这一 PE 部署过程；参数裁剪采用下一节的独立入口。Linux AArch64 的 `native-arm` 配方生成 ELF 共享库，构建器已处理其原生归档和公共实体。

## Linux AArch64 原生构建

在 AArch64 主机上使用本机 GCC、gcc-ar 及 GNU 二进制工具。已验证环境使用 GCC 11.4，配方指定 `-mcpu=neoverse-n1`，采用 `Os`、LTO 和配置目录中的全部平台选项。

```text
python3 -B tools/build.py plan --configuration native-arm --cc gcc --ar gcc-ar --nm nm --objdump objdump --size size --output out/arm-plan.xml
python3 -B tools/build.py build --plan out/arm-plan.xml --output out/arm-native
```

实际库为 `out/arm-native/artifacts/liblatticecore.so`，静态库和构建记录位于同一目录。构建阶段执行本机功能探针，所选参数、依赖和实际平台选项随产物保存。

## 从构建衔接到功能、资源和耗时

依次保存构建清单、实际库 SHA-256、标准检查、资源记录和计时配置。标准检查可以显式传入正常工作区；以下两行分别用于上述 Windows 和 ARM 产物：

```text
python -B tests/platform/check_public_acvp.py --library out/windows-native/latticecore.dll --workspace 9536 --output out/windows-acvp.xml
python3 -B tests/platform/check_public_acvp.py --library out/arm-native/artifacts/liblatticecore.so --workspace 9120 --output out/arm-acvp.xml
```

这两个工作区值对应当前原生紧凑配方。其他配方使用各自正常容量记录。检查逐例比较公开接口支持的标准输出，并核对工作区护栏与已使用区域的清理；内部 μ 和 HashML-DSA 向量按接口范围单列。

独立字节比较使用 `tests/platform/compare_public.py --left LIBRARY --right REFERENCE --count 200 --resource-mode record --output NEW_RESULT.xml`；`record` 允许两实现的内存布局不同，同时继续核对完整输出与熵请求。资源范围与入口见 [内存分项](MEMORY_OBSERVATIONS.md)，计时配置中的 `library` 和 `workspace` 必须与对应资源记录一致。

核心十八项计时见 [完整操作入口](../bench/complete_operations/README.md)，公开数据的导入和统计复算见 [观测数据导入](import_complete_operations.md)及[均值与尾部统计](mean_tail_statistics.md)。包含应用对象的正常资源及初始化至清理的计时见 [固定池应用](enrollment_owner.md)。独立原语从 `liblatticecore.a` 与同目录 `build.xml` 绑定实际函数，详见 [原语入口](../bench/primitive/README.md)。

## 参数裁剪

`LC_BUILD_MODE=pruned` 保留指定算法参数，`LC_PARAMETERS` 接受 `all`、`kem`、`dsa` 或逗号分隔的标准参数列表。

```text
cmake -S . -B build/kem768-dsa65 -DLC_BUILD_MODE=pruned -DLC_PARAMETERS=768,65 -DLC_CONFIGURATION=compact-rate -DLC_BACKEND=portable -DLC_OPT=Os -DLC_LTO=ON
cmake --build build/kem768-dsa65
```

裁剪构建保留八个公共入口。合法但未选中的标准参数返回 `LC_E_UNSUPPORTED=-8`，尺寸查询输出清零。调用方可包含 `configs/pruned/latticecore_pruned.h` 取得该错误码。

程序空间按实际链接映像的代码、只读数据与初始化数据计算，可写全局和线程局部存储另计入运行内存。裁剪入口含参数支持检查，因此全部参数的裁剪映像与普通六参数映像分别登记。每个范围均执行对应功能检查，符号、依赖与映像节信息随结果保存。

## 对照与原语

匹配对照包括成熟源适配的完整缓存、按需生成和可移植低内存实现。独立 PQClean 参考使用自身存储方式，并以公共接口适配长度、随机源和标准输入检查。

```text
python -B tools/build_pqclean.py --architecture x86_64 --cc <gcc或clang> --output <新目录>
python -B tests/pqclean/run_validation.py --library <PQClean库> --reference <同平台对照库> --output <检查目录>
```

完整十八项计时入口位于 `bench/complete_operations/`。原语实验分为独立参数化标量组件与实际算法静态库函数，具体数学接口、输入范围和计时条件见 [原语说明](../bench/primitive/README.md)。

## 32位目标程序

Cortex-M4 与 RV32IM 分别提供紧凑和逐行重算目标程序。构建需要对应裸机编译器与 QEMU，`--run` 实际执行目标映像。

```text
python -B tools/build_targets.py --target m4 --profile rate --workspace-bytes 10720 --stack-bytes 4096 --output <新目录> --run
python -B tools/build_targets.py --target rv32 --profile recompute --workspace-bytes 8128 --stack-bytes 4096 --output <新目录> --run
```

每次输出 ELF、链接脚本、完整控制台、标准向量子集、117项目标检查和内存账本。账本分别列出代码与只读区、工作区、输入输出对象、测试栈和控制栈。所选仿真板将代码映射到模拟 RAM；可写预算和完整映像空间分别统计。设备集成采用实际密码随机源回调。

## 独立源码副本

```text
python -B tools/build.py bundle --output <源码目录以外的新目录>
```

源码包按显式文件清单复制 C 与汇编代码、构建工具、配置、说明、许可证及测试向量，并保存相对路径、字节数和 SHA-256。编译依赖用于核对实际输入；Python、编译器与系统库由运行环境提供。

在新副本内生成构建清单并执行，便可核验独立重建。各类测试分别绑定产物：无插桩库用于正式性能，插桩库用于内存与秘密依赖检查，目标 ELF 用于32位指令仿真。数据中的版本、选项和摘要用于选择对应复现条件。

部分矩阵缓存、32位矩阵缓存和固定速度配方用于机制比较，见[部署策略说明](deployment_strategies.md)。矩阵存储、原位乘积及采样暂存方法见[矩阵存储与工作区复用](storage_schedule.md)。资源与性能结果必须按构建所得库的身份关联。
