# 参数化格运算内核

本工程以统一 C 接口提供 ML-KEM-512/768/1024 和 ML-DSA-44/65/87 的十八项完整操作。密钥、密文和签名采用 FIPS 203/204 标准格式。调用者提供工作区，同一上下文可顺序执行不同参数的操作。

## 两种部署策略

工程支持 Windows、Linux AArch64、CH32V307 和 STM32F407，提供低内存和高性能两种策略。公共接口、参数、工作区和基础组件共享；模数及处理器相关算术由专用后端实现。

| 执行平台 | 低内存 | 高性能 |
|---|---|---|
| Windows、Linux AArch64 | 紧凑表示和行复用 | ML-DSA-87 签名按工作区容量选用完整矩阵或五行缓存 |
| STM32F407 | 24 KiB，默认 compact | 32 KiB，默认 cached |
| CH32V307 | 28 KiB 固件 | 80 KiB 固件 |

每个 STM32F407 映像均可运行六组参数和两种策略。CH32V307 在构建时确定布局，运行时按预算选择对应固件。实板性能与资源见[实板配置与测试](../BOARD_DEPENDENCIES.md)。其他实验布局见[部署策略与实验对照](docs/deployment_strategies.md)。

## 直接构建

在源码根目录运行以下命令。输出目录须在源码树之外且尚不存在。Windows 需匹配的 MinGW 工具链，当前专用实现要求 AVX2、AVX-VNNI 和相应操作系统向量状态；AArch64 在真实 Linux ARM 主机上构建，使用 NEON。

```text
python -B tools/kernel.py --platform windows-x86_64 --strategy low-memory --output ../out/windows-low
python -B tools/kernel.py --platform windows-x86_64 --strategy performance --output ../out/windows-performance
python3 -B tools/kernel.py --platform linux-aarch64 --strategy low-memory --output ../out/arm-low
python3 -B tools/kernel.py --platform linux-aarch64 --strategy performance --output ../out/arm-performance
```

实板固件及编译参数见 `targets/board_firmware.xml`。连接开发板见[Quantum Kernel 使用说明](../README.md#打开交互界面)。主机工作区由调用者分配，完整应用另计输入输出、栈和应用状态。

## 构建与运行

需要 Python 3.10 以上、GCC 及匹配的归档和二进制工具；使用 CMake 时需要 3.24 以上版本。以下命令显式构建包含六组参数的紧凑实现：

```text
cmake -S . -B ../local-compact -G Ninja -DLC_CONFIGURATION=compact-rate -DLC_BACKEND=portable -DLC_OPT=Os -DLC_LTO=ON
cmake --build ../local-compact
```

选择其他实现时，更换构建目录和 `LC_CONFIGURATION`。原生实现还需将 `LC_BACKEND` 设为 `x86_64` 或 `aarch64`。复现实验使用数据中登记的编译器、优化选项和链接选项；构建输出保存共享库、静态库、链接映射、导出符号及功能检查记录。

|任务|入口|
|---|---|
|原生构建、Windows 部署重链接及完整选项|[构建说明](docs/build.md)|
|指定参数裁剪|`LC_BUILD_MODE=pruned`，以 `LC_PARAMETERS=768,65` 等选择标准参数集合|
|本地功能演示|[演示说明](demo/README.md)|
|设备公钥签发与密钥建立|[应用示例](examples/README.md)|
|固定内存池与签名缓冲区复用|[完整应用构建、资源、计时和复算](docs/enrollment_owner.md)|
|Cortex-M4、RV32 目标程序|[目标构建说明](targets/README.md)|
|CH32V307 实板|[连接与更换固件](targets/ch32v307/README.md)|
|STM32F407 实板|[连接与更换固件](targets/stm32f407/README.md)、[定模数约减对照](bench/stm32f407_poly/README.md)|
|独立多项式组件|`tools/build_primitives.py prepare --mode canonical`|
|PQClean 参考实现|`tools/build_pqclean.py` 与 [对照说明](baselines/pqclean/README.md)|

## 调用接口

头文件为 `include/latticecore.h`。所有长度以字节为单位，八个入口在各实现中一致。

|入口|功能|
|---|---|
|`lc_get_sizes`|查询公钥、私钥、密文、共享秘密及签名的标准长度|
|`lc_context_init`|绑定调用者工作区和随机源回调|
|`lc_keypair`|生成 ML-KEM 或 ML-DSA 密钥|
|`lc_encaps`、`lc_decaps`|封装、解封装 32 字节共享秘密|
|`lc_sign`、`lc_verify`|签名、验签；支持 0–255 字节上下文|
|`lc_error_string`|将返回码转换为文字说明|

先查询对象长度并分配输入输出缓冲区，再初始化工作区和上下文，随后调用所需密码操作。随机源回调为空时使用系统密码随机源。一个上下文顺序使用；并发调用使用独立上下文和工作区。

输入、输出、上下文与工作区须各自有效且互不重叠。输出容量可大于标准长度，输入密钥、密文和待验证签名须使用准确长度。对象检查在调用开始时完成；通过对象检查后的随机源或算法错误会清零对应的标准输出区。工作区不足时返回容量错误，重新提供足够工作区后可恢复调用。

|返回码|含义|
|---|---|
|0|成功|
|−1 / −2 / −3|参数无效 / 长度无效 / 对象重叠|
|−4 / −5|随机源失败 / 工作区不足|
|−6 / −7|操作拒绝 / 内部不变量异常|
|−8|合法标准参数未包含在当前裁剪构建中|

ML-KEM 对正确长度的无效密文执行隐式拒绝，返回成功码和替代共享秘密；私钥中公钥哈希不一致返回显式错误。ML-DSA 对无效签名返回拒绝码。完整调用与错误恢复例程见 `tests/public_api/probe.c`、`tests/normal_capacity/` 和 `tests/pruning/probe.c`。

## 验证与测量

标准向量入口 `tests/platform/check_public_acvp.py` 比较公开接口所支持的 NIST 向量；`compare_public.py` 比较完整输出字节与随机字节请求，并检查无效密文和签名的处理。随机源调用及错误恢复检查见 [平台与随机源说明](docs/platform_portable.md)。

核心完整操作的公开复现入口位于 `bench/complete_operations/`；包含密钥、签名、密文和应用状态的完整流程使用 `tools/application_timing.py`，见[应用说明](docs/enrollment_owner.md)。核心计时的每次调用从序列化密钥开始。两类测量均以随机完整区组组织，记录实际加载的算法库、编译条件和时间单位。数据保存原始顺序、预热、慢样本及失败结果；区间估计以完整配对区组为重采样单位。具体条件与调用范围见该目录的说明和数据协议。

PQClean 参考实现、由成熟实现适配的可移植低内存对照、原生完整缓存对照和按需生成对照分别登记。PQClean 保留自身堆栈分配方式，其接口中的工作区参数是未参与计算的占位参数；资源测量直接统计实际堆栈和可写存储。

独立多项式组件提供两个模数下的加减、NTT/INTT、变换域乘法与负循环卷积。算法原语测量从指定静态库链接实际函数，核对系数排列和 Montgomery 表示，并与独立卷积比较。原语名称、数学接口和计时范围见 [原语说明](bench/primitive/README.md)。

## 资源统计与第三方代码

算法预留内存由固定工作区、受约束栈、外部上下文、可写全局与线程局部存储、相关堆分配组成。可写存储包含链接映像中的运行时数据；堆测量覆盖线程初始化至退出。工作区与栈的实际使用峰值另列，固定容量用于部署选择。

应用预算进一步计入输入输出对象、应用状态、对齐填充、完整应用栈和应用全局变量。QEMU 实验记录 Cortex-M4、RV32 目标程序的功能执行、链接空间和存储需求。

工程保留 mlkem-native、mldsa-native、PQClean 等第三方代码的原始署名及许可证。依赖版本和许可证见 [第三方代码与许可证](docs/sources_and_licenses.md)。

构建验证、Docker、随附数据复算与本机重新采集的完整命令见[复现说明](docs/reproduction.md)。

矩阵的16位与8位分平面存储、频域原位乘积和采样工作区复用，见[矩阵存储与工作区复用](docs/storage_schedule.md)。
