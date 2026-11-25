# 来源、许可与依赖索引

本索引列出代码来源；各文件的署名、SPDX 标识及随附许可文本规定相应条款。

|组成|来源与随附条款|作用|
|---|---|---|
|ML-KEM 基础实现|`third_party/mlkem-native/LICENSE`、`META.yml`、`RELICENSE.md` 及源文件头|标准算法、采样、编码、可移植与原生算术|
|ML-DSA 基础实现|`third_party/mldsa-native/LICENSE`、`META.yml`、`RELICENSE.md` 及源文件头|标准算法、拒绝采样、签名流程、可移植与原生算术|
|本项目适配源码|各 `build/adapted_*`、`src/` 下实际源码及构建依赖清单|资源调度、紧凑编码、矩阵缓存、公共接口和目标适配|
|共享 Keccak 置换|`configs/shared_keccak_compact/owner_single.c`、生成脚本及 mlkem-native 原始许可|从上游布尔方程提取单轮循环，保留 24 个轮常数与原始署名；经上游扩展接口接入两算法|
|公开标准测试向量|`tests/vectors/acvp/UPSTREAM_README.md`、`commit.txt` 及每次测试的输入摘要|独立期望值与明确的公开接口测试子集|
|PQClean clean 对照|`baselines/pqclean/source_lock.xml`、六个 `clean/LICENSE`、各参数 `META.yml` 和 `common/` 文件头|固定官方归档版本的第三方实验基线|

mlkem-native 源于公开领域 Kyber 参考实现，其库代码按 Apache-2.0、ISC 或 MIT 三选一方式提供；mldsa-native 源于公开领域 Dilithium 参考实现，同样列出三种许可。随附 `LICENSE` 保留各许可完整文本，单文件具有其他 SPDX 标识时以该文件条款为准。适配代码继续保留上游头部与血缘说明。

独立参数化算术、工作区管理、测试驱动和演示模块的具体来源见各文件及源码清单。模3329与8380417的原生NTT、SHAKE并行算子保留上游归属；紧凑表示、缓冲复用、分组调度和公共接口的修改分别记录在项目源码中。

成熟原生对照的基础源码位于`third_party/mlkem-native`和`third_party/mldsa-native`，分别固定为提交`6b12c8cd67e1edd07c43f581386449a6b064e6e2`与`7625016fca797896fa7b87cf5455b587a0199682`。完整与低内存原生后端、逐调用前缀缓存和公开A会话由显式配方通过`tools/build.py`生成；前缀缓存、会话绑定及公共接口属于本项目对照适配，原采样和算术保留上游归属。独立生产适配树继续保留自身源码血缘，x86返回边界的具体上游来源另列。官方归档、原始文件摘要、局部适配摘要及返回边界来源见[原生实现来源](native_reference.xml)。

PQClean 的六个所选 clean 实现各自附有 Public Domain/CC0 声明，公共 FIPS202 文件保留原公共领域来源与作者注释。其 143 个官方文件按固定提交的原始 Git blob 与 SHA-256 同时锁定；适配和 nonce 包装在单独文件中，原算法文件不修改。具体范围见 `baselines/pqclean/README.md`。

## 外部运行与构建依赖

Windows 支撑附件提供官方 Python 3.13.15 x64 嵌入式运行时及 NumPy 2.2.5 离线 wheel。演示使用随附解释器和 WebView2 桌面窗口；科学统计复算从附件内准备独立 NumPy 目录。Python 原始 ZIP、逐文件摘要、完整许可证与 NumPy wheel 的完整许可证一并保留，位置见 `bin/runtime_inventory.xml`。其中 Microsoft Distributable Code、OpenSSL、libffi 及 NumPy 打包数值库分别适用原包注明的条款。

源码重建所用 GCC/Clang、binutils、CMake，目标模拟所用 QEMU，以及自动浏览器测试所用 Node.js 和 Edge 由开发环境安装；浏览器检查通过本机调试协议执行。源码包提供锁定来源和实际构建配方。科学对照驱动另使用 OpenSSL 3.6.4：许可原文保存在`docs/licenses/windows/openssl/LICENSE.txt`，重新采集时由本机安装提供头文件、共享库与链接库。对照工具绑定库路径、文件摘要、实际加载路径及版本。

Windows 公共接口使用操作系统 BCrypt 服务；Linux 使用 `getrandom`。裸机测试运行时及目标启动源码随工程提供，交叉编译产生的程序仍需检查所用运行时和 libgcc 等实际链接成分。已构建库和可执行文件的导入项、最终代码/只读数据及可写段，以对应二进制检查记录为准。

PQClean 的 Windows 配方将编译器和线程局部存储辅助运行库静态计入实际映像，malloc/free 仍使用 Windows CRT。源码包不复制独立编译器 DLL；分发已编译产物时，还须按实际所用工具链的运行库许可和例外条款处理其链接成分，不能仅引用 PQClean 的许可覆盖全部映像。

所用 Windows 运行库许可原文已按发行版本保存于 `docs/licenses/windows/`，逐文件来源、版本和 SHA-256 见其中 `sources.xml`。GCC 15.2.0 的运行库文本包括 GPLv3 与 GCC Runtime Library Exception 3.1；PQClean GCC 链接图实际保留的 emutls 与 winpthreads 分别对应 GCC 和 MinGW-w64 文本。LLVM-MinGW 保存自身 LLVM 许可及其固定 MinGW-w64 CRT 快照许可。许可文本可用不表示每个映像都链接了全部组件，具体对应以真实链接映射为准。

`tools/inspect_runtime_dependencies.py` 对指定PE和链接图记录导入项、映像摘要与静态运行库匹配。库和共享探针的实际依赖按各自映像登记，Windows系统CRT、Kernel32与BCrypt由系统提供。Python演示通过ctypes调用算法库，并在独立桌面窗口中呈现。显式加载的OpenSSL等科学对照依赖由配置另行记录，静态导入与实际加载身份分别核对。

实际独立互操作驱动的 PE 导入包含 `libcrypto-3-x64.dll`。本次 OpenSSL 3.6.4 映像 SHA-256 为 `5164f76251944f51c60e444721c0dec8665fe4aaf85b8067f42c8c64d99e0265`，其导入闭包为 Windows 自带 ADVAPI32、CRYPT32、KERNEL32、msvcrt、USER32 和 WS2_32。因此，这项驱动的额外动态分发组件为一份精确绑定的 libcrypto；系统 DLL 由 Windows 提供。Apache-2.0 许可原文及实际来源摘要已加入 Windows 许可索引。

Linux AArch64实测采用OpenSSL 3.6.4的`libcrypto.so.3`；公开采集入口按本机安装与工具链构建并核验对照驱动。该运行库 SHA-256 为 `4c86a7c18449bd9e9f4eb58ec39abe5afa2ceb18888a15a64fda15577bb77f61`；ELF 动态依赖为系统提供的 `libc.so.6` 和 `ld-linux-aarch64.so.1`，同用上述 Apache-2.0 许可。两平台十三种比较映像位于附件`bin/libraries-derived/{windows,arm}`，`data/comparison-images.json`逐项记录部署像、原测量像的执行等价收据和摘要。重新采集由`source/tools/export_collection_plan.py`显式接入本机OpenSSL安装并生成独立配置；随附统计复算直接读取原始样本。正常互操作的输入、结果与采集驱动版本保存在`data/verification-signing-pipeline/`，其`observations.xml`关联各组原始记录；驱动源码和重建入口位于`source/bench/complete_operations/`。路径以附件根目录为基准。

源码清单按相对路径和摘要登记代码、构建配置、说明、许可及标准向量。

## 桌面界面依赖

独立桌面宿主使用 Microsoft WebView2。SDK 1.0.4258.31 的头文件、LICENSE.txt 与 NOTICE.txt 保存在 `third_party/webview2/`；加载器与 Windows x64 固定运行时 155.0.4283.62 在软件演示程序的 `运行环境/` 目录。固定版完整保留官方文件及第三方许可查询入口。来源 URL、归档 SHA-256 和逐文件校验值记录在 `运行环境/WebView2来源.json`。这些组件用于桌面界面。
