# Quantum Kernel

面向资源受限设备的 ML-KEM / ML-DSA 可参数化格运算内核。支持 FIPS 203 / 204 的六组参数与 18 项完整密码操作，提供统一 C 接口、按工作区预算配置的实现，以及用于本地测试的 Quantum Kernel 交互界面。

| 目录 | 内容 |
| --- | --- |
| [kernel](kernel/) | C 接口、多项式算术、ML-KEM / ML-DSA、构建和测试代码 |
| [kernel/targets](kernel/targets/) | STM32F407、CH32V307 和模拟目标的适配代码 |
| [workbench](workbench/) | 交互界面与本地服务，含公开源码版启动入口 |

## 从源码构建

需要 Python 3.10+、CMake 3.24+、Ninja 和 GCC 工具链（Windows 使用 MinGW-w64）。从仓库根目录执行命令。

~~~sh
cmake -S kernel -B ../qk-out -G Ninja -DLC_CONFIGURATION=compact-rate -DLC_BACKEND=portable
cmake --build ../qk-out
~~~

构建会生成库并运行覆盖六组参数的功能探针。CMake 输出会显示本次的构建目录，artifacts 子目录内有动态库和构建记录。C API 与工作区用法见[内核说明](kernel/README.md)。

平台专用 Windows x86-64 / Linux AArch64 构建见[构建说明](kernel/docs/build.md)。其中原生 x86 后端需要对应 CPU 指令支持。

## 打开交互界面

在 Windows x86-64 或 Linux AArch64 上，将下面的 dll 或 so 路径替换为实际构建产物。Windows 的文件名为 latticecore.dll，Linux 的文件名为 liblatticecore.so。

~~~sh
python -B workbench/launch.py --library path/to/latticecore.dll --output ../qk-run
~~~

用浏览器打开 <http://127.0.0.1:8134/>。也可用 --performance-library 指定第二个构建的动态库。公开启动入口使用本机动态库，支持本机密码操作和测试。开发板部署、专用算术诊断产物及参赛档案需要相应固件或原部署配置。历史比赛启动代码在 [workbench/competition](workbench/competition/) 中供阅读。

## 开发板与许可证

- STM32F407 支持 24 / 32 KiB 配置，CH32V307 支持 28 / 80 KiB 配置。参阅[板端源码与构建说明](kernel/targets/README.md)和[板端依赖](BOARD_DEPENDENCIES.md)。
- 团队原创部分采用 [Apache-2.0](LICENSE)。第三方代码保留各自的文件头和许可。各组件出处见[第三方说明](NOTICE.md)及[依赖索引](kernel/docs/sources_and_licenses.md)。
