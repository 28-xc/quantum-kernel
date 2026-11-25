# 源码构建与实验复现

本目录包含格运算内核、公共接口、平台适配、测试程序、统计方法和第三方依赖。[构建说明](docs/build.md)。

## Quantum Kernel

[启动 Quantum Kernel](<../../Quantum Kernel.exe>) · [使用说明](<../../03_复现环境与运行程序/软件演示程序/使用说明.md>)

## 工程目录

`src`、`include`、`targets` 分别保存实现、公共接口和嵌入式适配；`tests` 与 `bench` 提供功能检查和性能采集；`analysis` 与 `tools` 提供统计及构建工具。`configs`、`baselines`、`third_party` 是构建所需配置和依赖。`demo`、`examples` 分别为演示程序和完整应用示例。

`build/adapted_mlkem` 和 `build/keccak_speed` 保存构建所需源码。

## 准备复现工作区

离线复算可使用 `02_测试代码与数据/复算数据/README.md` 中的任务入口。需要自行构建或执行依赖相对路径的脚本时，在支撑材料根目录运行：

```text
python -B 02_测试代码与数据/复算数据/工具/prepare_workspace.py --package-root . --output D:/lattice-replay
```

请把示例输出路径改为包外尚不存在的目录。工具按校验清单复制文件，生成包含 `source`、`data`、`report_tools` 和 `report` 的工作区。复制完成后，从相应目录执行实验说明中的命令。

Windows 用户可使用 `03_复现环境与运行程序/软件演示程序/运行环境/python/python.exe` 代替命令中的 `python`。自建程序仍需安装相应编译工具链。

## 平台条件

Windows 构建使用匹配的 MinGW 工具链；AArch64 程序需要在 ARM Linux 设备上运行。CH32V307 构建需要 WCH RISC-V 工具链，烧录和串口测试需要连接开发板。Cortex-M4、RV32IM 仿真需要相应交叉编译器和 QEMU。具体编译选项与处理器指令要求见 [构建说明](docs/build.md) 和 [目标平台说明](targets/README.md)。

RV32 工具链在 Windows 中文路径下生成的依赖文件可能使用系统代码页。准备仅含英文字母、数字等 ASCII 字符的工作区路径后再构建，例如 `D:/lattice-replay`。

## 重建与原测量一致的程序

要复建实测固件，使用对应的源码快照和编译参数。

CH32V307 三档实测固件使用以下入口。它会在包外准备原配方所需输入、构建固件并核对 BIN/HEX，不连接或烧录开发板：

```text
python -B 03_复现环境与运行程序/firmware/CH32V307/重建冻结固件.py --package-root . --profile compact --cc <WCH编译器完整路径> --output D:/lattice-build/ch32-32k
```

64 KiB、80 KiB 固件分别选择 `partial64`、`cached`，每次指定新的输出目录。

AArch64 完整设备接入的原计时驱动包含原设备上的动态库路径。换用另一台 ARM Linux 设备时，可使用 `03_复现环境与运行程序/完整设备接入应用/AArch64/重建驱动.py --output <包外空目录>`，重新链接所保存的驱动源码与动态库。追加 `--verify-library <本机AArch64算法库>` 可执行一次不计时的完整接入检查。`--check-only` 仅检查输入和依赖，不编译或执行 ARM 程序。

实验记录中的编译器、源文件摘要和原路径用于追溯测量条件，均保留原值。当前材料的实际位置可在 `02_测试代码与数据/复算数据/路径迁移映射.xml` 中查询。离线复算用于复核已有记录；重新采集性能应另存输出，并记录实际使用的平台与工具链。
