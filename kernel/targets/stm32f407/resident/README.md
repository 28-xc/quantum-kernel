# STM32F407 常驻固件

在源码根目录运行。使用 Windows x64 的 LLVM 17.0.2（Android NDK 26.1.10909125）和 Arm GNU Toolchain 13.2.rel1 的汇编器。可通过 LLVM_BIN 与 ARM_AS 指定路径，也可传入 --llvm-bin、--arm-as。输出目录位于支撑材料之外。

~~~powershell
py -3 -B targets/stm32f407/resident/build.py integrated-28 --output ..\..\..\F407构建
~~~

| 构型 | 高速28 integrated-28 | 独立算术28 independent-28 | 高速32 integrated-twist |
|---|---:|---:|---:|
| 完整 SRAM（字节） | 28504 | 28504 | 32568 |
| Flash（字节） | 220580 | 212132 | 220580 |
| 预留栈（字节） | 3328 | 3328 | 3328 |

每套映像均包含六组参数、两种运行策略。构建程序按照 inputs.tsv 从当前工程读取源码，在临时目录展开参数与存储配置，输出 BIN、ELF、MAP 及逐项重建记录。独立算术构型增加 --project-polynomials-only 时，仅保留项目的多项式组件，生成同一板端 BIN。来源、调度与工具链见[完整源码构建](完整源码构建.md)。
