# 目标平台

[STM32F407 实板](stm32f407/README.md) · [CH32V307 实板](ch32v307/README.md)

## Cortex-M4 / RV32 仿真

目标由本源码树的可移植紧凑七个编译单元、八入口接口和独立运行时组成。默认固定低位编码 `codec 1`，矩阵与秘密前缀缓存均为零。`LC_DSA_W0_CODEC=0/1/2` 分别选择原编解码、固定 19/20 位组、仅 65/87 的 24 位布局。每次构建记录所用源码、选项、工具、ELF、链接映射和向量哈希；更换目标或配置会产生新的二进制身份。

## 执行

在安装交叉编译器和 QEMU 的 Linux 主机，将整个源码树放入独立目录。示例的输出目录必须尚不存在：

```sh
python3 -B tools/build_targets.py --target m4 --codec 1 --run --output <新的m4目录>
python3 -B tools/build_targets.py --target rv32 --codec 1 --run --output <新的rv32目录>
```

Windows 上的构建产物写入 D 盘，例如 `--output D:/target-results/m4-codec1`。`--codec 0` 和 `--codec 2` 用于相同目标下的表示对照。省略 `--run` 只编译，状态为 `BUILD_ONLY`。工具未安装、链接溢出、用例失败或执行超时均保留实际退出码与日志。

工具需求：`arm-none-eabi-gcc` 及配套 `nm/size`，或具有真实 `rv32im/ilp32` multilib 的 `riscv64-unknown-elf-gcc` 及配套工具；QEMU 的 `qemu-system-arm` / `qemu-system-riscv32`。M4 使用 `mps2-an386`、软浮点 ABI；RV32 使用 `virt`、RV32IM/ILP32。RV32 编译按 ISA 2.2 解释 I 内的 CSR 指令，保持 RV32IM 库选择，不引入 RV64 运算库。C 启动代码不需要 newlib，内存函数由独立运行时提供，整数辅助运算来自对应目标的 libgcc。

## 检查范围

构建时从已锁定的 NIST ACVP 数据提取 21 条用例：每组参数的三个公开操作各一条，共 18 条；另有三个 ML-DSA 拒绝签名。签名只选 external/pure 接口及显式随机数输入，不包含 HashML-DSA 或 internal-mu。选择规则和原文件哈希见生成的 `vectors.xml`，完整期望字节保存在只读常量中。该子集用于目标 ISA 的功能一致性检查。

每个正向量另检查长度不足、合法对象重叠、工作区不足，并恢复同一个 context 再执行原向量。取随机数的 12 个操作另检查失败 callback 和未提供 callback 的错误码、标准输出范围清零。所有运行只使用测试向量明确给出的熵，系统随机源桩对非零请求一律失败。实际设备由应用提供可靠的随机源回调。

代码还检查工作区和输出缓冲区两侧哨兵、独立测试栈底 32 字节哨兵，并提供故意改写栈水位区的阳性控制。这组检查覆盖上述输出、工作区外缘和独立测试栈边界；内部子对象和秘密数据访问由对应的其他检测方法分析。

## 内存口径

每次公开操作通过独立汇编 trampoline 切换到测试栈；控制循环和打印使用另一个保留栈。切换遵守 AAPCS / RV32 psABI 的被调用者保存寄存器和栈对齐。栈预填 A5，返回控制栈后扫描最低被修改字节。该水位包括公开调用适配层，表示本次输入路径改写的预填区域；保持 A5 的写入和其他输入路径属于其观测边界。整镜像内存按**完整测试栈保留量**计算，水位另列为运行观察。

默认 writable 链接窗口为 65,536 字节，arena 容量 24,576 字节、测试栈 16,384 字节、控制栈 2,048 字节；真实使用及剩余空间由 ELF 和运行时共同报告。所有六参数使用同一固定工作区容量。输出 IO、哨兵、context、普通静态数据、arena 和两种栈分别计数；arena/IO 从普通 bss 统计中扣除后分别计入一次；动态堆用量为 0。改变容量必须创建新目录并保留原失败结果。

AN386 和 RISC-V virt 在本 QEMU 配置中都将执行映像/只读向量置于模拟 RAM。因此同时给出：

- `writable_image_span_bytes`：可写区域全部预留量，包括 IO、arena、两种栈、对齐间隙；
- `code_and_rodata_load_bytes`：代码、只读向量和 data 初值映像；
- `emulator_image_occupied_ram_bytes`：上述两个映像占用的和。

可写数据、代码与只读映像分别列示，并给出此仿真内存映射下的总映像占用。实物部署还需核对 Flash 布局，计入外设、RTOS、中断嵌套、驱动缓冲等整机项目及安全余量。

## 结果文件

`build.xml` 绑定来源和产物；`commands.xml` 保留每个命令/返回码/日志；`memory_ledger.xml` 来自最终 ELF 符号；`qemu_console.txt` 和 `checks.xml` 保留每个用例的错误码、arena 水位与栈水位。本入口采集功能与映像资源。

目标硬件定义核对来源：

- [QEMU MPS2/AN386 文档与模型](https://github.com/qemu/qemu/blob/v6.2.0/hw/arm/mps2.c)。
- [Arm AN386](https://documentation-service.arm.com/static/5ed1094dca06a95ce53f8a9f)。
- [QEMU RISC-V virt 文档](https://www.qemu.org/docs/master/system/riscv/virt.html)及 [v6.2.0 virt 模型](https://github.com/qemu/qemu/blob/v6.2.0/hw/riscv/virt.c)。

代码/算法的原有上游许可证继续适用；本目录只提供本项目独立的测试启动、运行和检查代码，不替上游重新授权。
