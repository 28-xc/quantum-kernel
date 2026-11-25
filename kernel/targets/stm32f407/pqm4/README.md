# Cortex-M4 实现

对照组使用 pqm4 的 ML-KEM 与 ML-DSA m4fstack 路径。六个映像按同一 USB 接口、DWT 区间、168 MHz 时钟和 SHA-256 读回过程运行。每组参数使用与作品一致的 NIST ACVP 输入和期望字节，随机数由同一批测试回调供给。m4fstack 保留上游 NTT、点乘、矩阵、采样和编码实现。项目 API 外层执行长度、别名、随机数和标准对象检查。

pqm4 提交为 5e5cc76d0b072ee7077e58afcbc619a1a67a53b4，mupq 提交为 ddcccedb2db9d0250856bd58ee5c46c61e506c5d。vendor/来源.tsv 记录原仓库路径、符号链接解析位置及文件 SHA-256。各文件保留原许可证。 [pqm4](https://github.com/mupq/pqm4/tree/5e5cc76d0b072ee7077e58afcbc619a1a67a53b4) · [mupq](https://github.com/mupq/mupq/tree/ddcccedb2db9d0250856bd58ee5c46c61e506c5d)

从工程根目录运行。C 编译器和链接器与 STM32F407 作品固件一致，手写汇编使用 GNU as 2.41.0.20231009（Arm GNU Toolchain 13.2.Rel1）。ARM_AS 指向该工具链中的 arm-none-eabi-as.exe。

```powershell
python -B targets/stm32f407/pqm4/build.py --output build/pqm4-stm32f407
python -B targets/stm32f407/engine.py kat --images build/pqm4-stm32f407/firmware --param 87 --strategy m4fstack
```

m4fstack 的手写汇编会使用 Cortex-M4F 的指令或将浮点寄存器用为暂存。代码通过 CPACR 使能相应寄存器。固定块栈预留为 16 KiB，Flash 执行构型另按链接映射统计工作区、栈、输入输出及 USB 数据。

## Keccak 位交织对照

独立构型保留作品原有的缓存、矩阵生成和多项式算术，替换 Keccak 状态的 XOR、Extract 和 Permute 三个入口。汇编来自 pqm4/common/keccakf1600.S，原文标注 CC0，采用小端 ARMv7-M 整数指令。SHAKE128/256 的空输入、速率边界、跨块输入和输出按字节与 Python hashlib 核对。ML-DSA 的增量接口还分别检查分段吸收和分段挤出。ML-KEM-512 和 ML-DSA-87 各取三个公开输入作时钟周期对照。

```powershell
python -B targets/stm32f407/pqm4/build_keccak.py --output build/stm32f407-keccak --params 512 87
python -B targets/stm32f407/pqm4/check_keccak.py --images build/stm32f407-keccak/firmware --baseline-images build/stm32f407/firmware --output measurements/keccak --params 512 87 --samples 3
```


