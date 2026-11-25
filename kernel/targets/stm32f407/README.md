# STM32F407

STM32F407 使用 Cortex-M4 和 8 MHz 外部晶振。PLL 将内核时钟设为 168 MHz，USB 时钟为 48 MHz。应用将 32 个 USB 全速帧的间隔与 DWT 周期计数交叉核对。

## 常驻固件

正式演示提供 24 KiB 低内存和 32 KiB 高性能两份六参数固件，默认部署为 32 KiB。两份固件均覆盖六组参数、十八项正常操作，并保留 compact/cached 两个请求键。连接 24 KiB 映像时默认低内存策略，连接 32 KiB 映像时默认高性能策略；连接后可切换策略与参数。

正式固件与预算由[部署索引](../../../../03_复现环境与运行程序/firmware/STM32F407/固件/部署索引.xml)固定，使用方法见[运行说明](../../../../03_复现环境与运行程序/firmware/STM32F407/运行.txt)。复建入口为[24 KiB](六参数部署/代表构型/24KiB/复建.py)和[32 KiB](六参数部署/代表构型/32KiB/复建.py)。更换映像、备份和恢复见[演示软件使用说明](../../../../03_复现环境与运行程序/软件演示程序/使用说明.md)。

## 单参数实验固件构建

在可参数化格运算内核的工程根目录运行。工具链为 Windows x64 版 Clang 17.0.2（Android NDK 26.1.10909125，r487747d）和 LLD 17.0.2。Python 使用标准库。

```powershell
$env:LLVM_BIN = Join-Path $env:LOCALAPPDATA 'Android\Sdk\ndk\26.1.10909125\toolchains\llvm\prebuilt\windows-x86_64\bin'
python -B targets/stm32f407/build.py --all --output build/stm32f407
python -B targets/stm32f407/flash32.py --firmware build/stm32f407/firmware --output build/stm32f407/flash32
```

每个参数分别生成 compact、cached、reference 的 ELF、BIN、链接映射和 XML。BIN 的 SHA-256 标识完整映像。16 字节构建标识随每个板端应答返回。工作区内存大小、栈保留量、编译选项由 build.py 固定。固件还链接了大赛工程中的 NIST ACVP 公开测试数据。

compact 的 ML-KEM 矩阵按单行计算，cached 改为两行。ML-DSA 对应签名路径分别重算矩阵、缓存最多四个展开多项式。reference 使用工程已有的 PQClean 可移植 C 实现、公开 API 的参数与对象检查，以及单线程 SHAKE 固定块内存池。ML-DSA-65/87 参考固件把完整公开矩阵与三个多项式向量分配到不同存储区，保留上游算术和拒绝采样步骤。两组公开向量的期望输出按完整字节的 SHA3-256 比较，其余固件按原始字节比较。

## 单参数固件运行

开发板使用板载 USB 数据口。BOOT0 接 3V3 后复位可进入片上 ROM。Windows 的 DFU 设备使用 WinUSB。关闭正在占用该板的编程器。主机先逐块写入 SRAM，读回完整映像，再启动 USB CDC 应用。USB 请求只包含公开挑战、参数、长度和预算。应用返回执行码、周期、工作区峰值及构建标识。应用收到返回指令或空闲约 90 秒后，软断开 USB 并在 BOOT0 为高时复位回 ROM。

```powershell
python -B targets/stm32f407/engine.py devices
python -B targets/stm32f407/engine.py run --param 512 --strategy compact --images build/stm32f407/firmware
python -B targets/stm32f407/engine.py kat --param 87 --strategy cached --images build/stm32f407/firmware
python -B targets/stm32f407/engine.py run --param 87 --strategy compact --mode insufficient --images build/stm32f407/firmware
python -B targets/stm32f407/engine.py dfu
```

默认使用 STM32 硬件随机源。正式配对测量显式选取公开确定性测试输入。ML-KEM 修改密文后检查共享秘密发生变化，ML-DSA 修改签名后检查拒绝码。显示的公开输出校验值用于配对核对，不含密钥或共享秘密。

## 单参数固件采样

```powershell
python -B targets/stm32f407/collect.py --images build/stm32f407/firmware --output measurements/stm32f407 --blocks 32 --batch-size 8
python -B targets/stm32f407/paired.py measurements/stm32f407
python -B targets/stm32f407/timing.py --images build/stm32f407/firmware --output measurements/stm32f407-timing --blocks 128 --params 512 44 --strategies compact cached
```

collect.py 记录每次请求的 256 字节板端应答和固件哈希。每个参数、区组使用相同的公开输入，三种实现按批次改变运行顺序。测量窗口围绕一个密码 API 调用，包含该调用的随机回调和内部清理。USB、主机调度、输出比较和额外擦除检查位于窗口外。栈峰值按填充值检查，链接器的栈保留量另列。paired.py 对有共同区组的逐项比值及同块 18 项等频总和复算中位改善幅度与 95% 百分位区间。单位为微秒时按板端时钟换算。timing.py 保留固定和变化输入的原始周期及返回帧，同一块内打乱两类输入次序。

SRAM 执行构型计入代码、标准向量、数据、USB、操作输入输出、工作区、栈及保护区。32 KiB 构型从 Flash 运行，完整可写对象由链接器限制在独立的 32 KiB SRAM 内。flash32.py 仅链接低内存构型。flash32check.py 用于已经写入、经独立读回并正在运行的对应固件。Flash 链接地址缺省为 0x080E0000，可通过 --address 设置为板上独立的 128 KiB 扇区。

USB 协议编号 1209:0001 来自 pid.codes 的私有原型测试编号。应用通过芯片 UID、构建标识和实时请求校验识别硬件。交付硬件产品时需要获授权的 VID/PID。USB 协议栈源文件、提交版本及许可见 vendor/libopencm3。

