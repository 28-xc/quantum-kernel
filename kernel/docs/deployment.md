# 按功能与资源预算生成程序

`tools/deploy.py` 接收目标平台、必需参数、操作集合及字节预算，调用统一构建入口，检查实际链接映像并运行标准向量和接口恢复测试。输出包含库、测试程序、能力头文件、资源明细与构建记录。

```text
python tools/deploy.py --request examples/deployment/client-windows-x86_64.xml --output ../deployment/client
python tools/deploy.py --request examples/deployment/pair-m4.xml --output ../deployment/pair-m4
```

输入的 `parameters` 列出全部必需参数；`operations` 为每个参数给出操作名。ML-KEM 使用 `keypair`、`encaps`、`decaps`，ML-DSA 使用 `keypair`、`sign`、`verify`。生成器据此裁剪参数实例和内部操作调度。公共八个接口保留，裁去的标准参数或操作返回 `LC_E_UNSUPPORTED`。无效参数返回 `LC_E_ARGUMENT`。

示例分别保留六组参数、ML-KEM-768 与 ML-DSA-65、以及接入方所需的 ML-KEM-768 封装与 ML-DSA-65 验签。第三种程序直接使用外部公钥、密文及签名，测试输入来自随包固定 NIST 向量；其构建无需额外保留密钥生成和签名实现。输入输出缓冲区按所选操作的实际长度生成。

`recipes` 给出有序的合法配置集合，最多四项。工具逐项构建并选择满足全部预算的首项；所有要求均写入结果。默认集合为 `compact-rate`、`compact-recompute`，默认工作区为 12288 字节。显式设置 `workspace_bytes` 可使用其他已知的合法容量。实际程序执行后记录分配峰值、清理结果及完整输出比对；源码、编译输入、映像和日志均保存 SHA-256。

## 预算口径

本地演示的“资源配置”页提供同一构建流程。选择目标平台、参数、操作、程序与内存上限后，点击“编译并验证”；完成后可下载程序包及本次资源结果。界面按本机已安装工具链列出平台，并检查当前原生配方所需的 CPU 指令与操作系统扩展状态。当前 x86-64 原生配方需要 AVX、AVX2、BMI2、AVX-VNNI 及 XMM/YMM 状态保存；AArch64 原生配方需要 FP/ASIMD。可移植配置使用标准 C 路径。界面构建一次最多运行十分钟，结果保存在源码目录外的 `deployment-runs`。源码中保留命令行入口，目标交叉编译器与 QEMU 安装后即可使用相同请求生成嵌入式程序。

“资源上限查询”根据归档测量选择已测配置；“按功能生成目标程序”按当前功能约束生成新映像，并显示其实际资源。新生成程序的功能与资源记录独立保存。

构建输出可放在任意可写的新目录中，并须位于源码树之外。输出目录已存在时，工具保留其内容并要求指定新的目录。

| 平台 | `program_bytes` | `ram_bytes` | 其他约束 |
|---|---|---|---|
| Windows x86-64 / Linux AArch64 | 静态验证程序的已分配只读节与初始化数据 | 同一程序全部可写节 | 池、输入输出、上下文和 65536 字节合法调用栈均已包含；宿主操作系统、装载器与控制线程另列 |
| Cortex-M4 / RV32 | 代码、只读常量及初始化数据装载副本 | 完整仿真程序的已占用 RAM | `writable_ram_bytes` 单独限制可写区；两个目标的代码也映射到 RAM |

目标程序的 `.data` 初始化副本在代码装载区，运行副本在可写区，两者占据不同地址。工作池、调用方缓冲区、测试栈和控制栈各有独立区间，均在可写区内计数一次。链接映像逐节核验区间归属和对齐；目标程序使用静态所有者与工作池，堆空间为零。向量与期望结果常量的字节数单独保存在 `vectors.xml`。

目标构建使用代码区、可写区、总占用三条链接断言。启用 `boundary_checks` 后，以同一组目标对象重新链接五个预算：精确容量、代码少一字节、可写区少一字节、总占用少一字节、放宽容量。三个不足配置在链接阶段结束；精确及放宽配置执行相同功能检查。密码测试均在合法栈容量下运行。

`deployment/` 中的 `deployment_capabilities.h` 为每个标准参数和操作给出 0/1 宏，`requirements.json` 与 `resources.xml` 对应实际选定程序。完整重建和审计时保留输出目录中的计划、对象、生成源、日志、向量与结果记录。

## 局部生命周期检查

```text
python tools/check_lifetimes.py --build ../deployment/client/configuration-0/artifacts/core --output ../deployment/layout-check
```

检查器从实际 ML-DSA 编译命令保留特征宏和后端条件，以真实类型的 `sizeof`、对齐及布局常量枚举每一行的读取、紧凑存储、哈希吸收及尾部复用区间。结果包含源码顺序与释放位置、编译出的尺寸以及每阶段的地址区间。一个纯地址模型中的重叠布局用于验证检查器会拒绝冲突；检查范围为所声明的行压缩与哈希生命周期。
