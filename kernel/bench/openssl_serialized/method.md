# OpenSSL 与公共序列化接口的同输入驱动

本比较固定 OpenSSL 3.6.4，并同时提供对应的实际库、头文件与构建记录。Windows/Linux 使用相同明确 tag。

此工具覆盖 ML-KEM-512/768/1024 的密钥生成、封装、解封装，以及 ML-DSA-44/65/87 的密钥生成、签名、验签，共 18 项。两个实现共用同一个 C 驱动、输入序列、计时位置与原始数据格式。

## 计时边界

每次操作的输入输出均为 FIPS 203/204 序列化字节。本作每次执行 `lc_context_init` 和对应公共入口；调用者预先保留 workspace，接口内部的分配、擦除和回收照常执行。OpenSSL 每次创建新的操作上下文；封装、解封装、签名、验签均从 `pub`/`priv` 字节新导入 EVP key，操作结束释放 key 与上下文；密钥生成还包括导出完整 `pub`/`priv` 字节。上述工作全部在该次计时内。没有在计时外跨调用缓存已展开的 A 矩阵或私钥 NTT 对象。

进程初始化的库装载、default provider 装载、显式算法 fetch、计时器频率查询、CPU 绑定与验证不计入每次操作。每次 EVP 上下文构建所发生的内部缓存查找仍计入。驱动使用私有 `OSSL_LIB_CTX`、显式 `provider=default`，同时核对 keymgmt 和 KEM/signature 的 provider 名，要求显式 expected-version，拒绝头文件或实际库版本不符（当前支持 3.6.4、3.6.4）。Windows 根据实际导入地址解析 libcrypto 模块，Linux 使用 `dlsym`/`dladdr`；Python 入口核对实际路径与指定库 SHA，避免 PATH 上另一个版本静默混入。

ML-KEM 的原生 OpenSSL key 对象保存完整矩阵，故导入不能被移出此序列化边界。私钥导入还具有可选 PCT：固定版本 [`ml_kem_kmgmt.c.in`](https://github.com/openssl/openssl/blob/openssl-3.6.4/providers/implementations/keymgmt/ml_kem_kmgmt.c.in) 在解析成功后执行 `ml_kem_pairwise_test`；其 [`key 文档`](https://github.com/openssl/openssl/blob/openssl-3.6.4/doc/man7/EVP_PKEY-ML-KEM.pod) 指定默认 random，可显式选择 none。驱动分别记录两个模式，不合并其时间：

| 模式 | 计入的 OpenSSL 私钥导入工作 | 解释 |
|---|---|---|
| `random` | 解析、矩阵展开、检查、随机 PCT 与其 RNG | 保留默认额外服务，不能把全部差异解释为内核优化 |
| `none` | 解析、矩阵展开及必要编码/哈希检查 | 只关闭可选 PCT，仍保留实际导入成本 |

源代码 [`parse_prvkey`](https://github.com/openssl/openssl/blob/openssl-3.6.4/crypto/ml_kem/ml_kem.c) 的私钥系数解析、公钥规范编码和 H(pk) 检查位于 PCT 之前，none 不关闭这些路径。驱动还实际验证 H(pk) 篡改和公钥系数 4095 被拒绝，以及规范编码但密钥两部分不一致时 none 接受导入、random 拒绝，从而检查配置确实生效。valid-input 测量包含 OpenSSL 的全部实际检查。

ML-DSA 固定 `message-encoding=1`、`mu=0`、相同 context 与完整消息，不使用预计算 mu。此含义来自固定版本 [签名参数文档](https://github.com/openssl/openssl/blob/openssl-3.6.4/doc/man7/EVP_SIGNATURE-ML-DSA.pod)。自然拒绝循环保持实现原样，不能固定重试次数。

OpenSSL 3.6.4 的 [ML-DSA 原始私钥导入](https://github.com/openssl/openssl/blob/openssl-3.6.4/crypto/ml_dsa/ml_dsa_encoders.c)还会[重建公钥和 t0](https://github.com/openssl/openssl/blob/openssl-3.6.4/crypto/ml_dsa/ml_dsa_key.c)，并核对 tr；本作签名入口不执行同样全面的私钥内部一致性检查。主测量比较公开序列化接口的完整服务成本；导入、操作与释放另作分项诊断。

## 输入与样本

测试种子驱动独立于库随机状态的固定字节序列。生成密钥输入 64 B（KEM）或 32 B（DSA）；封装和签名输入 32 B。本作回调在计时内复制这些字节，OpenSSL 在计时内通过 `seed`、`ikme` 或 `test-entropy` 参数接收同值。正常算法输入随机字节在计时外生成；这不是包含 OS RNG 的业务端到端时间。random PCT 内额外调用的库 RNG 则明确留在计时中，并单独标识。

`workspace_observed_test_highwater` 记录输入准备和字节对照时本作上下文的工作区水位；OpenSSL 的堆、栈与完整 RAM 由独立资源实验测量。

验签/解封装每个样本使用新生成的有效签名/密文；生成输入在计时外，输入准备的随机序列和操作实际消费熵分别记录。消息、context、entropy 的 SHA-256 与 `case_id` 逐行记录，整批输入/输出散列必须在两实现及两个 PCT 模式间一致。测试生成的私钥与随机字节不写入 CSV 或日志。缓冲区在退出路径清除。

Windows 使用 QPC，并要求显式指定的逻辑核通过 P 核检查；Linux 使用 CLOCK_MONOTONIC_RAW 和显式 sched_setaffinity。操作前后检查当前 CPU。每行保留原始 ticks、频率、ns、状态与 warmup 标记，不截尾、不删慢样本。默认正确性模式不调用样本计时器，时间列留空。计时模式在计时区外做最终字节核对；每次状态与 workspace 两侧 canary 都必须通过。任何失败保留部分 CSV、命令、标准输出/错误和 failure.json，不能作成功样本跳过。

## 使用

Windows 示例（全部输出为新的 D 盘目录）：

```powershell
py -3.13 -B bench/openssl_serialized/run.py --library D:/build/compact/latticecore.dll --crypto-library OPENSSL_PREFIX/bin/libcrypto-3-x64.dll --crypto-prefix OPENSSL_PREFIX --expected-version 3.6.4 --cpu 0 --mode verify --count 100 --output D:/lattice-check/openssl-verify
```

Linux 示例（固定版本库及头文件在同一 prefix）：

```sh
python3 -B bench/openssl_serialized/run.py --library /path/build/compact/liblatticecore.so --crypto-library /opt/openssl-3.6.4/lib64/libcrypto.so.3 --crypto-prefix /opt/openssl-3.6.4 --expected-version 3.6.4 --cpu 0 --mode verify --count 100 --output /path/new/openssl-verify
```

实际逻辑核必须属于该任务允许的 CPU 集合，不能照抄示例中的 0。`--mode sanity --count 10 --warmups 5` 仅检查计时链路，产物明确不是正式比较；`--mode collect` 仅采原始值，正式轮次、块顺序、留出数据和统计由上层冻结规则控制。可选参数包括 `--message-bytes`、`--context-bytes`、`--workspace`、`--seed`、`--parameters`、`--operations`。默认顺序只用于正确性/健全性检查，不应把未随机化的顺序运行自动当作正式实验。

输出含 driver/入口/头文件/本说明的源码副本与 SHA、实际编译器、目标、两个库 SHA、实际模块路径、CPU/计时信息、全部 CSV 和逐块结果。`tests.py` 提供原始样本校验器的缺行、状态、身份、时间及计时模式负例，并可对已构建驱动验证拒绝覆盖原始文件和非法参数。

## 独立分项诊断

`diagnose.py` 只重放已经通过正确性检查的完整输入矩阵，使用单独的 `diagnostic.c`，不修改 `driver.c` 的主计时函数。它记录 OpenSSL 的原始密钥导入、操作上下文建立及初始化、算法调用、密钥字节导出、上下文及密钥释放五段，并在同一行记录本作完整公开入口。两个实现先后顺序按样本奇偶交替。该顺序只用于诊断，不是正式随机区组设计。

密钥生成没有已序列化密钥输入，因此 import 为明确不适用的零区间。封装、解封装、签名和验签没有独立的 EVP 密钥导出调用；其输出编码仍在 operation 中，export 同样明确不适用。import 包括 `fromdata` 内部使用的导入上下文创建、检查和释放；setup 另计后续操作上下文。相邻阶段使用连续时间戳，阶段 tick 之和必须严格等于 OpenSSL 总 tick。计时器调用和分段造成的扰动不扣除，因此该分段总量不能替代主时间序列；各段中位数也不保证相加等于总量中位数。

每次诊断输出既与本作输出比较，也在计时外与未改动的 OpenSSL 主调用函数比较。逐行输入身份和整批输入、输出 SHA 必须与原正确性记录一致；两个库 SHA、实际加载路径、CPU、PCT 模式也再次核验。该模式将私钥检查和密钥导入保留在每次调用中，以 `phase_diagnostic_only_not_formal` 标识阶段诊断数据。完整操作性能使用独立计时记录。

```powershell
py -3.13 -B bench/openssl_serialized/diagnose.py --verify-evidence D:/lattice-check/openssl-verify --crypto-prefix OPENSSL_PREFIX --cc gcc --output D:/lattice-check/openssl-phases
```

Linux 使用相同入口和已安装的同版本 prefix。`diagnostic_tests.py` 对原始阶段加和、输入身份、缺失/重复记录、不适用阶段以及实际命令行拒绝路径作负面自检。它不采集有效操作的性能数据。

示例中的 `OPENSSL_PREFIX` 为本机 OpenSSL 3.6.4 安装目录；头文件和导入库用于重新编译对照驱动。已编译的驱动与运行库随支撑材料保存。
