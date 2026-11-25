# 多项式表示与签名组件验证

本目录检查矩阵缓存、低位编码、高位谓词和小系数稀疏乘法，并提供完整签名字节对照。组件探针直接包含所选源码的实际助手函数；完整操作由动态库公开接口执行。每次运行分别记录源码、构建和结果身份。

## 矩阵缓存与低位表示

```powershell
python -B tests/representation/run_probe.py --output D:/representation-checks/portable --codec 1 --cache-count 16
python -B tests/representation/run_probe.py --output D:/representation-checks/native --codec 2 --cache-count 4 --native-x86
python -B tests/representation/analyze_contracts.py --output D:/representation-checks/layout.xml
```

每次探针构建覆盖44、65、87三参数和24/32位两种缓存，共六个程序。各程序检查32个公开矩阵种子的全部系数、首次填充与后续读取、临时多项式覆盖后的缓存独立性，以及更换种子后的缓存失效；缓存读取还遍历模数范围内的全部整数。低位表示使用4,096行、1,048,576个系数，与独立逐位序列化逐项比较，覆盖极值、边界哨兵及原地压缩。

矩阵缓存保存非负模整数，有符号低位行保存中心化整数，两者分别验证。矩阵输入−1和2²⁴用于检验表示前提。地址分析穷举九种参数与编码组合，并记录ML-DSA-44采用24位低位行时与尾部SHAKE状态相交的反例。该分析对应实际字段布局与源代码结构，源码布局变更后重新运行。

缓存首次填充保存乘法前的公开矩阵系数；完整矩阵乘法结束后才设置就绪标志。临时多项式随后可用于挑战，多次外部调用分别初始化缓存。工作区核算按签名、密钥生成和验签的共同峰值进行。比较表示成本时固定缓存项数；比较等容量配置时按实际字节数匹配，例如24位四项与32位三项的系数区均为3,072字节。

## 高位谓词与提示生成

```powershell
python -B tests/representation/run_bitmap.py --output D:/representation-checks/bitmap --native-x86
```

探针覆盖三参数、两种低位编码和完整高位/非零谓词两种保存方式，比较标准高位编码、挑战哈希、重叠压缩与还原、提示生成及提示重量边界。完整高位先用于挑战哈希，随后保存提示生成所需的非零谓词；低位宽度依据严格范数检查后的整数范围确定。固定端点、固定种子和前提失效的反例共同检验这些条件。可用实际Clang路径及`--sanitize undefined`建立独立的可移植检查。

## 小系数编码与稀疏乘法

`checked_sparse_oracle.c`直接调用`lc_dsa_keycheck.h`和`lc_sparse8_blocks.h`。它构造三参数的所有编码值、全部256个系数位置及三种挑战符号分布，并与独立整数卷积逐系数比较。固定测试共24,576例、6,291,456个系数，包含合法编码和畸形编码的回退路径，同时检查输出两侧边界。

```powershell
gcc -O2 -std=c11 -mavx2 -DLC_DSA_CHECKED_SPARSE=1 -Isrc/common -Isrc/dsa_compact/build/sign_bitmap_stream_alias/adapted/src tests/representation/checked_sparse_oracle.c -o D:/representation-checks/checked-sparse.exe
D:/representation-checks/checked-sparse.exe
```

完整签名入口固定扫描秘密小系数的全部编码，并仅将编码是否合法这一聚合位用于选择计算分组。合法η=2系数按至多60项累加，部分和绝对值至多120；合法η=4系数按31项累加，界为124。畸形编码分别采用25项和11项分组，部分和界为125和121。每组扩展至16位累加，三参数的完整结果界分别为195、539和300。探针同时核对合法性判定与两种计算路径。

## 完整签名字节比较

```powershell
python -B tests/representation/check_signatures.py --left D:/build-left/latticecore.dll --right D:/build-right/latticecore.dll --count 300 --output D:/representation-checks/signatures.xml
```

两边使用相同序列化密钥、随机输入、消息和上下文，保留各自的公开调用上下文，并交替使用两组密钥。程序比较完整签名字节，执行验签和变异签名拒绝检查，保留算法自然重试；支持Windows动态库和Linux共享库。输出包括聚合哈希与构建元数据。上述组件检查与完整接口检查分别记录，性能统计使用独立的完整操作计时程序。

24位无损表示、按需生成、缓存与重算以及输出缓冲区复用均有既有研究基础。本目录验证本实现的具体数据范围、地址布局、生命周期与调用衔接；相关方法归属见`docs/signing_arithmetic.md`和`docs/signing_security.md`。
