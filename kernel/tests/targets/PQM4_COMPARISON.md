# Cortex-M4 同目标内存比较

基线使用 pqm4 的 ML-DSA `m4fstack` 路径，锁定 pqm4 提交 `5e5cc76d0b072ee7077e58afcbc619a1a67a53b4` 和 mupq 提交 `ddcccedb2db9d0250856bd58ee5c46c61e506c5d`。公开索引逐项给出实际编译输入的 SHA-256。上游 NTT、点乘、采样与 Keccak 汇编保留原实现；本项目两配置采用其可移植内核。

`fetch_pqm4.py --output 新目录` 显式获取上述上游版本并保留根目录说明及逐文件版权/许可。上游将许可按具体实现和文件组织；`common/keccakf1600.S` 使用其 CC0 声明，相关小模数 NTT 文件保留 Apache-2.0 头部。引用与归属应按照所用文件记录，避免把整个比较源树标成单一许可。

Linux 环境使用 `arm-none-eabi-gcc` 和 `qemu-system-arm`：

```text
python tests/targets/pqm4_compare.py --pqm4 上游目录 --output pqm4_memory --opt Os
python tests/targets/pqm4_compare.py --pqm4 上游目录 --output rate_memory --opt Os --core-profile rate --core-build 已生成的m4-rate目录
python tests/targets/pqm4_compare.py --pqm4 上游目录 --output row_memory --opt Os --core-profile recompute --core-build 已生成的m4-recompute目录
```

三实现均在 `mps2-an386/cortex-m4` 执行，相同 `Os`、目标 ABI、测试输入序列和 16 KiB 测试栈。每参数有 4 个标准向量/拒绝检查，以及 24 组完整生成、签名和验证，共 76 条操作记录；三参数共有 228 个配对输入。每个固件从同一测试随机状态开始，按同一次序消耗随机字节。144 个生成公钥/签名对象逐字节对齐，所有返回码与熵请求同时对齐。

算法观察内存为工作区、最大观察栈、上下文及持续可写对象之和。另表保留完整栈预留、输入输出、保护区、代码/常数和测试向量组成的映像占用。项目比较固件由六参数对象链接，链接器实际保留 ML-DSA 三操作及大小/上下文入口；每个映像的最终入口列表随符号证据给出。用于验证完整六参数移植的 117 例固件另行提供。

原始 ELF、完整串口输出、符号、内存账本和链接脚本位于 `m4_comparison` 数据集。离线检查使用 `tests/targets/recompute_comparison.py`。本实验记录功能与空间。
