# 完整操作实验重放

公开入口 `bench/complete_operations/` 覆盖六组参数的十八项操作。`prepare.py` 编译调用驱动，核验实际库与OpenSSL版本并执行功能检查；`collect.py` 根据技术配置运行完整随机区组。

```text
python bench/complete_operations/prepare.py --boundary serialized --library <算法库> --crypto-library <libcrypto> --crypto-prefix <OpenSSL目录> --expected-version 3.6.4 --output <新准备目录> --cpu <处理器编号>
python bench/complete_operations/collect.py --configuration <技术配置.xml> --output <新结果目录> --blocks-per-invocation 5
```

`serialized`从序列化密钥开始，每次包含密钥导入、上下文、算法、输出与释放。`reused`模式在批内保留OpenSSL密钥对象，各次仍建立操作上下文；本作使用序列化密钥接口。两种模式的密钥生成均包含完整输出编码，结果分别汇总。

技术配置列出驱动、库路径、实际版本、处理器、区组数、样本数、预热、种子、消息与上下文长度，并为每个实现指定工作区。完整示例和字段说明见 `bench/complete_operations/README.md`。十三种实现的主要操作实验采用20个区组、每格500次正式调用与20次预热；其他实验按各自协议登记的区组数、样本数和调用边界执行。

每个区组随机排列参数和操作，再随机排列同一单元中的实现；相同单元使用同一输入序列。采集器核对输入输出摘要、熵输入、CPU绑定、容量与库身份，逐行保留全部预热、慢样本和返回值。

可在完整区组结束后分批运行。恢复时使用同一配置和目录并添加 `--resume`，入口先核对已完成任务、原始文件及全部摘要，再继续未完成区组。失败或中断的输出保存在对应记录中。

Windows使用实际 `.dll` 与 `.exe`，AArch64使用本机 `.so` 与可执行程序。各平台以本平台相同条件的对照计算比值，编译、采样、压缩和其他负载与正式计时分开。

工作区容量与完整算法内存分别记录。PQClean适配保留其自身堆栈方式，资源探针另测栈、相关堆峰值、上下文和可写存储。完整操作时间、资源和程序空间以同一库摘要关联。

归档统计的复算入口读取观察清单、原样CSV和统计摘要，重新计算全部非预热样本的分布及配对区组区间。新采集使用新的配置、文件摘要和输出目录；已有数据仍按其原始采集器身份复算。
