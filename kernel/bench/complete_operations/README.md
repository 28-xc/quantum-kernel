# 完整操作的配对测量

本入口支持两种服务边界。`serialized` 在每次调用中处理序列化密钥，计时包括准备、密码操作、编码和调用结束时的清理。`reused` 由 OpenSSL 在批次内保留已导入的密钥，每次创建操作上下文；本作使用序列化密钥接口。两种模式的密钥生成均包含输出编码，结果按模式分别统计。

`prepare.py` 直接编译 `bench/openssl_serialized/driver.c` 或 `bench/openssl_reused/driver.c`，保存实际源码、编译命令与二进制 SHA256，并以全部六参数十八操作核对功能。`collect.py` 绑定该准备结果，随后执行确定的完整随机区组。

```text
python bench/complete_operations/prepare.py --boundary serialized --library PATH_TO_CORE --crypto-library PATH_TO_LIBCRYPTO --crypto-prefix OPENSSL_PREFIX --expected-version 3.6.4 --output NEW_PREPARED_DIRECTORY --cpu CPU_NUMBER
python bench/complete_operations/collect.py --configuration TECHNICAL_CONFIGURATION.xml --output NEW_RESULT_DIRECTORY --blocks-per-invocation 5
python bench/complete_operations/collect.py --configuration TECHNICAL_CONFIGURATION.xml --output SAME_RESULT_DIRECTORY --blocks-per-invocation 5 --resume
```

准备阶段使用 `--boundary reused` 即选择第二种边界。配置为以下技术字段，路径由复现机器的实际文件位置填写：

```xml
<record format="typed-xml-v1"><object><field><name>driver</name><string>PREPARED_DIRECTORY/driver</string></field><field><name>prepared</name><string>PREPARED_DIRECTORY/prepared.xml</string></field><field><name>crypto_library</name><string>OPENSSL_LIBRARY</string></field><field><name>boundary</name><string>serialized</string></field><field><name>expected_version</name><string>3.6.4</string></field><field><name>cpu</name><integer>2</integer></field><field><name>blocks</name><integer>30</integer></field><field><name>samples</name><integer>400</integer></field><field><name>warmups</name><integer>20</integer></field><field><name>seed</name><integer>2026092701</integer></field><field><name>message_bytes</name><integer>1024</integer></field><field><name>context_bytes</name><integer>0</integer></field><field><name>configurations</name><list><object><field><name>label</name><string>portable-low</string></field><field><name>library</name><string>REFERENCE_LIBRARY</string></field><field><name>provider</name><string>lattice</string></field><field><name>pct</name><string>none</string></field><field><name>workspace</name><integer>21120</integer></field></object><object><field><name>label</name><string>portable-minimum</string></field><field><name>library</name><string>CANDIDATE_LIBRARY</string></field><field><name>provider</name><string>lattice</string></field><field><name>pct</name><string>none</string></field><field><name>workspace</name><integer>8128</integer></field></object></list></field></object></record>
```

示例配置中的容量用于说明字段；正式复现以数据集记录的实际配置、二进制 SHA256 和工作区容量为准。加入 OpenSSL 对照时使用 `provider: "openssl"`，同时明确 `pct: "none"` 或 `"random"`。Windows 的可执行文件名为 `driver.exe`。

每区组先随机排列十八个参数—操作组合，再对各组合随机排列实现。组合种子采用 `SHA256(master_seed/block/parameter/operation)` 的前八字节，以原有整数映射得到；同组合各实现使用同一输入。每个批次核对实际输入和输出序列摘要、熵输入身份、CPU 绑定、消息和上下文长度、导入校验模式、工作区容量及实际加载的 OpenSSL 文件。

全部预热行和测量行逐条保留。统计以完整区组为重复单位，区组内使用全部测量行，配对区间通过重抽完整区组计算。不同计时边界单独汇总。

恢复仅从完整区组检查点开始。入口逐项复核冻结配置、程序与库 SHA256、已完成任务日志、所有 CSV/输出/错误流哈希、输入输出对应关系以及原始目录完整性。失败或中途退出的数据保存在原目录，新实验使用新目录。超时保留现有输出流、待执行任务身份和错误记录。

采集器与对应驱动、配置和源码摘要一同登记。
