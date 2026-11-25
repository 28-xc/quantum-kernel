# 紧凑内核验证材料

支撑材料的数据目录按被测构建分别保存记录：`verification-final-v1`为紧凑配置，`verification-cache-profiles-v1`为40项与56项矩阵缓存配置，`verification-speed32-v1`为32位矩阵缓存速度配置。各记录包含实际程序摘要、编译条件、测试输入范围、返回码及原始数据索引。插桩构建与用于性能测量的普通构建分别保留身份。

完整正确性验证包含六组参数的标准向量、完整操作输出、签名字节、接口容量和异常恢复。`verification-final-v1`另有低位表示、提示谓词、所有者生命周期及形式验证记录；`verification-speed32-arithmetic`提供两平台的32位矩阵读取与延迟约减检查。具体输入域和计数见各数据集的摘要。

`positive-control`保存四个便携C配置的显式秘密标记检查及提示分支阳性对照。每个构建执行96组流程，其中48组为ML-DSA、48组为ML-KEM。驱动在熵回调处标记随机字节，并在操作前标记完整序列化私钥。阳性对照只将`lc_hint_mask.h`的掩码谓词改为分支表达式，Valgrind返回77并定位三个参数的提示计算；四个正常构建的对应记录均为零告警。首次使用普通已定义输入的对照及其返回0的原记录也保留。`provenance.xml`绑定原始记录摘要和构建源清单，原掩码助手与当前该文件逐字相同。

AArch64缓存与速度配置具有各自的显式秘密标记记录。测试模型保留挑战、范数检查结果和最终提示等公开注解，并在独立验证副本中公开完整私钥编码是否合法的一个聚合位；600组完整流程、72项非法编码和12项恢复调用用于检查该注解副本与生产库的输出一致性。原生秘密采样器的内部访问模式按对应汇编单独审阅。

`deployment`保留Cortex-M4与RV32目标程序、编译参数、链接布局和实际仿真控制台。目标资源记录按可写内存、代码与只读数据分别核算。

在支撑材料的`source`目录可执行：

```text
python ../data/positive-control/recompute.py
python ../data/verification-final-v1/recompute.py ../data/verification-final-v1/observations.xml --check ../data/verification-final-v1/summary.xml
python tools/reproduce_scientific.py --help
```

普通构建入口`tools/build_variants.py`支持`--sanitize undefined`及`--sanitize address,undefined`；秘密标记驱动为`tests/compact_memory/taint.c`，目标构建入口为`tools/build_targets.py`。各配置的实际检查范围由其数据与构建记录确定。
