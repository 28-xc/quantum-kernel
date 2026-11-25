# 完整应用时延与实际内核原语

`application_latency_v1` 对 8 个构建、3 组 ML-KEM/ML-DSA 参数和两种身份生命周期保留 480 个进程的全部 CSV。每格有 10 个随机配对区组，每进程包含 16 次预热和 200 次正式调用。调用内完成上下文初始化、设备密钥生成、证书签名与验证、封装与解封装、共享密钥比较和秘密清理；新建身份模式同时包含签发方密钥生成，复用模式在计时前建立签发方身份。

单次时延的均值、中位数及 p95/p99 由每格全部 2,000 次调用计算。应用批吞吐量以 2,000 除以 10 个批次的总墙钟时间，批次包含内存记账和摘要校验；CSV 写出在批次计时之后。配置比较先在每个区组计算完整时延均值之比，再取几何平均。三组参数的汇总在区组内部平均对数比值。95% 区间以整区组为重采样单位，PCG64 固定种子、10,000 次重采样及线性分位数。全部慢样本与预热行保留。

`primitive_samples_v1` 绑定最终构建的真实静态库、构建记录、源文件哈希、实际链接实体和功能预检。每个配置有 10 个原语条件，每条件由 7 个独立进程采集；每进程保留 10 个预热批和 100 个正式批，每批执行 100 次。原语百分位数描述 **700 个批均值的分布**；均值区间重采样 7 个完整进程。可移植 LTO 静态库按记录中的编译器及 `Os` 链接，原语驱动使用独立测量入口。

从源码目录执行只读复算：

```text
python tests/measurement_views/audit.py --kind application-latency ../data/application_latency/windows/observations.xml --statistics ../data/application_latency/windows/statistics.xml
python tests/measurement_views/audit.py --kind primitive-batches ../data/primitive_samples/windows/observations.xml --statistics ../data/primitive_samples/windows/statistics.xml
```

使用 `--negative-tests 新目录` 验证字节篡改、丢记录、替换配置、额外字段、重复 JSON 字段、非有限数值及更新哈希后的无效样本。结果仅写入指定的新目录。实际采集入口分别为 `tests/application_workload/run.py` 与 `tools/build_primitives.py`；测试驱动、绑定静态库及元数据共同定义各次实验的测量对象。
