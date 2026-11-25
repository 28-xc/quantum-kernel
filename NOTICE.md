# 代码来源与许可

团队有权授权的原创部分按 Apache-2.0 发布。对第三方项目的代码和衍生文件，以该项目的随附许可及文件头为准。

- [mlkem-native](kernel/third_party/mlkem-native/) 和 [mldsa-native](kernel/third_party/mldsa-native/) 提供算法基础实现，已有改动和适配保留原始署名。
- [PQClean clean 实现](kernel/baselines/pqclean/)用于功能和性能对照。
- STM32 的 pqm4、mupq 和 libopencm3 相关代码沿用各自的来源说明及许可，见 [STM32 源码](kernel/targets/stm32f407/)。
- NIST ACVP 和 Wycheproof 测试向量保留来源、版本及原有声明，见[测试向量](kernel/tests/vectors/)。
- [详细来源及许可证索引](kernel/docs/sources_and_licenses.md)也记录本地构建或参赛复现过程中用到的外部工具。

编译器、SDK、运行库、已编译固件及参赛运行记录由对应环境提供。
