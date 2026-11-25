# 完整解封装的公开字段隔离诊断

此工具用于分析固定类别软件时序检查中的差异来源。全部观测和异常均纳入结果解释。它调用同一未修改动态库的完整 `lc_context_init` 与 `lc_decaps`，不复制融合 Keccak 或矩阵路径作为替身。

输入重放分组时序实验的 257 个生成密钥、固定随机密文、独立类别 PRNG 和密钥索引序列。构造输入时，`dk_PKE` 和末尾 `z` 始终取原 `pool[0]`，只有嵌入的 `ek || H(ek)` 来自被选原密钥。此输入满足编码与算术域要求，但通常不构成标准生成的一致密钥对。因此这是公开字段隔离诊断，不是新的合法密钥分布实验。

准备阶段逐个核验 257 个构造输入：公开密钥哈希正确、秘密前后缀固定、公开接口成功、输出等于独立标量参考计算的 `J(z0 || ct)`、输入未被修改且解封装不消耗随机数。Python `hashlib` 再核验每个公开密钥哈希，以及参考 sponge 的 SHA3/SHAKE 公共输入答案。仅保存公开片段和密文，不写出私钥池。

每次计时前将构造输入复制到同一固定地址。计时内保持与分组时序实验相同的完整公共接口边界，返回值、共享秘密和输入不变检查在计时后进行。这些附加的外围核验会影响调用间隔，故诊断时间不用于端到端性能比较。

准备与采集分开运行，准备过程不采时。示例中的目录需要替换为已完成的分组时序实验目录和独立输出目录，Windows 输出必须在 D 盘：

```text
python public_fields.py prepare --original D:/evidence/grouped-timing --output D:/evidence/public-fields --source-root D:/source/frozen-core
python D:/evidence/public-fields/public_fields.py collect --original D:/evidence/grouped-timing --output D:/evidence/public-fields --token EXPLICIT_COORDINATED_WINDOW
```

完整覆盖三参数乘三种子，各 100000 个观测和 1000 个热身。原始输入 FNV（包括热身）用于逐流重放核对，另保存实际构造输入的 FNV 与公开片段 FNV；公开池和密文另绑定 SHA-256。检查点、两种统计量、阈值沿用原始协议；不剔除观测、不按显著性停止、不自动重跑，失败日志和已写出的完整原始块保留。

诊断比较固定秘密前后缀、改变公开字段后的完整路径耗时。内部秘密计算仍执行，中间值可依赖公开字段；解释时结合 `z`、`dk_PKE` 隔离族、代码路径和全部原种子结果。

`prepared.xml` 和 `measurements/results.xml` 记录已完成的准备与采集。

## 分组时序实验一致性与方法归属

池生成顺序保持为每个密钥的 keygen、encaps、有效密文 decaps，257 次完成后才生成固定随机密文。预检不得消耗 PRNG 状态。类别流与输入流分离，每个 1000 次块以 500/500 初始化并执行相同 Fisher–Yates 洗牌；两类均消费一次随机池索引，热身块也进入重放 FNV。分组时序实验给 `fixed` 副本的 `z` 首字节清位用于其他模式，`decaps_key` 实际读取原始池；本诊断因此保留 `pool[0]` 的原始 `z`。

分组时序实验的密文依据登记的池生成、PRNG 消费路径及完整输入流校验重新构造；公开字段隔离实验记录密文 SHA，以绑定准备与采集。FNV 是重放一致性检查，不是密码学身份哈希；构造输入不与原始输入逐字节相同，这正是隔离实验的干预。

密钥字段、`H=SHA3-256` 和隐式拒绝 `J=SHAKE256(...,32)` 的定义来自 [FIPS 203](https://doi.org/10.6028/nist.fips.203)；参考 sponge 的置换、填充及域分隔来自 [FIPS 202](https://doi.org/10.6028/nist.fips.202)。固定/随机软件时序比较与 Welch 检查参考 Reparaz、Balasch、Verbauwhede 的 [Dude, is my code constant time?](https://doi.org/10.23919/date.2017.7927267)。对应文献库键为 `FIPS203`、`FIPS202`、`Reparaz2017`。

本工具复用分组时序检查器的 PRNG、计时/亲和性和独立标量 Keccak 参考实现；字段替换、逐流重放、实际动态库绑定及保留原异常是本项目的实验实现。实现许可见所用源文件。
