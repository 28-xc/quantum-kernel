# PQClean clean 公共调用对照

此目录固定 PQClean 官方归档提交 `0586a824fc0d49df0b6b6e9179d8d15d06d0974f`（2026-08-04），包含 ML-KEM-512/768/1024 和 ML-DSA-44/65/87 的 clean 实现及其公共 FIPS202 代码。`source_lock.xml` 逐文件记录官方 Git blob、SHA-256 与选择范围；`upstream/` 文件保持原始字节，保留六个实现的 LICENSE、META.yml 及公共文件的署名。

## 比较边界

八个 `lc_*` 入口让同一个实验驱动使用相同的序列化密钥、消息、上下文、随机输入和调用边界。该适配用于第三方实验对照，不作为作品部署配置。

|范围|实际处理|
|---|---|
|算法实现|原 clean C 算法和原 common FIPS202；无 AVX2 专用源码替换|
|长度、空指针和别名|与公共接口一致的准确输入长度、输出容量、0–255 B 上下文及对象分离检查|
|随机源|入口先取得原调用所需的 64 B 或 32 B，失败时清空有效输出；原 `randombytes` 通过每线程临时桥接消费同一字节序列|
|ML-KEM 封装密钥|固定遍历解码两个 12 bit 系数，逐个检查 `<3329`；rho 不参与模数检查|
|ML-KEM 解封装密钥|重新计算内嵌公钥的 SHA3-256，并完整比较存储的 32 B 摘要|
|ML-KEM 无效密文|保留原隐式拒绝流程及条件选择|
|ML-DSA 签名界|对原公开 attempt nonce 入口增加界限，44/65/87 分别为 16382/13106/9361，避免 16 bit nonce 回绕|
|堆、栈与失败|保留原 malloc/free、自动数组和分配失败 `exit(111)`；不改造成作品的工作区分配器|

官方 [issue 601](https://github.com/PQClean/PQClean/issues/601) 指出的 ML-KEM 公钥模数与私钥摘要检查在此提交中仍未提供，由适配层补齐，其耗时位于完整调用边界内。公开 nonce 守卫通过只针对 `polyvec.c` 的编译符号重命名与单独包装实现，原文件不修改。正常样本的算法输出及随机源消费须经完整差分确认。

工作区参数用于公共 ABI 与对象分离检查，原堆、栈分配保持不变，`arena_high_water` 因而为 0。完整资源比较计入实际堆峰值、调用栈和完整链接映像，并按独立测量状态列示。原分配失败通过 `exit(111)` 终止进程，自动秘密栈对象保留原清理语义；适配新增错误的标准输出、临时熵与桥接状态在返回前擦除。功能、错误恢复与秘密清理分别按上述范围解释。

## 可复现构建与功能检查

```text
python -B tools/build_pqclean.py --architecture x86_64 --cc <gcc或clang绝对路径> --ar <归档器> --nm <nm> --objdump <objdump> --size <size> --output <新的输出目录>
```

两种 x86 编译器均使用 O3、`-march=native`、相同的帧指针及 section/链接裁剪选项，不启用 LTO；Windows 对称使用 `-static -static-libgcc` 将编译器及线程局部存储辅助运行库计入实际映像，原 malloc/free 仍来自 Windows CRT。Linux AArch64 使用 `--architecture aarch64` 与匹配的本机 GCC，目标选项为 `-mcpu=neoverse-n1`。构建记录包括完整命令、依赖文件、实际源与对象摘要、共享/静态库、八个导出、链接映射、反汇编、段表和两种链接方式的真实六参数功能闭环。

```text
python -B tests/platform/check_public_acvp.py --library <实际库> --output <新的ACVP结果.xml>
python -B tests/platform/compare_public.py --left <同平台reference-full库> --right <PQClean适配库> --resource-mode record --count 100 --output <新差分结果.xml>
python -B tests/pqclean/check_adapter.py --library <实际库> --output <新边界结果.xml>
```

向量记录区分八入口可表达的 public/pure 用例与 HashML-DSA/internal-mu 范围外用例。差分核对完整字节、熵请求与变异输入；资源模式只记录两方真实差异。边界工具覆盖打包系数两半与每个多项式首尾、q 附近无效值、所有 32 个摘要位置、消息/上下文边界及随机源失败恢复。计时使用固定的随机完整区组设计；构建与正确性输出记录功能、来源和二进制身份。
