# 平台随机源与公共接口检查

宿主构建提供统一八入口。默认可移植紧凑配置为 `compact-rate`，低内存对照为 `reference-lowram`；完整参数、后端和编译选项见 [构建说明](build.md)。示例均在工程根执行，输出使用新目录。

```text
python -B tools/build_variants.py --output <新的目录> --config compact-rate --backend portable --opt Os --lto --probe-count 200
python -B tools/build_variants.py --output <另一个新目录> --config reference-lowram --backend portable --opt Os --lto --probe-count 200
```

Windows 生成 DLL、导入库及静态库；Linux 生成 PIC ELF 共享库与静态库。共享库只导出八个公共入口。构建分别运行共享与静态探针，覆盖正常闭环、长度与别名错误、随机源失效、工作区不足及恢复，并保存目标三元组、编译命令、实际源码依赖、链接映射与产物摘要。

## 随机源合同

调用者提供 `lc_random_fn` 时，公共接口仅使用该回调。它须提供密码学安全随机字节，完整写入后返回 0；确定性测试回调仅用于可复现测试。

回调为空时，Windows 使用 `BCryptGenRandom` 的系统优选随机源，Linux 使用 `getrandom(..., 0)`。Linux 每块最多 256 B，处理短读并在 `EINTR` 时重试；其他错误、零返回或异常超长返回均失败。失败时平台服务清空整个请求区，公共操作继续执行种子及有效标准输出范围的擦除。策略说明见 [getrandom(2)](https://man7.org/linux/man-pages/man2/getrandom.2.html)。

`LC_RNG_CALLBACK_ONLY` 配置要求应用提供可靠回调。密钥生成、封装、签名在缺少回调时返回 `LC_E_RANDOM`；解封装和验签不需要新随机数。Cortex-M4/RV32 的目标测试使用明确向量熵与独立运行时，实际入口和记录见 [目标说明](../targets/README.md)。

## 可执行检查

```text
python -B tests/platform/run_random_tests.py --output <新的随机源检查目录>
python -B tests/platform/check_public_acvp.py --library <实际共享库> --output <新的向量结果.xml>
python -B tests/platform/compare_public.py --left <参考库> --right <候选库> --count 100 --output <新的差分结果.xml>
```

Windows 可用 `py -3.13 -B`，路径改为 D 盘和实际 DLL；Linux 使用本机 ELF。`run_random_tests.py` 同时包含真实宿主随机调用、回调专用分支和生产 Linux 分支的短读/中断/失败注入，各类型单独记录。向量工具逐字节比较八入口可表达的标准结果，另列 HashML-DSA 和 internal-mu 等范围外用例。差分工具只保存聚合摘要和状态，不归档私钥与随机字节。

## 结果口径

实际宿主随机调用、受控系统调用故障和回调专用路径分别记录。功能结果包含返回值与错误恢复；时延和固定资源由对应实验工具另行采集。各平台的单调时钟、动态加载、LP64/LLP64、独立栈与保护页由相应工具处理，实际目标与二进制身份随结果保存。
