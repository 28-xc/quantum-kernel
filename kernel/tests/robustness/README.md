# 本地接口可靠性回归

本目录以公开固定种子生成密钥、密文、签名、消息和变异输入，检查库的接口边界、错误恢复和释放前清理。测试在本地运行，输出逐参数结果、计数、源文件与实际程序的 SHA-256。

`sequence.c` 使用彼此独立的操作调度与随机源状态。默认三个种子为 `a127202609240001`、`a127202609240002`、`a127202609240003`。每个种子依次运行 ML-KEM-512/768/1024 和 ML-DSA-44/65/87，每个参数包含：

- 固定边界检查：长度、空指针、实际可访问对象的别名、上下文与工作区重叠、256 字节域拒绝、空消息；每种算法操作均检查 32 字节不足工作区及恢复。随机有效签名的域长度在 0 至 255 字节内选择。
- 2048 步随机接口序列，包含有效密钥生成、有效封装/签名和验证、随机截短、部分写入后失败的随机源、工作区不足、别名和无效参数；每类动作必须实际出现。
- 两类解析目标各 10000 次变异。ML-KEM 为密文及封装公钥，ML-DSA 为签名及验证公钥。变异在有效对象副本上执行单比特、局部字节串、边界字节、全对象随机字节替换。正确长度密文按隐式拒绝语义返回成功，并检查重复解封装输出一致，不要求暴露密文有效性。
- 工作区故意不对齐；所有对象前后具有保护字节。算法错误和随机源错误检查标准输出范围清零，前置校验错误检查不消耗随机源且输出不变。周期性恢复有效操作、检查已经使用的 arena 范围被擦除。

所有种子、退出码、逐参数计数、随机源调用数、命令、源文件与二进制 SHA-256 均保存。发生异常时停止该执行并保存 `failure.xml` 及存在时的 `failure_input.bin`，输入文件由本次公开种子派生。`transcript_fnv64` 用于跨构建序列比对；标准向量、互通与完整签名另行采用逐字节检查。

## 运行实际发布库

在工程根目录执行，例如：

```powershell
python -B tests/robustness/run.py --mode release --package D:/lattice-build/staged56-s3 --output D:/lattice-check/release
```

输出目录必须不存在且位于 D 盘。程序先核对 `build.xml` 的库哈希，将确切 DLL 复制到测试程序旁，结束后再核对源库和加载副本哈希。该模式使用包含汇编路径的原生 DLL，并检查测试对象的保护字节。

## 独立检测构建

```powershell
python -B tests/robustness/run.py --mode asan --match-package D:/lattice-build/staged56-s3 --output D:/lattice-check/asan
python -B tests/robustness/run.py --mode ubsan --match-package D:/lattice-build/staged56-s3 --clang D:/llvm/bin/clang.exe --output D:/lattice-check/ubsan
```

Windows ASan 使用脚本列出的 Visual Studio 2022 Community、MSVC 14.44.35207 与 Windows SDK；UBSan 通过 `--clang` 选择 LLVM-MinGW Clang。编译中间文件、临时文件和日志均写 D 盘。独立检测构建包括当前公共 API、arena、可移植 ML-KEM 以及匹配配置的 ML-DSA 源码。所有操作使用测试随机回调。Linux 的 GCC ASan/UBSan 本地编译、三种配置与执行命令见 `README_linux_replay.md`。

选型确定后的复核使用 `--match-package D:/实际选定包`，从该包 `build.xml` 读取 DSA 缓存项数及 KEM rows/batch，同时核对 DLL 哈希和实际 C/头文件/汇编源哈希；它优先于手工 `--cache`。因此 balanced 类配置的 KEM 调度也会匹配，不会只变更 DSA 缓存。检测后端为 portable。未传该选项的有界最大结构实验使用 rows1/batch1。

编译后先执行检测阳性对照：ASan 必须报告堆越界，UBSan 必须报告有符号整数溢出，且进程非零退出。未检出则本次验证失败。随后执行与实际 DLL 相同的固定计划。检测构建和 GCC 原生 DLL 是不同产物，不能将其结果写为原生汇编已获得 ASan/UBSan 覆盖。ASan 也不自动识别单个大 arena 内各子分配的全部相互越界；本工具另行检查保护字节和擦除范围，但仍有覆盖界限。

本目录记录固定边界、随机接口序列、解析器变异及检测构建结果；标准向量、互通、时序和资源实验分别记录。

## 隔离源码与秘密前缀配置

`--source-root D:/独立源码` 显式选择待检源码；测试框架仍从本目录取用并单列其哈希。与 `--match-package` 合用时，接受清单中的 `secret_prefix_polys`（0至3）并生成同值 `LC_DSA_S1_CACHE_POLYS`，同时保留 SIGN_ONLY/BATCH4 及其余宏。检测结果仅适用于所绑定的源码和秘密前缀配置。

`check_prefix_cleanup.py --source-root ... --package ... --output D:/新目录` 链接原生静态库、包装分配/释放函数，针对固定三个poly前缀检查释放前清零及同ctx交替密钥。对象识别依8f18d11源顺序，其他分配顺序或前缀大小需要重新审查。它有自己的非零残留阳性对照；观察器使用原库对象。精确作用范围和测试数保存在结果中。

输入生成采用固定种子的普通随机回归，测试计数表示实际执行次数。
