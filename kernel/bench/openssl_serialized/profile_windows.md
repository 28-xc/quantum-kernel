# Windows 自有工作线程热点观测

本工具对新建测试进程的工作线程采样；观察线程持有从当前工作线程伪句柄复制出的句柄。每次暂存 CONTROL 上下文后只保留实际加载测试 DLL 内的指令偏移，其他指令位置写为 0，随即清零上下文。原始 CSV 保存全部样本及顺序。

这是会扰动执行的指令采样器，不是时间测量器。SuspendThread/ResumeThread、观察线程与 1 ms 定时器会影响被观测执行；标签比例只能描述所取得样本，不能解释为无偏耗时比例、周期数、整操作成本或性能提升。1 ms 为请求周期，不保证每周期必采。QPC 是恢复工作线程后的观察时刻；CPU 调度、低样本量、计时器相位、标签别名、内联及指令级归属均可能限制结论。

## 身份与路径

`prepare` 接受显式 JSON 列表，每项包含 `label`、`path`、`sha256`，可成对追加 `build_record` 与 `link_map` 的路径/摘要描述。后者将构建时源码哈希、实际链接图及该二进制身份绑定；仅认可与实际构建哈希绑定的源码。每库固定六参数和三操作共 18 格，迭代数和种子在执行前保存。加载后同时核对实际 DLL 路径/摘要；OpenSSL 使用 IAT 中的实际函数地址配合 GetModuleHandleExW/GetModuleFileNameW 取得模块身份，编译头文件、运行版本、绝对路径及摘要一致才接受。

映射来自同一实际 PE 的 ImageBase、可执行段、nm 符号及 objdump 指令地址。只将采样 RVA 与真实反汇编指令起始地址精确相配；保留未映射样本。标签和同地址别名不等于独立机器码实体，COFF 相邻标签间距不当作函数大小，工具不虚构源代码行或内联函数归属。原始反汇编、符号表、各源文件快照、编译命令、实际二进制和映射摘要一同记录。

## 生命周期与自测

观察线程先完成亲和性/定时器初始化，再经 ready/go 握手进入循环；工作线程结束后明确 join。只有 join 已证明退出才释放其共享样本缓冲区。join 超时以本测试进程退出码 72 结束；ResumeThread 失败由观察线程以 73 结束本测试进程，避免主线程仍暂停而清理共享数据。上层仅管理它自己创建的测试子进程，所有异常和已保存记录保留。异常退出记为采样失败。

`selftest` 包含已知函数自热点阳性、非代码保留页的全零范围阴性、故意观察线程延迟的超时退出、非法操作/CPU/版本和覆盖已有输出的拒绝测试。另对清单内每库全 18 格只执行正确性检查，计数 0 不启动观察线程。实际种子产生标准序列化密钥，完整操作与指定 OpenSSL 对照，保留非法输入/隐式拒绝及缓冲区保护检查。正式热点采集还要求同一 prepared 的成功 selftest；源码或库修改后须重新准备。

示例（所有输出应为新的 D 盘目录；完整采样需事先协调独占窗口）：

```text
py -3.13 -B bench/openssl_serialized/profile_windows.py prepare --libraries libraries.json --crypto-library OPENSSL_PREFIX/bin/libcrypto-3-x64.dll --crypto-prefix OPENSSL_PREFIX --expected-version 3.6.4 --cpu 0 --observer-cpu 2 --output D:/pqc-profile/prepared
py -3.13 -B bench/openssl_serialized/profile_windows.py selftest --prepared D:/pqc-profile/prepared/prepared.xml --output D:/pqc-profile/selftest
py -3.13 -B bench/openssl_serialized/profile_windows.py collect --prepared D:/pqc-profile/prepared/prepared.xml --selftest D:/pqc-profile/selftest/result.xml --output D:/pqc-profile/collection
```

接口依据：Microsoft [GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)、[线程暂停](https://learn.microsoft.com/en-us/windows/win32/procthread/suspending-thread-execution)、[GetModuleHandleExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)。线程暂停不是常规同步替代物；这里仅用于一次性、可丢弃的自有测试进程。

示例中的 `OPENSSL_PREFIX` 为本机 OpenSSL 3.6.4 安装目录；头文件和导入库用于重新编译对照驱动。已编译的驱动与运行库随支撑材料保存。
