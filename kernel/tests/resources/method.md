# 完整公开接口资源验证

资源探针使用八个公开接口并绑定实际库的构建清单与 SHA-256，不重编目标密码库。Windows x64、Linux AAPCS64 与 SysV x64 分别使用相应调用约定的栈切换实现。所有资源结果仅关联实际运行的精确映像。

## 固定配置与验证

对每个参数先用充足 arena 完成三操作，保留完整公钥、私钥、密文/签名和共享秘密作为同库无限额对照；标准符合性与独立实现对照由其他验收工具负责。以三操作最大实际高水位向上取 32 B 整数，作为同参数固定 arena。工作区基址按 32 B 对齐。实际验证该容量成功、低一档 32 B 发生 OOM。未知项记为 null。

随后三项操作分别统一扫描 256 B 至指定上限（默认 16384 B），步长 256 B，保留所有成功和失败。选取末端连续成功区间的首档；三操作取最大，再加 256 B 安全余量。该固定栈档位连同同一个 arena、同一个 lc_context，用至少 24 个新种子分别执行完整三操作。上下文初始化也在同一受限栈中完成一次；三操作之间不释放或缩小工作区。每步核输出、canary、高水位不越界及已释放 arena 字节，未执行步骤明确为 null。

探针分别记录“全前缀非零字节数”和“不同于初始标记的非零字节数”。DSA adapter 按 32 B 对齐分配，MLD_FREE 擦除原始对象长度，因此未使用的尾字节可保留初始 0xCC。第二项非零时停止并保留异常；仅第一项非零时记录对齐尾区状态。秘密销毁另结合源码、机器码及安全测试检查。

输出的水印是有限输入下的动态观察，不作为容量声明。声明采用实际受守护边界限制并通过新种子验证的固定保留区域。OS 异常终止和接口返回的 OOM 分别记录。arena 不足时检查公开错误码、输出清零；随后在同一个 context 对象上配置充足 arena，重做完整三操作验证恢复。

## 受限栈

Windows 在实际预留 128 KiB 的专用线程内预先触碰栈页，将下方整个区域设为 PAGE_NOACCESS，精确 top=L+S。保留原 Win64 unwind metadata，R12 保存调用者 SP；S 包含 shadow space、返回地址、分派器与完整公开函数调用。线程实际保留、提交页面与核心受限区分开记录。

Linux 使用 mmap 创建下方 1 MiB PROT_NONE、页向上取整的可读写区以及上守护页。函数入口栈顶严格设为页对齐下界 L 加声明 S，S 为 16 B 整数。AAPCS64 保存 x19/LR、由 x19 保存旧 SP，返回恢复；不改 x18 或其他非易失寄存器。被测调用的 dispatcher 和其下游都位于该区。页取整余量位于声明栈顶之上，栈容量按 S 计。

Linux SIGSEGV/SIGBUS 使用独立 64 KiB signal alternate stack，以 write/_exit 输出故障地址及是否实际命中保护区。这部分属于仪器，不计核心预算。RLIMIT_STACK、mmap 地址保留和 enabled pages 分别作为虚拟存储指标输出。Windows 异常退出保留原始状态码；缺少故障地址时记录“与守护区一致的访问/栈异常”。

每个库必须通过空调用、48 KiB 局部栈在 4 KiB 限额下故障且在 64 KiB 限额下成功、堆分配阳性对照。trampoline 的实际反汇编、源码 SHA 和可执行文件 SHA 均随结果保存。

## 资源统计

核心保守预算为固定 arena + 固定受限栈 + 栈外 lc_context + 目标库完整可写映像及单线程 TLS 保守副本 + 外部堆。PE 采用非 debug 可写段 VirtualSize；ELF 采用 SHF_ALLOC/SHF_WRITE 段大小。此可写项包括链接器/运行库元数据，明确是算法核心全局变量的保守超集；核心对象归属不能解析时，单独字段保持 null。程序空间为实际库非 debug 可分配只读部分及初始化可写镜像，文件尺寸、debug 内容、OS 映像页另列。

Windows 沿用 IAT calloc/realloc/free/malloc 截获。Linux glibc 单独 LD_PRELOAD 测量器在调用窗内截获对应分配，不链接进产品；其元数据、信号栈和测试 oracle 不计作库资源。阳性对照验证计数。任何未覆盖的分配类动态导入或实际非零外部堆都会令完整预算保持 UNKNOWN；“requested live bytes”统计存活分配的请求字节，分配器元数据和物理驻留量另计。

三操作 I/O 按真实 FIPS 字节长度分别列出，消息 1024 B、context-string 为空、随机输入采用调用者给定测试熵。该实验不计内核或 BCrypt/getrandom 服务内部的系统内存；真实部署随机源需另外满足安全与资源合同。64 KiB 核心预算之外另列测试 oracle、仪器 job、输入复制、OS loader、CRT 进程、原线程栈及映射。

16/32/64/128/256 KiB 档位从总预算扣除固定栈/context/可写映像后，按 32 B 配置真实 arena，实际执行完整三操作，保留成功及 OOM 恢复。无法容纳正容量 arena 或外部堆未知时，明确未作成功见证。本工具记录主机库资源；目标固件和耗时分别测量。

## 执行

```text
python3 -B tests/resources/run.py --build /path/reference-full /path/reference-lowram /path/compact-fixed /path/cache40-24 /path/balanced40 --output /path/new-resource-evidence
```

Windows 用 Python 3.13、明确 MinGW GCC/objdump 路径，并将输出放 D 盘。`--stage preflight` 仅构建、阳性控制、固定 arena 边界，不能产生最终完整资源证据；完整运行默认扫描全部范围。每个目录必须含相同构建产物的 build.xml 与 DLL/SO。程序 SHA 改变后重新测量。原始 trials.records.xml 包含每次真实命令、状态、标准输出/错误，失败不丢弃。

完整采集结束后可独立重算证据关系：

```text
python3 -B tests/resources/validate.py /path/new-resource-evidence --output /path/fresh-audit.xml
```

审计器核验源/可执行文件/日志/清单哈希，逐条重判原始退出状态，检查扫描全集、共享容量、新种子、OOM 恢复、预算实限及资源加和。它保留原始记录，仅在内存中构造损坏 canary、越界高水位、错误退出码、重复结果与保护区外故障等负例，确认这些异常不会成为有效证据。AAPCS64 trampoline 另核真实七条机器指令字节。
## 无分配器导入的 Windows 库

某些实际 Clang 库不导入 malloc/calloc/realloc/free，因此不存在可用于阳性对照的目标分配器 IAT。对此保留目标 PE 导入清单，并用相同记账包装器调用探针自身 CRT 的 calloc/realloc/free，确认 64→96 B 分配、释放及峰值计数。该对照标为 `standalone_accounting_no_target_allocator_imports`。具有完整分配器 IAT 的库继续使用原目标 IAT 对照；部分分配器入口无法完整覆盖时仍拒绝。目标调用记录、导入检查与 arena 分配规则共同确定堆统计范围。
## 六参数同一上下文检查

`run_common.py` 读取同一个实际二进制的完整资源记录，取六参数共同 `W=max(Wp)`、`S=max(Sp)`。`probe_common.c` 在每次序列内只调用一次 `lc_context_init`，保持同一 64 B context 对象、同一 32 B 对齐 arena 及同一随机回调用户地址；依次执行 `512→44→768→65→1024→87` 和反向顺序，每参数完整三操作。24 个新种子分别运行两个方向。每次操作核对上下文标识、完整输出字节、工作区边界及实际已改写释放区域。序列的参考输入和预期输出在约束实验外生成并存于测试进程，不计为算法工作区；接口输入输出与测试程序内存仍须另列。

仪器先运行三/六参数正常交错、空调用、4 KiB 下 48 KiB 故意超限、64 KiB 下同一阳性函数成功及堆核算阳性。随后测 `W−32` 的真实不足工作区错误与输出清零；恢复阶段明确重新初始化同一个 context 对象到独立大 arena，它不属于前面“初始化一次”的成功序列。16/32/64/128/256 KiB 总核心预算分别扣除 `S+context+globals+heap` 后实际分配剩余 arena，并完整保留失败记录。Windows 线程的 OS 保留映射、受控核心栈容量和 Linux enabled pages 分列。

controller 的测量视图只是已验证库的同字节副本，原始 manifest、profile、实际编译/链接命令及其哈希保留于 `derived_from`。它不构成一次新构建。控制器对每次有限输入扫描重新校验二进制身份，逐子任务独立审计；之前任何不同 SHA 的成功记录均不继承。
