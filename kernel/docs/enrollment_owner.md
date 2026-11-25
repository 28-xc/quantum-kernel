# 固定内存池的设备接入应用

本应用将设备公钥签发与密钥建立连接为一个完整流程，支持 ML-KEM-512/ML-DSA-44、ML-KEM-768/ML-DSA-65 和 ML-KEM-1024/ML-DSA-87 三组搭配。签发方用 ML-DSA 签署新生成的设备 ML-KEM 公钥；接收方验签后封装共享秘密，设备解封装并核对两端结果。上下文字符串为 `A1-27 device enrollment v2`。

一个内存池容纳应用状态、序列化密钥、签名、密文、共享秘密和算法工作区。布局 `0` 分别存放各序列化对象。布局 `1` 直接引用ML-KEM私钥中已包含的公钥，密钥生成的独立公钥输出暂存于尚未使用的签名缓冲区；验签和签名摘要处理完成后，该缓冲区继续用于密文及两个32字节共享秘密。三组参数分别省去800、1184和1568字节的重复公钥存储。两种布局执行相同密码操作。`fresh_identity=0` 在批次内复用签发密钥；`fresh_identity=1` 在每个流程中重新生成签发密钥。

每个流程结束时清理设备私钥和共享秘密，重新生成身份模式同时清理签发私钥。`app_finish` 清理对象区和完整工作区并结束熵回调，`app_close` 清理整个内存池。功能检查覆盖随机源失败、工作区不足、验签失败、流程取消及共享秘密不一致后的状态和恢复。

## 构建和功能检查

入口支持 Windows x86-64 与 Linux AArch64，使用 Python 3.10 以上和本机 GCC。以下示例在源码根目录执行，输出目录使用新路径。Windows 的源码和输出目录位于 D 盘。密码核心先按[原生构建说明](build.md)生成，Windows 使用完成部署重链接后的 DLL。

```text
python -B tools/application_owner.py build --cc gcc --output out/application
python -B tools/application_owner.py check --build out/application --library out/windows-native/latticecore.dll --baseline out/pqclean/latticecore.dll --workspace 9536 --output out/application-check
```

`--build` 指向包含应用 `build.xml` 的目录，`--library` 为被测核心，`--baseline` 为逐字节比较所用的参考核心。检查驱动为逐字节比较的参考库预留262144字节工作区；被测库容量由`--workspace`指定，按32字节对齐。两侧实际容量分别传递，资源与正式计时使用被测配置自己的测量值。

应用通过函数表调用核心库。构建结果包括应用模块、功能检查程序和资源探针：Windows 使用 `application.dll`，Linux 使用 `libapplication.so`，Linux 另生成资源计量用的 `heap_audit.so`。`build.xml` 保存源码、工具和全部产物身份。

功能检查使用三组参数、两种身份模式、两种布局和 24 组固定输入，逐阶段比较密码输出；生命周期检查核对返回码、同会话恢复、对象边界和清理。检查程序使用确定性测试熵；实际调用 `app_open` 时将 `seed` 设为零，即通过空熵回调使用核心库的系统密码随机源。

Linux AArch64 使用同一入口，命令中的共享库改为 `.so`：

```text
python3 -B tools/application_owner.py build --cc gcc --output out/application-arm
python3 -B tools/application_owner.py check --build out/application-arm --library out/arm-native/artifacts/liblatticecore.so --baseline out/pqclean/liblatticecore.so --workspace 9120 --output out/application-arm-check
```

`build --sanitizer address-undefined` 可生成诊断构建，用于功能和生命周期检查；资源和耗时分别使用普通构建。

## 正常资源及容量恢复

`tools/application_resources.py` 读取现有普通应用构建和核心库。栈容量先由独立的宽裕正常容量检查确定，并按协议保留安全余量；本入口验证所传入的完整应用栈预留，不自动搜索最小栈。工作区、栈和堆预留均显式传入。

```text
python -B tools/application_resources.py --build out/application --library out/windows-native/latticecore.dll --workspace 9536 --stack-bytes 2816 --heap-bound 0 --failure-workspace 32 --output out/application-resources
python -B tools/application_resources.py --build out/application --library out/native-lowram/latticecore.dll --workspace 21120 --stack-bytes 9728 --heap-bound 0 --failure-workspace 32 --output out/native-lowram-application-resources
```

第一条命令对应Windows紧凑配置，第二条对应当前成熟低内存O3实现。AArch64紧凑配置采用工作区9120字节、完整应用栈2448字节和零外部堆预留；成熟低内存O3实现采用工作区21120字节、完整应用栈6432字节和零外部堆预留。重新构建或更换运行时后，先核对实际模块和正常资源记录，再确定本次容量。

十配置完整应用数据分别位于附件`data/windows-application-owner`与`data/arm-application-owner`，覆盖五种部署配置、40项矩阵缓存对照、成熟完整与两种编译条件的低内存对照，以及使用32位矩阵和独立变换向量的同条件控制。每份配置均使用对应最终库和普通应用模块。完整应用栈先通过独立宽裕容量探针确定水位并保留256字节余量：Windows按256字节对齐，AArch64按16字节对齐；同平台各配置采用相同规则，随后验证正式预留量及护栏。实际容量见两平台`signing-pipeline-*/technical-validation`中的资源记录。

每个资源采集包含两个正常探针控制条件和 48 批完整流程，每批四个流程，共 192 个流程。控制条件为空调用及已知 96 字节堆分配。六个参数搭配—布局单元分别保存工作区峰值、栈水位、堆活动、护栏和清理状态。

`--failure-workspace` 为可选项，其值须小于正常工作区。设置后追加六组操作级容量不足及新进程正常容量恢复，实际组数写入 `capacity_recovery_count`。32 字节正常工作区的 PQClean 对照省略此选项，按自身存储方式完成正常流程。应用功能检查另保留同会话错误恢复。

完整应用资源按以下范围汇总：

- 运行内存：内存池、完整应用栈、核心库与应用模块的可写全局区及单线程 TLS、应用控制区、区外堆预留。
- 内存池：应用状态、密钥、消息、签名、密文、共享秘密、算法工作区和对齐填充。
- 程序空间：核心库与应用模块的实际非调试映像节之和，包含相应导入表和展开元数据。

核心上下文已包含在应用状态中，核心调用栈已包含在完整应用栈中，各自汇总一次。核心资源表与包含序列化输入输出的应用资源表分别保存。`result.xml` 给出六个单元的实测值，`commands.xml` 和原始进程记录保留在同一目录。

## 初始化至清理的完整应用计时

`tools/application_timing.py` 使用单独的普通 C 驱动，链接同一个已完成资源检查的应用模块。计时依次覆盖 `app_open`、上下文初始化、`app_prepare`、全部 `app_flow`、`app_finish` 和 `app_close`；最后一步的整池清理计入耗时。库加载、符号解析、物理内存池分配与释放、计时外宽工作区摘要核对，以及测后的零值和护栏检查位于计时区间外。

计时驱动不带堆钩子或资源栈扫描。`prepare` 读取同一核心、同一应用构建的正常资源结果，核对六个资源单元、48 批正常记录以及预留容量。这样资源计量与普通计时使用相同模块身份，计量探针的额外工作保留在资源实验中。

先构建计时驱动：

```text
python -B tools/application_timing.py build-driver --build out/application --cc gcc --output out/application-timing-driver
```

建立 `out/application-libraries.xml`，显式列出2至10个待比较配置。下面给出两配置示例，每个文件引用包含 `path` 和 `sha256`。路径按执行命令的当前目录解析，也可以填实际文件的绝对路径；摘要填写文件的64位小写十六进制SHA-256。

```xml
<record format="typed-xml-v1"><object><field><name>libraries</name><list><object><field><name>id</name><string>lattice-native</string></field><field><name>library</name><object><field><name>path</name><string>out/windows-native/latticecore.dll</string></field><field><name>sha256</name><string>&lt;被测核心文件的SHA-256&gt;</string></field></object></field><field><name>resources</name><object><field><name>path</name><string>out/application-resources/result.xml</string></field><field><name>sha256</name><string>&lt;被测应用资源结果的SHA-256&gt;</string></field></object></field></object><object><field><name>id</name><string>pqclean-reference</string></field><field><name>library</name><object><field><name>path</name><string>out/pqclean/latticecore.dll</string></field><field><name>sha256</name><string>&lt;参考核心文件的SHA-256&gt;</string></field></object></field><field><name>resources</name><object><field><name>path</name><string>out/pqclean-application-resources/result.xml</string></field><field><name>sha256</name><string>&lt;参考应用资源结果的SHA-256&gt;</string></field></object></field></object></list></field></object></record>
```

各配置采用互异的英文小写标识，通过平台和文件摘要区分实现。全部资源结果须来自同一应用构建，且各自目录中的 `commands.xml` 保持可读。可以同时列入紧凑、40项缓存、48项缓存、56项缓存、32位矩阵缓存、速度配置、成熟完整与两种编译条件的低内存对照，以及分离存储控制。分离存储控制使用32位矩阵与独立变换向量，其差异由构建配置逐项给出，用于比较存储组织的整体贡献。占位摘要替换后，按以下顺序执行：

```text
python -B tools/application_timing.py prepare --build out/application --driver out/application-timing-driver/driver.xml --config out/application-libraries.xml --cpu 2 --output out/application-timing-plan
python -B tools/application_timing.py check --plan out/application-timing-plan/plan.xml --output out/application-timing-check
python -B tools/application_timing.py collect --plan out/application-timing-plan/plan.xml --output out/application-timing-results
python -B tools/application_timing.py analyze --input out/application-timing-results --output out/application-timing-statistics
```

Windows的已验证入口固定使用逻辑CPU 2；Linux的 `--cpu` 可选当前进程允许使用的逻辑CPU。Linux命令使用 `python3` 并填写同平台 `.so` 路径。设配置数为N，`check` 执行24N个无计时批次，核对相同输入的流程摘要、完成次数、对象边界和最终整池清理。通过后运行 `collect`。采集前留出所选CPU，测量期间保持相同环境条件。

固定设计包含九个完整随机区组。每区组覆盖N个配置、两种布局、三组参数、两种身份模式及每批1或200个流程，共24N个独立进程；全部实验包含216N个进程。相同条件下的配置与布局使用同一组输入。Windows使用QPC，Linux使用单调原始时钟；每个进程上限30秒，整批上限300N秒，最多2400秒。源码和 `plan.xml` 固定顺序种子与统计条件。

每个进程的原始标准输出和错误流先落盘，再核对状态与摘要。失败结果保存到原目录；新测量使用新目录。进程摘要为64位流程摘要，完整密码字节的一致性由前述独立功能检查验证。全部216N批均进入统计。

`analyze` 需要NumPy，输出 `statistics.xml`。统计包含24N个条件的算术平均批次耗时、95%置信区间和完整流程吞吐量，以及12×C(2N,2)个配置—布局配对的均值时间比及区间。区间使用同一组50000次完整配对区组重抽样；吞吐量为每批流程数除以平均批次耗时。一次批次含1或200个流程，分布与区间均以完整批次为统计单位。

## 公开数据与离线复算

完成的采集可由 `tools/import_application_owner.py` 转为可移动的公开数据目录。导入只读取既有结果，不运行密码操作：

```text
python -B tools/import_application_owner.py --input out/application-timing-results --output out/application-observations
python -m publicschemas.application_owner_v1 out/application-observations/observations.xml --check out/application-observations/summary.xml
```

若分发包中包含已验证的 Windows CPython 3.13 和 NumPy 2.2.5，可在包根目录使用同一统计实现离线复算：

```text
bin/python/python.exe source/tools/offline_analysis.py --bundle . --entry application-owner -- data/windows-application-owner/observations.xml --check data/windows-application-owner/summary.xml
```

多项式原语的逐批观测采用 `primitive-samples` 入口。将下面两个文件名替换为对应平台的观测文件和新输出文件路径，命令从全部原始批次重算统计摘要：

```text
bin/python/python.exe source/tools/offline_analysis.py --bundle . --entry primitive-samples -- OBSERVATIONS.xml RECOMPUTED.xml
```

算术观测保留七次独立进程、每进程100批、每批100次调用的完整设计。

公开目录保存 `observations.xml`、`summary.xml`、`summary.csv` 和原样进程输出。第二条命令从公开数据独立重算并核对摘要中的统计结果。返回材料移动路径后，可在导入时重复指定 `--path-map ORIGINAL_PREFIX=LOCAL_PREFIX`；文件哈希仍须逐项一致。`--current-id ID` 仅映射公开技术标识，保留核心和应用文件摘要；`--audit FILE` 将本地路径映射记录到公开目录之外。

演示按平台、核心库摘要和工作区匹配对应应用数据。十配置应用的资源与时延通过相同核心和应用模块身份逐项关联。公开数据字段和复算范围见[完整应用观测说明](application_owner_observations.md)。

## 源码与许可

应用位于 `examples/enrollment_owner`，其 `source_identity.xml` 保存应用及接口、探针源文件的摘要；实际构建记录绑定本次使用的源码与产物。计时驱动位于 `bench/application_owner/timing.c`，采集与统计入口位于 `tools/application_timing.py`。应用实现及带 SPDX 标识的配套代码采用 Apache-2.0，其余接口和辅助文件沿用相应许可证，见[来源与许可](sources_and_licenses.md)。

应用闭包检查为 `python tests/test_application_owner_closure.py`，核对公开文件清单、源身份和工作区参数边界。
