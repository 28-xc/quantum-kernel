# Quantum Kernel 本地服务

随包桌面版的操作见 [Quantum Kernel 使用说明](<../../../03_复现环境与运行程序/软件演示程序/使用说明.md>)。本文记录内核工程自带的服务和桌面宿主构建方法。

## 从源码运行

在内核工程根目录执行，`local_demo.xml` 为本地配置文件。

~~~text
python -B demo/server.py --config local_demo.xml --port 8134
~~~

复算所需的依赖见 `docs/analysis_requirements.txt`。

## 配置与接口

启动配置采用schema 4。`libraries`登记实际部署库及其SHA-256、参数、工作区和宿主指令要求；可选`derivation`绑定去调试信息前后的执行节等价收据。服务核验收据后将当前部署像与原测量像关联，功能导出同时保留两种SHA-256。`deployment_profiles`绑定经过资源验证的测量像身份。科学结果通过下列字段登记：

|字段|内容|
|---|---|
|`scientific_views`|标准验证、算法资源及机制实验|
|`pooled_views`|完整操作的统计结果与原始分片索引|
|`timing_views`|输入分组时序观测及阳性对照|
|`resource_limit_views`|Linux 内存与 CPU 约束实验|
|`process_footprint_views`|实际目标进程的驻留量|
|`mean_tail_views`|同条件完整操作均值、尾部分位数及配对区间|
|`application_owner_views`|固定内存池应用的资源与包含关闭清理的耗时|
|`instruction_views`|实际程序的指令采样与符号映射|
|`verification_record_views`|逐文件复算的标准、互操作与接口验证|
|`qualification_views`|当前速度配置的适用标准向量、完整字节、互操作与容量记录|

原生 x86 库通过独立宿主探针检查 CPU 指令和操作系统寄存器保存能力。数据路径以配置文件为基准解析，原始分片由相邻索引逐项绑定。更换算法库时，应同时登记对应构建的工作区、执行条件和资源数据。

|接口|内容|
|---|---|
|`GET /api/catalog`|已加载库、参数及数据目录|
|`POST /api/run`|真实密码流程|
|`GET /api/resources`、`GET /api/budget`|资源数据与预算查询|
|`GET /api/results`|技术结果摘要|
|`GET /export/results.xlsx`、`GET /export/results.csv`|结果表|
|`GET /export/science.xlsx`、`GET /export/science.csv`|完整科学数据|
|`GET /export/observations-manifest.xml`|原始文件索引|
|`GET /export/raw.csv`、`GET /export/raw.xml`、`GET /export/raw.bin`|索引中的原始记录|
|`GET /export/run/标识.xlsx`|本进程最近一百次功能调用中的指定结果|

数据导出接口使用 `dataset` 选择数据集合，原始文件接口另用 `ordinal` 选择索引序号。服务在读取原始文件时再次核对摘要。数据结构和校验逻辑位于 `publicschemas/`。

### 已有测量与当前程序的关联

当两次链接的文件摘要不同而PE装载视图相同时，可在对应库中登记`measurement_reuse`。每项明确指定`dataset_id`、`purpose`、原测量程序的`measured_binary_sha256`以及含`path`与`sha256`的`equivalence`收据。`purpose`取`instruction_samples`或`layout_ablation`。服务逐项读取收据两侧程序，核验部署派生关系、代码、常数、重定位及执行元数据；原测量身份同时须出现在指定数据集内。该关联只作用于所登记的指令采样或布局消融结果。当前性能、资源、资格和预算仍按实际测量程序精确匹配。

`GET /api/results?library=...`的关联视图保留原始统计，并通过`measurement_binding`给出所选部署程序、所选测量程序、原测量程序和等价收据的摘要。`GET /export/results.xlsx?dataset=...&library=...`及对应CSV导出相同的选定视图与身份字段；`GET /export/image-equivalence.xml?dataset=...&library=...`提供经过核验的收据。省略`library`的科学数据导出保留整个原始数据集。

基础运算实验由独立静态库和采集程序测量。选择同平台程序时，界面显示该实验并保留各静态库、采集程序与构建记录的身份；`measurement_binding.mode`为`independent_arithmetic_archive`。这类结果的测量对象由静态库与采集程序定义。

## 本地服务与检查

服务仅监听回环地址。请求检查令牌、Host、Origin、字段与长度；文件读取范围由启动配置和已验证索引确定。页面返回操作状态与公开结果，私钥和共享秘密保留在本地调用中。调用结束后清零显式敏感缓冲区；Python 比较过程中产生的临时字节对象由运行时管理。

`tests/demo/browser_presentation_qa.mjs` 使用实际 Python 服务和浏览器，检查五页交互、六组参数、容量不足后的恢复及登记数据导出。`--screenshots` 保存实际页面。该入口用于功能与交互检查，完整操作计时使用独立驱动。

## 桌面宿主构建

原生宿主源码为 `windows_desktop.cpp`，使用 Win32 与 Microsoft WebView2。已有 MinGW-w64 G++ 时运行 `python -B demo/build_windows_launcher.py --cc <g++路径> --output <包外新EXE路径>`。头文件和原始许可位于 `third_party/webview2/`。调试自动化可显式传 `--test-debug-port <端口>`，普通启动不开放调试端口；`--test-fixed-runtime` 可检查随包运行时。
