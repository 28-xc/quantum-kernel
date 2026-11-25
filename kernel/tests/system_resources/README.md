# Linux 系统资源实验的源码与复现

本目录提供实际采集器的原始源码、逐文件 SHA-256、原编译选项和本地复现入口。`source_lock.xml` 将源码版本、已测驱动摘要和四份公开观测集绑定。接收者可直接复算附件数据，也可在 Linux AArch64 上重新构建采集器，按同一固定条件生成新的观察记录。

|公开观测集|任务数|实际控制器/驱动|
|---|---:|---|
|资源主实验·容量|144|`constraints/run.py`，原 v1|
|资源主实验·内存限额|864|`constraints/run_v2.py`|
|资源主实验·CPU 配额|864|`constraints/run_v2.py`|
|256 KiB 冷文件页边界|216|`constraints/run_v2.py`|
|进程地址空间占用|72|`footprint/footprint.c`|
|PMU 配置比较|40|`pmu/run_pmu.py`，pmu-v3 驱动|
|PMU 机制消融|90|同上，独立公开种子组|

`constraints`、`pmu` 和 `footprint` 三个子目录保留历史采集器的 12 个 C/头文件/Python 文件；Python 文件的读写格式已迁移。容量控制器使用原有暖文件状态；后续内存、CPU 和边界控制器在每次启动前仅对所测项目可执行文件和密码库发出文件页丢弃建议。采集器记录完整退出状态、部分输出、cgroup 计数和采样内存轨迹。

PMU 使用原有五个用户态事件，32 次预热结束后通过 FIFO 应答握手启用计数器，完成指定数量的上下文初始化和完整操作后停计数。40 项和 90 项任务分别保留各自次序、种子、重复编号和调用次数。`footprint` 在完整操作及清理后读取当前进程 `/proc/self/status`；其 `VmHWM` 与继承的 `ru_maxrss` 分别记录。

## 准备和重建

从支撑附件根目录执行。`prepare` 可在 Windows 或 Linux 上运行，只生成固定任务表：

```text
python source/tests/system_resources/replay.py prepare --bundle . --output <新的准备目录>
python source/tests/system_resources/test_replay.py --bundle .
```

该入口读取公开 observations 和 `image_inventory.xml`，以二进制 SHA 定位本地库，核对全部科学输入和条件；保留 2,290 项任务。每项绑定参数、操作、工作区、CPU、随机种子、样本数、限额、文件页策略和采集器版本。运行前会再次从公开观测重建条件表，拒绝变化的种子、限额、控制器或缺失条件。

在原生 Linux AArch64 上构建四个采集器：

```text
python source/tests/system_resources/replay.py build --cc gcc --output <新的构建目录>
python source/tests/system_resources/replay.py smoke --bundle . --tasks <准备目录>/tasks.xml --build <构建目录> --output <新的功能目录>
```

普通功能检查执行六参数十八操作，每操作两次调用，并检查进程占用采集器。历史版本在 Ubuntu 22.04/GCC 11.4.0 的独立目录完成上述步骤；四个历史重建可执行文件与实际测量驱动的 SHA 全部相同。实测驱动另保存在 `methods/system_resources/`，用于按文件身份核对。

## 显式采集一个固定批次

```text
python source/tests/system_resources/replay.py run --bundle . --tasks <准备目录>/tasks.xml --build <构建目录> --batch configurations --uid <本地用户UID> --gid <本地用户GID> --output <新的PMU目录>
```

`--batch` 从表中七个实验标识选择一个：`memory_capacity`、`memory_latency`、`cpu_quota`、`memory_boundary`、`process_footprint`、`configurations`、`mechanisms`。每批次数量固定，每进程超时分别为容量 5 s，内存/CPU/边界/占用 10 s，PMU 45 s。新结果写入独立目录，保持归档观测原件。

cgroup 批次需要本地管理员或已配置的 CPU/memory 控制器权限，短进程进入新建实验组后降至显式 UID/GID 执行密码操作；PMU 需要操作系统允许相应事件计数。正式采集应在该机器没有编译、压缩和其他基准任务时执行。

原始数据复算仍使用附件统一离线入口：`offline_analysis.py --entry resource-limits`、`memory-boundary`、`process-footprint`、`complete-pmu`。这里的采集入口补充新环境复现实验，统计入口负责重算已保存的科学观测。
