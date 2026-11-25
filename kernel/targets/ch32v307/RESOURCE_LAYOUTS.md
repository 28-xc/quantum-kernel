# CH32V307 的两种策略与静态布局

对外策略由 `tools/kernel.py` 统一选择。`low-memory` 使用 `compact`；`performance` 根据完整固件 RAM 预算选择 `partial64` 或 `cached`。三者均覆盖 ML-KEM-512/768/1024 与 ML-DSA-44/65/87 的 18 项完整操作。32/64/80 KiB 布局分别在构建时确定。

|策略|内部构建布局|完整固件 RAM / B|程序装载空间 / B|典型应用预算|
|---|---|---:|---:|---:|
|低内存|compact|28096|46624|32 KiB|
|性能|partial64|63968|45472|64 KiB|
|性能|cached|70112|45216|80 KiB|

上述完整 RAM 来自链接映像，包含全局数据、工作区及保护字节、调用者输入输出和通信缓冲、2048 字节 API 栈与 1024 字节控制栈。板上物理 RAM 为 128 KiB，与应用预算分别核算；其他应用状态或中断栈需要另行计入。

`partial64` 延用 `cached` 的算法和 CH32 专用算术后端，仅将 ML-DSA-87 的矩阵缓存上限由 56 个多项式调为 48 个，保存完整六列，最后一列按需生成。ML-DSA-44/65 仍使用完整缓存。实际工作区从 52320 字节降至 46176 字节，完整固件 RAM 降低 6144 字节。64 KiB 链接脚本有硬容量断言。

该布局的收益是满足 64 KiB 部署边界。2026-10-16 同板、96 MHz、12 个配对交错块的实测中，18 项等频总耗时比 `cached` 增加 2.60%，ML-DSA-87 签名平均增加 12.45%。数据位于工作区外层 `artifacts/board/paired-cached-partial64`。

## 公共源码与专用差异

三个配方各登记 135 个输入。所有相同内容均按 SHA-256 校验；构建器将逻辑输入放入独立输入视图，记录实际依赖。

* `cached` 与 `partial64` 的 135 个输入内容完全相同，差异在构建常量、链接限制与固件版本。
* `cached`/`partial64` 各引用 36 个主工程公共源，`compact` 引用 69 个。主要包括 `src/dsa_compact/build/sign_bitmap_stream_alias/adapted` 中的公共 ML-DSA 代码、`src/dsa_packed` 的公共工作区头，以及 `build/adapted_mlkem` 的公共 ML-KEM 代码。
* CH32 的标量约减、蝶形与点积、缓存实现、平台启动/计时/串口仍保留专用输入。`compact` 与缓存布局使用各自的算术实现。
* API 头文件快照与配方一同登记，用于重建对应控制映像。
* 控制构建使用目标源码快照；三种布局的依赖见 `profiles/*/recipe.xml`。

`cached`、`compact` 及 `partial64` 的 BIN/HEX 重建一致性记录见 `artifacts/board/common-source-aliases-applied.json` 和 `*-common-rebuild/result.xml`。

## 构建与验证

三个已验证布局均通过 `profiles.xml` 登记，统一使用 `build.py --profile <布局>`，要求 BIN/HEX 与已验证的登记映像逐字节一致。构建要求显式 WCH 工具链路径及新的源树外输出目录，不自行访问硬件。研究阶段的配方快照保留在 `profiles/history-before-source-unification/partial64-validated-research-recipe.xml`；`build_research.py` 仅供未登记的新候选使用。

`research_device.py`、`research_flows.py` 是显式指定实板和映像的验证工具，不是资源管理 API。板上测试使用固定时钟、关闭可屏蔽中断、固定熵回调；1744 字节的缓存布局静态 API 栈界和动态高水位仅适用于该构建及调用环境。移植时按实际回调和中断条件核算栈。

签名重试诊断映像、计数数组与脚本保存在实验产物目录，用于重试行为检查。
