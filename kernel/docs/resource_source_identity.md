# 资源结果的源码身份

`lattice.deployment_resources.v3` 为每个测量点记录独立的源码身份。完整源码清单位于 `sources/<SHA256>.json`，实际构建消费清单位于 `builds/<SHA256>.json`。两份文件采用相对路径和 SHA-256；构建消费清单同时绑定实际程序、原始构建记录、完整源码清单、参数集合及编译配置。

`publicschemas.resources.load()` 核验外部清单的完整字节、清单间引用和每项消费源码。`validate()` 负责数据结构核验；文件导入及公开服务使用 `load()`。资源预算查询沿用同平台、同程序和同工作区的完整操作统计。

各测量点分别关联源码清单、编译条件和程序摘要，能够区分同平台的不同实现。标准验证由逐映像验证数据集提供，资源文件保存分项容量及共同上下文证据。

`tools/import_resource_identities.py`从资源记录、源码清单、构建记录与实际程序生成公开资源视图，逐一核验文件摘要。公开输出使用相对文件名，保持原始数值及每个测量点的身份。

共同上下文和内存水位分别使用`lattice.common_context_observations.v2`与`lattice.resource_watermarks.v2`。观察文件关联资源文件摘要，并为各程序保存`source_build_binding_sha256`。复算器检查数据、程序和资源的对应关系，再计算共同工作区、完整栈及其他预留容量。
