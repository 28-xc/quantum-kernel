# 分配失败与释放前清理检查

本测试对六组参数的十八项完整操作逐一观察实际分配，在每个成功路径经过的分配位置注入一次失败，再使用同一接口上下文恢复运行。输入和随机种子固定，恢复后的完整输出逐字节比较；签名比较包含全部签名字节。

每次对象分配后填入固定非零模式，并在对象返回分配器之前检查全部对象字节已经清零，同时检查后进先出释放顺序、工作区两侧保护字节、容量错误传播和失败输出清理。测试包含故意保留非零对象的检测器正控制。检测范围是这些固定输入所经过的分配位置；容量连续扫描由其他接口测试完成。

## 运行

先从待测源码正常构建包含六参数的静态库，保留 `build.xml`、`commands.xml` 和原构建源码，再执行：

```text
python tests/owner_boundaries/run.py --source-root SOURCE --package BUILD --output NEW_RESULT_DIRECTORY --cc gcc
```

输出目录必须为尚不存在的新目录。测试分别使用Windows GCC/MinGW64与Linux AArch64 GCC。原始构建命令所指的源文件和头文件应仍然可用。`SOURCE` 用于定位公开接口头文件，`BUILD` 中必须有 `liblatticecore.a`。

## 观察方法与结果

链接时间优化可能在链接包装之前已经解析分配器调用。为保持观察入口有效，脚本仅重编译原构建中的 `arena.c` 和 `adapter.c`：保持分配器函数体及其他函数内容，给分配器增加测试观察入口，并对这两个翻译单元关闭 LTO。其余算法对象直接来自原静态库。

脚本分别生成直接链接原静态库的程序和带观察入口的程序，并逐字节比较十八项操作的完整输出。带观察入口的程序还执行逐分配失败、恢复和清理检查。输出 `result.xml` 保存编译器版本、全部编译命令、退出状态、源文件、修改后的测试副本、静态库与可执行程序摘要以及逐项结果。原静态库保持不变。

这项测试验证故障传播与对象生命周期。程序经过测试插桩，性能测量使用正常构建。

## 裁剪后的静态库

部署重链接目录的`commands.xml`通常只保存重链接命令。此时先生成独立测试目录，将最终静态库和构建记录原样复制，并从其完整父构建补入`arena.c`与`adapter.c`的两条成功编译命令：

```text
python tests/owner_boundaries/prepare_package.py --parent FULL_BUILD --package DEPLOYED_BUILD --output NEW_TEST_PACKAGE
python tests/owner_boundaries/run.py --source-root SOURCE --package NEW_TEST_PACKAGE --output NEW_RESULT_DIRECTORY --cc gcc
```

`FULL_BUILD`和`DEPLOYED_BUILD`均指包含`build.xml`、`commands.xml`及`liblatticecore.a`的目录。适配工具不重新编译或重链接库，原始归档保持不变；测试副本中的归档与部署归档逐字节一致。它只为观察驱动补齐两条原编译命令，保留部署目录的全部命令，并生成`view-receipt.xml`，记录输入文件、复制文件、选择的命令和源码摘要。运行时仍需能访问这些原编译命令引用的源码与头文件。

完整构建已经包含两条编译命令时，直接使用前述`run.py`入口。分配观察结果保留派生元数据的身份，生产库的性能与资源记录继续绑定原始构建。
