# PE 归档实体裁剪与重链接

`relink_pe.py` 接收 GCC 已完成构建中的 `build.xml`、`commands.xml`、`obj/`、原生汇编归档及导出定义。它保留输入对象，分别生成完整对照和裁剪候选，并重放动态、静态接口测试。两个输出目录必须全新且彼此独立。

```text
python tools/relink_pe.py --parent BUILD --control CONTROL --output OUTPUT
  --cc GCC --ar GCC_AR --nm NM --objdump OBJDUMP
  --omit-member EXACT_ARCHIVE_MEMBER.o
```

参数须在同一命令中提供；每个待省略成员使用一次 `--omit-member`。名称必须来自原 `libnative_assembly.a`。工具链应与原构建一致，归档成员及优化选项取自已记录命令。

工具从待省略成员的实际全局定义建立符号集合，重汇编链接器保存的最终 LTO 机器汇编，检查所有节的重定位及未定义符号。对照保留对象自身的元数据单独存档。对照的 `.text`、`.pdata`、`.xdata` 必须与原构建相同；候选保留导入、导出及每条仍在使用的 Windows 展开记录。

输出包含 `closure.json`、`paired-link-record.xml`、更新后的 `build.xml`、逐条命令日志和全部原对象。失败过程保存在新目录，原构建保持原样。`build.xml` 绑定原源码身份和本次重链接证据；算法一致性、完整性能及资源测试按生成后的程序身份另行执行。
