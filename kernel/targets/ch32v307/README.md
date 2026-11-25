# CH32V307 实板构建

## 决赛两档

实板演示提供低内存和高性能两套固件。构建及实测固件对应关系见 [两档固件](finals/README.md)。下列历史配置对应各自实测记录。

`direct-twiddles` 为 80 KiB 速度配置，`compact-direct-twiddles` 为 32 KiB 紧凑配置，64 KiB 采用 `partial64`。原 `cached` 和 `compact` 分别重建融合半表及逐层变换对照。`native-*` 与 `pr91*` 为具名公开对照，`without-*` 为逐项机制消融。所有配置均保存各自精确源文件、编译器、选项和预留空间。

```text
python targets/ch32v307/build.py --profile direct-twiddles --output <源码以外的新目录> --cc <riscv-none-embed-gcc路径>
```

映像验证逐字节核对完整 BIN/HEX，构建标识用于匹配实测固件。调试 ELF 仅生成在输出目录，不随源码分发。源码清单与构建日志分别记录当前输入身份。
