# CH32V307 双策略固件

使用 MounRiver Studio 2 附带的 WCH RISC-V Embedded GCC 8.2.0。设置 WCH_GCC 或用 --cc 指定 riscv-none-embed-gcc.exe。在源码根目录运行，输出目录位于支撑材料之外且尚未创建。

~~~powershell
py -3 -B targets/ch32v307/finals/build.py --strategy both --out ..\..\..\CH32构建
~~~

低内存与高性能配置分别为 32k-dynamic-wide、high-sponge-fixed2。两档编译输入依路径和 SHA-256 记入 inputs.tsv。构建程序核对工具、源码、RAM 构成、固件 build_id、BIN、HEX 及发布 ELF。发布 ELF 将链接器记录在 STT_FILE 中的构建目录移除。程序头、加载段、运行地址和符号含义均与实测 ELF 对应。原始与发布 ELF 的校验值见 [发布ELF对应](发布ELF对应.xml)。

固件和演示入口位于支撑材料的 03_复现环境与运行程序/firmware/CH32V307/双策略。该目录的 original/firmware.elf 是原现场运行程序的公开构建产物。设备的整片备份保存在现场电脑的输出目录，恢复后重新校验。
