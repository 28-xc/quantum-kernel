# 实板主机驱动

`ch32_serial.py` 是实测使用的固定版本驱动，SHA-256 为 `28952091587d469bfa00639c5350faf3d65e1f21f04ee297b7737534b1c703c2`。`vendor/serial` 为相同实测环境的 pySerial 3.5 Python 源文件；保留文件头及 BSD-3-Clause 许可。文件内容和来源哈希记录在 `source-manifest.xml`。

pySerial 许可证来源：[pySerial v3.5 LICENSE.txt](https://raw.githubusercontent.com/pyserial/pyserial/v3.5/LICENSE.txt)。

仅导入本驱动不会访问串口；明确创建 `SerialDevice` 才连接设备。研究工具接受 `--port` 和 `--driver`。实际烧录工具另需显式提供 `--openocd` 或环境变量 `LC_CH32_OPENOCD`。OpenOCD 固定为已验证 SHA-256：`0f49153f490e8d89b391da9717e01f67c380f641c59600aec483113762469b65`，同目录需包含 WCH 的 `wch-riscv.cfg`。

所有烧录操作仍须给出已构建映像、独立输出目录和回退目录；目标芯片识别、工具身份和回退文件先于写入核对。WCH 工具链及 OpenOCD 由使用者自行安装，仓库不重新分发它们。

`research_device.py` 即使不传 `--flash`，也会连接调试器、暂停处理器并在读取后重启当前映像。实测发现 WCH 调试器重新连接后直接继续运行可能扰动串口状态，因此保留读取的运行后证据，再明确重启以恢复固件初始化。非烧写映像核对采用 Flash 装载段直接读回，不在正在运行的固件 RAM 中执行校验算法。串口采样和 SWD 检查须串行进行。
