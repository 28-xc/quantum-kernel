# 板端构建依赖

本仓库包含寄存器适配、算法、链接及体积限制配置源码。正式实验映像的历史构建配方验证输入 SHA-256，并依据所用工具链产生固件。

- **STM32F407**。见 [STM32F407 构建说明](kernel/targets/stm32f407/README.md)和[六参数部署目录](kernel/targets/stm32f407/六参数部署/构建.md)。复刻原映像须另备配方要求的工具链与静态库。
- **CH32V307**。准备与[构建配方](kernel/targets/ch32v307/profiles/)匹配的 WCH 工具链。按 [SDK 说明](kernel/targets/ch32v307/SDK-NOTICE.md)从芯片厂商取得 WCH SDK。配方中的 SDK 输入位于 kernel/targets/ch32v307/source/targets/ch32v307/sdk/ 下。核对配方中的文件路径及摘要后，使用[板端构建入口](kernel/targets/ch32v307/build.py)在新目录构建。

精确复刻 CH32 参赛映像还需要原部署包配方登记的 WCH 派生启动文件 startup_ch32v30x_D8C_monitored.S。该文件与 WCH SDK 由原环境补齐。公开仓库保留项目的算法、计时、链接配置和板端适配源码。
