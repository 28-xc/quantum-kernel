# 工具使用说明

本作品使用Codex辅助完成代码编写、实验工具开发、数据分析、图表制作、报告与演示材料整理。工具使用范围和实际检查方式如下，算法及第三方实现的来源另见[来源与许可](sources_and_licenses.md)。

## AI辅助范围

Codex辅助代码与测试工具开发、实验设计、数据分析及文稿制作。使用的工作流包括 experimental-design、scientific-critical-thinking、nature-writing、nature-polishing、nature-figure 和 presentations:Presentations。代码通过构建、固定向量、差分及资源检查验证；统计结论对应随附原始数据和复算程序。

科研工作流中的scientific-critical-thinking采用Scientific Agent Skills提供的程序性指导。工具库说明见Kassis等，*Scientific Agent Skills: A Library of Procedural Knowledge for Research Agents*，arXiv:2609.00065v2，2026，https://doi.org/10.48550/arXiv.2609.00065。

## 编译、验证与测量

|工具|实际用途与检查范围|
|---|---|
|GCC、Clang及二进制工具|构建Windows与AArch64算法库，生成C与汇编对象，检查指令、程序段、符号、共享常数及展开信息；编译选项由各构建记录保存。|
|AddressSanitizer、UndefinedBehaviorSanitizer|在记录的有限正常、边界与差分输入上检查地址访问和未定义行为。|
|CBMC|对选定编码、符号恢复和提示判定性质进行有界模型检查，保存输入前提、循环展开与检查结果。|
|QEMU及交叉编译器|执行本作Cortex-M4与RV32目标程序，检查功能、字长、布局与资源；结果按仿真目标标识。|
|OpenSSL、Go、liboqs、BoringSSL及固定标准向量|按相应接口和参数范围进行标准一致性或独立互操作检查，保存实际库、版本与逐例结果。|
|独立测试驱动与操作系统接口|执行完整算法和固定内存池应用，记录实际耗时、栈水位、工作区、清理状态及错误恢复；应用计时包含初始化到关闭清理。|

## 数据与材料制作

Python用于数据整理、SHA-256身份核对和实验编排，NumPy用于均值、分位数和区组重采样统计，Matplotlib用于科学绘图。Windows统计复算环境使用Python 3.13.2与NumPy 2.2.5，AArch64统计环境使用Python 3.10.12与NumPy 1.26.4；绘图使用Matplotlib 3.10.9或3.10.1，具体版本按各图记录。各数据集和图形记录其实际运行环境，随包离线NumPy版本为2.2.5。跨架构复算逐项核验原始样本、源码与区组抽样，浮点派生值采用公开的数值容差，并记录实际最大差异。随附数据保留预热及正式原始样本，统计入口按记录的配对、区组和采样条件复算。

Microsoft Word用于模板前页，XeLaTeX用于报告正文排版，PowerPoint COM用于重建16页可编辑演示文稿，并检查版面、导出PDF和原生文本形状。Edge浏览器通过CDP截取实际界面，演示视频按实际帧时间编码；终端截图记录真实程序输出，PDF与逐页图像用于版面检查。正文、图表和演示材料的数值以对应数据文件为依据。

从完整附件根目录开始，构建、验证、离线复算与显式重新采集的命令见[复现说明](reproduction.md)。各步骤输出实际命令、退出状态及文件摘要。
