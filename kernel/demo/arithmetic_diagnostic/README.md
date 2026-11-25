# Windows 算术库

Windows x64 的 `native_arithmetic.dll` 由此目录的 C 适配层链接作品自身的 `compact-rate / portable / Os / LTO` 构建。加减、环乘、NTT 和 INTT 直接调用工程中的 `lc_poly_*`。约减、采样、精确编解码及密文量化调用相应算法已存在的源代码。

在内核源代码根目录运行以下命令，使用 Windows x64 MinGW 工具链，测试使用 GCC 15.2.0。输出路径选择包外全新的目录。

```powershell
python -B .\demo\arithmetic_diagnostic\build_diagnostic.py --source . --output D:\a127-arithmetic-rebuild
```

输出 `build.json` 保存诊断 DLL 和已链接静态库的摘要，`build-commands.json` 保存构建参数。适配层用整数负循环卷积、直接多项式求值、独立 SHAKE 和标准位串规则检查输出。测试使用公开种子和系数。
