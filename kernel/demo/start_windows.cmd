@echo off
chcp 65001 >nul
setlocal
set "DEMO=%~dp0..\..\..\03_复现环境与运行程序\软件演示程序\格运算内核演示.exe"
if not exist "%DEMO%" (
  echo 请完整解压支撑材料，并从 03_复现环境与运行程序 中打开格运算内核演示.exe。
  pause
  exit /b 2
)
start "" "%DEMO%"
