#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>
#include <string>

static int show_error(const wchar_t* message, DWORD code) {
    wchar_t details[2048];
    _snwprintf(details, 2048, L"%ls\n\n系统错误码：%lu", message, code);
    details[2047] = 0;
    MessageBoxW(nullptr, details, L"Quantum Kernel", MB_OK | MB_ICONERROR);
    return 1;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR arguments, int) {
    wchar_t executable[32768];
    DWORD length = GetModuleFileNameW(nullptr, executable, 32768);
    if (!length || length >= 32768)
        return show_error(L"无法读取启动程序的位置。", GetLastError());
    wchar_t* separator = wcsrchr(executable, L'\\');
    if (!separator)
        return show_error(L"无法读取支撑材料目录。", ERROR_PATH_NOT_FOUND);
    *separator = 0;
    std::wstring directory(executable);
    directory += L"\\03_复现环境与运行程序\\软件演示程序";
    std::wstring target = directory + L"\\Quantum Kernel Desktop.exe";
    DWORD attributes = GetFileAttributesW(target.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
        return show_error(L"未找到 Quantum Kernel 主程序。请将本启动程序保留在支撑材料根目录，并确认“03_复现环境与运行程序\\软件演示程序”目录完整。", ERROR_FILE_NOT_FOUND);
    std::wstring command = L"\"" + target + L"\"";
    if (arguments && *arguments) {
        command += L" ";
        command += arguments;
    }
    STARTUPINFOW startup = {};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process = {};
    if (!CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE,
                        0, nullptr, directory.c_str(), &startup, &process))
        return show_error(L"Quantum Kernel 启动失败。请检查当前目录的访问权限。", GetLastError());
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 0;
}
