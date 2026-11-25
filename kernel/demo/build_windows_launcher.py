"""仅重建原生 Windows 桌面宿主，不编译或修改密码算法。"""
from pathlib import Path
import argparse, ctypes, os, shutil, subprocess, tempfile
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cc', default='g++', help='MinGW-w64 G++ 路径')
p.add_argument('--output', type=Path, required=True, help='支撑材料之外、不存在的 EXE 路径')
p.add_argument('--work-root',type=Path,help='可选的包外英文临时构建目录')
p.add_argument('--root-entry',action='store_true',help='生成放在支撑材料根目录的启动入口')
a=p.parse_args()
source=Path(__file__).resolve().parent/('windows_root_entry.cpp' if a.root_entry else 'windows_desktop.cpp')
header=source.parent.parent/'third_party/webview2/WebView2.h'
icon=source.with_name('quantum-kernel.ico')
output=a.output.resolve();package=source.parents[3]
if output.exists() or output.is_relative_to(package):p.error('请指定支撑材料之外、不存在的 EXE 路径')
if not a.root_entry and not header.is_file():p.error('缺少随附 Microsoft WebView2 SDK 头文件')

def ascii_path(path):
    path=path.resolve()
    if str(path).isascii():return path
    if os.name=='nt':
        value=ctypes.create_unicode_buffer(32768)
        if ctypes.windll.kernel32.GetShortPathNameW(str(path),value,len(value)) and value.value.isascii():return Path(value.value)
    return None

candidates=[a.work_root] if a.work_root else [Path(tempfile.gettempdir()),output.parent]
work_root=None
for candidate in candidates:
    candidate=candidate.resolve()
    if candidate.is_relative_to(package):continue
    candidate.mkdir(parents=True,exist_ok=True)
    work_root=ascii_path(candidate)
    if work_root:break
if not work_root:p.error('编译器需要英文临时路径，请用 --work-root 指定包外英文目录')
output.parent.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='lattice-desktop-',dir=work_root) as temporary:
    work=Path(temporary);shutil.copyfile(source,work/'windows_desktop.cpp')
    if not a.root_entry:shutil.copyfile(header,work/'WebView2.h')
    shutil.copyfile(icon,work/'quantum-kernel.ico')
    (work/'desktop.rc').write_text('101 ICON "quantum-kernel.ico"\n',encoding='ascii')
    resource_compiler=str(Path(a.cc).with_name('windres.exe' if os.name=='nt' else 'windres'))
    subprocess.run([resource_compiler,'desktop.rc','-O','coff','-o','desktop-icon.o'],cwd=work,check=True)
    command=[a.cc,'-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wno-unknown-pragmas',
             '-Wno-missing-field-initializers','-Wno-cast-function-type','-municode','-mwindows','-static',
             'windows_desktop.cpp','desktop-icon.o','-I','.','-o','desktop.exe','-lcomctl32','-lcomdlg32','-lshell32','-lgdi32',
             '-lws2_32','-lole32','-luuid','-ladvapi32']
    result=subprocess.run(command,cwd=work)
    if result.returncode:raise SystemExit(result.returncode)
    if not (work/'desktop.exe').is_file():p.error('编译器未生成桌面程序')
    with output.open('xb') as destination,(work/'desktop.exe').open('rb') as generated:shutil.copyfileobj(generated,destination)
print('已生成桌面程序：'+str(output))
