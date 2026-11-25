"""Compiler discovery and checked subprocess execution; tools can live outside the source tree."""
from pathlib import Path
import csv,hashlib,os,shutil,subprocess
LLVM=Path(os.environ.get('LLVM_BIN',str(Path(os.environ.get('LOCALAPPDATA',''))/'Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin')))
ARM=['--target=arm-none-eabi','-mcpu=cortex-m4','-mthumb','-mfloat-abi=soft','-ffreestanding','-fno-builtin','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-unaligned-access','-ffunction-sections','-fdata-sections','-Os','-Wno-unknown-attributes','-DSTM32F4']
AS=None
LOG=[]
def need(v,msg):
    if not v:raise ValueError(str(msg))
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write(path,rows):
    with path.open('w',encoding='utf-8',newline='') as f:
        wr=csv.DictWriter(f,fieldnames=rows[0],delimiter='\t');wr.writeheader();wr.writerows(rows)
def run(args,cwd):
    prog=subprocess.run([str(q) for q in args],cwd=cwd,capture_output=True)
    if prog.returncode:raise RuntimeError(subprocess.list2cmdline(list(map(str,args)))+'\n'+prog.stderr.decode('utf-8','replace')[-4000:])
    LOG.append((str(args[0]),str(cwd),list(map(str,args[1:]))))
    return prog.stdout.decode('utf-8','replace')
