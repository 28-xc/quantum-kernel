"""Store Crangler configurations as typed XML and pass its native input by pipe."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

for parent in Path(__file__).resolve().parents:
    if (parent / 'record_io.py').is_file():
        sys.path.insert(0,str(parent))
        break
import record_io


def windows_pipe(command, payload):
    import ctypes
    from ctypes import wintypes as win
    import time
    import uuid

    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.CreateNamedPipeW.argtypes=[win.LPCWSTR,win.DWORD,win.DWORD,win.DWORD,win.DWORD,win.DWORD,win.DWORD,win.LPVOID]
    api.CreateNamedPipeW.restype=win.HANDLE
    api.ConnectNamedPipe.argtypes=[win.HANDLE,win.LPVOID]
    api.SetNamedPipeHandleState.argtypes=[win.HANDLE,ctypes.POINTER(win.DWORD),win.LPVOID,win.LPVOID]
    api.WriteFile.argtypes=[win.HANDLE,win.LPCVOID,win.DWORD,ctypes.POINTER(win.DWORD),win.LPVOID]
    api.FlushFileBuffers.argtypes=[win.HANDLE]
    api.CloseHandle.argtypes=[win.HANDLE]
    pipe=r'\\.\pipe\cbmc-config-'+uuid.uuid4().hex
    # Outbound byte stream, one reader, initially nonblocking while connecting.
    handle=api.CreateNamedPipeW(pipe,0x80000|2,1,1,65536,0,0,None)
    if handle==win.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        with subprocess.Popen([*command,pipe]) as process:
            try:
                deadline=time.monotonic()+30
                while not api.ConnectNamedPipe(handle,None):
                    error=ctypes.get_last_error()
                    if error==535:break  # ERROR_PIPE_CONNECTED
                    if process.poll() is not None:return process.returncode or 1
                    if error!=536:raise ctypes.WinError(error)
                    if time.monotonic()>deadline:raise TimeoutError('Crangler did not open its configuration')
                    time.sleep(.01)
                blocking=win.DWORD(0)
                if not api.SetNamedPipeHandleState(handle,ctypes.byref(blocking),None,None):
                    raise ctypes.WinError(ctypes.get_last_error())
                offset=0
                while offset<len(payload):
                    chunk=payload[offset:offset+65536]
                    size=win.DWORD()
                    if not api.WriteFile(handle,chunk,len(chunk),ctypes.byref(size),None) or not size.value:
                        raise ctypes.WinError(ctypes.get_last_error())
                    offset+=size.value
                if not api.FlushFileBuffers(handle):
                    raise ctypes.WinError(ctypes.get_last_error())
                api.CloseHandle(handle)
                handle=None
                return process.wait()
            except BaseException:
                if process.poll() is None:process.kill()
                raise
    finally:
        if handle is not None:api.CloseHandle(handle)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='operation',required=True)
    encode=commands.add_parser('store')
    encode.add_argument('path',type=Path)
    encode.add_argument('--source',required=True)
    encode.add_argument('--output',required=True)
    for field in ('include','define','function','object'):
        encode.add_argument('--'+field, action='append', default=[])
    run=commands.add_parser('run')
    run.add_argument('path',type=Path)
    run.add_argument('executable',nargs='+')
    args=parser.parse_args()
    if args.path.suffix.lower()!='.xml':
        parser.error('Crangler configuration requires an .xml path')
    if args.operation=='store':
        value={
            'sources': [args.source], 'includes': args.include, 'defines': args.define,
            'functions': [{name: ['remove static'] for name in args.function}],
            'objects': [{name: ['remove static'] for name in args.object}],
            'output': args.output,
        }
        temp=None
        try:
            with tempfile.NamedTemporaryFile('w',encoding='utf8',dir=args.path.parent,delete=False) as out:
                temp=out.name
                record_io.dump(value,out)
            os.replace(temp,args.path)
        finally:
            if temp:Path(temp).unlink(missing_ok=True)
        return 0
    source=args.path.read_bytes()
    if not source.lstrip().startswith(b'<record'):
        raise ValueError('Expected a typed XML Crangler configuration')
    payload=json.dumps(record_io.loads(source),ensure_ascii=False).encode('utf8')
    if os.name=='nt':
        return windows_pipe(args.executable,payload)
    return subprocess.run([*args.executable,'/dev/stdin'],input=payload).returncode


if __name__=='__main__':
    sys.exit(main())
