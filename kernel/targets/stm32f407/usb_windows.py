"""Windows USB discovery and synchronous CDC records. Uses Python's standard library."""
import ctypes as c
from ctypes import wintypes as w
import re
import secrets
import struct
import time
import uuid
import winreg

K = c.WinDLL("kernel32", use_last_error=True)
CM = c.WinDLL("cfgmgr32")
DFU_GUID = "01105872-bf45-43be-8b67-3c0f2b8cf0d9"
COM_GUID = "86e0d1e0-8089-11d0-9ce4-08003e301f73"
def win(name, args, result=w.BOOL):
    func=getattr(K, name)
    func.argtypes=args
    func.restype=result
    return func
open_file=win("CreateFileW",[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE],w.HANDLE)
close_handle=win("CloseHandle",[w.HANDLE])
read_file=win("ReadFile",[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p])
write_file=win("WriteFile",[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p])
get_state=win("GetCommState",[w.HANDLE,c.c_void_p])
set_state=win("SetCommState",[w.HANDLE,c.c_void_p])
set_timeouts=win("SetCommTimeouts",[w.HANDLE,c.c_void_p])
purge_comm=win("PurgeComm",[w.HANDLE,w.DWORD])
def require(ok, label):
    if not ok:
        code=c.get_last_error()
        raise OSError(code, label+": "+c.FormatError(code).strip())

class EngineError(RuntimeError):
    def __init__(self, code, message=None):
        self.code=code
        super().__init__(message or code)

def interfaces(guid):
    key=c.create_string_buffer(uuid.UUID(guid).bytes_le)
    size=w.ULONG()
    if CM.CM_Get_Device_Interface_List_SizeW(c.byref(size),key,None,0):
        return []
    for _ in range(3):
        block=c.create_unicode_buffer(size.value+1)
        status=CM.CM_Get_Device_Interface_ListW(key,None,block,len(block),0)
        if status==0:
            return [x for x in block[:].split("\0") if x]
        if CM.CM_Get_Device_Interface_List_SizeW(c.byref(size),key,None,0): break
    return []

def devices():
    found=[]
    for mode,guid,vidpid in (("dfu",DFU_GUID,"vid_0483&pid_df11"),("cdc",COM_GUID,"vid_1209&pid_0001")):
        for path in interfaces(guid):
            if vidpid not in path.lower(): continue
            parts=path[4:].split("#")
            if len(parts)<4: continue
            port=""
            if mode=="cdc":
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Enum\\"+"\\".join(parts[:3])+"\\Device Parameters") as key:
                        port=winreg.QueryValueEx(key,"PortName")[0]
                except OSError: pass
            found.append(dict(mode=mode,port=port,path=path,serial=parts[2].upper(),platform="STM32F407"))
    return found

def fnv(data):
    v=2166136261
    for b in data: v=((v^b)*16777619)&0xffffffff
    return v

try:
    from demo.platform_protocol import observe_frame
except ModuleNotFoundError as error:
    if error.name != 'demo':
        raise

    def observe_frame(*_args):
        pass


class Port:
    def __init__(self, item):
        name="\\\\.\\"
        self.h=open_file(name+item["port"] if item["port"] else item["path"],0xc0000000,0,None,3,0,None)
        if self.h==c.c_void_p(-1).value: raise EngineError("busy",str(c.WinError(c.get_last_error())))
        try:
            dcb=c.create_string_buffer(28)
            struct.pack_into("<I",dcb,0,28)
            require(get_state(self.h,dcb),"GetCommState")
            struct.pack_into("<II",dcb,4,115200,0x11)
            struct.pack_into("<BBB",dcb,18,8,0,0)
            require(set_state(self.h,dcb),"SetCommState")
            times=(w.DWORD*5)(0xffffffff,0,100,0,1500)
            require(set_timeouts(self.h,times),"SetCommTimeouts")
            require(purge_comm(self.h,0x0c),"PurgeComm")
        except BaseException:
            self.close()
            raise
    def close(self):
        if self.h is not None: close_handle(self.h);self.h=None
    def __enter__(self): return self
    def __exit__(self,*exc): self.close()
    def command(self,cmd,nonce=None,param=0,profile=0,budget=0,mlen=0,clen=0,entropy=0,flags=0,timeout=30,*,trace=None):
        if trace is None and cmd in (2,3):
            family='ML-KEM' if param>100 else 'ML-DSA'
            trace = f'{family}-{param} · '+('密码流程' if cmd==2 else 'ACVP 测试')
        label = f'命令 {cmd}'+(f' · {trace}' if trace else '')
        n=bytes.fromhex(nonce) if nonce is not None else secrets.token_bytes(16)
        if len(n)!=16:raise EngineError("invalid_request","nonce requires 16 bytes")
        seq=secrets.randbits(32)
        data=struct.pack("<4I16s7I",0x514d3441,1,cmd,seq,n,param,profile,budget,mlen,clen,entropy,flags)
        data+=struct.pack("<I",fnv(data))
        count=w.DWORD()
        require(write_file(self.h,data,len(data),c.byref(count),None),"CDC write")
        if count.value:
            observe_frame('STM32 USB CDC','TX',data[:count.value],label)
        if count.value!=len(data):raise EngineError("transport","short CDC write")
        deadline=time.monotonic()+timeout
        buf=c.create_string_buffer(256)
        result=bytearray()
        while len(result)<256:
            if time.monotonic()>=deadline:raise EngineError("timeout","CDC response timed out")
            require(read_file(self.h,buf,256-len(result),c.byref(count),None),"CDC read")
            result.extend(buf.raw[:count.value])
        r=struct.unpack("<64I",result)
        observe_frame('STM32 USB CDC','RX',bytes(result),f'{label} · 状态字 {r[23]:#x}')
        if (r[:4]!=(0x524d3441,1,cmd,seq) or bytes(result[16:32])!=n
            or fnv(result[:252])!=r[63]):raise EngineError("protocol","CDC response identity, sequence or checksum")
        if r[15]&0xfff!=0x413 or (r[14]>>4)&0xfff!=0xc24:raise EngineError("identity","unexpected target")
        return r

def select(mode=None,serial=None):
    ds=[x for x in devices() if (not mode or x["mode"]==mode) and (not serial or x["serial"].casefold()==str(serial).casefold())]
    if len(ds)!=1:raise EngineError("ambiguous" if ds else "no_device")
    return ds[0]

def hello(item):
    with Port(item) as port:r=port.command(1)
    if r[23]!=1: raise EngineError("protocol","HELLO was rejected")
    return dict(connected=True,mode="cdc",platform="STM32F407",serial=item["serial"],port=item["port"],uid=struct.pack("<3I",*r[16:19]).hex().upper(),build_tag=struct.pack("<4I",*r[8:12]).hex(),parameter=r[12],profile=r[13],clock_hz=r[19],cpuid=hex(r[14]),device_id=hex(r[15]),dwt_enabled=bool(r[22]),image_bytes=r[39],static_ram_bytes=r[40])

if __name__=="__main__":
    import sys
    if "--dfu" in sys.argv:
        with Port(select("cdc")) as p: print("DFU return:",p.command(6)[23])
    elif "--list" in sys.argv: print(devices())
    else: print(hello(select("cdc")))

