"""Read STM32 standard DfuSe status, transfer only within the upper on-chip SRAM window."""
import ctypes as c
from ctypes import wintypes as wt
import hashlib, re, struct, sys, time
from pathlib import Path

K=c.WinDLL('kernel32',use_last_error=True)
W=c.WinDLL('winusb',use_last_error=True)
BASE=0x20008000
END=0x20020000
BOX=BASE+0x100
ROOT=Path(__file__).resolve().parent
class Setup(c.LittleEndianStructure):
    _pack_=1
    _fields_=[('kind',c.c_uint8),('request',c.c_uint8),('value',c.c_uint16),('index',c.c_uint16),('length',c.c_uint16)]
def api(lib,name,args,rest=wt.BOOL):
    fn=getattr(lib,name); fn.argtypes=args; fn.restype=rest; return fn
open_dev=api(K,'CreateFileW',[wt.LPCWSTR,wt.DWORD,wt.DWORD,c.c_void_p,wt.DWORD,wt.DWORD,wt.HANDLE],wt.HANDLE)
close=api(K,'CloseHandle',[wt.HANDLE])
init=api(W,'WinUsb_Initialize',[wt.HANDLE,c.POINTER(wt.HANDLE)])
free=api(W,'WinUsb_Free',[wt.HANDLE])
transfer=api(W,'WinUsb_ControlTransfer',[wt.HANDLE,Setup,c.c_void_p,wt.ULONG,c.POINTER(wt.ULONG),c.c_void_p])
get_desc=api(W,'WinUsb_GetDescriptor',[wt.HANDLE,c.c_uint8,c.c_uint8,c.c_uint16,c.c_void_p,wt.ULONG,c.POINTER(wt.ULONG)])
get_alt=api(W,'WinUsb_GetCurrentAlternateSetting',[wt.HANDLE,c.POINTER(c.c_uint8)])
def err(op):
    n=c.get_last_error(); return OSError(n,op+': '+c.FormatError(n).strip())
def log(*a):
    pass
class Device:
    def __init__(self,device_path):
        self.file=open_dev(device_path,0xc0000000,3,None,3,0x40000000,None); self.dev=wt.HANDLE()
        if self.file==c.c_void_p(-1).value:raise err('open DFU')
        if not init(self.file,c.byref(self.dev)):
            ex=err('WinUsb_Initialize');close(self.file);self.file=None;raise ex
    def close(self):
        if self.dev:free(self.dev);self.dev=None
        if self.file:close(self.file);self.file=None
    def descriptor(self,t,i=0,lang=0):
        buf=c.create_string_buffer(1024); l=wt.ULONG()
        if not get_desc(self.dev,t,i,lang,buf,len(buf),c.byref(l)):raise err('descriptor')
        return bytes(buf.raw[:l.value])
    def ctrl(self,reading,request,value=0,payload=b'',length=0):
        n=length if reading else len(payload)
        buf=c.create_string_buffer(max(1,n))
        if not reading and n:c.memmove(buf,payload,n)
        out=wt.ULONG();header=Setup(0xA1 if reading else 0x21,request,value,0,n)
        if not transfer(self.dev,header,buf if n else None,n,c.byref(out),None):
            raise err(f'DFU request {request} value {value}')
        if out.value!=n:raise RuntimeError(f'short control transaction {request} {out.value}/{n}')
        return buf.raw[:n] if reading else b''
    def status(self):
        b=self.ctrl(True,3,length=6)
        return b[0],int.from_bytes(b[1:4],'little'),b[4]
    def idle(self):
        rc,ms,state=self.status()
        if rc:raise RuntimeError(f'DFU reported status={rc}, state={state}; stop')
        if state in (5,9):
            self.ctrl(False,6)
            rc,ms,state=self.status()
        if rc or state!=2:raise RuntimeError(f'DFU not idle status={rc} state={state}')
    def finish_download(self):
        end=time.monotonic()+4
        while time.monotonic()<end:
            rc,ms,st=self.status()
            if rc:raise RuntimeError(f'DFU operation rejected: status={rc}, state={st}')
            if st==5:return
            if st not in (3,4) or ms>3500:raise RuntimeError(f'unexpected DFU state={st} timeout={ms}')
            time.sleep(max(ms/1000,0.001))
        raise TimeoutError('DFU download status timeout')
    def pointer(self,addr):
        if not BASE<=addr<END:raise ValueError('address outside upper SRAM')
        self.idle();self.ctrl(False,1,0,b'\x21'+struct.pack('<I',addr));self.finish_download()
    def read(self,addr,n):
        if not (BASE<=addr and 1<=n<=2048 and addr+n<=END):raise ValueError('read outside upper SRAM')
        self.pointer(addr);self.idle();data=self.ctrl(True,2,2,length=n);self.idle();return data
    def write(self,addr,data):
        if not (BASE<=addr and 1<=len(data)<=2048 and addr+len(data)<=END):raise ValueError('write outside upper SRAM')
        self.pointer(addr);self.ctrl(False,1,2,data);self.finish_download()
    def leave(self):
        self.pointer(BASE);self.ctrl(False,1,2,b'')
        try:log('leave GETSTATUS',self.status())
        except OSError as e:log('leave, USB detached during status:',e)
def identify(dev):
    desc=dev.descriptor(1)
    if len(desc)!=18:raise ValueError('invalid USB descriptor')
    vendor,product,bcd=struct.unpack_from('<HHH',desc,8)
    if (vendor,product)!=(0x0483,0xdf11):raise ValueError('unexpected DFU VID/PID')
    cfg=dev.descriptor(2);i=0;alts=[]
    while i+2<=len(cfg) and cfg[i]>=2:
        ln,t=cfg[i:i+2];item=cfg[i:i+ln]
        if t==4 and ln>=9:alts.append((item[2],item[3],item[5:8].hex(),item[8]))
        if t==0x21 and ln>=9:log('DFU functional descriptor',item.hex(),'transfer size',int.from_bytes(item[5:7],'little'))
        i+=ln
    cur=c.c_uint8()
    if not get_alt(dev.dev,c.byref(cur)):raise err('GetCurrentAlternateSetting')
    if cur.value!=0 or not any(inter==0 and alt==0 and cl=='fe0102' for inter,alt,cl,idx in alts):raise ValueError('STM32 DfuSe interface required')
    log(f'USB device {vendor:04x}:{product:04x} bcdDevice={bcd:04x} alt={cur.value}',alts)
    for inter,alt,cl,idx in alts:
        if idx:
            try:log('alt descriptor',alt,dev.descriptor(3,idx,0x409)[2:].decode('utf-16-le'))
            except OSError:pass
    log('DFU status, poll ms, state',dev.status())
