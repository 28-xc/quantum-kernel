"""ROM DfuSe read-only recognition and GO for the packaged upper-Flash application."""
import contextlib, hashlib, struct, time
from pathlib import Path
from . import dfu_transport
from . import engine as legacy
from . import unified_engine as unified

BASE=0x08020000
def _idle(dev):
    status,ms,state=dev.status()
    if (status,state)==(10,10):dev.ctrl(False,4)
    dev.idle()
def _address(dev,addr,end):
    if not BASE<=addr<end<=0x08100000:raise ValueError('invalid upper-Flash address')
    dev.idle()
    # DfuSe SET_ADDRESS_POINTER. No erase and no data download.
    dev.ctrl(False,1,0,b'\x21'+struct.pack('<I',addr))
    dev.finish_download()
def _read(dev,address,length,end):
    if length<1 or length>1024 or address+length>end:raise ValueError('invalid bounded ROM read')
    _address(dev,address,end);dev.idle()
    data=dev.ctrl(True,2,2,length=length);dev.idle()
    return data

def _session(serial,read_action):
    # Retry read-only setup after Windows enumerates WinUSB. Never retry a GO command.
    deadline=time.monotonic()+8
    for attempt in range(4):
        dev=None
        try:
            item=legacy._wait('dfu',serial,timeout=max(.1,deadline-time.monotonic()))
            if item['serial']!=serial:raise unified.EngineError('identity','ROM serial changed')
            dev=dfu_transport.Device(item['path']);dfu_transport.identify(dev);_idle(dev)
            return read_action(dev)
        except OSError as exc:
            no=getattr(exc,'winerror',None) or getattr(exc,'errno',None)
            if no in (5,32):raise unified.EngineError('busy','USB programmer owns the ROM interface') from exc
            if no not in (22,1167) or attempt==3 or time.monotonic()>=deadline:raise
        finally:
            if dev:dev.close()
        time.sleep(.16*(attempt+1))
    raise unified.EngineError('timeout')

def check_installed(path,serial,launch=False,*,verify=False):
    meta,cells=unified.read_manifest(path)
    data=Path(path).with_suffix('.bin').read_bytes()
    limit=BASE+len(data)
    def inspect(dev):
        # A catalog probe only recognizes the packaged vector/header prefix; it never starts the MCU.
        if _read(dev,BASE,64,limit)!=data[:64]:return False
        if not (launch or verify):return True
        h=hashlib.sha256()
        for off in range(0,len(data),1024):
            h.update(_read(dev,BASE+off,min(1024,len(data)-off),limit))
        if h.hexdigest()!=meta['sha256']:raise unified.EngineError('identity','installed upper-Flash image SHA-256 mismatch')
        if not launch:return True
        _address(dev,BASE,limit)
        # Mark the GO attempt separately so a write/status detachment cannot replay it.
        try:
            dev.ctrl(False,1,2,b'')
            try:dev.status()
            except OSError as exc:
                if (getattr(exc,'winerror',None) or getattr(exc,'errno',None)) not in (31,1167,22):raise
        except OSError as exc:
            raise unified.EngineError('transport','ROM GO delivery uncertain; reconnect to identify current mode') from exc
        return True
    return _session(serial,inspect)

