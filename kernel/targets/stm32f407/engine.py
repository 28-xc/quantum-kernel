"""STM32F407 challenge/response through the board's USB CDC application.

ROM DfuSe is used only to verify and load a reviewed upper-SRAM image.
Application requests and responses travel through the CDC port.
"""
from pathlib import Path
import contextlib
import ctypes
from ctypes import wintypes as wt
import hashlib
import os
import secrets
import struct
import sys
import time
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
if str(HERE) not in sys.path:sys.path.insert(0,str(HERE))
from usb_windows import devices, EngineError, Port, hello
import dfu_transport as dfu

PARAMETERS=(512,768,1024,44,65,87)
PROFILES={"probe":0,"compact":1,"cached":2,"reference":3,"m4fstack":4,"cached-m4f":5}
_verified={}
def _rom_serial(uid):
    try: a,b,c=struct.unpack("<3I",bytes.fromhex(uid))
    except (ValueError,struct.error):return ""
    return f"{(a+c)&0xffffffff:08X}{b>>16:04X}"

def _select(serial=None):
    rows=devices()
    if serial:
        value=str(serial).upper()
        rows=[x for x in rows if value in (x["serial"],_rom_serial(x["serial"])) or _rom_serial(value)==x["serial"]]
    if len(rows)!=1:raise EngineError("ambiguous" if rows else "no_device")
    return rows[0]

def image_folder(image_dir=None):
    if image_dir is not None:return Path(image_dir).resolve()
    candidates=[HERE/"firmware"]
    for parent in HERE.parents:
        folder=parent/"03_复现环境与运行程序/firmware/STM32F407"
        if folder.is_dir(): candidates.extend([folder/"固件",folder/"firmware",folder])
    for f in candidates:
        if (f/"p512-compact.xml").is_file():return f
    return candidates[0]

def capabilities(image_dir=None):
    images=[]
    for p in sorted(image_folder(image_dir).glob("p*-*.xml")):
        try:
            row=ET.parse(p).getroot()
            if row.tag!="image" or row.get("strategy") not in PROFILES:continue
            d=dict(row.attrib)
            for k in ("parameter","profile","image_bytes","workspace_capacity","clock_hz","main_sram_bytes","ccm_bytes","stack_capacity"):d[k]=int(d[k])
            d["build_tag"]=d["tag"]
            if (p.parent/(p.stem+".bin")).is_file():images.append(d)
        except (OSError,ValueError,KeyError,ET.ParseError):continue
    return dict(strategies=[k for k in ("compact","cached") if any(i["strategy"]==k for i in images)],images=images,parameters=list(PARAMETERS),message_lengths=[0,32,256],context_lengths=[0,8,32],modes=["normal","insufficient"])

@contextlib.contextmanager
def _device_lock():
    lib=ctypes.WinDLL("kernel32",use_last_error=True)
    create=lib.CreateMutexW;create.argtypes=[ctypes.c_void_p,wt.BOOL,wt.LPCWSTR];create.restype=wt.HANDLE
    wait=lib.WaitForSingleObject;wait.argtypes=[wt.HANDLE,wt.DWORD];wait.restype=wt.DWORD
    release=lib.ReleaseMutex;release.argtypes=[wt.HANDLE]
    close=lib.CloseHandle;close.argtypes=[wt.HANDLE]
    handle=create(None,False,"Local\\A127_STM32F407_SRAM_ENGINE")
    if not handle:raise EngineError("transport","cannot create hardware session lock")
    acquired=wait(handle,0) in (0,0x80)
    try:
        if not acquired:raise EngineError("busy")
        yield
    finally:
        if acquired:release(handle)
        close(handle)

def probe(image_dir=None,serial=None):
    try:
        item=_select(serial)
        if item["mode"]=="dfu":
            return dict(connected=True,mode="dfu",platform="STM32F407",serial=item["serial"],port="",verified_application=False)
        with _device_lock():
            result=hello(item)
            result["rom_serial"]=_rom_serial(result["uid"])
            return result
    except EngineError as ex:
        if ex.code=="no_device":return dict(connected=False,mode="disconnected",platform="STM32F407")
        raise
    except OSError as ex:raise EngineError("transport",str(ex)) from ex

def _wait(mode,serial,timeout=18):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            item=_select(serial)
            if item["mode"]==mode:return item
        except EngineError as ex:
            if ex.code=="ambiguous":raise
        time.sleep(0.15)
    raise EngineError("timeout","waiting for "+mode)

def _identity(result,meta,rom_serial):
    if result['build_tag']!=meta['tag'] or result['parameter']!=meta['parameter'] or result['profile']!=meta['profile'] or result['image_bytes']!=meta['image_bytes'] or _rom_serial(result['uid'])!=rom_serial:
        raise EngineError("identity","SRAM image, UID or build differs from the selected target")
    if result['clock_hz']!=168000000 or not result['dwt_enabled']:
        raise EngineError("identity","clock/DWT register validation failed")

def _image(param,strategy,image_dir):
    meta=next((r for r in capabilities(image_dir)["images"] if r["parameter"]==param and r["strategy"]==strategy),None)
    if not meta:raise EngineError("image_missing",f"{param}/{strategy}")
    data=(image_folder(image_dir)/(meta['name']+'.bin')).read_bytes()
    if len(data)!=meta['image_bytes'] or hashlib.sha256(data).hexdigest()!=meta["sha256"] or not 128<len(data)<dfu.END-dfu.BASE:
        raise EngineError("image_invalid","length or SHA-256 mismatch")
    sp,entry=struct.unpack_from("<II",data)
    if not (dfu.BASE<sp<dfu.END and sp%8==0 and dfu.BASE<=entry-1<dfu.BASE+len(data) and entry&1):
        raise EngineError("image_invalid","SRAM vector table")
    return meta,data

def _upload_sram(rom,data,sha256):
    # A freshly enumerated WinUSB device can return ERROR_BAD_COMMAND (22) or
    # ERROR_DEVICE_NOT_CONNECTED (1167) before DfuSe requests are ready.
    # SRAM staging is idempotent. After LEAVE is issued no retry is allowed.
    deadline=time.monotonic()+10
    attempts=0
    while True:
        attempts+=1
        dev=None
        try:
            item=_wait("dfu",rom,timeout=max(.1,deadline-time.monotonic()))
            if item["serial"]!=rom:raise EngineError("identity","ROM serial changed during staging")
            dev=dfu.Device(item['path'])
            dfu.identify(dev)
            err,state=dev.status()[::2]
            if (err,state)==(10,10):dev.ctrl(False,4)
            dev.idle()
            for off in range(0,len(data),1024):
                dev.write(dfu.BASE+off,data[off:off+1024])
            h=hashlib.sha256()
            for off in range(0,len(data),1024):
                h.update(dev.read(dfu.BASE+off,min(1024,len(data)-off)))
            if h.hexdigest()!=sha256:raise EngineError("image_invalid","on-board SRAM readback mismatch")
        except OSError as ex:
            if dev is not None:dev.close()
            number=getattr(ex,'winerror',None) or getattr(ex,'errno',None)
            if number not in (22,1167):raise
            if attempts>=5 or time.monotonic()>=deadline:
                raise EngineError("timeout",f"DFU {rom} was not ready after {attempts} attempts (Windows {number})") from ex
            time.sleep(min(.2*attempts,.8))
            continue
        except BaseException:
            if dev is not None:dev.close()
            raise
        try:
            dev.leave()
        finally:
            dev.close()
        return

def _ensure(param,strategy,image_dir,serial):
    meta,data=_image(param,strategy,image_dir)
    item=_select(serial)
    if item["mode"]=="cdc":
        status=hello(item);rom=_rom_serial(status['uid'])
        if status['build_tag']==meta['tag'] and _verified.get(rom)==meta['sha256']:
            _identity(status,meta,rom)
            return item,meta,status
        with Port(item) as p:
            if p.command(6)[23]!=1:raise EngineError("protocol","DFU transition rejected")
        item=_wait("dfu",rom)
    rom=item['serial']
    _verified.pop(rom,None)
    _upload_sram(rom,data,meta['sha256'])
    item=_wait("cdc",rom)
    deadline=time.monotonic()+5
    while True:
        try:status=hello(item);break
        except EngineError as ex:
            if ex.code!="busy" or time.monotonic()>=deadline:raise
            time.sleep(.15)
    _identity(status,meta,rom)
    _verified[rom]=meta['sha256']
    return item,meta,status

def signed(x):return x if x<0x80000000 else x-0x100000000
def run(parameter,strategy="compact",mode="normal",message_len=32,context_len=8,nonce=None,image_dir=None,serial=None,workspace_bytes=None,*,entropy="hardware",command="run"):
    n=nonce or secrets.token_hex(16)
    try:nb=bytes.fromhex(n)
    except (TypeError,ValueError) as ex:raise EngineError("invalid_request","16-byte nonce") from ex
    if len(nb)!=16 or len(n)!=32 or parameter not in PARAMETERS or strategy not in PROFILES or PROFILES[strategy]==0 or mode not in ("normal","insufficient") or not 0<=message_len<=256 or not 0<=context_len<=255 or entropy not in ("hardware","deterministic") or command not in ("run","kat","timing","clock","boundary"):
        raise EngineError("invalid_request")
    try:
        with _device_lock():
            item,meta,identity=_ensure(parameter,strategy,image_dir,serial)
            cap=meta['workspace_capacity']
            budget=workspace_bytes if workspace_bytes is not None else (1 if mode=="insufficient" else cap)
            if type(budget) is not int or not 1<=budget<=cap:raise EngineError("invalid_request","workspace budget outside compiled allocation")
            cmd={"run":2,"kat":3,"timing":7,"clock":5,"boundary":4}[command]
            with Port(item) as p:
                r=p.command(cmd,n,parameter,meta['profile'],budget,message_len,context_len,int(entropy=='hardware'),int(mode=='insufficient'),timeout=45)
            if struct.pack("<4I",*r[8:12]).hex()!=meta['tag'] or r[12]!=parameter or r[13]!=meta['profile'] or struct.pack("<3I",*r[16:19]).hex().upper()!=identity['uid'] or (r[20]&12)!=8 or (r[21]&63)!=8 or ((r[21]>>6)&511)!=336 or not (r[22]&1):
                raise EngineError("identity","response build, chip UID, clock or DWT mismatch")
            response=dict(identity,request_id=bytes(n).hex() if isinstance(n,bytes) else n.lower(),firmware_sha256=meta['sha256'],firmware_readback=True,strategy=strategy,mode=mode,implementation=strategy,parameter=parameter,operation_names=["keypair","encaps","decaps"] if parameter>100 else ["keypair","sign","verify"],clock_hz=r[19],cycles=list(r[28:32]),workspace_peaks=list(r[32:36]),stack_peaks=list(r[57:61]),stack_peak=max(r[36],*r[57:61]),stack_capacity=r[37],workspace_capacity=r[38],image_bytes=r[39],static_ram_bytes=r[40],workspace_bytes=r[41],message_len=r[42],context_len=r[43],clock_cfgr=hex(r[20]),clock_pllcfgr=hex(r[21]),clock_cr=hex(r[55]),flash_kib=r[56],return_codes=[signed(v) for v in r[24:28]],raw_words=r,entropy_source=entropy)
            mask=r[23]
            if cmd==5:
                response.update(passed=mask==1,usb_frames=r[41],sof_cycles=r[42],measured_clock_hz=r[43])
                return response
            response.update(guard_intact=bool(r[52]),reference_heap_peak=r[62])
            if cmd==3:
                count=3 if parameter>100 else 4
                response.update(passed=mask==(1<<count)-1 and bool(r[52]),kat_ids=list(r[44:44+count]),kat_count=r[48],checks={"case"+str(i+1):bool(mask&(1<<i)) for i in range(count)})
                return response
            checks={key:bool(mask&bit) for key,bit in (("keypair",1),("operation2",2),("operation3",4),("tamper",8),("cleanup",16),("random_failure",32),("bounds",64),("alias",512))}
            checks["guards"]=bool(r[52])
            if cmd==4:
                checks.update(canonical_reject=signed(r[53])==-6,misaligned_arena=signed(r[54])==0,length_limit=signed(r[61])==-2)
                response.update(encoding_rc=signed(r[53]),misaligned_rc=signed(r[54]),limit_rc=signed(r[61]))
            if mode=="insufficient":checks.update(capacity_rejected=bool(mask&128),recovered=bool(mask&256))
            response.update(passed=all(checks.values()),checks=checks,tamper_check=checks['tamper'],insufficient_rc=signed(r[44]) if mode=="insufficient" else None,recovery_rc=signed(r[45]) if mode=="insufficient" else None,entropy_failure_rc=signed(r[46]),length_failure_rc=signed(r[47]),alias_failure_rc=signed(r[51]),public_key_checksum=f"{r[49]:08x}",public_output_checksum=f"{r[50]:08x}")
            return response
    except EngineError:raise
    except TimeoutError as ex:raise EngineError("timeout",str(ex)) from ex
    except OSError as ex:
        errno=getattr(ex,'winerror',None) or getattr(ex,'errno',None)
        code="busy" if errno in (5,32) else "no_device" if errno in (1167,31) else "transport"
        raise EngineError(code,str(ex)) from ex
    except (ValueError,RuntimeError) as ex:
        raise EngineError("transport",str(ex)) from ex

def return_dfu(serial=None):
    with _device_lock():
        item=_select(serial)
        if item['mode']=='dfu':return True
        known=hello(item)
        with Port(item) as p:
            if p.command(6)[23]!=1:raise EngineError("protocol")
        _wait("dfu",_rom_serial(known['uid']))
        return True

if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument('action',choices=['devices','probe','dfu','run','kat','boundary','clock'])
    p.add_argument('--param',type=int,default=512);p.add_argument('--strategy',default='compact')
    p.add_argument('--mode',default='normal');p.add_argument('--entropy',default='hardware')
    p.add_argument('--images',type=Path);p.add_argument('--nonce')
    args=p.parse_args()
    if args.action=='devices':print(devices())
    elif args.action=='probe':print(probe())
    elif args.action=='dfu':print(return_dfu())
    else:
        result=run(args.param,args.strategy,args.mode,nonce=args.nonce,image_dir=args.images,entropy=args.entropy,command=args.action)
        for key,val in result.items():print(key,val,sep='\t')
        sys.exit(0 if result['passed'] else 1)

