"""Persistent CDC client. All results come from one live STM32F407 application."""
import argparse, contextlib, csv, hashlib, secrets, struct, sys, xml.etree.ElementTree as ET
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from usb_windows import Port,EngineError,devices

PARAMETERS=(512,768,1024,44,65,87)
PROFILE={'compact':1,'cached':2}
from engine import image_folder
DEFAULT_IMAGE=image_folder()/'stm32f407-unified.xml'
def decode_i32(x):return x-(1<<32) if x&(1<<31) else x
def as_bytes(words):return struct.pack('<'+'I'*len(words),*words)
def read_manifest(image=None):
    image=Path(image or DEFAULT_IMAGE)
    if image.is_dir():image=image/'stm32f407-unified.xml'
    tree=ET.parse(image).getroot();m=dict(tree.attrib)
    expected=bytes.fromhex(m['sha256']);data=image.with_suffix('.bin').read_bytes()
    if hashlib.sha256(data).digest()!=expected or len(data)!=int(m['image_bytes']):raise EngineError('image_invalid','firmware file digest or length mismatch')
    lo=int(m['base'],0);hi=lo+len(data);sp,pc=struct.unpack_from('<II',data)
    if lo!=0x08020000 or hi>0x08100000 or (sp&7) or not (0x20008000<sp<=0x20010000) or not (pc&1 and lo<=pc-1<hi):raise EngineError('image_invalid','firmware vector or memory span')
    cells={(int(e.get('parameter')),e.get('strategy')):int(e.get('workspace_capacity')) for e in tree.findall('implementation')}
    if not cells or any(p not in PARAMETERS or s not in PROFILE or cap<=0 for (p,s),cap in cells.items()):raise EngineError('image_invalid','invalid selectable implementations')
    return m,cells
def choose(serial=None):
    items=[d for d in devices() if d['mode']=='cdc' and (not serial or d['serial'].upper()==serial.upper())]
    if len(items)!=1:raise EngineError('ambiguous' if items else 'no_device','one running unified STM32F407 is required')
    return items[0]
def caps(image=None):
    _,cells=read_manifest(image)
    return {f'{p}/{s}':v for (p,s),v in cells.items()}

class Session:
    def __init__(self,image=None,serial=None):
        self.image=image;self.serial=serial;self.port=None
    def __enter__(self):
        self.meta,self.cells=read_manifest(self.image)
        self.device=choose(self.serial);self.port=Port(self.device)
        try:
            hello=self.port.command(1)
            m=self.meta
            if (hello[23],hello[12],hello[13],hello[41],hello[42])!=(1,0,240,0x554e4931,len(self.cells)):raise EngineError('identity','expected a unified firmware capability response')
            mask=sum(1<<PARAMETERS.index(p) for p in set(p for p,s in self.cells))
            if hello[43]!=mask or hello[44]!=6 or hello[39]!=int(m['image_bytes']) or hello[40]!=int(m['full_reserved_ram_bytes']) or as_bytes(hello[8:12]).hex()!=m['tag']:raise EngineError('identity','capability or build tag differs')
            self.uid=as_bytes(hello[16:19]).hex().upper()
            if self.device['serial'].upper()!=self.uid:raise EngineError('identity','USB serial and on-chip UID differ')
            self._validate_chip(hello)
            check=self.port.command(11,timeout=10)
            self._validate_chip(check)
            if not (check[23]==1 and check[49]==int(m['base'],0) and check[50]==int(m['image_bytes']) and as_bytes(check[41:49]).hex()==m['sha256']):raise EngineError('identity','computed on-board Flash SHA-256 differs from distribution')
            self.hello_words=hello;self.hash_words=check
            self.identity=dict(connected=True,mode='cdc',platform='STM32F407',serial=self.uid,uid=self.uid,port=self.device['port'],build_tag=m['tag'],firmware_sha256=m['sha256'],firmware_readback=True,firmware_hash_method='SHA-256 of executing image read by STM32',image_storage='flash',image_bytes=hello[39],static_ram_bytes=hello[40],clock_hz=hello[19],cpuid=hex(hello[14]),device_id=hex(hello[15]),verified_application=True,dwt_enabled=bool(hello[22]))
            return self
        except BaseException:self.close();raise
    def _validate_chip(self,r):
        if as_bytes(r[16:19]).hex().upper()!=self.uid or as_bytes(r[8:12]).hex()!=self.meta['tag'] or r[19]!=168000000 or r[20]&12!=8 or (r[21]&63)!=8 or ((r[21]>>6)&511)!=336 or not r[22]&1:raise EngineError('identity','UID, clock, DWT or build changed')
    def close(self):
        if self.port is not None:self.port.close();self.port=None
    def __exit__(self,*args):self.close()
    def run(self,parameter,strategy='compact',mode='normal',message_len=32,context_len=8,nonce=None,workspace_bytes=None,*,entropy='hardware',command='run'):
        cap=self.cells.get((parameter,strategy));n=nonce or secrets.token_hex(16)
        if not cap or mode not in ('normal','insufficient') or command not in ('run','kat','boundary','clock','timing') or entropy not in ('hardware','deterministic') or type(message_len)!=int or type(context_len)!=int or not (0<=message_len<=256 and 0<=context_len<=255):raise EngineError('invalid_request')
        try:
            if len(n)!=32 or len(bytes.fromhex(n))!=16:raise ValueError
        except (TypeError,ValueError):raise EngineError('invalid_request','nonce must encode 16 bytes')
        budget=(1 if mode=='insufficient' else cap) if workspace_bytes is None else workspace_bytes
        if type(budget)!=int or not 1<=budget<=cap:raise EngineError('invalid_request','workspace capacity')
        code={'run':2,'kat':3,'boundary':4,'clock':5,'timing':7}[command]
        r=self.port.command(code,n,parameter,PROFILE[strategy],budget,message_len,context_len,int(entropy=='hardware'),int(mode=='insufficient'),timeout=45)
        self._validate_chip(r)
        if (r[12],r[13],r[38],r[39],r[40])!=(parameter,PROFILE[strategy],cap,int(self.meta['image_bytes']),int(self.meta['full_reserved_ram_bytes'])):raise EngineError('identity','selected implementation or allocation differs')
        mask=r[23]
        result=dict(self.identity,parameter=parameter,strategy=strategy,implementation=strategy,mode=mode,request_id=n.lower(),operation_names=['keypair','encaps','decaps'] if parameter>100 else ['keypair','sign','verify'],cycles=list(r[28:32]),workspace_peaks=list(r[32:36]),stack_peaks=list(r[57:61]),stack_peak=max(r[36],*r[57:61]),stack_capacity=r[37],workspace_capacity=r[38],workspace_bytes=r[41],message_len=r[42],context_len=r[43],clock_cfgr=hex(r[20]),clock_pllcfgr=hex(r[21]),clock_cr=hex(r[55]),flash_kib=r[56],return_codes=[decode_i32(x) for x in r[24:28]],raw_words=r,entropy_source=entropy)
        if command=='clock':
            result.update(passed=mask==1,usb_frames=r[41],sof_cycles=r[42],measured_clock_hz=r[43]);return result
        result.update(guard_intact=r[52]==1,reference_heap_peak=r[62])
        if command=='kat':
            count=3 if parameter>100 else 4
            result.update(passed=mask==(1<<count)-1 and bool(r[52]),kat_ids=list(r[44:44+count]),kat_count=r[48],checks={'case'+str(i+1):bool(mask&(1<<i)) for i in range(count)});return result
        checks={k:bool(mask&v) for k,v in (('keypair',1),('operation2',2),('operation3',4),('tamper',8),('cleanup',16),('random_failure',32),('bounds',64),('alias',512))}
        checks['guards']=bool(r[52])
        if command=='boundary':checks.update(canonical_reject=decode_i32(r[53])==-6,misaligned_arena=decode_i32(r[54])==0,length_limit=decode_i32(r[61])==-2)
        if mode=='insufficient':checks.update(capacity_rejected=bool(mask&128),recovered=bool(mask&256))
        result.update(passed=all(checks.values()),checks=checks,tamper_check=checks['tamper'],insufficient_rc=decode_i32(r[44]) if mode=='insufficient' else None,recovery_rc=decode_i32(r[45]) if mode=='insufficient' else None,entropy_failure_rc=decode_i32(r[46]),length_failure_rc=decode_i32(r[47]),alias_failure_rc=decode_i32(r[51]),public_key_checksum=f'{r[49]:08x}',public_output_checksum=f'{r[50]:08x}',encoding_rc=decode_i32(r[53]),misaligned_rc=decode_i32(r[54]),limit_rc=decode_i32(r[61]))
        return result

def probe(image_dir=None,serial=None):
    with Session(image_dir,serial) as s:return dict(s.identity)
def run(parameter,strategy='compact',mode='normal',message_len=32,context_len=8,nonce=None,image_dir=None,serial=None,workspace_bytes=None,*,entropy='hardware',command='run'):
    with Session(image_dir,serial) as s:
        return s.run(parameter,strategy,mode,message_len,context_len,nonce,workspace_bytes,entropy=entropy,command=command)

def smoke(image,serial,output):
    output=Path(output)
    output.mkdir(parents=True,exist_ok=True)
    dst=output/'live-frames.tsv'
    if dst.exists():raise FileExistsError(dst)
    partial=output/'live-frames.in-progress.tsv'
    with partial.open('x',encoding='utf-8-sig',newline='') as f,Session(image,serial) as board:
        with (output/'session-open.bin').open('xb') as evidence:
            evidence.write(as_bytes(board.hello_words));evidence.write(as_bytes(board.hash_words))
        writer=csv.writer(f,delimiter='\t',lineterminator='\n')
        writer.writerow(('index','uid','port','parameter','strategy','kind','mode','entropy','request_id','passed','sha256',*(f'w{i}' for i in range(64))))
        trials=[]
        cells=list(board.cells)
        for cmd,mode,entropy in (('clock','normal','deterministic'),('kat','normal','deterministic'),('run','normal','deterministic'),('run','insufficient','deterministic'),('boundary','normal','hardware')):
            ns={p:secrets.token_hex(16) for p,s in cells}
            for p,st in cells:
                trials.append((p,st,cmd,mode,entropy,ns[p]))
            cells.reverse()
        seen={}
        for i,(p,st,cmd,mode,en,n) in enumerate(trials):
            r=board.run(p,st,mode,256 if cmd=='boundary' else 32,255 if cmd=='boundary' else 8,n,entropy=en,command=cmd)
            writer.writerow((i,r['uid'],r['port'],p,st,cmd,mode,en,n,int(r['passed']),r['firmware_sha256'],*r['raw_words']));f.flush()
            if not r['passed']:raise RuntimeError(('failed physical trial',i,p,st,cmd,r.get('checks'),r['return_codes']))
            if en=='deterministic' and cmd=='run':
                k=(p,cmd,mode,n);pair=(r['public_key_checksum'],r['public_output_checksum'])
                if seen.setdefault(k,pair)!=pair:raise RuntimeError('public outputs differ across strategies')
        final=board.port.command(11,timeout=10);board._validate_chip(final)
        if final[23]!=1 or as_bytes(final[41:49]).hex()!=board.meta['sha256']:raise RuntimeError('final resident image digest changed')
        with (output/'session-close.bin').open('xb') as evidence:evidence.write(as_bytes(final))
        print('physical cases',len(trials),'one live USB handle',board.uid,board.device['port'],board.meta['sha256'],flush=True)
    partial.replace(dst)

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('command',choices=['capabilities','probe','run','smoke']);ap.add_argument('--image',type=Path,default=DEFAULT_IMAGE);ap.add_argument('--serial');ap.add_argument('--param',type=int,default=512);ap.add_argument('--strategy',choices=PROFILE,default='compact');ap.add_argument('--mode',choices=['normal','insufficient'],default='normal');ap.add_argument('--output',type=Path);a=ap.parse_args()
    if a.command=='capabilities':print(caps(a.image))
    elif a.command=='probe':print(probe(a.image,a.serial))
    elif a.command=='run':print({k:v for k,v in run(a.param,a.strategy,a.mode,image_dir=a.image,serial=a.serial).items() if k!='raw_words'})
    elif a.output:smoke(a.image,a.serial,a.output)
    else:ap.error('--output is required for smoke')

