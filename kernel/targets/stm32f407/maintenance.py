"""Maintain the resident F407 firmware in previously empty sectors 5, 6 and 7."""
from pathlib import Path
import argparse,contextlib,hashlib,os,re,secrets,shutil,struct,subprocess,sys,tempfile,time,xml.etree.ElementTree as ET
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import engine as legacy
import unified_engine as resident
from usb_windows import Port,devices,hello

UID='350048000D51353338393837'
BASE=0x08000000
SIZE=1<<20
FIRST=0x08020000
END=0x08080000
FILL=b'\xff'*(END-FIRST)
def sha(blob):return hashlib.sha256(blob).hexdigest()
def package_root():
    return next((p for p in HERE.parents if (p/'01_源代码').is_dir() and (p/'03_复现环境与运行程序').is_dir()),None)
def default_image():
    path=legacy.image_folder()/'stm32f407-unified.xml'
    if path.is_file():return path
    raise FileNotFoundError('locate stm32f407-unified.xml using --image')
def find_cli(value=None):
    paths=[value,os.environ.get('STM32_CUBE_CLI'),shutil.which('STM32_Programmer_CLI.exe')]
    for env in ('ProgramFiles','ProgramFiles(x86)'):
        p=os.getenv(env)
        if p:paths.append(Path(p)/'STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI.exe')
    if os.name=='nt':
        import winreg
        uninstall=r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        for hive in (winreg.HKEY_LOCAL_MACHINE,winreg.HKEY_CURRENT_USER):
            for bits in (winreg.KEY_WOW64_64KEY,winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(hive,uninstall,0,winreg.KEY_READ|bits) as stem:
                        for i in range(winreg.QueryInfoKey(stem)[0]):
                            try:
                                with winreg.OpenKey(stem,winreg.EnumKey(stem,i)) as entry:
                                    title=winreg.QueryValueEx(entry,'DisplayName')[0]
                                    if not str(title).casefold().startswith('stm32cubeprogrammer'):continue
                                    for field in ('InstallLocation','DisplayIcon'):
                                        try:item=winreg.QueryValueEx(entry,field)[0]
                                        except OSError:continue
                                        if not item:continue
                                        path=Path(str(item).split(',',1)[0].strip('"'))
                                        folder=path if field=='InstallLocation' else path.parent.parent
                                        paths.append(folder/'bin/STM32_Programmer_CLI.exe')
                            except OSError:continue
                except OSError:continue
    for item in paths:
        if item and Path(item).is_file():return Path(item).resolve()
    raise FileNotFoundError('locate STM32CubeProgrammer using --cube-cli')
def saved(path,data):
    if path.exists():raise FileExistsError(path)
    with path.open('xb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())
    if path.read_bytes()!=data:raise IOError('local verification failed: '+str(path))
def marker(path,fields):
    raw=ET.tostring(ET.Element('maintenance',{k:str(v) for k,v in fields.items()}),encoding='utf-8',xml_declaration=True)
    saved(path,raw)
def select_one(uid):
    rom=legacy._rom_serial(uid);matches=[x for x in devices() if x['serial'].upper() in (uid,rom)]
    if len(matches)!=1:raise RuntimeError('one selected original board must be connected in USB DFU or the verified application')
    return matches[0]
def expected_bytes(before,data):
    if not (len(before)==SIZE and 128<len(data)<=END-FIRST):raise ValueError('device or image span mismatch')
    off=FIRST-BASE
    return before[:off]+data+before[off+len(data):]
class Board:
    def __init__(self,image,cli,uid,log=None,probe_images=None):
        self.image=image.resolve(strict=True);self.m,_=resident.read_manifest(self.image)
        self.blob=self.image.with_suffix('.bin').read_bytes();self.cli=cli;self.uid=uid;self.rom=legacy._rom_serial(uid);self.log=log
        directories=(probe_images,self.image.parent,legacy.image_folder())
        self.probe_images=next((Path(d).resolve() for d in directories if d and (Path(d)/'p512-compact.xml').is_file()),None)
        if int(self.m['base'],0)!=FIRST or int(self.m['end_exclusive'],0)!=FIRST+len(self.blob) or len(self.blob)>END-FIRST:raise ValueError('image exceeds allowed sectors 5-7')
    def cmd(self,argv):
        found=select_one(self.uid)
        if found['mode']!='dfu' or found['serial']!=self.rom:raise RuntimeError('intended DFU device required')
        self.cli=find_cli(self.cli)
        cmd=[str(self.cli),'-c','port=USB1','sn='+self.rom,*map(str,argv)]
        proc=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120,creationflags=subprocess.CREATE_NO_WINDOW)
        out=proc.stdout.decode('utf-8','replace').replace('\x00','')
        if self.log:
            with self.log.open('a',encoding='utf-8') as f:
                f.write(' '.join(map(str,argv))+'\n'+out+'\n');f.flush()
        ids=re.findall(r'(?mi)^\s*SN\s*:\s*([A-F0-9]+)\s*$',out);dev=re.search(r'(?mi)^\s*Device ID\s*:\s*(0x[0-9a-f]+)',out)
        if proc.returncode or re.search(r'(?i)\bError\s*:',out) or ids!=[self.rom] or not dev or int(dev[1],16)!=0x413:raise RuntimeError('programmer device identity or transaction failed: '+out[-500:])
        return out
    def snapshot(self,address,n):
        if not (BASE<=address<BASE+SIZE and 0<n<=BASE+SIZE-address):raise ValueError('read beyond physical Flash')
        with tempfile.TemporaryDirectory(prefix='a127-read-') as d:
            path=Path(d)/'data.bin';self.cmd(['-u',hex(address),hex(n),path]);data=path.read_bytes()
            if len(data)!=n:raise IOError('truncated ROM upload')
            return data
    def identify_application(self,item):
        deadline=time.monotonic()+35
        while True:
            current=select_one(self.uid)
            if item.get('serial')!=self.uid or current.get('serial')!=self.uid or current.get('mode')!='cdc':
                raise RuntimeError('application serial or mode changed while waiting for release')
            try:
                status=hello(current)
                break
            except legacy.EngineError as exc:
                remaining=deadline-time.monotonic()
                if exc.code!='busy' or remaining<=0:raise
                time.sleep(min(.25,remaining))
        if status['uid']!=self.uid or (int(status['device_id'],16)&0xfff)!=0x413 or ((int(status['cpuid'],16)>>4)&4095)!=0xc24:raise RuntimeError('96-bit chip UID or Cortex-M4 identifier mismatch')
        return status
    def to_rom(self,item):
        with Port(item) as port:
            rsp=port.command(6,timeout=8)
            if rsp[23]!=1 or resident.as_bytes(rsp[16:19]).hex().upper()!=self.uid:raise RuntimeError('ROM transition rejected')
        legacy._wait('dfu',self.rom,timeout=30)
    def qualify(self):
        item=select_one(self.uid)
        if item['mode']=='cdc':
            self.identify_application(item);self.to_rom(item)
        # A bin from this same distribution executes in SRAM and reads true immutable MCU UID,
        # core ID, Flash capacity and 32 USB/SOF frames. This cannot write or erase Flash.
        if self.probe_images is None:raise RuntimeError('the distribution must contain the verified p512-compact SRAM firmware')
        meta,data=legacy._image(512,'compact',self.probe_images)
        legacy._upload_sram(self.rom,data,meta['sha256'])
        app=legacy._wait('cdc',self.rom,timeout=25)
        status=self.identify_application(app);legacy._identity(status,meta,self.rom)
        try:
            with Port(app) as p:r=p.command(5,param=512,profile=1,budget=meta['workspace_capacity'],timeout=10)
            if r[23]!=1 or r[41]!=32 or r[56]!=1024 or resident.as_bytes(r[16:19]).hex().upper()!=self.uid:raise RuntimeError('1 MiB Flash, 168 MHz clock or UID was not confirmed')
        finally:self.to_rom(app)
    def program(self):
        self.cmd(['--skipErase','-d',self.image.with_suffix('.bin'),hex(FIRST),'-v'])
    def erase_installed_sectors(self):
        self.cmd(['-e','5','6','7'])
class DeploymentError(ValueError):
    def __init__(self, message, *, can_reconnect=False):
        super().__init__(message)
        self.can_reconnect = can_reconnect


def boot_deployment(image, rom, uid=None):
    from . import resident_dfu

    if not resident_dfu.check_installed(image, rom, launch=True):
        raise legacy.EngineError('identity', 'resident image does not match the selected build')
    live = legacy._wait('cdc', rom, timeout=20)
    with resident.Session(image, uid or live['serial']) as running:
        if running.uid != live['serial'] or legacy._rom_serial(running.uid) != rom:
            raise legacy.EngineError('identity', 'a different USB device returned from ROM')
        return running.uid


def switch_deployment(current, requested, cli, uid, records):
    # The caller owns the hardware lock. Keep the full original image outside the package.
    records.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='stm32-deploy-', dir=records))
    previous = Board(current, cli, uid, log=folder/'programmer.log')
    target = Board(requested, cli, uid, log=folder/'programmer.log')
    start, stop = FIRST - BASE, END - BASE
    before = None
    dirty = False

    def enter_rom():
        item = select_one(uid)
        if item['mode'] == 'cdc':
            previous.identify_application(item)
            previous.to_rom(item)

    try:
        enter_rom()
        before = previous.snapshot(BASE, SIZE)
        previous_area = previous.blob + FILL[len(previous.blob):]
        if (before[start:stop] != previous_area or
                previous.snapshot(FIRST, END - FIRST) != previous_area):
            raise DeploymentError('当前 Flash 扇区与已登记固件不一致。')
        saved(folder/'original.bin', before)
        marker(folder/'backup.xml', dict(
            uid=uid, rom_serial=previous.rom, before_sha256=sha(before),
            previous_sha256=sha(previous.blob), target_sha256=sha(target.blob),
            span_start=hex(FIRST), span_end_exclusive=hex(END)))
        expected = before[:start] + target.blob + FILL[len(target.blob):] + before[stop:]
        dirty = True
        target.erase_installed_sectors()
        target.program()
        if target.snapshot(BASE, SIZE) != expected:
            raise DeploymentError('写入后整片 Flash 回读不一致。')
        boot_deployment(requested, target.rom, uid)
        marker(folder/'verified.xml', dict(uid=uid, image_sha256=sha(target.blob),
               full_flash_sha256=sha(expected), ram_budget_bytes=target.m['ram_budget_bytes']))
    except Exception as error:
        reason = str(error) if isinstance(error, DeploymentError) else 'STM32 部署未完成。'
        try:
            if dirty:
                enter_rom()
                present = previous.snapshot(BASE, SIZE)
                if present[:start] != before[:start] or present[stop:] != before[stop:]:
                    raise RuntimeError('Flash outside the authorized sectors changed')
                if present != before:
                    previous.erase_installed_sectors()
                    previous.program()
                    if previous.snapshot(BASE, SIZE) != before:
                        raise RuntimeError('Restored Flash readback differs from the backup')
            if select_one(uid)['mode'] == 'dfu':
                boot_deployment(current, previous.rom, uid)
            else:
                with resident.Session(current, uid):
                    pass
        except Exception:
            message = '请重新连接 STM32。'
            if (folder/'original.bin').is_file():
                message = f'原固件备份位于 {folder}。'
            raise DeploymentError(reason + message) from error
        raise DeploymentError(reason + '已重新核验原档固件。', can_reconnect=True) from error


def load_backup(folder,board):
    path=folder/'backup.xml';node=ET.parse(path).getroot()
    original=(folder/'original.bin').read_bytes();check=(folder/'blank-sectors-5-7.bin').read_bytes()
    if (node.tag!='maintenance' or node.get('uid')!=board.uid or node.get('rom_serial')!=board.rom or
        node.get('image_sha256')!=sha(board.blob) or node.get('before_sha256')!=sha(original) or len(original)!=SIZE or
        original[FIRST-BASE:END-BASE]!=FILL or check!=FILL):raise ValueError('backup identity or original sector contents differ')
    return original
def inspect(board):
    item=select_one(board.uid)
    if item['mode']=='cdc':
        status=board.identify_application(item)
        if (status['parameter'],status['profile'])!=(0,240):
            return f'{board.uid} 当前运行单体应用；本次未读取 Flash。'
        with resident.Session(board.image,board.uid) as s:
            return f'{s.uid} 常驻固件已运行；片上 SHA-256 {s.meta["sha256"]}'
    raw=board.snapshot(BASE,SIZE);target=raw[FIRST-BASE:END-BASE]
    if target==FILL:kind='5–7 扇区为空'
    elif target==board.blob+FILL[len(board.blob):]:kind='已安装选定版本'
    else:kind='5–7 扇区存在其他数据'
    # A ROM serial is a shortened derivative of the 96-bit UID. No app is started during a read-only check.
    return f'ROM {board.rom}，设备组 0x413，{kind}；全片 SHA-256 {sha(raw)}'
def install(board,folder):
    folder.mkdir(parents=True,exist_ok=True)
    if any(folder.iterdir()):raise ValueError('installation requires a fresh backup directory')
    board.log=folder/'programmer.log'
    board.qualify();original=board.snapshot(BASE,SIZE);old=original[FIRST-BASE:END-BASE]
    if old!=FILL:raise RuntimeError('sectors 5-7 contain existing data; no write was issued')
    independent=board.snapshot(FIRST,END-FIRST)
    if independent!=old:raise RuntimeError('independent sector read differs')
    saved(folder/'original.bin',original);saved(folder/'blank-sectors-5-7.bin',independent)
    image_copy=folder/'installed-image';image_copy.mkdir()
    saved(image_copy/'stm32f407-unified.xml',board.image.read_bytes())
    saved(image_copy/'stm32f407-unified.bin',board.blob)
    marker(folder/'backup.xml',dict(uid=board.uid,rom_serial=board.rom,before_sha256=sha(original),image_sha256=sha(board.blob),span_start=hex(FIRST),span_end_exclusive=hex(END)))
    if load_backup(folder,board)!=original:raise IOError('original Flash recovery set is incomplete')
    expected=expected_bytes(original,board.blob)
    try:board.program()
    except Exception:
        try:
            interrupted=board.snapshot(BASE,SIZE)
            saved(folder/'after-interruption.bin',interrupted)
            marker(folder/'interruption.xml',dict(uid=board.uid,read_sha256=sha(interrupted),image_sha256=sha(board.blob)))
        except Exception:pass
        raise
    after=board.snapshot(BASE,SIZE);saved(folder/'installed.bin',after)
    if after!=expected:raise RuntimeError('full-chip verification differs; backup preserved, no erase issued')
    marker(folder/'installed.xml',dict(uid=board.uid,after_sha256=sha(after),image_sha256=sha(board.blob)))
    return f'已安装并逐字节核对 1 MiB。备份 {folder}。开发板停在 ROM，可以打开原演示软件。'
def restore(board,folder):
    original=load_backup(folder,board);expected=expected_bytes(original,board.blob)
    board.log=folder/'programmer.log'
    board.qualify();present=board.snapshot(BASE,SIZE)
    if present==original:return '整片 Flash 已与原始备份一致。'
    if present!=expected:
        partial=folder/'after-interruption.bin';receipt=folder/'interruption.xml'
        authentic=False
        if partial.is_file() and receipt.is_file():
            rec=ET.parse(receipt).getroot()
            a,b=FIRST-BASE,END-BASE
            observed=present[a:b];goal=expected[a:b]
            # Hardware programming may stop at a partial word. Outside the installation and
            # inside every written byte, disallow any bit clear that the selected image did not request.
            authentic=(rec.get('uid')==board.uid and rec.get('image_sha256')==sha(board.blob)
                and rec.get('read_sha256')==sha(present) and partial.read_bytes()==present
                and present[:a]==original[:a] and present[b:]==original[b:]
                and all((x&y)==y for x,y in zip(observed,goal)))
        if not authentic:raise RuntimeError('current Flash includes unrecognized data; sectors were preserved')
    board.erase_installed_sectors();after=board.snapshot(BASE,SIZE)
    if after!=original:raise RuntimeError('restored bytes differ from the original full backup')
    proof=folder/'restored.bin'
    if proof.exists():
        if proof.read_bytes()!=original:raise RuntimeError('existing recovery evidence differs')
    else:saved(proof,after)
    return '原始 1 MiB 已逐字节恢复。SHA-256 '+sha(after)
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('action',choices=['check','install','restore']);ap.add_argument('--image',type=Path);ap.add_argument('--uid',default=UID);ap.add_argument('--cube-cli',type=Path);ap.add_argument('--backup-dir',type=Path);ap.add_argument('--probe-images',type=Path);a=ap.parse_args()
    uid=a.uid.upper()
    if not re.fullmatch('[0-9A-F]{24}',uid):ap.error('specify the board 96-bit UID as 24 hexadecimal characters')
    if a.action!='check' and a.backup_dir is None:ap.error('--backup-dir required')
    if a.backup_dir and package_root() and a.backup_dir.resolve().is_relative_to(package_root()):ap.error('store the original firmware backup outside the delivery package')
    image=a.image or (a.backup_dir/'installed-image/stm32f407-unified.xml' if a.action=='restore' else default_image())
    board=Board(image,a.cube_cli,uid,probe_images=a.probe_images)
    with legacy._device_lock():
        print(inspect(board) if a.action=='check' else install(board,a.backup_dir.resolve()) if a.action=='install' else restore(board,a.backup_dir.resolve()))

