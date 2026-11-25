"""CH32 profile change behind the existing local demo. All selectable files are pinned."""
import contextlib
import hashlib
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from xml.etree import ElementTree as ET

import record_io
from demo import platform_config, platform_protocol as wire
from demo.platform_protocol import observe_frame

class Ch32UpdateError(RuntimeError):
    pass

def digest(data):return hashlib.sha256(data).hexdigest()

def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+"."+secrets.token_hex(4)+".pending")
    with temp.open("xb") as handle:
        handle.write(data);handle.flush();os.fsync(handle.fileno())
    os.replace(temp,path)

def xml(path,value):write(path,record_io.dumps(value).encode("utf8"))

def checked(root,item):
    file=(root/item["path"]).resolve()
    if not file.is_relative_to(root.resolve()) or digest(file.read_bytes())!=item["sha256"]:
        raise Ch32UpdateError("板端文件校验失败，请恢复完整演示目录。")
    return file

def segments(image,raw):
    elf=image.read_bytes();head=struct.unpack_from("<16sHHIIIIIHHHHHH",elf)
    if elf[:6]!=b"\x7fELF\x01\x01" or head[9]!=32:raise Ch32UpdateError("所选固件 ELF 格式无效。")
    seen=0
    for i in range(head[10]):
        kind,off,_,where,n,_,_,_=struct.unpack_from("<8I",elf,head[5]+i*32)
        if kind==1 and n:
            if where+n>len(raw) or elf[off:off+n]!=raw[where:where+n]:
                raise Ch32UpdateError("板端读取内容与所选 ELF 加载段不一致。")
            seen+=1
    if not seen:raise Ch32UpdateError("所选固件没有可验证加载段。")


def diagnostic_read(probe, name, address, length):
    probe.command(f"dump_image {name} {address:#x} {length}")
    data = (probe.folder/name).read_bytes()
    if name in ('result.bin','receipt.bin','coefficients.bin') or name.startswith('output'):
        observe_frame('CH32 板端 RAM','RX',data,name)
    if len(data) != length:
        raise Ch32UpdateError("没有读到完整的板端结果。")
    return data


def diagnostic_load(probe, name, address, data):
    if not 0x20000000 <= address < address+len(data) <= 0x20020000:
        raise Ch32UpdateError("测试数据超出板上 RAM。")
    write(probe.folder/name,data)
    probe.command(f"load_image {name} {address:#x} bin")
    if name == 'input.bin':
        observe_frame('CH32 板端 RAM','TX',data,name)


def read_diagnostic(file, expected):
    data = file.read_bytes()
    if digest(data) != expected:
        raise Ch32UpdateError("诊断程序或测试文件不完整。")
    return data

def identity(serial):
    vendor = Path(__file__).resolve().parents[1] / 'targets/ch32v307/host/vendor'
    try:
        ports = platform_config.present_wch_ports(vendor)
    except (ImportError, OSError) as error:
        raise Ch32UpdateError("无法读取 WCH-Link 串口。") from error
    if len(ports) != 1 or (ports[0].serial_number or '').upper() != serial.upper():
        raise Ch32UpdateError("请连接登记的 CH32V307，并只保留这一支 WCH-Link。")
    port = ports[0].device.upper()
    if not re.fullmatch(r'COM[1-9][0-9]*', port):
        raise Ch32UpdateError("无法确定 CH32V307 的活动串口。")
    return port


class Probe:
    def __init__(self,tool,folder):
        self.folder=folder;self.log=[];self.sock=None;self.proc=None
        self.out=(folder/"openocd.log").open("wb")
        self.err=(folder/"openocd-errors.log").open("wb")
        try:
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1",0));port=reserve.getsockname()[1]
            cmd=[str(tool),"-c","gdb_port disabled","-c",f"tcl_port {port}","-c","telnet_port disabled",
                 "-c","bindto 127.0.0.1","-s",".","-f","wch-riscv.cfg","-c","chip_id CH32V30x"]
            self.proc=subprocess.Popen(cmd,cwd=folder,stdout=self.out,stderr=self.err,creationflags=subprocess.CREATE_NO_WINDOW)
            end=time.monotonic()+10
            while time.monotonic()<end and self.proc.poll() is None:
                try:self.sock=socket.create_connection(("127.0.0.1",port),timeout=.2);break
                except OSError:time.sleep(.08)
            if self.sock is None:raise Ch32UpdateError("WCH-Link 编程器没有接通。")
            self.sock.settimeout(45)
            if "30700568" not in self.command("mdw 0x1ffff704 1"):
                raise Ch32UpdateError("硬件识别字不属于已登记的 CH32V307。")
        except Exception:
            self.close();raise
    def command(self,cmd):
        request = ("set r [catch {"+cmd+"} v]; format \"LC=%d\\n%s\" $r $v\x1a").encode("ascii")
        self.sock.sendall(request)
        observe_frame('OpenOCD TCL','TX',request,cmd)
        reply=bytearray()
        while not reply.endswith(b"\x1a"):
            part=self.sock.recv(8192)
            if not part:raise OSError("CH32 probe disconnected")
            reply.extend(part)
        msg=bytes(reply[:-1]).decode("utf8",errors="replace")
        observe_frame('OpenOCD TCL','RX',bytes(reply),msg.strip().partition(chr(10))[0][:160])
        self.log.append({"command":cmd,"reply":msg});xml(self.folder/"探针命令.xml",self.log)
        if not msg.startswith("LC=0\n"):raise OSError(msg)
        return msg
    def dump(self,name,n=196608):
        data=[]
        for pos in range(0,n,16384):
            file=f"{name}-{pos:05x}.bin";part=min(16384,n-pos)
            self.command(f"dump_image {file} {pos} {part}");data.append((self.folder/file).read_bytes())
        result=b"".join(data)
        if len(result)!=n:raise OSError("Incomplete flash read")
        return result
    def boot(self):
        self.command("reset halt");self.command("resume 0x00000000");time.sleep(.45)
    def close(self):
        if self.sock:
            try:self.sock.sendall(b"shutdown\x1a")
            except OSError:pass
            self.sock.close()
        if self.proc:
            try:self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:self.proc.terminate();self.proc.wait(timeout=5)
        self.out.close();self.err.close()

class StrategyController:
    def __init__(self,package,records):
        self.package=Path(package).resolve();self.records=Path(records).resolve()
        self.root=self.package/"03_复现环境与运行程序/firmware/CH32V307/双策略"
        self.index=record_io.loads((self.root/"策略索引.xml").read_bytes())
        self.local=Path(os.environ.get("LATTICE_CH32_STORAGE",
                str(Path(os.environ.get("LOCALAPPDATA",str(Path.home())))/"CACR2026LatticeDemo/CH32")))
        self.local=self.local/self.index["serial"]
        self.lock=threading.RLock()
        self.expected_origin=self.index["original_flash_sha256"]
    @contextlib.contextmanager
    def transaction(self):
        import msvcrt
        self.local.mkdir(parents=True,exist_ok=True)
        with self.lock,(self.local/"device.lock").open("a+b") as token:
            token.seek(0,2)
            if token.tell()==0:token.write(b"L");token.flush()
            token.seek(0)
            try:msvcrt.locking(token.fileno(),msvcrt.LK_NBLCK,1)
            except OSError:raise Ch32UpdateError("另一个 CH32 板端操作正在进行。") from None
            try:yield
            finally:
                token.seek(0);msvcrt.locking(token.fileno(),msvcrt.LK_UNLCK,1)
    def original_connection(self):
        path=self.package/"03_复现环境与运行程序/软件演示程序/资料配置/CH32V307.xml"
        _,config=platform_config.read_config(path)
        if config.get("expected_elf_sha256")!=self.index["original_elf_sha256"] or config.get("library_id")!="ch32-partial64":
            raise Ch32UpdateError("原现场串口配置与登记的 ELF 不一致。")
        return path

    def diagnostic_metadata(self):
        path = self.package/'03_复现环境与运行程序/软件演示程序/入口/unified_workbench/arithmetic'
        manifest = record_io.loads((path/'ch32-diagnostics.xml').read_bytes())
        if (manifest['original_flash'],manifest['original_elf']) != (self.expected_origin,self.index['original_elf_sha256']):
            raise Ch32UpdateError("诊断程序与 64 KiB 固件不匹配。")
        return path,manifest

    @contextlib.contextmanager
    def diagnostic(self, profile):
        with self.transaction():
            identity(self.index['serial'])
            folder = self.records/('ram-test-'+secrets.token_hex(8))
            folder.mkdir(parents=True)
            tools = {key:checked(self.root,row) for key,row in self.index['tools'].items()}
            write(folder/'wch-riscv.cfg',tools['config'].read_bytes())
            probe = Probe(tools['openocd'],folder)
            try:
                probe.command('halt')
                before = probe.dump('before')
                if profile == '64':
                    valid = digest(before) == self.expected_origin
                else:
                    selected = self.index['strategies'][{'28':'low','80':'high'}[profile]]
                    binary = checked(self.root,selected['bin']).read_bytes()
                    valid = before.startswith(binary)
                if not valid:
                    raise Ch32UpdateError("板上固件与当前档位不符，请重新连接。")
                yield probe
                if probe.dump('after') != before:
                    raise Ch32UpdateError("板上 Flash 读回结果发生变化。")
            finally:
                try:
                    probe.boot()
                finally:
                    probe.close()

    def run_acvp(self, profile, cases, *, on_start=None, on_reply=None, edit_fixture=None, timed=False, stop=None):
        base = self.package/'02_测试代码与数据/correctness/CH32V307/标准向量与存储核验'
        pins = {node.get('path'):node.get('sha256') for node in ET.parse(base/'核验.xml').getroot().findall('file')}
        def fixture(relative):
            return read_diagnostic(base/relative,pins[relative])
        role = '高性能' if profile=='80' else '低内存'
        if timed:
            if profile not in ('28', '80'):
                raise Ch32UpdateError('当前固件不可运行逐项计时。')
            directory, _ = self.diagnostic_metadata()
            binding = json.loads((directory/'ch32-timing.json').read_text(encoding='ascii'))[profile]
            driver = read_diagnostic(directory/f'ch32-timing-{profile}.bin',binding['sha256'])
            entry, input_addr, result_addr = (binding[key] for key in ('entry','input','result'))
            if profile == '28':
                output_addresses = binding['octets0'],binding['octets1']
        elif profile == '64':
            directory,metadata = self.diagnostic_metadata()
            binding = metadata['ch32-acvp-64']
            driver = read_diagnostic(directory/'ch32-acvp-64.bin',binding['sha256'])
            entry, input_addr, result_addr = (binding[k] for k in ('qual_entry','input','result'))
            output_addresses = binding['octets0'],binding['octets1']
        else:
            driver = fixture(f'{role}/向量程序/qual.bin')
            if role == '低内存':
                entry, input_addr, result_addr = 0x20012000, 0x200123a0, 0x20016400
                output_addresses = 0x20017764,0x20016444
            else:
                entry, input_addr, result_addr = 0x2000f2e0,0x2000f6e0,0x2000f760
        results = []
        receipt_format = '<3Ii8I' if timed else '<3Ii5I'
        receipt_size = struct.calcsize(receipt_format)
        with self.diagnostic(profile) as probe:
            try:
                diagnostic_load(probe,'driver.bin',entry,driver)
                if diagnostic_read(probe,'driver-check.bin',entry,len(driver)) != driver:
                    raise Ch32UpdateError("板上诊断程序读回不一致。")
                for index,(parameter,op,tc) in enumerate(cases):
                    if stop is not None and stop():
                        break
                    if on_start: on_start(index)
                    data = bytearray(fixture(f'{role}/p{parameter}-op{op}-tc{tc}/input.bin'))
                    if profile == '64':
                        struct.pack_into('<I',data,16,metadata['workspace'])
                    if edit_fixture is not None:
                        edit_fixture(index, data)
                    if role == '高性能':
                        fields = struct.unpack_from('<23I',data)
                        if fields[5]-256 != input_addr:
                            raise Ch32UpdateError("高性能用例的输入地址已变动。")
                        output_addresses = fields[19],fields[21]
                    diagnostic_load(probe,'input.bin',input_addr,data)
                    diagnostic_load(probe,'receipt-clear.bin',result_addr,bytes(receipt_size))
                    probe.command(f'resume {entry:#x}')
                    limit = time.monotonic()+5
                    while True:
                        time.sleep(.06)
                        probe.command('halt')
                        reply = struct.unpack(receipt_format,diagnostic_read(probe,'receipt.bin',result_addr,receipt_size))
                        if reply[:2] == (0x51444f4e,tc):
                            break
                        if time.monotonic()>=limit:
                            raise Ch32UpdateError("ACVP 用例没有返回结果。")
                        probe.command('resume')
                    lengths = reply[7:9]
                    if any(n>4896 for n in lengths):
                        raise Ch32UpdateError("板端输出长度无效。")
                    actual = [diagnostic_read(probe,f'output{i}.bin',address,n) if n else b''
                              for i,(address,n) in enumerate(zip(output_addresses,lengths))]
                    results.append((reply,actual))
                    if on_reply: on_reply(index,reply,actual)
            finally:
                probe.command('halt')
                diagnostic_load(probe,'clear-test-ram.bin',entry,bytes(0x20020000-entry))
        return results

    def run_ring(self,profile,a,b,q,*,report=None,operation='mul'):
        start,config,end = 0x20018000,0x20019000,0x2001f000
        if operation != 'mul':
            directory,_ = self.diagnostic_metadata()
            name = f'ch32-transform-{profile}'
            metadata = json.loads((directory/'ch32-transforms.json').read_text(encoding='utf-8'))
            driver = read_diagnostic(directory/f'{name}.bin', metadata[name]['sha256'])
        elif profile=='64':
            directory,metadata=self.diagnostic_metadata()
            driver=read_diagnostic(directory/'ch32-ring-64.bin',metadata['ch32-ring-64']['sha256'])
        else:
            directory=self.package/'02_测试代码与数据/performance/多项式运算/完整环乘实板测量/ch32'
            name={'28':'retired-response87','80':'wire80-eight'}[profile]
            plan=json.loads((directory/'fixed-plan.json').read_text(encoding='utf-8'))
            driver=read_diagnostic(directory/name/'driver.bin',plan['profiles'][name]['driver_sha256'])
        op = {'mul': 0, 'ntt': 2, 'intt': 4, 'add': 6, 'sub': 8, 'reduce': 10}[operation] + int(q != 3329)
        kind = 'i' if op & 1 or operation in ('add','sub') else 'h'
        body = bytearray([0xa5])*(end-config)
        cookie = secrets.randbits(32)
        struct.pack_into('<2I',body,0,cookie,op)
        body[0x100:0x240]=bytes(320)
        for offset,array in ((0x400,a),(0xc00,b)):
            struct.pack_into('<256'+kind,body,offset,*array)
        if report: report('正在启动板上算术诊断')
        with self.diagnostic(profile) as probe:
            try:
                diagnostic_load(probe,'driver.bin',start,driver)
                diagnostic_load(probe,'input.bin',config,body)
                if diagnostic_read(probe,'driver-check.bin',start,len(driver)) != driver:
                    raise Ch32UpdateError("板上诊断程序读回不一致。")
                if report:
                    report('已发送测试数据')
                    report('正在请求开发板执行算术运算')
                probe.command(f'resume {start:#x}')
                time.sleep(.25)
                probe.command('halt')
                result=diagnostic_read(probe,'result.bin',config+0x100,320)
                head=struct.unpack_from('<8I',result)
                n=struct.calcsize('<256'+kind)
                if head != (0x52494e47,cookie,op,5,0xe000f008,9,n,0):
                    raise Ch32UpdateError("未收到完整的算术结果。")
                begin,finish=struct.unpack_from('<2Q',result,32)
                if not 0<finish-begin<10000000:
                    raise Ch32UpdateError("板上周期计数无效。")
                raw=diagnostic_read(probe,'coefficients.bin',start+0x4400,n)
                if report: report('已收到板端结果')
                return list(struct.unpack('<256'+kind,raw)),finish-begin
            finally:
                probe.command('halt')
                diagnostic_load(probe,'clear-test-ram.bin',start,bytes(end-start))

    def run_primitive(self,profile,packet,*,label,report):
        directory,_=self.diagnostic_metadata()
        binary=directory/'ch32-primitives.bin'
        manifest=json.loads((directory/'primitives.json').read_text(encoding='ascii'))
        driver=read_diagnostic(binary,manifest[binary.name])
        entry,args,receipt=0x20018000,0x2001d800,0x2001de00
        cookie,=struct.unpack_from('<I',packet)
        with self.diagnostic(profile) as probe:
            try:
                diagnostic_load(probe,'driver.bin',entry,driver)
                if diagnostic_read(probe,'driver-check.bin',entry,len(driver))!=driver:
                    raise Ch32UpdateError('板上诊断程序读回不一致。')
                diagnostic_load(probe,'input.bin',args,packet)
                diagnostic_load(probe,'receipt-clear.bin',receipt,bytes(20))
                if report: report(label+' · 请求板端执行')
                limit=time.monotonic()+5
                probe.command(f'resume {entry:#x}')
                while True:
                    time.sleep(.06)
                    probe.command('halt')
                    magic,ident,status,cycles=struct.unpack('<IIiQ', diagnostic_read(probe,'receipt.bin',receipt,20))
                    if (magic,ident)==(0x504f4c59,cookie):
                        break
                    if time.monotonic()>=limit:
                        raise Ch32UpdateError('CH32 算术诊断未返回。')
                    probe.command('resume')
                if not cycles:
                    raise Ch32UpdateError('未收到板端周期。')
                output=diagnostic_read(probe,'output.bin',args+28,wire.PRIMITIVE_OUTPUT.size)
            finally:
                probe.command('halt')
                diagnostic_load(probe,'clear-test-ram.bin',entry,bytes(0x20020000-entry))
        return status,output,cycles,None

    def annotate(self,request,result):
        library=request.get("library")
        if library not in {"ch32-finals-"+key for key in self.index["strategies"]}:return
        role=library.removeprefix("ch32-finals-");profile=self.index["strategies"][role]
        active=profile["parameter_workspace_bytes"][str(request["parameter"])]
        metrics=result["device_metrics"];resources=metrics["resources"]
        if resources["static_ram_bytes"]!=profile["ram"] or resources["flash_bytes"]!=profile["flash"]:
            raise Ch32UpdateError("本次应答的存储布局与所选 ELF 不一致。")
        metrics["verified_profile"]={"build_id":profile["build_id"],"elf_sha256":profile["elf"]["sha256"],
                "bin_sha256":profile["bin"]["sha256"],"active_workspace_bytes":active,
                "maximum_parameter_workspace_bytes":resources["workspace_bytes"]}
        resources["workspace_bytes"]=active
        if "workspace_bytes" in result:result["workspace_bytes"]=active
    def select(self,app,choice):
        if choice!="original" and choice not in self.index["strategies"]:raise Ch32UpdateError("未知的 CH32 板端策略。")
        with self.transaction():
            port=identity(self.index["serial"])
            folder=self.records/("switch-"+time.strftime("%Y%m%d-%H%M%S")+"-"+secrets.token_hex(4));folder.mkdir(parents=True)
            tools={key:checked(self.root,row) for key,row in self.index["tools"].items()}
            write(folder/"wch-riscv.cfg",tools["config"].read_bytes())
            original=self.local/"原现场-196608.bin";journal=self.local/"未完成事务.xml"
            profiles=self.index["strategies"]
            candidates={}
            for key,row in profiles.items():
                image=checked(self.root,row["elf"]);raw=checked(self.root,row["measured"]).read_bytes()
                segments(image,raw);candidates[key]=raw
                checked(self.root,row["bin"]);checked(self.root,row["config"])
            probe=Probe(tools["openocd"],folder);wrote=False
            try:
                probe.command("halt");current=probe.dump("before")
                if digest(current)==self.expected_origin:
                    if original.exists() and digest(original.read_bytes())!=self.expected_origin:
                        raise Ch32UpdateError("已有原现场备份未通过校验。")
                    if not original.exists():write(original,current)
                if not original.is_file() or digest(original.read_bytes())!=self.expected_origin:
                    raise Ch32UpdateError("这块板缺少可验证的原现场备份，未写入固件。")
                backup=original.read_bytes()
                segments(checked(self.root,self.index["original_elf"]),backup)
                states={"original":backup}
                for key,raw in candidates.items():states[key]=raw+backup[len(raw):]
                before=next((k for k,raw in states.items() if current==raw),None)
                if before is None and not journal.is_file():
                    raise Ch32UpdateError("当前 Flash 与登记过的现场或策略不符，未写入固件。")
                span=((max(map(len,candidates.values()))+4095)//4096)*4096
                if before is None:
                    recovery=record_io.loads(journal.read_bytes())
                    if recovery.get("serial")!=self.index["serial"] or recovery.get("original_sha256")!=self.expected_origin:
                        raise Ch32UpdateError("未完成写入的记录与这块板不符。")
                    if current[span:]!=backup[span:]:raise Ch32UpdateError("固件写入范围外的内容已改变。")
                if current!=states[choice]:
                    xml(journal,dict(serial=self.index["serial"],original_sha256=self.expected_origin,requested=choice))
                    write(folder/"selected-prefix.bin",states[choice][:span])
                    probe.command("reset halt");wrote=True
                    probe.command("flash write_image erase selected-prefix.bin 0 bin")
                    actual=probe.dump("after")
                    if actual!=states[choice]:raise Ch32UpdateError("写入后整片 Flash 未通过逐字节核验。")
                else:actual=current
                probe.boot()
            except Exception as exc:
                if wrote:
                    try:
                        write(folder/"rollback-prefix.bin",backup[:span]);probe.command("reset halt")
                        probe.command("flash write_image erase rollback-prefix.bin 0 bin")
                        if probe.dump("rolled-back")!=backup:raise OSError("recovery readback")
                        probe.boot();journal.unlink(missing_ok=True)
                    except Exception:
                        raise Ch32UpdateError("写入中断。请重新接好原 WCH-Link，再点“恢复原现场”。") from exc
                else:
                    try:probe.boot()
                    except OSError:pass
                raise
            finally:probe.close()
            config=(self.original_connection() if choice=="original" else checked(self.root,profiles[choice]["config"]))
            previous=app.providers.get("ch32")
            app.providers["ch32"]=platform_config.board_provider(config,records_directory=self.records)
            app.remote_rows.pop("ch32",None)
            try:answer=app.connect("ch32",restored_original_elf=self.index["original_elf_sha256"] if choice=="original" else None)
            except Exception as failure:
                app.remote_rows.pop("ch32",None)
                if previous:app.providers["ch32"]=previous
                xml(folder/"核验失败.xml",dict(strategy=choice,flash_sha256=digest(actual),port=port))
                if wrote:
                    path=folder/"identity-rollback";path.mkdir();write(path/"wch-riscv.cfg",tools["config"].read_bytes())
                    try:
                        rollback=Probe(tools["openocd"],path)
                        try:
                            write(path/"rollback-prefix.bin",backup[:span]);rollback.command("reset halt")
                            rollback.command("flash write_image erase rollback-prefix.bin 0 bin")
                            if rollback.dump("original")!=backup:raise OSError("recovery readback")
                            rollback.boot()
                        finally:rollback.close()
                        app.providers["ch32"]=platform_config.board_provider(self.original_connection(),records_directory=self.records)
                        app.connect("ch32",restored_original_elf=self.index["original_elf_sha256"]);journal.unlink(missing_ok=True)
                        xml(path/"已恢复原现场.xml",{"flash_sha256":self.expected_origin,"hello_verified":True})
                    except Exception:
                        raise Ch32UpdateError("所选固件未通过串口核验。重新接好登记板卡后可点“恢复原现场”。") from failure
                    raise Ch32UpdateError("所选固件未通过串口核验，已自动恢复原现场并核对整片和串口。") from failure
                raise Ch32UpdateError("串口身份核验未完成，请重新核验。") from failure
            journal.unlink(missing_ok=True)
            report=dict(strategy=choice,before=before,flashed=wrote,serial=self.index["serial"],port=port,
                original_sha256=self.expected_origin,observed_full_sha256=digest(actual),ram_capacity_bytes=131072,
                verified_elf=profiles[choice]["elf"]["sha256"] if choice!="original" else self.index["original_elf_sha256"])
            xml(folder/"切换校验.xml",report)
            answer["ch32_switch"]=report
            return answer
