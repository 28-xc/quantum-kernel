"""STM32F407 board adapter shared by the desktop UI and the command line."""
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
from pathlib import Path
import csv
import hashlib
import re
import struct
import secrets
import threading

from demo import platform_protocol as wire
from demo.platform_providers import ProviderError

SOURCE = Path(__file__).resolve().parents[1]
HISTORY = Path('03_复现环境与运行程序/软件演示程序/入口/history/STM32F407当前/operations.tsv')
PARAMETERS = (512, 768, 1024, 44, 65, 87)
NAMES = {'keygen': '密钥生成', 'encaps': '封装', 'decaps': '解封装', 'sign': '签名', 'verify': '验签'}
TOKEN = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,55}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
STRATEGY_NAMES = {'compact': '低内存', 'cached': '高性能', 'speed': '高性能', 'fast': '高性能',
                  'low_memory': '低内存', 'throughput': '高性能',
                  'release': '作品实现', 'reference': '参考实现'}
HISTORY_FIELDS = ('param', 'operation', 'implementation', 'samples', 'median_cycles',
                  'clock_hz', 'median_us', 'arena_bytes', 'stack_bytes')


def require(condition, code='BAD_RESPONSE'):
    if not condition:
        raise ProviderError(code)


def number(value, minimum=0):
    require(type(value) is int and minimum <= value <= (1 << 63) - 1)
    return value


def op_keys(parameter):
    return ('keygen', 'encaps', 'decaps') if parameter > 100 else ('keygen', 'sign', 'verify')



def _history_identity(package, table):
    directory=Path(package)/HISTORY.parent
    evidence=directory/'evidence.xml'
    if not evidence.is_file():return None
    import xml.etree.ElementTree as ET
    meta=ET.parse(evidence).getroot()
    firmware=Path(package)/'03_复现环境与运行程序/firmware/STM32F407/固件/stm32f407-unified.xml'
    image=ET.parse(firmware).getroot()
    h=image.get('sha256')
    node=next((x for x in meta if x.get('path')==table),None)
    if (not HASH.fullmatch(h or '') or meta.get('firmware_sha256')!=h or meta.get('build_tag')!=image.get('tag')
            or node is None or hashlib.sha256((directory/table).read_bytes()).hexdigest()!=node.get('sha256')):
        raise ValueError('测量或固件身份不符')
    return h

def read_history(package):
    path = Path(package) / HISTORY
    if not path.is_file():
        return []
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('历史测量表过大')
    expected = _history_identity(package,"operations.tsv")
    rows = []
    with path.open(encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f, delimiter='\t')
        if not set(HISTORY_FIELDS) <= set(reader.fieldnames or ()):
            raise ValueError('历史测量表列名不匹配')
        for item in reader:
            if expected and item.get("sha256")!=expected:raise ValueError("性能记录的固件身份不符")
            row = {key: item[key] for key in HISTORY_FIELDS}
            if row['operation']=='keypair':row['operation']='keygen'
            parameter = int(row['param'])
            if parameter not in PARAMETERS or row['operation'] not in op_keys(parameter):
                raise ValueError('历史参数或操作不匹配')
            if not TOKEN.fullmatch(row['implementation']):
                raise ValueError('历史配置标识不匹配')
            for key in ('samples', 'clock_hz'):
                if int(row[key]) <= 0:
                    raise ValueError('历史测量条件无效')
            for key in ('median_cycles', 'median_us', 'arena_bytes', 'stack_bytes'):
                if row[key] in ('', 'NA', 'N/A') and key in ('arena_bytes', 'stack_bytes'):
                    row[key] = None
                    continue
                try:
                    value = Decimal(row[key])
                except InvalidOperation as error:
                    raise ValueError('历史测量值无效') from error
                if not value.is_finite() or value < 0:
                    raise ValueError('历史测量值无效')
            rows.append(row)
    return rows


MEMORY_FIELDS = ('param', 'implementation', 'main_sram_bytes', 'ccm_bytes', 'stack_capacity',
                 'arena_capacity', 'image_bytes', 'total_ram_bytes')


def read_memory(package):
    path = Path(package) / HISTORY.parent / 'memory.tsv'
    if not path.is_file():
        return []
    if path.stat().st_size > 1024 * 1024:
        raise ValueError('历史资源表过大')
    expected = _history_identity(package,'memory.tsv')
    result = []
    with path.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream, delimiter='\t')
        if not set(MEMORY_FIELDS) <= set(reader.fieldnames or ()):
            raise ValueError('历史资源表列名不匹配')
        for row in reader:
            if not TOKEN.fullmatch(row['implementation']):
                raise ValueError('历史配置标识不匹配')
            if expected and row.get('sha256')!=expected:raise ValueError('资源记录的固件身份不符')
            medium=row.get('image_storage','sram')
            if medium not in ('sram','flash'):raise ValueError('存储介质无效')
            item = {key: int(row[key]) if key != 'implementation' else row[key] for key in MEMORY_FIELDS}
            if (item['param'] not in PARAMETERS or min(item[key] for key in MEMORY_FIELDS[2:]) < 0
                    or item['main_sram_bytes'] + item['ccm_bytes'] != item['total_ram_bytes']
                    or (medium=='sram' and item['image_bytes'] > item['main_sram_bytes'])):
                raise ValueError('历史资源统计不一致')
            item['image_storage']=medium
            result.append(item)
    return result


class F407Provider:
    prefix = 'stm32f407-'

    def __init__(self, engine=None, image_dir=None, package=None, records_directory=None):
        self._engine = engine
        self.image_dir = image_dir
        self.package = Path(package) if package is not None else SOURCE.parents[1]
        self.records_directory = Path(records_directory).resolve() if records_directory else None
        if self.records_directory and self.records_directory.is_relative_to(self.package.resolve()):
            raise ValueError('实板运行记录应在支撑材料之外')
        self._lock = threading.Lock()
        self.capabilities = {}
        self.images = {}
        self.state = 'disconnected'
        self.mode = None
        self.port = None

    @property
    def engine(self):
        if self._engine is None:
            try:
                from targets.stm32f407.presentation_engine import PresentationEngine
            except ImportError:
                raise ProviderError('FIRMWARE_MISSING') from None
            self._engine = PresentationEngine()
        return self._engine

    @contextmanager
    def _transaction(self):
        if not self._lock.acquire(blocking=False):
            raise ProviderError('BUSY')
        self.state = 'busy'
        try:
            yield
        except Exception as error:
            self.state = 'disconnected'
            self.mode = None
            self.port = None
            self.images = {}
            self.capabilities = {}
            if isinstance(error, ProviderError):
                raise
            code = getattr(error, 'code', None)
            raise ProviderError(code if isinstance(code, str) else 'DEVICE_UNAVAILABLE') from error
        else:
            self.state = 'connected'
        finally:
            self._lock.release()

    def observed_mode(self):
        # Startup and historical browsing never open a connection.
        # Monitor a previously established link by enumeration only.
        if self.state != 'connected' or not self._lock.acquire(blocking=False):
            return self.mode
        try:
            try:
                visible = self.engine.devices()
                matching = [item for item in visible if item.get('mode') == self.mode and
                            (not self.port or item.get('serial') == self.port)]
            except (OSError, RuntimeError, ValueError):
                matching = []
            if len(matching) != 1:
                self.state = 'disconnected'
                self.mode = None
                self.port = None
            return self.mode
        finally:
            self._lock.release()

    def catalog(self):
        with self._transaction():
            identity = self.engine.probe(image_dir=self.image_dir)
            require(isinstance(identity, dict) and identity.get('connected') is True,
                    identity.get('code', 'DEVICE_UNAVAILABLE') if isinstance(identity, dict) else 'DEVICE_UNAVAILABLE')
            self.mode = identity.get('mode')
            require(self.mode in ('dfu', 'cdc'), 'DEVICE_UNAVAILABLE')
            self.port = identity.get('serial') or None
            cap = self.engine.capabilities(image_dir=self.image_dir)
            images = {}
            for image in cap['images']:
                param, strategy = image['parameter'], image['strategy']
                if strategy not in cap['strategies']:
                    continue
                require(type(param) is int and param in PARAMETERS and TOKEN.fullmatch(strategy))
                require(HASH.fullmatch(image['sha256']) and number(image['workspace_capacity'], 1)
                        and number(image['image_bytes'], 1) and image['build_tag'])
                require((param, strategy) not in images)
                images[param, strategy] = image
            require(images, 'FIRMWARE_MISSING')
            self.capabilities, self.images = cap, images
            rows = []
            for strategy in cap['strategies']:
                require(TOKEN.fullmatch(strategy))
                selected = [p for p in PARAMETERS if (p, strategy) in images]
                if not selected:
                    continue
                sizes = {str(p): images[p, strategy]['workspace_capacity'] for p in selected}
                rows.append(dict(id=self.prefix + strategy, title=((str(cap['deployment_kib'])+' KiB 部署 · ') if cap.get('deployment_kib') else '')+STRATEGY_NAMES.get(strategy, strategy),
                                 configuration=strategy, representative_strategy=((cap.get('deployment_kib'),strategy) in ((24,'compact'),(32,'cached'))), platform='stm32f407', parameters=selected,
                                 workspace_bytes=max(sizes.values()), workspace_by_parameter=sizes,
                                 execution_available=True, run_presets={key: cap[key] for key in
                                 ('message_lengths', 'context_lengths', 'modes')}))
            require(rows, 'FIRMWARE_MISSING')
            return {'libraries': rows}

    def deploy(self, profile):
        from targets.stm32f407.maintenance import DeploymentError

        require(self.records_directory and self.state == 'connected', 'NOT_CONNECTED')
        try:
            with self._transaction():
                self.engine.deploy(profile, self.records_directory/'deployments', image_dir=self.image_dir)
        except ProviderError as error:
            if isinstance(error.__cause__, DeploymentError):
                raise error.__cause__ from None
            raise

    def boot_resident(self):
        require(self.can_run_kat() and self.mode == 'dfu','NOT_CONNECTED')
        with self._transaction():
            identity=self.engine.boot_resident()
            self.mode,self.port=identity['mode'],identity['serial']

    def can_run_kat(self):
        return self.state == 'connected' and self.engine.selected in ('resident', 'resident-rom')

    @contextmanager
    def _diagnostic(self, path, *, report, title):
        import json
        from targets.stm32f407 import engine, resident_dfu
        from targets.stm32f407.usb_windows import Port

        require(self.can_run_kat(),'NOT_CONNECTED')
        metadata = json.loads(path.with_suffix('.json').read_text(encoding='utf-8'))
        data = path.with_suffix('.bin').read_bytes()
        require(hashlib.sha256(data).hexdigest()==metadata['driver_sha256'],'IDENTITY_MISMATCH')
        rom=self.engine.rom_serial
        with self._transaction(), engine._device_lock():
            in_rom = self.engine.selected=='resident-rom'
            uid = self.engine.uid
            if in_rom:
                production, _ = resident_dfu.unified.read_manifest(self.engine.manifest)
                require(production['sha256']==metadata['production_bin_sha256'],'IDENTITY_MISMATCH')
                if report: report('正在通过 STM32 DFU 接口核验当前固件')
                require(resident_dfu.check_installed(self.engine.manifest,rom,verify=True),'IDENTITY_MISMATCH')
                production_tag = production['tag']
            else:
                resident = self.engine.resident
                require(resident is not None and resident.identity['firmware_sha256']==metadata['production_bin_sha256'],
                        'IDENTITY_MISMATCH')
                production_tag = resident.identity['build_tag']
            failure = None
            def progress(message):
                if report:
                    report(message)

            phase = '切换至 STM32 USB 启动模式'
            try:
                progress(title)
                if not in_rom:
                    require(resident.port.command(6,timeout=8)[23]==1)
                    self.engine.close()
                    progress('已收到模式切换应答，正在等待 STM32 DFU 接口')
                    phase = '等待 STM32 DFU 接口'
                    engine._wait('dfu',rom,timeout=18)
                phase = '上传和核验 SRAM 诊断程序'
                progress('已检测到 DFU 接口，正在上传并核验 SRAM 诊断程序')
                engine._upload_sram(rom,data,metadata['driver_sha256'])
                phase = '等待 STM32 诊断串口'
                progress('诊断程序已上传，正在等待诊断串口')
                live=engine._wait('cdc',rom,timeout=18)
                require((uid is None or live['serial']==uid) and engine._rom_serial(live['serial'])==rom,
                        'IDENTITY_MISMATCH')
                uid = live['serial']
                phase = '执行板上诊断'
                with Port(live) as driver:
                    def command(cmd,*args,timeout=8,**kwargs):
                        words=driver.command(cmd,*args,timeout=timeout,**kwargs)
                        require(struct.pack('<3I',*words[16:19]).hex().upper()==uid
                                and struct.pack('<4I',*words[8:12]).hex()==metadata['tag']
                                and words[19]==168000000 and words[22]==1 and words[23]==1)
                        return words
                    yield command
            except (RuntimeError, ValueError, OSError) as error:
                failure = error
                progress(phase+'失败')
            finally:
                self.engine.close()
                progress('正在恢复并核验原固件连接')
                try:
                    device = self._diagnostic_device(engine, rom, uid)
                    if device['mode']=='cdc':
                        with Port(device) as connection:
                            hello = connection.command(1,timeout=8)
                            tag=struct.pack('<4I',*hello[8:12]).hex()
                            uid = device['serial']
                            require(struct.pack('<3I',*hello[16:19]).hex().upper()==uid,'IDENTITY_MISMATCH')
                            if tag != production_tag:
                                require(tag==metadata['tag'],'IDENTITY_MISMATCH')
                                require(connection.command(6,timeout=8)[23]==1)
                        if tag != production_tag:
                            device = engine._wait('dfu',rom,timeout=18)
                    if device['mode']=='dfu':
                        require(resident_dfu.check_installed(self.engine.manifest,rom,launch=True),'IDENTITY_MISMATCH')
                        active = engine._wait('cdc',rom,timeout=18)
                        require(uid is None or active['serial']==uid,'IDENTITY_MISMATCH')
                        uid = active['serial']
                    self.engine._attach(uid)
                    self.engine.selected='resident'
                    self.mode,self.port='cdc',uid
                    progress('已恢复并核验原固件连接')
                except (RuntimeError, ValueError, OSError) as recovery:
                    progress('原固件连接恢复失败')
                    if failure is not None and getattr(recovery,'code',None)!='STM32_USB_MISSING':
                        raise failure from recovery
                    raise
        if failure is not None:
            raise ProviderError(getattr(failure,'code','DEVICE_UNAVAILABLE')) from failure

    @staticmethod
    def _diagnostic_device(engine, rom, uid):
        matches = [item for item in engine.devices() if
                   (item['serial'] == rom if item['mode']=='dfu' else
                    item['serial']==uid if uid else engine._rom_serial(item['serial'])==rom)]
        if not matches:
            raise ProviderError('STM32_USB_MISSING')
        require(len(matches)==1,'MULTIPLE_DEVICES')
        return matches[0]

    def run_ring(self, a, b, q, *, report=None, operation='mul'):
        from targets.stm32f407.usb_windows import fnv

        require(self.can_run_kat(),'NOT_CONNECTED')
        profile = self.capabilities['deployment_kib']
        selector = {'mul': 0, 'ntt': 2, 'intt': 4, 'add': 6, 'sub': 8, 'reduce': 10}[operation] + int(q != 3329)
        path = self.package / '03_复现环境与运行程序/软件演示程序/入口/unified_workbench/arithmetic' / f'stm32-transform-{profile}'
        with self._diagnostic(path,report=report,title='正在启动板上算术诊断') as exchange:
            operation_label = {'mul':'完整环乘','ntt':'NTT','intt':'INTT',
                               'add':'多项式加法','sub':'多项式减法','reduce':'系数约减'}[operation]
            param_label = 'ML-KEM' if q == 3329 else 'ML-DSA'
            phases = {1:'查询算术诊断',20:'写入系数',21:'执行运算',22:'读取系数',23:'读取周期'}
            def command(cmd,*args,**kwargs):
                trace = f'{param_label} · {operation_label} · {phases[cmd]}'
                return exchange(cmd,*args,trace=trace,**kwargs)
            require(command(1)[41]==0x52494e47)
            for side,values in enumerate((a,b)):
                for offset in range(0,256,9):
                    chunk=[value & 0xffffffff for value in (values[offset:offset+9]+[0]*9)[:9]]
                    command(20,struct.pack('<4I',*chunk[:4]).hex(),param=side,profile=offset,
                            budget=chunk[4],mlen=chunk[5],clen=chunk[6],entropy=chunk[7],flags=chunk[8])
            nonce=secrets.token_hex(16)
            if report:
                report('已发送测试数据')
                report('正在请求开发板执行算术运算')
            start=command(21,nonce,param=selector,profile=0)
            checksum=fnv(struct.pack('<512I',*(value & 0xffffffff for value in a+b)))
            require(start[41:43]==(selector,0) and start[43]==checksum)
            stats=command(23,nonce,param=0)
            coeff=[]
            for page in range(8):
                row=command(22,nonce,param=0,profile=page)
                require(row[56:60]==(selector,0,0,page))
                coeff.extend(row[24:56])
            cycles=(stats[25]-stats[24])&0xffffffff
            require(stats[29:32]==(selector,0,0) and stats[32]==checksum and 0<cycles<2000000
                    and fnv(struct.pack('<256I',*coeff))==stats[28])
            if report: report('已收到板端结果')
        return [value if value < 2**31 else value - 2**32 for value in coeff], cycles

    def run_acvp_bytes(self, items, *, report=None, on_start=None, on_reply=None, stop=None):
        profile = self.capabilities['deployment_kib']
        path = self.package / '03_复现环境与运行程序/软件演示程序/入口/unified_workbench/arithmetic' / f'stm32-acvp-{profile}'
        with self._diagnostic(path,report=report,title='正在启动 STM32 板上 ACVP 字节核验') as exchange:
            require(exchange(1, trace='查询 ACVP 字节核验')[41] == 0x41564350)
            for index,(parameter,operation,tc,fields) in enumerate(items):
                if stop is not None and stop():
                    break
                if on_start: on_start(index,parameter,operation,tc)
                prefix = 'ML-KEM' if parameter>100 else 'ML-DSA'
                title = f'{prefix}-{parameter} · tc{tc}'
                meta, payload = [], bytearray()
                for field in ('coins','public_key','secret_key','ciphertext','signature','message','context'):
                    value = fields.get(field,b'')
                    meta.extend((len(payload),len(value)))
                    payload.extend(value)
                blob = struct.pack('<18I',parameter,operation,tc,0,*meta)+payload
                require(len(blob) <= 12360, 'INVALID_REQUEST')
                exchange(29,param=len(blob),trace=title+' · 准备输入')
                for offset in range(0,len(blob),36):
                    chunk=bytes(blob[offset:offset+36]).ljust(36,b'\0')
                    words=struct.unpack('<5I',chunk[16:])
                    reply=exchange(30,chunk[:16].hex(),param=offset,budget=words[0],mlen=words[1],
                                   clen=words[2],entropy=words[3],flags=words[4],trace=title+' · 发送测试输入')
                    require(reply[24] == min(offset+36,len(blob)))
                reply = exchange(31,param=parameter,profile=tc,timeout=30,trace=title+' · 请求执行')
                require(reply[25] == tc and all(0 <= n <= 4896 for n in reply[26:28])
                        and all(v in (0,1) for v in (reply[28],reply[31],reply[33])))
                output=[]
                for field,size in enumerate(reply[26:28]):
                    data=bytearray()
                    for offset in range(0,size,128):
                        frame=exchange(32,param=field,profile=offset,trace=title+' · 回传实际输出')
                        require(frame[56:59] == (field,offset,min(size-offset,128)))
                        data.extend(struct.pack('<32I',*frame[24:56])[:frame[58]])
                    output.append(bytes(data))
                if on_reply: on_reply(index,reply,output)
            exchange(33,trace='清理 ACVP 诊断缓冲区')

    def run_primitive(self, packet, *, label, report):
        profile = self.capabilities['deployment_kib']
        path = self.package / '03_复现环境与运行程序/软件演示程序/入口/unified_workbench/arithmetic' / f'stm32-primitives-{profile}'
        cookie, = struct.unpack_from('<I',packet)
        with self._diagnostic(path,report=report,title='正在启动 STM32 算术诊断') as exchange:
            require(exchange(1,trace='查询原语算术诊断')[41] == 0x504f4c59)
            for offset in range(0,len(packet),36):
                chunk=packet[offset:offset+36].ljust(36,b'\0')
                args=struct.unpack('<5I',chunk[16:])
                reply=exchange(35,chunk[:16].hex(),param=offset,budget=args[0],mlen=args[1],
                               clen=args[2],entropy=args[3],flags=args[4],trace=label+' · 发送测试输入')
                require(reply[24] == min(offset+36,len(packet)))
            if report: report(label+' · 请求板端执行')
            reply=exchange(36,param=cookie,timeout=20,trace=label+' · 执行')
            require(reply[25] == cookie and reply[26] > 0)
            output=bytearray()
            size=wire.PRIMITIVE_OUTPUT.size
            for offset in range(0,size,128):
                frame=exchange(37,param=offset,profile=cookie,trace=label+' · 回传结果')
                require(frame[56:59] == (offset,min(size-offset,128),cookie))
                output.extend(struct.pack('<32I',*frame[24:56])[:frame[57]])
            exchange(34,trace='清理算术缓冲区')
        status=struct.unpack('<i',struct.pack('<I',reply[24]))[0]
        return status,bytes(output),reply[26],None

    def run_kat(self, request, expected_ids):
        require(self.can_run_kat(), 'NOT_CONNECTED')
        parameter, strategy = request['parameter'], request['strategy']
        require((parameter, strategy) in self.images, 'INVALID_REQUEST')
        image = self.images[parameter, strategy]
        nonce = secrets.token_hex(16)
        with self._transaction():
            response = self.engine.run(parameter=parameter, strategy=strategy, message_len=0, context_len=0,
                                       nonce=nonce, entropy='deterministic', command='kat')
            require(response.get('request_id') == nonce and response.get('parameter') == parameter
                    and response.get('strategy') == strategy and response.get('firmware_sha256') == image['sha256']
                    and response.get('firmware_readback') is True and response.get('entropy_source') == 'deterministic',
                    'IDENTITY_MISMATCH')
            require(response.get('kat_ids') == list(expected_ids) and response.get('kat_count') == len(expected_ids)
                    and len(response['return_codes']) == 4 and len(response['workspace_peaks']) == 4
                    and all(type(code) is int for code in response['return_codes'])
                    and type(response['guard_intact']) is bool
                    and set(response['checks']) == {f'case{i+1}' for i in range(len(expected_ids))}
                    and all(type(value) is bool for value in response['checks'].values()))
            if self.mode == 'dfu':
                self.port = None
            self.mode = 'cdc'
            return response

    def run(self, request):
        if self.state != 'connected':
            raise ProviderError('BUSY' if self.state == 'busy' else 'NOT_CONNECTED')
        fields = {'library', 'parameter', 'message_bytes', 'context_bytes', 'mode'}
        require(type(request) is dict and set(request) == fields, 'INVALID_REQUEST')
        p, mode = request['parameter'], request['mode']
        library = request['library']
        require(type(library) is str and library.startswith(self.prefix), 'INVALID_REQUEST')
        strategy = library[len(self.prefix):]
        message, context = request['message_bytes'], request['context_bytes']
        require(type(p) is int and (p, strategy) in self.images and mode in self.capabilities['modes'], 'INVALID_REQUEST')
        require(type(message) is int and message in self.capabilities['message_lengths'] and
                type(context) is int and context in self.capabilities['context_lengths'] and
                (p < 100 or (message == 0 and context == 0)), 'INVALID_REQUEST')
        with self._transaction():
            observation = self._execute(p, strategy, mode, message, context)
            if self.mode == 'dfu':
                self.port = None  # The ROM serial and the CDC device ID use different encodings.
            self.mode = 'cdc'
            return observation

    def _execute(self, p, strategy, mode, message, context):
        image = self.images[p, strategy]
        nonce = secrets.token_hex(16)
        raw = self.engine.run(parameter=p, strategy=strategy, mode=mode, message_len=message,
                              context_len=context, nonce=nonce, image_dir=self.image_dir, serial=self.port)
        require(isinstance(raw, dict) and raw.get('request_id') == nonce and raw.get('parameter') == p
                and raw.get('strategy') == strategy and raw.get('mode') == mode, 'IDENTITY_MISMATCH')
        require(raw.get('firmware_sha256') == image['sha256'] and raw.get('build_tag') == image['build_tag']
                and raw.get('firmware_readback') is True
                and raw.get('message_len') == message and raw.get('context_len') == context,
                'IDENTITY_MISMATCH')
        require(raw.get('device_id') and raw.get('uid') and raw.get('cpuid') and raw.get('platform') == 'STM32F407')
        require(raw.get('entropy_source') == 'hardware')
        require(raw.get('operation_names') == ['keypair', *op_keys(p)[1:]])
        for key in ('cycles', 'workspace_peaks', 'stack_peaks', 'return_codes'):
            require(isinstance(raw.get(key), (list, tuple)) and len(raw[key]) == 4)
        clock = number(raw['clock_hz'], 1)
        require(clock == image['clock_hz'] and raw.get('image_bytes') == image['image_bytes']
                and raw.get('workspace_capacity') == image['workspace_capacity']
                and raw.get('firmware_readback') is True, 'IDENTITY_MISMATCH')
        operations = []
        fourth = 'decaps_modified_ciphertext' if p > 100 else 'verify_modified_signature'
        for i, key in enumerate((*op_keys(p), fourth)):
            cycles = number(raw['cycles'][i])
            peak = number(raw['workspace_peaks'][i])
            require(peak <= image['workspace_capacity'] and number(raw['stack_peaks'][i]) <= raw['stack_capacity'])
            rc = raw['return_codes'][i]
            require(type(rc) is int)
            title = (NAMES[key] if i < 3 else '篡改密文解封装' if p > 100 else '篡改签名验签')
            operations.append(dict(operation=key, operation_title=title, return_code=rc, cycles=cycles,
                                   stack_bytes=number(raw['stack_peaks'][i]),
                                   microseconds=round(cycles * 1_000_000 / clock, 3),
                                   arena_high_water_bytes=peak))
        plans=raw.get('resource_plans')
        if plans:
            require(len(plans)==3 and all(x['parameter']==p and x['strategy']==strategy and
                    x['operation']==j and x['address_mod_32']==0 and x['plan_code']==0 and
                    x['full_ram_bytes']==raw['static_ram_bytes'] for j,x in enumerate(plans)))
            for j,row in enumerate(operations):
                bound=number(plans[min(j,2)]['aligned_workspace_bound'],1)
                require(row['arena_high_water_bytes']<=bound)
                row['workspace_bound_bytes']=bound
        checked = self.checks(raw, mode, p)
        passed = bool(checked) and all(checked.values())
        passed = (passed and raw.get('passed') is True
                  and all(row['return_code'] == 0 and row['cycles'] > 0 for row in operations[:3])
                  and operations[3]['return_code'] == (0 if p > 100 else -6) and operations[3]['cycles'] > 0)
        if mode == 'insufficient':
            require(type(raw.get('insufficient_rc')) is int and type(raw.get('recovery_rc')) is int)
            passed = passed and raw['insufficient_rc'] == -5 and raw['recovery_rc'] == 0
        raw_words = raw.get('raw_words')
        require(isinstance(raw_words, (list,tuple)) and len(raw_words) == 64 and
                all(type(word) is int and 0 <= word <= 0xffffffff for word in raw_words))
        packet = struct.pack('<64I', *raw_words)
        require(packet[16:32].hex() == nonce, 'IDENTITY_MISMATCH')
        raw_file = None
        if self.records_directory:
            self.records_directory.mkdir(parents=True, exist_ok=True)
            raw_file = nonce + '.bin'
            with (self.records_directory / raw_file).open('xb') as handle:
                handle.write(packet)
            if plans:
                with (self.records_directory/(nonce+'-workspace.bin')).open('xb') as handle:
                    for plan in plans:handle.write(struct.pack('<64I',*plan['raw_words']))

        return dict(response_file=raw_file, response_sha256=hashlib.sha256(packet).hexdigest(), insufficient_code=raw.get('insufficient_rc') if mode == 'insufficient' else None,
                    recovery_code=raw.get('recovery_rc') if mode == 'insufficient' else None,
                    test_workspace_bytes=raw['workspace_bytes'] if mode == 'insufficient' else None,
                    kind='stm32f407_live_observation', protocol='stm32f407', platform='STM32F407',
                    source='本次实板运行', request_id=nonce, library=self.prefix + strategy,
                    algorithm='ML-KEM' if p > 100 else 'ML-DSA', parameter=p, mode=mode, strategy=strategy,
                    message_bytes=message, context_bytes=context, firmware_sha256=image['sha256'],
                    build_tag=image['build_tag'], device_id=raw['device_id'], uid=raw['uid'], cpuid=raw['cpuid'],
                    entropy_source='板载硬件随机数发生器', clock_hz=clock,
                    workspace_bytes=number(raw['workspace_capacity']), stack_peak=number(raw['stack_peak']),
                    static_ram_bytes=number(raw['static_ram_bytes']), image_bytes=number(raw['image_bytes']),
                    image_storage=raw.get('image_storage','sram'), stack_capacity=raw['stack_capacity'],
                    checks=checked, functional_checks_passed=passed, operations=operations)

    @staticmethod
    def checks(raw, mode, parameter):
        values = raw['checks']
        require(isinstance(values, dict) and values and all(type(v) is bool for v in values.values()))
        titles = {'keypair': '密钥生成', 'operation2': '封装' if parameter > 100 else '签名',
                  'operation3': '解封装' if parameter > 100 else '验签',
                  'tamper': '篡改密文隐式拒绝' if parameter > 100 else '篡改签名拒绝',
                  'cleanup': '工作区清理', 'random_failure': '随机源故障处置', 'bounds': '缓冲区边界',
                  'capacity_rejected': '容量不足被拒绝', 'recovered': '恢复容量后执行', 'alias': '重叠缓冲区检查', 'guards': '栈与缓冲区哨兵'}
        required = {'keypair', 'operation2', 'operation3', 'tamper', 'cleanup', 'random_failure', 'bounds', 'alias', 'guards'}
        if mode == 'insufficient':
            required |= {'capacity_rejected', 'recovered'}
        require(required <= set(values))
        require(type(raw['tamper_check']) is bool and values['tamper'] == raw['tamper_check'])
        return {title: values[key] for key, title in titles.items() if key in values}
