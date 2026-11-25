"""Owner-injected real UART driver -> closed UI provider contract.

This module never imports a serial implementation or chooses a COM port. The
operator supplies a factory for the verified SerialDevice and retains flashing,
readback, timer qualification and transport ownership.
"""
from package_layout import from_legacy_anchor

from pathlib import Path
import copy
import datetime
import hashlib
# Shared typed XML persistence; transport JSON remains in memory.
import sys as _record_sys
from pathlib import Path as _RecordPath
for _record_parent in _RecordPath(__file__).resolve().parents:
    _record_candidate = _record_parent / 'record_io.py'
    if not _record_candidate.is_file():
        _record_candidate = _record_parent / '01_源代码/可参数化格运算内核/record_io.py'
    if _record_candidate.is_file():
        _record_sys.path.insert(0, str(_record_candidate.parent))
        break
import record_io as json
import secrets
import struct
import threading

from demo import platform_protocol as wire
from demo.platform_providers import BoardProvider, ProviderError

TIMER_STRUCT = struct.Struct('<4I4Q2I8Q4Q2I')
EXPECTED_FIELDS = {'build_id', 'clock_hz', 'systick_control', 'flash_capacity_bytes', 'ram_capacity_bytes',
                   'flash_load_bytes', 'ram_reserved_bytes', 'workspace_bytes', 'test_stack_bytes',
                   'control_stack_bytes', 'caller_io_bytes', 'rcc_control', 'rcc_config', 'usart1_brr'}
TIMER_SCOPE = 'public-api-including-internal-cleanup;excluding-outer-cleanup-hash-uart'


def read_timer(descriptor, expected_elf_sha256):
    wire.require(type(descriptor) is dict and set(descriptor) == {'path', 'sha256'} and
                 type(descriptor['sha256']) is str and wire.SHA256.fullmatch(descriptor['sha256']), 'Pinned timer receipt required')
    path = Path(descriptor['path']).resolve(strict=True)
    raw = path.read_bytes()
    wire.require(hashlib.sha256(raw).hexdigest() == descriptor['sha256'], 'Timer receipt changed')
    wire.require(0 < len(raw) <= wire.MAX_RESPONSE, 'Invalid timer receipt size')
    receipt = json.loads(raw) if raw.removeprefix(b'\xef\xbb\xbf').lstrip().startswith(b'<') else wire.decode(raw, wire.MAX_RESPONSE)
    wire.require(receipt['status'] == 'HARDWARE_TIMER_SELFTEST_PASS' and receipt['elf_sha256'] == expected_elf_sha256,
                 'Timer qualification belongs to another firmware')
    timer = receipt['timer']
    binary = receipt.get('timer_binary_path', 'timer-selftest.bin')
    wire.require(type(binary) is str and not Path(binary).is_absolute(), 'Invalid timer input')
    timer_bytes = from_legacy_anchor(path.parent, binary).read_bytes()
    wire.require(len(timer_bytes) == TIMER_STRUCT.size and
                 hashlib.sha256(timer_bytes).hexdigest() == receipt['timer_binary_sha256'], 'Raw timer evidence changed')
    words = TIMER_STRUCT.unpack(timer_bytes)
    names = ['magic', 'version', 'pass_mask', 'final_ctlr', 'carry_written', 'carry_read', 'monotonic_first',
             'monotonic_last', 'monotonic_failures', 'monotonic_reads']
    reconstructed = dict(zip(names, words[:10]))
    reconstructed['empty_read_ticks'] = list(words[10:18])
    reconstructed.update(zip(['hclk_start', 'hclk_end', 'div8_start', 'div8_end', 'nop_iterations', 'reserved'], words[18:]))
    wire.require(timer == reconstructed, 'Timer receipt and raw readback differ')
    wire.require(timer['magic'] == 0x5354494d and timer['version'] == 1 and timer['pass_mask'] == 15 and
                 timer['final_ctlr'] == 5 and timer['carry_written'] == 0xfffffff0 and
                 0x100000000 <= timer['carry_read'] < 0x100010000 and timer['monotonic_failures'] == 0 and
                 timer['monotonic_reads'] == 128 and timer['monotonic_last'] > timer['monotonic_first'], 'Incomplete timer validation')
    full = timer['hclk_end'] - timer['hclk_start']; divided = timer['div8_end'] - timer['div8_start']
    wire.require(divided > 0 and divided*6 < full < divided*10 and timer['nop_iterations'] == 1024 and
                 timer['reserved'] == 0, 'Timer clock-source check failed')
    return receipt


class UARTTrace:
    def __init__(self, port):
        self.port = port

    def __getattr__(self, name):
        return getattr(self.port, name)

    def write(self, data):
        size = self.port.write(data)
        if size:
            wire.observe_frame('CH32 串口','TX',data[:size],'发送串口帧')
        return size

    def read(self, size):
        data = self.port.read(size)
        if data:
            wire.observe_frame('CH32 串口','RX',data,'读取串口数据')
        return data


class Ch32Exchange:
    """One physical connection per request; private raw evidence is mandatory.

    driver_factory() must create the owner's SerialDevice with pinned HELLO
    expected fields. flow() is called WITHOUT an entropy override, using that
    driver's host OS CSPRNG. No retry, simulated fallback or cached HELLO.
    """
    def __init__(self, driver_factory, *, expected_elf_sha256, expected_hello, timer_receipt,
                 records_directory, library_id='ch32_compact', title='CH32V307 紧凑配置'):
        wire.require(callable(driver_factory), 'Injected driver factory required')
        wire.require(type(expected_elf_sha256) is str and wire.SHA256.fullmatch(expected_elf_sha256), 'Explicit firmware ELF SHA required')
        wire.require(type(expected_hello) is dict and set(expected_hello) == EXPECTED_FIELDS and
                     type(expected_hello['build_id']) is str and wire.SHA256.fullmatch(expected_hello['build_id']), 'Expected HELLO build/layout identity required')
        wire.require(all(type(v) is int and v > 0 for k,v in expected_hello.items() if k != 'build_id') and
                     expected_hello['systick_control'] == 5, 'Invalid pinned device layout')
        wire.require(type(library_id) is str and wire.TOKEN.fullmatch(library_id) and type(title) is str and
                     0 < len(title) <= 64 and not any(ord(c)<32 for c in title), 'Invalid device library descriptor')
        root = Path(records_directory)
        wire.require(root.is_absolute(), 'Private evidence directory must be absolute')
        root = root.resolve()
        source = Path(__file__).resolve().parents[1]
        wire.require(root != source and source not in root.parents, 'Evidence must remain outside the source tree')
        read_timer(timer_receipt, expected_elf_sha256)
        self.factory = driver_factory
        self.image_sha = expected_elf_sha256
        self.expected = copy.deepcopy(expected_hello)
        self.timer_descriptor = copy.deepcopy(timer_receipt)
        self.records = root
        self.library_id = library_id
        self.title = title
        self.lock = threading.Lock()

    def provider(self):
        return BoardProvider(self, {self.library_id: self.image_sha})

    def _hello(self, device):
        info = device.handshake()
        wire.require(type(info) is dict and all(info.get(k) == v for k,v in self.expected.items()), 'Actual firmware/layout differs')
        wire.require(info.get('status') == 0 and info.get('flags') == 3 and info.get('detail') == 0 and
                     info.get('version') == 1 and type(info.get('session_nonce')) is int and
                     0 < info['session_nonce'] < 2**64 and type(info.get('request_sequence')) is int and
                     info['request_sequence'] > 0 and type(info.get('run_sequence')) is int and
                     0 <= info['run_sequence'] < 2**32, 'Invalid actual HELLO state')
        wire.require(info['flash_load_bytes'] <= info['flash_capacity_bytes'] and
                     info['ram_reserved_bytes'] <= info['ram_capacity_bytes'], 'Device exceeds fixed partition')
        wire.require(type(info.get('maximum_payload_bytes')) is int and 112 <= info['maximum_payload_bytes'] <= 4096 and
                     type(info.get('maximum_message_bytes')) is int and 0 <= info['maximum_message_bytes'] <= info['maximum_payload_bytes']-112 and
                     type(info.get('maximum_context_bytes')) is int and 0 <= info['maximum_context_bytes'] <= 255 and
                     info.get('operation_mask') == 0x3ffff and info.get('kem_entropy_bytes') == 96 and
                     info.get('dsa_entropy_bytes') == 64, 'Unsupported actual capability')
        return info

    def _presets(self, info):
        contexts = [n for n in (0,1,255) if n <= info['maximum_context_bytes']]
        messages = [n for n in (0,32,1024) if n <= info['maximum_message_bytes'] and
                    n+max(contexts) <= info['maximum_payload_bytes']-112]
        wire.require(messages, 'No complete message/context preset supported')
        return dict(message_lengths=messages, context_lengths=contexts, modes=['normal'])

    def _catalog(self, info):
        return {'libraries': [dict(id=self.library_id, title=self.title, configuration=self.library_id,
                                   platform='ch32v307', parameters=list(wire.PARAMETERS), binary_sha256=self.image_sha,
                                   workspace_bytes=info['workspace_bytes'], execution_available=True,
                                   clock_hz=info['clock_hz'], static_ram_bytes=info['ram_reserved_bytes'],
                                   flash_bytes=info['flash_load_bytes'],
                                   execution_reason='实际串口身份已核对', run_presets=self._presets(info))]}

    def _result(self, raw, info, request):
        wire.require(raw.get('version') == 1 and raw.get('session_nonce') == info['session_nonce'] and
                     raw.get('build_id') == info['build_id'] and raw.get('clock_hz') == info['clock_hz'] and
                     raw.get('run_sequence') == info['run_sequence']+1 and
                     type(raw.get('request_sequence')) is int and raw['request_sequence'] > info['request_sequence'], 'Device run identity mismatch')
        wire.require(raw.get('parameter') == request['parameter'] and raw.get('message_bytes') == request['message_bytes'] and
                     raw.get('context_bytes') == request['context_bytes'] and raw.get('record_count') == 4, 'Device input/result mismatch')
        wire.require(type(raw.get('pass_mask')) is int and 0 <= raw['pass_mask'] <= 255 and
                     type(raw.get('status')) is int and raw['status'] <= 0 and raw.get('detail') == 0, 'Invalid FLOW result status')
        rows = raw.get('operations');wire.require(type(rows) is list and len(rows) == 4, 'Four actual device records required')
        wire.require(raw.get('maximum_arena_bytes') == max(x['arena_high_water_bytes'] for x in rows) and
                     raw.get('maximum_stack_watermark_bytes') == max(x['stack_watermark_bytes'] for x in rows), 'Device maxima differ from records')
        names = ['keygen','encaps','decaps','decaps_modified_ciphertext'] if request['parameter'] > 100 else [
                 'keygen','sign','verify','verify_modified_signature']
        public_ops=[];metrics=[];finished=False
        for i,row in enumerate(rows):
            wire.require(row.get('operation_id') == i, 'Device operation order mismatch')
            rc=row.get('return_code')
            if rc == -127: finished=True
            else:
                wire.require(not finished and type(rc) is int and -16 <= rc <= 0, 'Invalid executed operation prefix')
                public_ops.append(dict(operation=names[i], return_code=rc, outcome='SUCCESS' if rc==0 else
                                       'CAPACITY_INSUFFICIENT' if rc==-5 else 'REJECTED' if rc==-6 else 'ERROR',
                                       arena_high_water_bytes=row['arena_high_water_bytes']))
            metrics.append(dict(operation=names[i],return_code=rc,ticks=row['ticks'],
                                observed_stack_bytes=row['stack_watermark_bytes'],
                                observed_arena_high_water_bytes=row['arena_high_water_bytes']))
        mask=raw['pass_mask'];success=raw['status']==0
        wire.require(not success or (mask==255 and raw.get('flags')==3 and
                     raw.get('entropy_consumed')==(96 if request['parameter']>100 else 64) and
                     all(x.get('allocation_failures')==0 for x in rows)), 'Inconsistent FLOW success')
        checks=dict(shared_secret_equal=bool(mask&4),implicit_rejection=bool(mask&8)) if request['parameter']>100 else dict(
                    signature_verified=bool(mask&4),modified_signature_rejected=bool(mask&8))
        result=dict(schema=1,kind='local_functional_observation',run_id=f"ch32-{info['session_nonce']:016x}-{raw['run_sequence']:08x}",
                    algorithm='ML-KEM' if request['parameter']>100 else 'ML-DSA',binary_sha256=self.image_sha,
                    performance_measurement=True, operations=public_ops,checks=checks,functional_checks_passed=success,
                    workspace_bytes=info['workspace_bytes'],observed_arena_high_water_bytes=raw['maximum_arena_bytes'],
                    canaries_ok=bool(mask&16),failure_output_zero=None,**request)
        result['device_metrics']=dict(schema='lattice.device_metrics.v1',scope=TIMER_SCOPE,
            timer=dict(source='systick-hclk',frequency_hz=info['clock_hz'],counter_bits=64,validated=True),operations=metrics,
            resources=dict(flash_bytes=info['flash_load_bytes'],static_ram_bytes=info['ram_reserved_bytes'],
                           workspace_bytes=info['workspace_bytes'],test_stack_reserved_bytes=info['test_stack_bytes'],
                           control_stack_reserved_bytes=info['control_stack_bytes'],caller_io_bytes=info['caller_io_bytes']))
        return wire.functional_result(result,request)

    def __call__(self, envelope):
        sent=wire.request(envelope)
        wire.require(self.lock.acquire(blocking=False), 'A device exchange is already in progress')
        record=dict(schema='lattice.private_uart_exchange.v1',status='INCOMPLETE',
                    utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),request=copy.deepcopy(sent),
                    firmware_elf_sha256=self.image_sha,timer_receipt=copy.deepcopy(self.timer_descriptor),
                    entropy_source='host_os_csprng;not_board_trng',session_identity_scope='host_connection_nonce;not_physical_boot_identity')
        device=None
        try:
            read_timer(self.timer_descriptor,self.image_sha)
            if sent['action']=='run':
                q=sent['payload'];wire.require(q['library']==self.library_id and q['mode']=='normal' and
                    q['message_bytes'] in (0,32,1024) and q['context_bytes'] in (0,1,255), 'Unsupported board preset')
            device=self.factory()
            if wire.RUN_TRAFFIC.get() is not None:
                device.serial = UARTTrace(device.serial)
            info=self._hello(device);record['hello']=copy.deepcopy(info)
            if sent['action']=='catalog': body=self._catalog(info);sequence=info['request_sequence']
            else:
                q=sent['payload'];cap=self._presets(info)
                wire.require(q['message_bytes'] in cap['message_lengths'] and q['context_bytes'] in cap['context_lengths'], 'Unsupported actual board preset')
                message=bytes((i*29+7)&255 for i in range(q['message_bytes']))
                domain=bytes((i*17+3)&255 for i in range(q['context_bytes']))
                # Deliberately do not provide the optional entropy argument.
                raw=device.flow(q['parameter'],message,domain);record['flow']=copy.deepcopy(raw)
                body=self._result(raw,info,q);sequence=raw['request_sequence']
            reply=dict(schema=wire.SCHEMA,request_id=sent['request_id'],action=sent['action'],platform_id='ch32',
                       session_id=f"ch32-connection-{info['session_nonce']:016x}",sequence=sequence,ok=True,body=body)
            wire.response(reply,sent,'ch32')
            record['status']='PASS' if sent['action']=='catalog' or body['functional_checks_passed'] else 'VALID_FAILURE_RESULT'
            return reply
        except Exception as error:
            record['error_type']=type(error).__name__
            record['error']=str(error)
            code=getattr(error,'ui_code',None)
            if code in ('CH32_HANDSHAKE','CH32_RESPONSE','IDENTITY_MISMATCH'):
                if code=='CH32_RESPONSE' and device and device.records and device.records[-1]['command']==1:
                    code='CH32_HANDSHAKE'
                raise ProviderError(code) from error
            raise
        finally:
            try:
                if device is not None:
                    record['transport_records']=copy.deepcopy(device.records)
                    try: device.close();record['closed']=True
                    except Exception:
                        record['closed']=False;record['status']='CLOSE_FAILED';raise
            finally:
                try:
                    self.records.mkdir(parents=True,exist_ok=True)
                    path=self.records/(sent['request_id']+'-'+secrets.token_hex(4)+'.xml')
                    with path.open('x',encoding='utf8') as f:
                        json.dump(record,f,ensure_ascii=False,allow_nan=False,indent=2);f.write('\n')
                finally:self.lock.release()
