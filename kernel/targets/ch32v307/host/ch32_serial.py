"""Real CH32V307 UART protocol v1. Each cryptographic operation is sent once."""
from __future__ import annotations
import argparse
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
import pathlib
import secrets
import struct
import sys
import threading
import time
import zlib

HEADER = struct.Struct('<4sIIII')
PREFIX = struct.Struct('<IiIIQII')
OPERATION = struct.Struct('<IiQIIII')
PARAMETERS = (512, 768, 1024, 44, 65, 87)
# Fixed half-duplex turnaround allowance, outside all device API timing.
# Every image receives the same allowance. Failed commands are never resent.
REQUEST_QUIET_SECONDS = 0.005
HELLO_TIMEOUT_SECONDS = 2.0
HELLO_SYNC_BYTES = 512


class ProtocolError(RuntimeError):
    ui_code = 'CH32_RESPONSE'


class HelloSyncError(ProtocolError):
    ui_code = 'CH32_HANDSHAKE'


class IdentityError(ProtocolError):
    ui_code = 'IDENTITY_MISMATCH'


def require(ok, reason):
    if not ok:
        raise ProtocolError(reason)


def frame(command, sequence, payload, magic=b'PQC1'):
    require(type(command) is int and 0 <= command <= 0xffffffff, 'command range')
    require(type(sequence) is int and 0 < sequence <= 0xffffffff, 'sequence range')
    require(type(payload) is bytes and len(payload) <= 4096, 'payload bound')
    prefix = struct.pack('<4sIII', magic, command, sequence, len(payload))
    return prefix + struct.pack('<I', zlib.crc32(prefix + payload)) + payload


def prefix(data, command, sequence, nonce):
    require(len(data) >= PREFIX.size, 'missing response prefix')
    version, status, echoed, run_sequence, label, flags, detail = PREFIX.unpack_from(data)
    require(version == 1 and echoed == sequence, 'wrong response version/sequence')
    require(label == nonce, 'device connection label changed')
    require(flags & ~3 == 0, 'unknown response flags')
    return dict(version=version, status=status, request_sequence=echoed,
                run_sequence=run_sequence, session_nonce=label, flags=flags, detail=detail)


def hello(data, sequence, nonce):
    require(len(data) == 152, 'HELLO length')
    result = prefix(data, 1, sequence, nonce)
    require(result['status'] == 0 and result['detail'] == 0 and result['flags'] == 3,
            'HELLO configuration/cleanup failed')
    names = ('clock_hz', 'systick_control', 'flash_capacity_bytes', 'ram_capacity_bytes',
             'flash_load_bytes', 'ram_reserved_bytes', 'workspace_bytes', 'test_stack_bytes',
             'control_stack_bytes', 'caller_io_bytes', 'maximum_payload_bytes',
             'maximum_message_bytes', 'maximum_context_bytes', 'operation_mask',
             'kem_entropy_bytes', 'dsa_entropy_bytes')
    result.update(zip(names, struct.unpack_from('<16I', data, 32)))
    result['build_id'] = data[96:128].hex()
    result['rcc_control'], result['rcc_config'], result['counter'], result['gpioa_cfghr'], result['usart1_brr'] = struct.unpack_from('<IIQII', data, 128)
    require(result['systick_control'] == 5 and result['clock_hz'] > 0, 'invalid timer configuration')
    require(result['flash_load_bytes'] <= result['flash_capacity_bytes'] and
            result['ram_reserved_bytes'] <= result['ram_capacity_bytes'], 'firmware exceeds declared memory')
    require(112 <= result['maximum_payload_bytes'] <= 4096 and
            result['maximum_message_bytes'] <= result['maximum_payload_bytes']-112 and
            result['maximum_context_bytes'] <= 255 and result['operation_mask'] == 0x3ffff and
            result['kem_entropy_bytes'] == 96 and result['dsa_entropy_bytes'] == 64,
            'unsupported firmware capability')
    return result


def flow_response(data, sequence, nonce, parameter, message, domain, info):
    require(len(data) in (32, 256), 'FLOW response length')
    result = prefix(data, 2, sequence, nonce)
    if len(data) == 32:
        require(result['status'] < 0, 'truncated successful FLOW')
        return result
    names = ('parameter', 'message_bytes', 'context_bytes', 'entropy_consumed', 'pass_mask',
             'maximum_arena_bytes', 'maximum_stack_watermark_bytes', 'record_count')
    result.update(zip(names, struct.unpack_from('<8I', data, 32)))
    require((result['parameter'], result['message_bytes'], result['context_bytes']) ==
            (parameter, len(message), len(domain)), 'FLOW request echo differs')
    require(result['record_count'] == 4, 'incomplete FLOW records')
    result['public_key_sha3_256'] = data[64:96].hex()
    result['public_output_sha3_256'] = data[96:128].hex()
    result['operations'] = []
    for i in range(4):
        values = OPERATION.unpack_from(data, 128 + 32*i)
        row = dict(zip(('operation_id','return_code','ticks','arena_high_water_bytes',
                        'stack_watermark_bytes','allocations','allocation_failures'),values))
        require(row['operation_id'] == i and -127 <= row['return_code'] <= 0, 'invalid operation record')
        require(row['arena_high_water_bytes'] <= info['workspace_bytes'] and
                row['stack_watermark_bytes'] <= info['test_stack_bytes'] - 32,
                'operation memory exceeds reservation')
        result['operations'].append(row)
    require(result['maximum_arena_bytes'] == max(r['arena_high_water_bytes'] for r in result['operations']) and
            result['maximum_stack_watermark_bytes'] == max(r['stack_watermark_bytes'] for r in result['operations']),
            'resource maximum differs from operation records')
    if result['status'] == 0:
        require(result['flags'] == 3 and result['detail'] == 0 and result['pass_mask'] == 255 and
                result['entropy_consumed'] == (96 if parameter > 100 else 64) and
                [r['return_code'] for r in result['operations']] == ([0,0,0,0] if parameter > 100 else [0,0,0,-6]) and
                all(r['ticks'] > 0 and r['allocation_failures'] == 0 for r in result['operations']),
                'inconsistent successful FLOW')
    return result


class SerialDevice:
    def __init__(self, port, expected, timeout=120, serial_factory=None):
        require(type(expected) is dict and len(expected.get('build_id','')) == 64, 'expected firmware build identity required')
        self.expected = dict(expected)
        self.timeout = timeout
        self.lock = threading.Lock()
        self.records = []
        self.sequence = 0
        self.nonce = secrets.randbits(64) or 1
        self.info = None
        self.last_run_sequence = None
        if serial_factory is None:
            vendor = pathlib.Path(__file__).resolve().parent / 'vendor'
            if vendor.is_dir():
                sys.path.insert(0, str(vendor))
            import serial
            serial_factory = serial.Serial
        self.serial = serial_factory(port=None, baudrate=115200, bytesize=8, parity='N', stopbits=1,
                                     timeout=.1, write_timeout=5, xonxoff=False, rtscts=False, dsrdtr=False)
        self.serial.port = port
        self.serial.dtr = False
        self.serial.rts = False
        self.serial.open()

    def close(self):
        self.serial.close()

    def _read(self, count, deadline, record, phase):
        result = bytearray()
        while len(result) < count:
            if time.monotonic() >= deadline:
                record['partial_'+phase+'_hex'] = result.hex()
                raise ProtocolError('serial response timeout; operation not resent')
            part = self.serial.read(count-len(result))
            result.extend(part)
        return bytes(result)

    def _hello_reply(self, deadline, record):
        # A new OS handle can start in the middle of a previous UART frame.
        # Only HELLO has a fresh nonce and is safe to align or renegotiate.
        pending = bytearray()
        skipped = bytearray()
        first = bytearray()
        try:
            while time.monotonic() < deadline:
                while len(pending) >= 4:
                    pos = pending.find(b'PQCR')
                    if pos != 0:
                        count = pos if pos > 0 else len(pending)-3
                    elif len(pending) < HEADER.size:
                        break
                    else:
                        _, command, seq, length, crc = HEADER.unpack_from(pending)
                        if (command,seq,length) != (1,self.sequence,152):
                            count = 1
                        elif len(pending) < HEADER.size+length:
                            break
                        else:
                            head = bytes(pending[:HEADER.size])
                            body = bytes(pending[HEADER.size:HEADER.size+length])
                            if zlib.crc32(head[:16]+body) != crc:
                                record['invalid_response_hex'] = (head+body).hex()
                                raise ProtocolError('HELLO response CRC differs')
                            if struct.unpack_from('<Q',body,16)[0] == self.nonce:
                                return head,body
                            # The CRC-valid reply is from another connection.
                            count = HEADER.size+length
                    skipped.extend(pending[:count])
                    del pending[:count]
                    if len(skipped) > HELLO_SYNC_BYTES:
                        raise HelloSyncError('HELLO alignment byte limit exceeded')
                # A first read waits for one byte. A second drains available bytes only.
                # A read never consumes data after a current validated HELLO frame.
                n = min(HEADER.size+152-len(pending),max(1,getattr(self.serial,'in_waiting',0)))
                part = self.serial.read(n)
                first.extend(part[:max(0,HEADER.size-len(first))])
                pending.extend(part)
            raise HelloSyncError('no complete HELLO for the current connection')
        finally:
            if skipped:
                record['alignment_discarded_bytes'] = len(skipped)
                record['alignment_discarded_hex'] = skipped[:HELLO_SYNC_BYTES].hex()
            if skipped or pending and len(pending) < HEADER.size+152:
                record['first_observed_header_hex'] = first.hex()
                if pending and len(pending) < HEADER.size+152:
                    record['partial_hello_hex'] = pending.hex()

    def _exchange(self, command, payload):
        self.sequence += 1
        request = frame(command, self.sequence, payload)
        quiet_start = time.monotonic_ns()
        time.sleep(REQUEST_QUIET_SECONDS)
        quiet_elapsed = time.monotonic_ns() - quiet_start
        started = time.monotonic_ns()
        record = dict(command=command, request_sequence=self.sequence,
                      request_bytes=len(request), request_sha256=hashlib.sha256(request).hexdigest(),
                      requested_quiet_seconds=REQUEST_QUIET_SECONDS, actual_quiet_ns=quiet_elapsed)
        self.records.append(record)
        try:
            require(self.serial.write(request) == len(request), 'partial serial write')
            self.serial.flush()
            if command == 1:
                deadline = time.monotonic() + min(self.timeout,HELLO_TIMEOUT_SECONDS)
                raw_header,data = self._hello_reply(deadline,record)
            else:
                deadline = time.monotonic() + self.timeout
                raw_header = self._read(HEADER.size, deadline, record, 'header')
                magic, echoed_command, sequence, length, crc = HEADER.unpack(raw_header)
                if (magic,echoed_command,sequence) != (b'PQCR',command,self.sequence) or not 32 <= length <= 4096:
                    record['invalid_header_hex'] = raw_header.hex()
                    raise ProtocolError('unexpected serial response header')
                data = self._read(length, deadline, record, 'payload')
                if zlib.crc32(raw_header[:16]+data) != crc:
                    record['invalid_response_hex'] = (raw_header+data).hex()
                    raise ProtocolError('response CRC differs')
            record.update(status='RECEIVED', response_hex=(raw_header+data).hex(),
                          host_elapsed_ns=time.monotonic_ns()-started)
            return data
        except Exception as error:
            record.update(status='INCOMPLETE', error=str(error), host_elapsed_ns=time.monotonic_ns()-started)
            if not isinstance(error,HelloSyncError):
                self.close()
            raise

    def handshake(self):
        with self.lock:
            try:
                try:
                    data = self._exchange(1, struct.pack('<Q',self.nonce))
                except HelloSyncError:
                    # The original HELLO was read-only. Give the one extra handshake a
                    # different sequence AND nonce so a late first reply cannot satisfy it.
                    # Uniform among all nonzero 64-bit labels except the prior one.
                    candidate = secrets.randbelow((1<<64)-2)+1
                    self.nonce = candidate+int(candidate>=self.nonce)
                    data = self._exchange(1, struct.pack('<Q',self.nonce))
                info = hello(data,self.sequence,self.nonce)
                for name,value in self.expected.items():
                    if info.get(name) != value:
                        raise IdentityError('firmware identity/layout differs: '+name)
                self.info = info
                self.last_run_sequence = info['run_sequence']
                return dict(info)
            except Exception:
                self.info = None
                self.close()
                raise

    def flow(self, parameter, message=b'', domain=b'', entropy=None):
        require(parameter in PARAMETERS and type(parameter) is int, 'parameter not supported')
        require(type(message) is bytes and type(domain) is bytes, 'byte inputs required')
        require(self.info is not None, 'HELLO required')
        require(len(domain) <= self.info['maximum_context_bytes'] and
                len(message) <= self.info['maximum_message_bytes'] and
                len(message)+len(domain) <= self.info['maximum_payload_bytes']-112 and
                (parameter < 100 or not message and not domain), 'message/context length unsupported')
        entropy_count = 96 if parameter > 100 else 64
        entropy = secrets.token_bytes(entropy_count) if entropy is None else entropy
        require(type(entropy) is bytes and len(entropy) == entropy_count, 'wrong entropy length')
        payload = struct.pack('<4I',parameter,len(message),len(domain),entropy_count)
        payload += entropy + bytes(96-entropy_count) + message + domain
        with self.lock:
            try:
                data = self._exchange(2,payload)
                result = flow_response(data,self.sequence,self.nonce,parameter,message,domain,self.info)
                if len(data) == 256:
                    require(result['run_sequence'] == self.last_run_sequence+1, 'device run counter differs')
                    self.last_run_sequence = result['run_sequence']
                else:
                    require(result['run_sequence'] == self.last_run_sequence, 'rejected request executed a flow')
                result['clock_hz'] = self.info['clock_hz']
                result['build_id'] = self.info['build_id']
                result['host_transport_elapsed_ns'] = self.records[-1]['host_elapsed_ns']
                return result
            except Exception:
                self.info = None
                self.close()
                raise


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--port',default='COM13')
    p.add_argument('--expected',type=pathlib.Path,required=True)
    p.add_argument('--output',type=pathlib.Path,required=True)
    p.add_argument('--parameter',type=int,choices=PARAMETERS)
    p.add_argument('--message-bytes',type=int,default=32)
    p.add_argument('--context-bytes',type=int,default=0)
    p.add_argument('--test-seed-hex')
    a=p.parse_args()
    require(not a.output.exists(),'fresh output file required')
    require(0 <= a.message_bytes <= 3984 and 0 <= a.context_bytes <= 255 and
            a.message_bytes+a.context_bytes <= 3984, 'message/context length unsupported')
    expected=json.loads(a.expected.read_text(encoding='utf-8'))
    device=SerialDevice(a.port,expected)
    result={'hardware':'CH32V307','transport':'physical_uart','status':'INCOMPLETE'}
    try:
        result['hello']=device.handshake()
        if a.parameter:
            message=bytes((i*17+3)&255 for i in range(a.message_bytes)) if a.parameter<100 else b''
            domain=bytes((i*13+7)&255 for i in range(a.context_bytes)) if a.parameter<100 else b''
            entropy=None
            if a.test_seed_hex:
                entropy=hashlib.shake_256(bytes.fromhex(a.test_seed_hex)).digest(96 if a.parameter>100 else 64)
            result['entropy_source']='deterministic_test_fixture' if entropy is not None else 'host_os_csprng'
            result['flow']=device.flow(a.parameter,message,domain,entropy)
            require(result['flow']['status']==0,'device flow failed')
        result['status']='PASS'
    finally:
        result['transport_records']=device.records
        a.output.parent.mkdir(parents=True,exist_ok=True)
        a.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
        device.close()
    print(json.dumps({'status':result['status'],'parameter':a.parameter,'output':str(a.output)}))


if __name__=='__main__':
    main()
