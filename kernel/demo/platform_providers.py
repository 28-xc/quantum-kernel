"""Local, fixed-command SSH and injected board providers. No automatic retries."""
from pathlib import Path, PurePosixPath
import copy
import os
import re
import secrets
import shlex
import subprocess
import threading
import time

from demo import platform_protocol as wire


class ProviderError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class LocalProvider:
    platform_id = 'windows'

    def __init__(self, application):
        self.application = application

    def catalog(self):
        return self.application.catalog()

    def run(self, value):
        wire.run_request(value)
        result = copy.deepcopy(self.application.run(value))
        result['execution'] = dict(platform_id=self.platform_id, transport='local', live=True,
                                   image_sha256=result['binary_sha256'])
        return result


class ExchangeProvider:
    """Board driver injection receives a request dict and returns the envelope.

    The owner driver owns all serial/USB access and hardware identity checks.
    Pins map library IDs to actual executable/firmware SHA256 values.
    """
    def __init__(self, platform_id, exchange, image_pins, transport):
        wire.require(wire.TOKEN.fullmatch(platform_id), 'Invalid platform')
        wire.require(callable(exchange), 'Provider exchange must be callable')
        wire.require(type(image_pins) is dict and image_pins and all(
            type(k) is str and wire.TOKEN.fullmatch(k) and type(v) is str and wire.SHA256.fullmatch(v)
            for k, v in image_pins.items()), 'Explicit image pins required')
        self.platform_id = platform_id
        self.exchange = exchange
        self.image_pins = dict(image_pins)
        self.transport = transport
        self.lock = threading.Lock()
        self.state = 'disconnected'
        self._sequences = {}
        self.capabilities = {}

    def _call(self, action, payload):
        sent = wire.request(dict(schema=wire.SCHEMA, request_id=secrets.token_hex(16), action=action, payload=payload))
        if not self.lock.acquire(blocking=False):
            raise ProviderError('BUSY')
        self.state = 'busy'
        try:
            started = time.monotonic_ns()
            received = self.exchange(copy.deepcopy(sent))
            round_trip_ns = time.monotonic_ns() - started
            wire.response(received, sent, self.platform_id)
            session = received['session_id']
            wire.require(received['sequence'] > self._sequences.get(session, 0), 'Repeated device response')
            # One-shot SSH runners legitimately start a new process session.
            self._sequences[session] = received['sequence']
            if len(self._sequences) > 256:
                self._sequences.pop(next(iter(self._sequences)))
            if not received['ok']:
                raise ProviderError(received['error'])
            self._validate_body(action, received['body'], payload)
            self.state = 'connected'
            return received, round_trip_ns
        except Exception:
            self.state = 'disconnected'
            raise
        finally:
            self.lock.release()

    def _validate_body(self, action, body, payload):
        if action == 'security':
            wire.require(self.platform_id == 'arm', 'Unexpected security provider')
            wire.security_result(body, payload)
            wire.require(body['binary_sha256'] == self.image_pins[payload['library']],
                         'Remote security library mismatch')
            return
        if action == 'performance':
            wire.require(self.platform_id == 'arm', 'Unexpected timed provider')
            wire.performance_result(body, payload)
            wire.require(body['binary_sha256'] == self.image_pins[payload['library']],
                         'Remote timing library mismatch')
            return
        if action == 'arithmetic':
            field = 'output' if 'binding' in payload else 'coefficients'
            wire.require(self.platform_id == 'arm' and set(body)=={'status','duration_ns',field,'binary_sha256'},
                         'Invalid arithmetic response')
            wire.require(wire.SHA256.fullmatch(body['binary_sha256']) and
                type(body['status']) is int and -1<=body['status']<=0 and
                type(body['duration_ns']) is int and body['duration_ns'] >= 0, 'Invalid arithmetic result')
            if field=='output':
                wire.binary_field(body[field],wire.PRIMITIVE_OUTPUT.size)
            else:
                wire.decode_polynomials(body[field],256,payload['modulus'])
            return
        if action == 'acvp':
            wire.require(self.platform_id=='arm' and set(body)=={'binary_sha256','rows','details'}
                         and body['binary_sha256']==self.image_pins[payload['library']],
                         'Remote ACVP library mismatch')
            rows=body['rows']
            wire.require(type(rows) is list and [[row['parameter'],row['case_id']] for row in rows]==payload['cases']
                         and all(type(row['verified']) is bool and type(row['return_code']) is int for row in rows)
                         and type(body['details']) is dict and set(body['details'])=={row['case_id'] for row in rows},
                         'Remote ACVP results are incomplete')
            for value in body['details'].values():
                wire.require(type(value['inputs']) is dict and type(value['outputs']) is list,'Invalid ACVP detail')
                for data in (*value['inputs'].values(),*(item[key] for item in value['outputs'] for key in ('actual','expected'))):
                    wire.require(type(data) is str and len(data)<=16384 and len(data)%2==0 and re.fullmatch('[0-9a-f]*',data),
                                 'Invalid ACVP bytes')
            return
        if action == 'run':
            wire.functional_result(body, payload)
            wire.require('device_metrics' not in body or self.platform_id == 'ch32', 'Device metric source is not registered')
            wire.require(body['binary_sha256'] == self.image_pins[payload['library']], 'Remote run image mismatch')
            return
        wire.require(type(body.get('libraries')) is list, 'Missing capability catalog')
        seen = set()
        capabilities = {}
        for item in body['libraries']:
            key = item.get('id')
            wire.require(key in self.image_pins and key not in seen, 'Unexpected or duplicate remote library')
            wire.require(item.get('binary_sha256') == self.image_pins[key], 'Remote image changed')
            wire.require(type(item.get('parameters')) is list and item['parameters'] and all(
                type(p) is int and p in wire.PARAMETERS for p in item['parameters']), 'Invalid parameter capability')
            wire.run_presets(item.get('run_presets'))
            wire.require(type(item.get('execution_available')) is bool, 'Explicit execution availability required')
            if 'workspace_options' in item:
                options=item['workspace_options']
                wire.require(type(options) is list and len(options)==2 and len(set(options))==2 and all(type(n) is int and 32<=n<=1048576 and n%32==0 for n in options)
                             and item.get('workspace_bytes') in options,'Invalid remote workspace options')
            capabilities[key] = copy.deepcopy(item)
            seen.add(key)
        wire.require(seen == set(self.image_pins), 'Missing expected remote library')
        self.capabilities = capabilities

    def catalog(self):
        return self._call('catalog', {})[0]['body']

    def run(self, value):
        wire.run_request(value)
        wire.require(value['library'] in self.image_pins, 'Unregistered remote library')
        if not self.capabilities:
            self.catalog()
        capability = self.capabilities[value['library']]
        if 'workspace_bytes' in value:
            wire.require(value['workspace_bytes'] in capability.get('workspace_options',[capability.get('workspace_bytes')]),'Unregistered remote workspace choice')
        wire.require(capability['execution_available'] and value['parameter'] in capability['parameters'], 'Unsupported device parameter')
        presets = capability['run_presets']
        wire.require(value['message_bytes'] in presets['message_lengths'] and value['context_bytes'] in presets['context_lengths'] and
                     value['mode'] in presets['modes'], 'Unsupported device preset')
        reply, round_trip_ns = self._call('run', value)
        body = reply['body']
        result = copy.deepcopy(body)
        result['execution'] = dict(platform_id=self.platform_id, transport=self.transport, live=True,
                                  request_id=reply['request_id'], session_id=reply['session_id'],
                                  sequence=reply['sequence'], device_run_id=body['run_id'],
                                  image_sha256=body['binary_sha256'])
        result['execution']['host_round_trip_ns'] = round_trip_ns
        result['execution']['host_round_trip_scope'] = 'device-execution-and-transport;not-cryptographic-timing'
        return result


def _bounded_command(argv, data, timeout, observe=None):
    """Bound stdout/stderr while running; stop only our own local SSH process."""
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()

    def read_stream(stream, out, limit, direction=None):
        try:
            while True:
                part = stream.read1(4096)
                if not part:
                    break
                if len(out) + len(part) > limit:
                    overflow.set()
                    return
                out.extend(part)
                if observe and direction:
                    observe(direction, part)
        finally:
            stream.close()

    readers = [threading.Thread(target=read_stream, args=(process.stdout, buffers[0], wire.MAX_RESPONSE, 'RX'), daemon=True),
               threading.Thread(target=read_stream, args=(process.stderr, buffers[1], 65536), daemon=True)]
    for worker in readers:
        worker.start()
    try:
        process.stdin.write(data)
        process.stdin.flush()
        if observe:
            observe('TX', data)
        process.stdin.close()
        until = time.monotonic() + timeout
        while process.poll() is None:
            if overflow.is_set():
                raise ProviderError('RESPONSE_TOO_LARGE')
            if time.monotonic() >= until:
                raise ProviderError('TRANSPORT_TIMEOUT')
            time.sleep(.01)
        for worker in readers:
            worker.join(timeout=2)
        if overflow.is_set() or any(worker.is_alive() for worker in readers):
            raise ProviderError('INCOMPLETE_TRANSPORT')
        if process.returncode != 0:
            raise ProviderError('TRANSPORT_FAILED')
        return bytes(buffers[0])
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if not process.stdin.closed:
            process.stdin.close()
        for worker in readers:
            worker.join(timeout=2)


class SshProvider(ExchangeProvider):
    """Constructs one fixed remote program; all operation data travels on stdin."""
    def __init__(self, config):
        fields = {'ssh_executable', 'host', 'user', 'port', 'identity_file', 'known_hosts_file',
                  'remote_python', 'remote_runner', 'remote_config', 'timeout_seconds', 'image_pins'}
        wire.require(type(config) is dict and set(config) == fields, 'Unknown SSH configuration fields')
        for name in ('ssh_executable', 'identity_file', 'known_hosts_file'):
            p = Path(config[name]).expanduser()
            wire.require(p.is_absolute() and p.is_file(), 'External SSH input absent')
        wire.require(type(config['host']) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', config['host']), 'Invalid SSH host')
        wire.require(type(config['user']) is str and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', config['user']), 'Invalid SSH user')
        wire.require(type(config['port']) is int and 1 <= config['port'] <= 65535, 'Invalid SSH port')
        wire.require(type(config['timeout_seconds']) is int and 1 <= config['timeout_seconds'] <= 180, 'Invalid SSH timeout')
        for name in ('remote_runner', 'remote_config'):
            wire.require(type(config[name]) is str and PurePosixPath(config[name]).is_absolute() and
                         not any(ord(c) < 32 for c in config[name]), 'Expected fixed absolute remote path')
        python = config['remote_python']
        wire.require(type(python) is str and (python in ('python3', 'python') or PurePosixPath(python).is_absolute()) and
                     not any(ord(c) < 32 for c in python), 'Invalid remote interpreter')
        self.config = dict(config)
        super().__init__('arm', self._exchange, config['image_pins'], 'ssh-stdin')

    def command(self):
        c = self.config
        remote = shlex.join([c['remote_python'], '-B', c['remote_runner'], '--config', c['remote_config'], '--platform', 'arm'])
        return [str(Path(c['ssh_executable']).expanduser()), '-F', 'none', '-T', '-a',
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                '-o', 'UserKnownHostsFile=' + str(Path(c['known_hosts_file']).expanduser()),
                '-i', str(Path(c['identity_file']).expanduser()), '-p', str(c['port']),
                c['user'] + '@' + c['host'], remote]

    def _exchange(self, sent):
        recorder = wire.RUN_TRAFFIC.get()
        action = sent['action']
        label = {'run': '密码操作', 'acvp': 'ACVP 测试', 'arithmetic': '算术运算',
                 'performance': '操作计时', 'security': '安全检查', 'catalog': '查询设备'}[action]
        def observe(direction, chunk):
            recorder.observe('Linux SSH', direction, chunk, label+' · '+('标准输入' if direction=='TX' else '标准输出'))
        output = _bounded_command(self.command(), wire.encode(sent, wire.MAX_REQUEST),
                                  self.config['timeout_seconds'], observe if recorder is not None else None)
        reply = wire.decode(output, wire.MAX_RESPONSE)
        if recorder is not None:
            wire.observe_frame('Linux SSH','RX',b'',label+' · '+('已解码应答' if reply.get('ok') else '设备返回错误'))
        return reply

    def run_arithmetic(self, operation, modulus, coefficients):
        return self._call('arithmetic',dict(operation=operation,modulus=modulus,
                                           coefficients=wire.encode_polynomials(coefficients)))[0]['body']

    def run_primitive(self, packet, **_):
        reply=self._call('arithmetic',dict(binding=wire.b64encode(packet).decode('ascii')))[0]['body']
        return (reply['status'],wire.binary_field(reply['output'],wire.PRIMITIVE_OUTPUT.size),
                reply['duration_ns'],reply['binary_sha256'])

    def run_performance(self, library, parameter, operation):
        capability = self.capabilities.get(library, {})
        wire.require(capability.get('operation_timing') is True and
                     parameter in capability['parameters'], 'Remote operation timing is unavailable')
        return self._call('performance', dict(library=library, parameter=parameter, operation=operation))[0]['body']

    def run_security(self, library, parameter, case):
        capability = self.capabilities.get(library, {})
        wire.require(capability.get('security_checks') is True and parameter in capability['parameters'],
                     'Remote security runner is unavailable')
        return self._call('security', dict(library=library, parameter=parameter, case=case))[0]['body']

    def run_acvp(self, library, cases):
        wire.require(self.capabilities.get(library,{}).get('acvp') is True,'Remote ACVP runner is unavailable')
        return self._call('acvp',dict(library=library,cases=cases))[0]['body']


class BoardProvider(ExchangeProvider):
    def __init__(self, exchange, image_pins):
        super().__init__('ch32', exchange, image_pins, 'serial-uart')
