"""Portable, external connection files. Loading configuration never opens a device."""
from package_layout import from_legacy_anchor

from pathlib import Path
import hashlib
import re
import sys
import types

from demo import platform_protocol as wire
from demo.ch32_bridge import Ch32Exchange
from demo.platform_providers import ProviderError


def read_config(path):
    path = Path(path).expanduser().resolve(strict=True)
    data = path.read_bytes()
    wire.require(0 < len(data) <= wire.MAX_RESPONSE, 'Invalid connection file size')
    if data.removeprefix(b'\xef\xbb\xbf').lstrip().startswith(b'<'):
        import record_io
        return path, record_io.loads(data)
    return path, wire.decode(data, wire.MAX_RESPONSE)


def local_path(base, value):
    wire.require(type(value) is str and value and not any(ord(c) < 32 for c in value), 'Invalid external path')
    path = Path(value).expanduser()
    return from_legacy_anchor(base, path.as_posix())


def arm_config(path):
    path, value = read_config(path)
    wire.require(type(value) is dict, 'Expected ARM configuration object')
    for name in ('ssh_executable', 'identity_file', 'known_hosts_file'):
        value[name] = str(local_path(path.parent, value[name]))
    return value


def checked_file(base, item):
    wire.require(type(item) is dict and set(item) == {'path', 'sha256'} and
                 type(item['sha256']) is str and wire.SHA256.fullmatch(item['sha256']), 'Pinned input required')
    path = local_path(base, item['path'])
    raw = path.read_bytes()
    wire.require(hashlib.sha256(raw).hexdigest() == item['sha256'], 'External input changed')
    return path, raw


def default_board(package):
    return Path(package) / '03_复现环境与运行程序/firmware/CH32V307/双策略/high/连接.xml'


def present_wch_ports(vendor):
    sys.path.insert(0, str(vendor))
    try:
        from serial.tools import list_ports
        return [port for port in list_ports.comports() if port.vid == 0x1A86 and port.pid == 0x8010]
    finally:
        sys.path.pop(0)


def board_provider(path, *, records_directory=None):
    path, value = read_config(path)
    fields = {'schema', 'driver', 'dependencies', 'port', 'timeout_seconds', 'expected_elf_sha256',
              'expected_hello', 'timer_receipt', 'records_directory', 'library_id', 'title'}
    wire.require(type(value) is dict and set(value) == fields and value['schema'] == 'lattice.ch32_connection.v1',
                 'Unsupported board connection file')
    wire.require(type(value['port']) is str and (value['port'] == 'WCH' or
                 re.fullmatch(r'COM[1-9][0-9]{0,3}', value['port'])), 'Expected Windows COM port')
    if value['port'] == 'WCH' and records_directory is None:
        raise ValueError('Automatic port selection requires an external session directory')
    wire.require(type(value['timeout_seconds']) is int and 1 <= value['timeout_seconds'] <= 180, 'Invalid device timeout')
    wire.require(type(value['dependencies']) is list and len(value['dependencies']) <= 128, 'Bounded driver dependencies required')
    driver_path, _ = checked_file(path.parent, value['driver'])
    dependencies = [checked_file(path.parent, item)[0] for item in value['dependencies']]
    wire.require(driver_path not in dependencies and len(set(dependencies)) == len(dependencies), 'Repeated driver input')
    timer_path, _ = checked_file(path.parent, value['timer_receipt'])
    # No module execution, pyserial import, or port access until an explicit UI request.
    def factory():
        try:
            current_path, raw = checked_file(path.parent, value['driver'])
            for item in value['dependencies']:
                checked_file(path.parent, item)
            module = types.ModuleType('_verified_ch32_serial')
            module.__file__ = str(current_path)
            exec(compile(raw, str(current_path), 'exec'), module.__dict__)
            wire.require(callable(getattr(module, 'SerialDevice', None)), 'Registered SerialDevice absent')
            port = value['port']
            if port == 'WCH':
                ports = present_wch_ports(current_path.parent / 'vendor')
                if len(ports) != 1:
                    raise ProviderError('MULTIPLE_DEVICES' if ports else 'DEVICE_UNAVAILABLE')
                port = ports[0].device
            return module.SerialDevice(port, expected=value['expected_hello'], timeout=value['timeout_seconds'])
        except ProviderError:
            raise
        except (ImportError, OSError):
            raise ProviderError('DEVICE_UNAVAILABLE') from None
    return Ch32Exchange(factory, expected_elf_sha256=value['expected_elf_sha256'],
                        expected_hello=value['expected_hello'],
                        timer_receipt={'path': str(timer_path), 'sha256': value['timer_receipt']['sha256']},
                        records_directory=str(Path(records_directory).resolve() if records_directory else local_path(path.parent, value['records_directory'])),
                        library_id=value['library_id'], title=value['title']).provider()
