"""Create a movable, external CH32 connection file without opening any device."""
from pathlib import Path
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
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo import platform_config
from demo import platform_protocol as wire


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'expected-hello', 'timer', 'records', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    for name in ('driver-sha256', 'expected-hello-sha256', 'timer-sha256', 'elf-sha256', 'port'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--library-id', default='ch32_compact')
    p.add_argument('--title', default='CH32V307 紧凑配置')
    a = p.parse_args()
    output = a.output.resolve()
    if output.exists(): raise ValueError('Output must be fresh')
    def portable(file):
        # A Windows user profile and the unpacked package often live on different volumes.
        try:
            return os.path.relpath(file, output.parent)
        except ValueError:
            return str(file)
    def item(file, expected=None):
        file = file.resolve(strict=True)
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        if expected is not None and digest != expected: raise ValueError('Selected input differs from supplied SHA')
        return dict(path=portable(file), sha256=digest)
    driver = item(a.driver, a.driver_sha256)
    hello_item = item(a.expected_hello, a.expected_hello_sha256)
    raw = a.expected_hello.read_bytes()
    wire.require(0 < len(raw) <= wire.MAX_RESPONSE, 'Invalid HELLO size')
    expected = json.loads(raw) if raw.removeprefix(b'\xef\xbb\xbf').lstrip().startswith(b'<') else wire.decode(raw, wire.MAX_RESPONSE)
    vendor = a.driver.resolve().parent/'vendor'/'serial'
    if not vendor.is_dir(): raise ValueError('Offline serial driver dependency directory is required')
    # Only imported Python source is registered; caches/tests are not package inputs.
    deps = [item(q) for q in sorted(vendor.rglob('*.py')) if '__pycache__' not in q.parts]
    value = dict(schema='lattice.ch32_connection.v1', driver=driver, dependencies=deps,
                 port=a.port, timeout_seconds=120, expected_elf_sha256=a.elf_sha256,
                 expected_hello=expected, timer_receipt=item(a.timer, a.timer_sha256),
                 records_directory=portable(a.records.resolve()),
                 library_id=a.library_id, title=a.title)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Validate through a temporary sibling so relative paths have their final base.
    temporary = output.with_name(output.name+'.validation-pending')
    with temporary.open('x', encoding='utf8') as f: json.dump(value, f, ensure_ascii=False, indent=2); f.write('\n')
    platform_config.board_provider(temporary)  # factory is deliberately not invoked
    temporary.rename(output)
    receipt = output.with_name(output.name+'.provenance.xml')
    with receipt.open('x', encoding='utf8') as f:
        json.dump(dict(status='CONFIGURATION_FILES_VERIFIED_NO_CONNECTION', configuration_sha256=item(output)['sha256'],
                       expected_hello_source=hello_item, driver_dependencies=len(deps)), f, ensure_ascii=False, indent=2)
        f.write('\n')
    print('连接文件已生成并校验；尚未连接开发板。')


if __name__ == '__main__': main()
