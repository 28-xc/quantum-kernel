"""Explicit physical-board qualification of an already built research image.

This tool touches only the attached CH32V307 (chip ID checked before writes).
No simulated fallback, automatic retry, or global device/process cleanup.
"""
from pathlib import Path
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
import argparse, hashlib, importlib.util, record_io as json, os, socket, struct, subprocess, time

OPENOCD = Path(os.environ['LC_CH32_OPENOCD']) if os.environ.get('LC_CH32_OPENOCD') else None
OPENOCD_SHA256 = '0f49153f490e8d89b391da9717e01f67c380f641c59600aec483113762469b65'
DRIVER = Path(__file__).resolve().parent / 'host/ch32_serial.py'
DRIVER_SHA256 = '991a4a49007e89133daec7eb1e05908b25d892fc87ab8a43b6b4227fd6b9bf24'
CHIP_WORD = '30700568'


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def write(p, v):
    Path(p).write_text(json.dumps(v, indent=2) + '\n', encoding='utf-8')


class Debugger:
    def __init__(self, out):
        if OPENOCD is None:
            raise ValueError('Supply --openocd or LC_CH32_OPENOCD; no debugger is started implicitly')
        if sha(OPENOCD) != OPENOCD_SHA256:
            raise ValueError('OpenOCD differs from the qualified tool; no hardware access performed')
        self.out = out
        self.records = []
        test = socket.socket()
        test.bind(('127.0.0.1', 16666))
        test.close()
        self.stdout = (out / 'openocd.stdout.log').open('wb')
        self.stderr = (out / 'openocd.stderr.log').open('wb')
        args = [str(OPENOCD), '-c', 'gdb_port disabled', '-c', 'tcl_port 16666',
                '-c', 'telnet_port disabled', '-c', 'bindto 127.0.0.1',
                '-s', str(OPENOCD.parent), '-f', str(OPENOCD.parent / 'wch-riscv.cfg'),
                '-c', 'chip_id CH32V30x']
        self.proc = subprocess.Popen(args, stdout=self.stdout, stderr=self.stderr,
                                     creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.sock = None
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError('OpenOCD failed to start; inspect its log')
            try:
                self.sock = socket.create_connection(('127.0.0.1', 16666), timeout=.3)
                break
            except OSError:
                time.sleep(.1)
        if self.sock is None:
            self.close()
            raise RuntimeError('Debugger did not start')
        self.sock.settimeout(20)
        ident = self.command('mdw 0x1ffff704 1')
        if CHIP_WORD not in ident:
            self.close()
            raise RuntimeError('Unexpected physical chip; no flash write performed')

    def command(self, command):
        wire = f'set lc_rc [catch {{{command}}} lc_result]; format "LCSTATUS=%d\\n%s" $lc_rc $lc_result'
        self.sock.sendall((wire + '\x1a').encode())
        raw = bytearray()
        while not raw.endswith(b'\x1a'):
            part = self.sock.recv(65536)
            if not part:
                raise RuntimeError('Debugger connection closed')
            raw.extend(part)
        response = bytes(raw[:-1]).decode()
        self.records.append(dict(command=command, response=response))
        write(self.out / 'debug-transcript.xml', self.records)
        if not response.startswith('LCSTATUS=0\n'):
            raise RuntimeError(response)
        return response

    def close(self):
        if self.sock:
            try:
                self.sock.sendall(b'shutdown\x1a')
            except OSError:
                pass
            self.sock.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        self.stdout.close()
        self.stderr.close()
        write(self.out / 'debug-transcript.xml', self.records)


def symbols(build):
    result = {}
    for line in (build / 'symbols.log').read_text().splitlines():
        row = line.split()
        if len(row) >= 3:
            try:
                result[row[2]] = int(row[0], 16)
            except ValueError:
                pass
    return result


def verify_load_segments(debugger, elf, out):
    """Read flash bytes without running a target-side checksum/working-area stub."""
    raw = elf.read_bytes()
    if raw[:6] != b'\x7fELF\x01\x01':
        raise ValueError('Expected little-endian ELF32')
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', raw)
    phoff, phentsize, phnum = header[5], header[9], header[10]
    if phentsize != 32:
        raise ValueError('Unexpected ELF program header size')
    records = []
    for i in range(phnum):
        kind, offset, virtual, physical, count, memory, flags, alignment = struct.unpack_from('<8I', raw, phoff + i * phentsize)
        if kind != 1 or not count:
            continue
        if physical + count > 196608:
            raise ValueError('Load segment is outside the qualified flash partition')
        file = out / f'flash-load-segment-{i}.bin'
        debugger.command(f'dump_image {file.as_posix()} {physical} {count}')
        observed = file.read_bytes()
        if observed != raw[offset:offset + count]:
            raise ValueError('Physical flash load segment differs from selected ELF')
        records.append(dict(physical_address=physical, bytes=count, sha256=sha(file)))
    if not records:
        raise ValueError('No ELF load segments')
    write(out / 'load-segments.xml', records)
    return records


def readback(debugger, build, out):
    syms = symbols(build)
    debugger.command('halt')
    try:
        for name, count in [('timer_selftest', 160), ('control_stack_observation', 28),
                            ('live_state', 4), ('live_fault_cause', 4),
                            ('__control_stack_bottom', 1024)]:
            debugger.command(f'dump_image {(out / (name + ".bin")).as_posix()} {syms[name]} {count}')
        debugger.command('mdw 0x40021000 3')
        debugger.command('mdw 0xe000f000 4')
    finally:
        debugger.command('resume')
    timer = (out / 'timer_selftest.bin').read_bytes()
    magic, version, mask, ctl = struct.unpack_from('<4I', timer)
    assert (magic, version, mask, ctl) == (0x5354494d, 1, 15, 5), 'Timer self-test failed'
    observation = struct.unpack('<7I', (out / 'control_stack_observation.bin').read_bytes())
    assert observation[0:2] == (0x4353544b, 1) and observation[5:] == (1, 0), 'Control-stack guard failed'
    assert (out / '__control_stack_bottom.bin').read_bytes()[:32] == b'\xa5' * 32, 'Control stack bottom guard damaged'
    assert struct.unpack('<I', (out / 'live_fault_cause.bin').read_bytes())[0] == 0, 'Firmware fault was recorded'
    assert struct.unpack('<I', (out / 'live_state.bin').read_bytes())[0] == 1, 'Firmware is not ready'
    return dict(timer_pass_mask=mask, control_stack_current_bytes=observation[3],
                control_stack_peak_bytes=observation[4], control_stack_guard_ok=True,
                no_fault_recorded=True)


def main():
    global OPENOCD, DRIVER
    ap = argparse.ArgumentParser()
    ap.add_argument('--build', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--rollback', type=Path, required=True)
    ap.add_argument('--flash', action='store_true')
    ap.add_argument('--port', default='COM13')
    ap.add_argument('--openocd', type=Path, default=OPENOCD)
    ap.add_argument('--driver', type=Path, default=DRIVER)
    a = ap.parse_args()
    if a.openocd is None:
        ap.error('--openocd or LC_CH32_OPENOCD is required')
    OPENOCD = a.openocd.resolve(strict=True)
    DRIVER = a.driver.resolve(strict=True)
    build, out = a.build.resolve(), a.output.resolve()
    assert not out.exists(), 'Fresh evidence directory required'
    out.mkdir(parents=True)
    info = json.loads((build / 'result.xml').read_text())
    elf = build / 'latticecore-live.elf'
    if 'elf' in info['artifacts']:
        assert sha(elf) == info['artifacts']['elf']
    assert sha(build / 'latticecore-live.bin') == info['artifacts']['bin']
    backup = json.loads((a.rollback / 'backup-result.xml').read_text())
    assert sha(a.rollback / 'flash-full-before.bin') == backup['flash_backup_sha256']
    assert sha(a.rollback / 'cached.elf') == backup['cached_elf_sha256']
    assert sha(DRIVER) == DRIVER_SHA256
    result = dict(status='INCOMPLETE', transport='physical_uart', chip_id='0x' + CHIP_WORD,
                  port=a.port, firmware_elf_sha256=sha(elf), firmware_bin_sha256=info['artifacts']['bin'],
                  build_id=info['build_id'], openocd_sha256=sha(OPENOCD), flashed=a.flash)
    debug = None
    try:
        debug = Debugger(out)
        if a.flash:
            debug.command('halt')
            debug.command('reset halt')
            debug.command('flash write_image erase ' + elf.as_posix())
            debug.command('verify_image ' + elf.as_posix())
            debug.command('reset halt')
            debug.command('resume 0x00000000')
            time.sleep(.35)
        else:
            debug.command('halt')
            try:
                result['verified_load_segments'] = verify_load_segments(debug, elf, out)
            finally:
                debug.command('resume')
        result['debug_checks'] = readback(debug, build, out)
        if not a.flash:
            # Reconnecting this WCH debugger disturbed the running UART state
            # in observed tests. Preserve the post-run readback above, then
            # explicitly boot the unchanged image before releasing the probe.
            debug.command('reset halt')
            debug.command('resume 0x00000000')
            time.sleep(.35)
            restored = out / 'restored-boot'
            restored.mkdir()
            result['restored_boot_checks'] = readback(debug, build, restored)
            result['restarted_after_readback'] = True
        result['status'] = 'PHYSICAL_IMAGE_AND_TIMER_PASS'
    finally:
        if debug:
            debug.close()
        write(out / 'result.xml', result)
    expected = dict(build_id=info['build_id'], clock_hz=96000000, systick_control=5,
                    flash_load_bytes=info['resources']['code_and_rodata_load_bytes'],
                    ram_reserved_bytes=info['resources']['writable_image_span_bytes'])
    write(out / 'expected-hello.xml', expected)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
