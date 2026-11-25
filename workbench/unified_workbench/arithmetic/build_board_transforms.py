"""Rebuild the SRAM-only transform harnesses from the frozen board sources."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE = Path(__file__).resolve().parent
RING = Path('02_测试代码与数据/performance/多项式运算/完整环乘实板测量')
TOOLCHAIN = Path('01_源代码/可参数化格运算内核/targets/ch32v307/实板构型/toolchain/bin')
CORE = Path('01_源代码/可参数化格运算内核')


def build(package, sources, output):
    archive = package / RING
    output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(archive / 'stm32'))
    import build_driver as stm

    with TemporaryDirectory() as folder:
        tmp = Path(folder)
        stm.HERE = tmp
        kernel = package / CORE / 'src/backends'
        includes = ['-I' + str(tmp), '-I' + str(package / CORE / 'include'), '-I' + str(kernel)]
        stm.FLAGS.extend(includes)
        (tmp / 'formal_ring_driver.h').write_bytes((archive / 'stm32/ring_driver.c').read_bytes())
        (tmp / 'string.h').write_text('#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t);\n', encoding='ascii')
        (tmp / 'ring_driver.c').write_bytes((sources / 'transform-stm32.c').read_bytes() +
                                          b'\n#include "canonical.c"\n')
        for profile in (24, 32):
            name = f'{profile}KiB'
            stm.main(name)
            for ext in ('bin', 'json'):
                (output / f'stm32-transform-{profile}.{ext}').write_bytes(
                    (tmp / name / f'driver.{ext}').read_bytes())
        original = (archive / 'ch32/measure_ring.c').read_text(encoding='utf-8')
        header, marker, _ = original.partition('__attribute__((noinline,used)) static void run(void)')
        if not marker:
            raise ValueError('CH32 diagnostic source differs from the frozen layout')
        (tmp / 'formal_ring_driver.h').write_text(header, encoding='utf-8')
        source = tmp / 'transform-ch32.c'
        source.write_bytes((sources / source.name).read_bytes())
        tool = package / TOOLCHAIN
        flags = ['-mabi=ilp32', '-march=rv32imacxw', '-std=c11', '-Os',
                 '-fno-builtin', '-ffreestanding', '-msmall-data-limit=0', '-mno-save-restore',
                 '-ffunction-sections', '-fdata-sections', '-nostdlib', '-Wl,--no-relax,--gc-sections']
        links = {28: archive / 'ch32/retired-response87/driver.ld',
                 64: sources / 'ch32-transform-64.ld',
                 80: archive / 'ch32/wire80-eight/driver.ld'}
        manifest = {}
        for profile, layout in links.items():
            label = f'ch32-transform-{profile}'
            elf, binary = tmp / f'{label}.elf', output / f'{label}.bin'
            subprocess.run([tool / 'riscv-none-embed-gcc.exe', *flags, *includes, '-T', layout,
                            source, kernel / 'canonical.c', '-o', elf], check=True)
            subprocess.run([tool / 'riscv-none-embed-objcopy.exe', '-O', 'binary',
                            elf, binary], check=True)
            payload = binary.read_bytes()
            if not 0 < len(payload) < 4096:
                raise ValueError('CH32 transform diagnostic does not fit its SRAM region')
            manifest[label] = {'sha256': hashlib.sha256(payload).hexdigest(),
                               'layout_sha256': hashlib.sha256(layout.read_bytes()).hexdigest()}
        (output / 'ch32-transforms.json').write_text(
            json.dumps(manifest, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build(args.package.resolve(), HERE, args.output.resolve())
