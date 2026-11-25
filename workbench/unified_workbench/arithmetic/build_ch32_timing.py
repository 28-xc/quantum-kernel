"""Build CH32 SRAM-only timing diagnostics from the pinned vector drivers."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

SOURCE = Path('01_源代码/可参数化格运算内核')
FIXTURES = Path('02_测试代码与数据/correctness/CH32V307/标准向量与存储核验')
STAMP = """
static uint64_t stamp(void) {
    volatile uint32_t *timer = (volatile uint32_t *)0xe000f008u;
    uint32_t high, low;
    do { high = timer[1]; low = timer[0]; } while (high != timer[1]);
    return ((uint64_t)high << 32) | low;
}
"""


def inject(source, profile):
    if profile == 28:
        source = source.replace('failures, z0, z1;', 'failures, z0, z1, cycles_lo, cycles_hi, timer_control;')
        source = source.replace('__attribute__((used,noinline)) void qualify_one', STAMP + '\n__attribute__((used,noinline)) void qualify_one')
        start, end, receipt = '  if(input.operation==0){', '  if(rc==(input.accepted', 'result'
    else:
        source = source.replace('arena,failures,n0,n1;', 'arena,failures,n0,n1,cycles_lo,cycles_hi,timer_control;')
        source = source.replace('__attribute__((used,noinline)) void qualify_io', STAMP + '\n__attribute__((used,noinline)) void qualify_io')
        start, end, receipt = '  if(qual_input.op==0)', '  if(rc==(qual_input.accept', 'qual_result'
    assert 'cycles_lo' in source and source.count(start) == source.count(end) == 1
    source = source.replace(start, '  uint64_t started = stamp();\n' + start)
    source = source.replace(end, f"""  uint64_t elapsed = stamp() - started;
  {receipt}.cycles_lo = (uint32_t)elapsed;
  {receipt}.cycles_hi = (uint32_t)(elapsed >> 32);
  {receipt}.timer_control = *(volatile uint32_t *)0xe000f000u;
""" + end)
    return source


def build(root, output):
    tools = root/SOURCE/'targets/ch32v307/实板构型/toolchain/bin'
    output.mkdir(parents=True, exist_ok=True)
    metadata = {}
    with TemporaryDirectory() as temporary:
        stage = Path(temporary)
        for profile, role in ((28, '低内存'), (80, '高性能')):
            fixtures = root/FIXTURES/role/'向量程序'
            driver = stage/'driver.c'
            driver.write_text(inject((fixtures/'driver.c').read_text(encoding='utf-8'), profile), encoding='utf-8')
            elf = stage/'test.elf'
            target = output/f'ch32-timing-{profile}.bin'
            subprocess.run([tools/'riscv-none-embed-gcc.exe', '-mabi=ilp32', '-march=rv32imacxw',
                            '-Os', '-std=c11', '-ffreestanding', '-fno-builtin', '-msmall-data-limit=0',
                            '-mno-save-restore', '-ffunction-sections', '-fdata-sections', '-nostdlib',
                            '-Wl,--no-relax,--gc-sections', '-I', root/SOURCE/'include',
                            '-T', fixtures/'qual.ld', driver, '-o', elf], check=True)
            subprocess.run([tools/'riscv-none-embed-objcopy.exe', '-O', 'binary', elf, target], check=True)
            symbols = {name:int(address,16) for address, _, name in (line.split() for line in subprocess.check_output(
                [tools/'riscv-none-embed-nm.exe', '-n', '--defined-only', elf], text=True).splitlines())}
            data = target.read_bytes()
            entry = symbols['qual_entry']
            if profile == 28:
                addresses = {key:symbols[key] for key in ('input','result','octets0','octets1')}
                assert entry+len(data)<=addresses['input'] and addresses['input']+16480<=addresses['result']
                assert max(addresses['octets0'], addresses['octets1'])+4896<=0x20020000
            else:
                addresses = dict(input=symbols['qual_input'], result=symbols['qual_result'])
                assert entry+len(data)<=addresses['input'] and addresses['result']+48<=addresses['input']+256
            metadata[str(profile)] = dict(sha256=hashlib.sha256(data).hexdigest(), entry=entry, **addresses)
    (output/'ch32-timing.json').write_text(json.dumps(metadata, indent=2)+'\n', encoding='utf-8')


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    build(args.package, args.output)

