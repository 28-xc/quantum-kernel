"""Two deployment strategies; detailed historical recipes stay in build.py.

Build only. This entry does not flash a board or connect to a remote machine.
Host workspace capacity is selected at the call boundary, not a firmware RAM
claim. CH32 budgets are checked against the complete linked firmware ledger.
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
import argparse, record_io as json, platform, subprocess, sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ('windows-x86_64', 'linux-aarch64', 'ch32v307', 'stm32f407')
STRATEGIES = ('low-memory', 'performance')
HOST_RECIPES = {
    ('windows-x86_64', 'low-memory'): 'native-x86-low-memory',
    ('windows-x86_64', 'performance'): 'native-x86-performance',
    ('linux-aarch64', 'low-memory'): 'native-arm-low-memory',
    ('linux-aarch64', 'performance'): 'native-arm-performance',
}

def board_layout(strategy, ram_bytes):
    if type(ram_bytes) is not int or ram_bytes <= 0:
        raise ValueError('Positive complete firmware RAM budget required')
    if strategy == 'low-memory':
        if ram_bytes < 32768:
            raise ValueError('The qualified low-memory deployment requires a 32 KiB budget')
        return 'compact-direct-twiddles'
    if strategy != 'performance':
        raise ValueError('Unknown strategy')
    if ram_bytes >= 81920:
        return 'direct-twiddles'
    if ram_bytes >= 65536:
        return 'partial64'
    raise ValueError('Performance deployment requires a qualified 64 or 80 KiB budget; select low-memory for 32 KiB')

def execute(a):
    out = a.output.resolve()
    if out.exists() or out.is_relative_to(ROOT) or ROOT.is_relative_to(out):
        raise ValueError('Use a fresh output directory outside the source tree')
    if a.platform not in ('ch32v307', 'stm32f407') and (a.ram_bytes is not None or a.program_bytes is not None):
        raise ValueError('Hosted full RAM must be measured with its application; use resource queries for workspace capacity')
    if a.platform == 'windows-x86_64' and not (sys.platform == 'win32' and platform.machine().lower() in ('amd64','x86_64')):
        raise ValueError('Run this build on the intended Windows x86-64 platform')
    if a.platform == 'linux-aarch64' and not (sys.platform.startswith('linux') and platform.machine().lower() in ('aarch64','arm64')):
        raise ValueError('Run this build on the intended Linux AArch64 platform')
    command = [sys.executable, '-B']
    out.mkdir(parents=True)
    request = dict(schema='lattice.kernel_strategy_request.v1', platform=a.platform,
                   strategy=a.strategy, parameters=[512,768,1024,44,65,87], complete_operations=18)
    def run(argv, name):
        result = subprocess.run([str(v) for v in argv], cwd=ROOT, capture_output=True)
        (out/(name+'.log')).write_bytes(json.capture_bytes(result.stdout+result.stderr))
        if result.returncode:
            raise RuntimeError(name+' failed; see '+str(out/(name+'.log')))
    if a.platform == 'stm32f407':
        target = ROOT / 'targets/stm32f407'
        low = a.strategy == 'low-memory'
        profile = 'compact' if low else 'cached'
        budget = a.ram_bytes if a.ram_bytes is not None else (32768 if low else 192 * 1024)
        if budget <= 0:
            raise ValueError('RAM budget must be positive')
        build = out / 'build'
        for param in request['parameters']:
            run(command + [target/'build.py', '--source', ROOT, '--output', build,
                           '--param', param, '--profile', profile], f'build-{param}')
        firmware = build / 'firmware'
        if low:
            run(command + [target/'flash32.py', '--source', ROOT, '--firmware', firmware,
                           '--output', out/'flash32'], 'flash-layout')
            firmware = out/'flash32/firmware'
        ledgers = []
        for param in request['parameters']:
            unit = f'p{param}-compact-flash32' if low else f'p{param}-cached'
            meta = ET.parse(firmware/(unit+'.xml')).getroot().attrib
            ram = (int(meta['full_reserved_ram_bytes']) if low else
                   int(meta['main_sram_bytes']) + int(meta['ccm_bytes']))
            image = int(meta['used_flash_bytes' if low else 'image_bytes'])
            if ram > budget or (a.program_bytes is not None and image > a.program_bytes):
                raise ValueError(f'{unit} exceeds the requested resource budget')
            ledgers.append(dict(parameter=param, ram_bytes=ram, image_bytes=image,
                                file=(firmware/(unit+'.bin')).relative_to(out).as_posix(),
                                sha256=meta['sha256']))
        request.update(layout=profile, execution='flash' if low else 'sram',
                       complete_ram_budget=budget, program_budget=a.program_bytes,
                       images=ledgers, result='BUILT')
    elif a.platform == 'ch32v307':
        budget = a.ram_bytes if a.ram_bytes is not None else (32768 if a.strategy == 'low-memory' else 81920)
        selected = board_layout(a.strategy,budget)
        if not a.cc: raise ValueError('CH32 requires the explicitly qualified RISC-V compiler path')
        request.update(layout=selected, complete_ram_budget=budget, program_budget=a.program_bytes)
        run(command+[ROOT/'targets/ch32v307/build.py','--profile',selected,'--output',out/'build','--cc',a.cc],'build')
        result = json.loads((out/'build/result.xml').read_text(encoding='utf-8'))
        r = result['resources']
        if r['writable_image_span_bytes'] > budget:
            raise ValueError('The linked complete firmware exceeds the requested RAM budget')
        if a.program_bytes is not None and r['code_and_rodata_load_bytes'] > a.program_bytes:
            raise ValueError('The linked load image exceeds the requested program-space budget')
        request.update(result='BUILT_AND_WITHIN_LINKED_BUDGET', hardware_tested_by_this_command=False)
    else:
        selected = HOST_RECIPES[a.platform,a.strategy]
        recipes = json.loads((ROOT/'configs/recipes.xml').read_text(encoding='utf-8'))['recipes']
        if selected not in recipes:
            raise ValueError('This strategy is not finalized in this source snapshot: '+selected)
        request.update(recipe=selected)
        plan = command+[ROOT/'tools/build.py','plan','--configuration',selected,'--output',out/'plan.xml']
        for name in ('cc','ar','nm','objdump','size'):
            if getattr(a,name): plan.extend(['--'+name,getattr(a,name)])
        run(plan,'plan')
        run(command+[ROOT/'tools/build.py','build','--plan',out/'plan.xml','--output',out/'build'],'build')
        request.update(result='BUILT_AND_FUNCTIONALLY_CHECKED', full_application_ram_claimed=False)
    (out/'strategy.xml').write_text(json.dumps(request,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps(request,ensure_ascii=False))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--platform',choices=PLATFORMS,required=True)
    p.add_argument('--strategy',choices=STRATEGIES,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--ram-bytes',type=int)
    p.add_argument('--program-bytes',type=int)
    for name in ('cc','ar','nm','objdump','size'): p.add_argument('--'+name)
    a = p.parse_args()
    if a.program_bytes is not None and a.program_bytes <= 0: p.error('Program budget must be positive')
    execute(a)

if __name__ == '__main__': main()
