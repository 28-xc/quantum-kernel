"""Build the pinned pqm4 m4fstack implementations for the same STM32F407 measurement path."""
import argparse,concurrent.futures,hashlib,os,re,shutil,struct,sys,xml.etree.ElementTree as ET
from pathlib import Path

HERE=Path(__file__).resolve().parent
ENGINE=next((p for p in (HERE.parent,HERE.parent/'target') if (p/'board.c').is_file()),HERE.parent)
sys.path.insert(0,str(ENGINE))
import importlib.util
spec=importlib.util.spec_from_file_location("m4_common_build",ENGINE/"build.py")
core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
PQM4='5e5cc76d0b072ee7077e58afcbc619a1a67a53b4'
MUPQ='ddcccedb2db9d0250856bd58ee5c46c61e506c5d'
def native_adapter(param,src,objd):
    root=src/'baselines/pqclean';text=(root/'adapter.c').read_text(encoding='utf-8')
    prefix=f'PQCLEAN_{"MLKEM" if param>100 else "MLDSA"}{param}_CLEAN'
    def replace(m):
        call=re.search(r'return '+prefix+r'_([a-z0-9_]+\([^;]+\));',m[2])
        return m[1]+'{(void)p;return '+(call[1] if call else 'LC_E_ARGUMENT')+';}'
    text,n=re.subn(r'(static int raw_(?:keypair|enc|dec|sign|verify)\([^\n{}]+\))\{switch\(p\)\s*\{(.*?)\}\}',replace,text,flags=re.S)
    if n!=5:raise ValueError('original ABI dispatch changed')
    text='#include "api.h"\n'+text
    (objd/'native_adapter.c').write_text(text,encoding='utf-8')
    (objd/'randombytes.h').write_text('#include <stddef.h>\n#include <stdint.h>\nint randombytes(uint8_t*,size_t);\n')
    (objd/'stdio.h').write_text('#include <stddef.h>\n')
    (objd/'hal.h').write_text('/* Upstream DBENCH instrumentation is disabled. */\n')
    (objd/'native_abort.c').write_text('#include "board.h"\n#include <stdlib.h>\nvoid abort(void){reset_to_dfu();}\nvoid exit(int n){(void)n;reset_to_dfu();}\n')
def build(param,src,out):
    vendor=HERE/'vendor';usb=ENGINE/'vendor/libopencm3'
    algo=vendor/'pqm4'/('crypto_kem' if param>100 else 'crypto_sign')/(('ml-kem-' if param>100 else 'ml-dsa-')+str(param))/'m4fstack'
    common=vendor/'mupq/common'
    obj=out/'objects'/f'p{param}-m4fstack';rel=out/'firmware';obj.mkdir(parents=True,exist_ok=True);rel.mkdir(parents=True,exist_ok=True)
    sys.path[:0]=[str(src),str(src/'tools'),str(src/'tests/targets')]
    from generate_vectors import generate
    generate(src,obj,{(param,op) for op in range(3)})
    native_adapter(param,src,obj)
    boot=(ENGINE/'startup.S').read_text().replace(' cpsid i',' cpsid i\n ldr r1,=0xe000ed88\n ldr r2,[r1]\n orr r2,r2,#0xf00000\n str r2,[r1]\n dsb\n isb',1)
    (obj/'startup.S').write_text(boot)
    source=(ENGINE/'experiment.c').read_text()
    (obj/'experiment.c').write_text(source)
    stack=16384;capacity=32
    (obj/'sram.ld').write_text((ENGINE/'sram.ld.in').read_text().replace('STACK_BYTES',str(stack)))
    units=[obj/'startup.S',ENGINE/'board.c',src/'targets/common/runtime.c']+[usb/n for n in core.USB_FILES]+[obj/'native_adapter.c',ENGINE/'reference_jump.S',obj/'native_abort.c',common/'fips202.c',vendor/'pqm4/common/keccakf1600.S',obj/'experiment.c']+sorted(p for p in algo.iterdir() if p.suffix.lower() in ('.s','.c'))
    gas=os.environ.get('ARM_AS') or shutil.which('arm-none-eabi-as')
    if not gas:raise RuntimeError('set ARM_AS to the GNU Arm Embedded assembler')
    for include in algo.glob('*.i'):shutil.copyfile(include,obj/include.name)
    inc=[ENGINE/'freestanding',src/'targets/include',src/'targets/common',src/'include',src/'baselines/pqclean',usb/'include',ENGINE,obj,algo,common,vendor/'pqm4/common']
    flags=core.ARM+['-mfpu=fpv4-sp-d16','-DLC_RNG_CALLBACK_ONLY=1','-D_Thread_local=','-DPQCLEAN_randombytes=randombytes',f'-DPARAM={param}','-DPROFILE=4',f'-DARENA_BYTES={capacity}']+['-I'+str(p) for p in inc]
    digest=hashlib.sha256(PQM4.encode()+MUPQ.encode()+repr((param,stack,capacity,core.ARM)).encode())
    digest.update((vendor/'来源.tsv').read_bytes());digest.update((obj/'vectors.h').read_bytes())
    for p in units:digest.update(p.read_bytes())
    tag=digest.digest()[:16]
    (obj/'build_tag.h').write_text('#define BUILD_TAG {'+','.join(hex(w)+'u' for w in struct.unpack('<4I',tag))+'}\n')
    def compile_unit(n_source):
        i,p=n_source;dest=obj/(f'{i:02d}-'+p.stem+'.o')
        if p.suffix.lower()=='.s' and (p.parent==algo or p.parent==vendor/'pqm4/common'):
            asm=p
            if p.suffix=='.S':
                asm=obj/(f'{i:02d}-'+p.stem+'-pp.s')
                core.run([core.LLVM/'clang.exe',*flags,'-E','-P','-x','assembler-with-cpp',p,'-o',asm],obj)
            else:
                asm=obj/p.name;shutil.copyfile(p,asm)
            # GNU as 2.41 for mingw32 accepts narrow argv paths. Its working
            # directory is set by CreateProcessW; relative filenames are ASCII.
            core.run([gas,'-mcpu=cortex-m4','-mfpu=fpv4-sp-d16','-mthumb','-I','.','-o',dest.name,asm.name],obj)
        else:
            core.run([core.LLVM/'clang.exe',*flags,'-MMD','-MF',dest.with_suffix('.d'),'-c',p,'-o',dest],obj)
        return dest
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:objects=list(pool.map(compile_unit,enumerate(units)))
    unit=f'p{param}-m4fstack';elf=rel/(unit+'.elf');binary=rel/(unit+'.bin')
    core.run([core.LLVM/'ld.lld.exe','--gc-sections','-T',obj/'sram.ld','-Map='+str(rel/(unit+'.map')),*objects,'-o',elf],obj)
    core.run([core.LLVM/'llvm-objcopy.exe','-O','binary',elf,binary],obj)
    nm=core.run([core.LLVM/'llvm-nm.exe','-n',elf],obj);(obj/'symbols.txt').write_text(nm)
    sym={v[2]:int(v[0],16) for l in nm.splitlines() if len(v:=l.split())==3}
    data=binary.read_bytes();sp,pc=struct.unpack_from('<II',data)
    if not(sp==sym['__boot_stack_top'] and 0x20008000<sp<0x20020000 and pc&1 and ((pc&~1)==(sym['Reset_Handler']&~1)) and sym['__image_bytes']==len(data)):raise ValueError('invalid image layout')
    meta=dict(parameter=str(param),strategy='m4fstack',profile='4',name=unit,sha256=core.sha(binary),elf_sha256=core.sha(elf),tag=tag.hex(),image_bytes=str(len(data)),main_sram_bytes=str(sp-0x20008000),ccm_bytes=str(sym['__stack_top']-0x10000000),stack_capacity=str(stack),workspace_capacity=str(capacity),clock_hz='168000000',pqm4=PQM4,mupq=MUPQ,source_variant='m4fstack',kat_expected='official bytes')
    ET.ElementTree(ET.Element('image',meta)).write(rel/(unit+'.xml'),encoding='utf-8',xml_declaration=True)
    print(unit,len(data),meta['sha256'])
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,default=core.SOURCE);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--params',type=int,nargs='+',default=[512,768,1024,44,65,87]);a=ap.parse_args()
    for p in a.params:build(p,a.source.resolve(),a.output.resolve())

