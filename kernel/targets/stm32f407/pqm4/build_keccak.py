"""M4F SHAKE permutation, XOR and extract integration for the project's cached profile.

All three operations use one interleaved state representation. The original
matrix scheduling, NTTs, encodings, allocation policy and public API are kept.
"""
from pathlib import Path
import argparse,concurrent.futures,hashlib,importlib.util,os,re,shutil,struct,sys,xml.etree.ElementTree as ET
HERE=Path(__file__).resolve().parent
ENGINE=next((p for p in (HERE.parent,HERE.parent/'target') if (p/'board.c').is_file()),HERE.parent)
sys.path.insert(0,str(ENGINE))
def module(name,p):
    sp=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
core=module('core_build',ENGINE/'build.py')
from algorithm_build import algorithm_units
def overlay(original,copy,prefix):
    shutil.copytree(original,copy,dirs_exist_ok=True)
    k=copy/'src/fips202/keccakf1600.c';text=k.read_text(encoding='utf-8')
    names={'extract_bytes':'KeccakF1600_StateExtractBytes(state,data,offset,length);','xor_bytes':'KeccakF1600_StateXORBytes(state,data,offset,length);','permute':'KeccakF1600_StatePermute(state);'}
    for name,body in names.items():
        pattern=r'(\nvoid '+prefix+'_keccakf1600_'+name+r'\([^\{]+\)\s*\{).*?\n\}'
        text,n=re.subn(pattern,lambda m:m[1]+'\n  '+body+'\n}',text,count=1,flags=re.S)
        if n!=1:raise ValueError('production Keccak definition changed '+str(k)+': '+name)
    k.write_text(text.replace('#include "keccakf1600.h"','#include "keccakf1600.h"\n#include "a127_keccak_asm.h"',1),encoding='utf-8')
    f=copy/'src/fips202/fips202.c'
    # These functions stay in the same SCU and use the ordinary production SHAKE interfaces.
    with f.open('a',encoding='utf-8') as h:h.write('\n'+(HERE/'xof_calls.c.in').read_text(encoding='utf-8')+'\n')
def build(p,src,out):
    obj=out/'objects'/f'p{p}-cached-m4f';rel=out/'firmware';obj.mkdir(parents=True,exist_ok=True);rel.mkdir(parents=True,exist_ok=True)
    capacity={512:7168,768:9216,1024:12288,44:12288,65:12288,87:12288}[p];stack=6144
    usb=ENGINE/'vendor/libopencm3';asm=HERE/'vendor/pqm4/common/keccakf1600.S';gas=os.environ.get('ARM_AS') or shutil.which('arm-none-eabi-as')
    if not gas:raise ValueError('set ARM_AS to the GNU Arm assembler')
    original=src/('build/adapted_mlkem' if p>100 else 'src/dsa_compact/build/sign_bitmap_stream_alias/adapted')
    adapted=obj/'adapted';overlay(original,adapted,'mlk' if p>100 else 'mld')
    (obj/'a127_keccak_asm.h').write_text('#include <stdint.h>\nvoid KeccakF1600_StateExtractBytes(uint64_t*,unsigned char*,unsigned,unsigned);\nvoid KeccakF1600_StateXORBytes(uint64_t*,const unsigned char*,unsigned,unsigned);\nvoid KeccakF1600_StatePermute(uint64_t*);\n')
    boot=(ENGINE/'startup.S').read_text().replace(' cpsid i',' cpsid i\n ldr r1,=0xe000ed88\n ldr r2,[r1]\n orr r2,r2,#0xf00000\n str r2,[r1]\n dsb\n isb',1)
    (obj/'startup.S').write_text(boot)
    test=(ENGINE/'experiment.c').read_text();needle='if(q->w[8]!=PARAM||q->w[9]!=PROFILE)return;'
    if test.count(needle)!=1:raise ValueError('board transaction layout changed')
    test=test.replace(needle,needle+'\n    if(q->w[2]==9){xof_request(q,r);return;}')
    (obj/'experiment.c').write_text(test.replace('#include "board.h"','#include "board.h"\nvoid xof_request(const m4_request*,m4_response*);',1))
    (obj/'sram.ld').write_text((ENGINE/'sram.ld.in').read_text().replace('STACK_BYTES',str(stack)))
    units=[(obj/'startup.S',[]),(ENGINE/'board.c',[]),(src/'targets/common/runtime.c',[])]+[(usb/f,[]) for f in core.USB_FILES]
    extra,common=algorithm_units(p,'cached',capacity,src,obj)
    def translate(t):return str(t).replace(str(original),str(adapted))
    units.extend((Path(translate(path)),[translate(x) for x in options]) for path,options in extra)
    units += [(obj/'experiment.c',[]),(HERE/'xof_request.c',[]),(asm,[])]
    flags=core.ARM+['-I'+str(x) for x in (ENGINE/'freestanding',src/'targets/include',src/'targets/common',src/'include',usb/'include',ENGINE,obj)]
    flags += [f'-DPARAM={p}','-DPROFILE=5',f'-DARENA_BYTES={capacity}']+[translate(i) for i in common]
    if p>100:flags.append('-DA127_KECCAK_KEM=1')
    dig=hashlib.sha256(f'cached-m4f/{p}/{stack}/{capacity}/Clang-17-Os-Arm-AS-2.41'.encode())
    for a in (adapted/'src/fips202/fips202.c',adapted/'src/fips202/keccakf1600.c',obj/'vectors.h',ENGINE/'sram.ld.in'):dig.update(a.read_bytes())
    for a,o in units:
        dig.update(a.read_bytes())
        dig.update(repr([z.replace(str(src),'<source>').replace(str(obj),'<objects>') for z in o]).encode())
    tag=dig.digest()[:16];(obj/'build_tag.h').write_text('#define BUILD_TAG {'+','.join(hex(w)+'u' for w in struct.unpack('<4I',tag))+'}\n')
    def cc(part):
        i,(a,flags2)=part;f=obj/(f'{i:02d}-'+a.stem+'.o')
        if a==asm:
            pp=obj/'keccak-pp.s';core.run([core.LLVM/'clang.exe',*flags,'-E','-P','-x','assembler-with-cpp',a,'-o',pp],obj)
            core.run([gas,'-mcpu=cortex-m4','-mfpu=fpv4-sp-d16','-mthumb','-o',f.name,pp.name],obj)
        else:core.run([core.LLVM/'clang.exe',*flags,*flags2,'-MMD','-MF',f.with_suffix('.d'),'-c',a,'-o',f],obj)
        return f
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:objects=list(pool.map(cc,enumerate(units)))
    unit=f'p{p}-cached-m4f';elf=rel/(unit+'.elf');binary=rel/(unit+'.bin')
    core.run([core.LLVM/'ld.lld.exe','--gc-sections','-T',obj/'sram.ld','-Map='+str(rel/(unit+'.map')),*objects,'-o',elf],obj)
    core.run([core.LLVM/'llvm-objcopy.exe','-O','binary',elf,binary],obj)
    nm=core.run([core.LLVM/'llvm-nm.exe','-n',elf],obj);(obj/'symbols.txt').write_text(nm)
    sym={v[2]:int(v[0],16) for l in nm.splitlines() if len(v:=l.split())==3}
    raw=binary.read_bytes();sp,pc=struct.unpack_from('<II',raw)
    if len(raw)!=sym['__image_bytes'] or sp!=sym['__boot_stack_top'] or pc-1!=(sym['Reset_Handler']&~1):raise ValueError('image layout')
    meta=dict(parameter=str(p),strategy='cached-m4f',profile='5',name=unit,sha256=core.sha(binary),elf_sha256=core.sha(elf),tag=tag.hex(),image_bytes=str(len(raw)),main_sram_bytes=str(sp-0x20008000),ccm_bytes=str(sym['__stack_top']-0x10000000),stack_capacity=str(stack),workspace_capacity=str(capacity),clock_hz='168000000',keccak='pqm4 bit-interleaved Cortex-M4F',algorithm_strategy='cached')
    ET.ElementTree(ET.Element('image',meta)).write(rel/(unit+'.xml'),encoding='utf-8',xml_declaration=True)
    print(unit,len(raw),meta['sha256'],flush=True)
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,default=core.SOURCE);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--params',type=int,nargs='+',default=[512,768,1024,44,65,87]);a=ap.parse_args()
    for p in a.params:build(p,a.source.resolve(),a.output.resolve())

