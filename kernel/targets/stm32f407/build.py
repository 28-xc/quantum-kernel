"""Build the target with Clang/LLD for bare ARM. The source root is explicit."""
from pathlib import Path
import argparse, concurrent.futures, hashlib, os, re, shutil, struct, subprocess, sys, xml.etree.ElementTree as ET
HERE=Path(__file__).resolve().parent
SOURCE=next((p for p in HERE.parents if (p/'include/latticecore.h').is_file() and (p/'tools/pruning_sources.py').is_file()),HERE.parents[1])
COMMIT='a3977e14519e4cff8d1feb96445655465797908b'
USB_FILES=['lib/usb/'+n+'.c' for n in ('usb','usb_control','usb_standard','usb_microsoft','usb_dwc_common','usb_f107')]+['lib/stm32/common/rcc_common_all.c']
LLVM=Path(os.environ.get('LLVM_BIN',str(Path(os.environ.get('LOCALAPPDATA',''))/'Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin')))
ARM=['--target=arm-none-eabi','-mcpu=cortex-m4','-mthumb','-mfloat-abi=soft','-ffreestanding','-fno-builtin','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-unaligned-access','-ffunction-sections','-fdata-sections','-Os','-Wno-unknown-attributes','-DSTM32F4']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,s):p.write_text(s,encoding='utf-8')
def run(args,cwd):
    proc=subprocess.run([str(a) for a in args],cwd=cwd,capture_output=True)
    if proc.returncode:raise RuntimeError(subprocess.list2cmdline(list(map(str,args)))+'\n'+proc.stderr.decode('utf-8','replace')[-3500:])
    return proc.stdout.decode('utf-8','replace')
def build(param,profile,src,out,vendor):
    src=src.resolve(); out=out.resolve(); vendor=vendor.resolve()
    unit='p'+str(param)+'-'+profile
    objd=out/'objects'/unit; objd.mkdir(parents=True,exist_ok=True)
    release=out/'firmware';release.mkdir(parents=True,exist_ok=True)
    profile_id={'probe':0,'compact':1,'cached':2,'reference':3}[profile]
    stack={0:2048,1:6144,2:6144,3:57344}[profile_id]
    large=profile=='reference' and param in (65,87)
    if large:stack=46592 if param==87 else 39936
    capacity={0:0,512:5120,768:6656,1024:8448,44:4608,65:4608,87:4608}[param]
    if profile=='cached':capacity={512:7168,768:9216,1024:12288,44:12288,65:12288,87:12288}[param]
    if profile=='reference':capacity=32
    # Filled per source tree + compile configuration below; this tag is returned by the application protocol.
    seed=[b'A127-CDC-1',str((param,profile,capacity,stack,ARM)).encode(),COMMIT.encode()]
    for n in ('board.c','board.h','startup.S','sram.ld.in','probe.c' if not param else 'experiment.c'):
        seed.append((HERE/n).read_bytes())
    units=[(HERE/'startup.S',[]),(HERE/'board.c',[]),(src/'targets/common/runtime.c',[])]
    units += [(vendor/n,[]) for n in USB_FILES]
    flags=[*ARM,'-I'+str(HERE/'freestanding'),'-I'+str(src/'targets/include'),'-I'+str(src/'targets/common'),'-I'+str(src/'include'),'-I'+str(vendor/'include'),'-I'+str(HERE),'-I'+str(objd),f'-DPARAM={param}',f'-DPROFILE={profile_id}',f'-DARENA_BYTES={capacity}']
    if param==0:units.append((HERE/'probe.c',[]))
    else:
        from algorithm_build import algorithm_units
        extra,common=algorithm_units(param,profile,capacity,src,objd)
        units+=extra;flags+=common;units.append((HERE/'experiment.c',[]))
    linker=HERE/'sram.ld.in'
    if large:
        from large_reference import startup_source,experiment_source
        linker=HERE/'sram_reference.ld.in'
        boot=objd/'startup.S';write(boot,startup_source((HERE/'startup.S').read_text()))
        test=objd/'experiment.c';write(test,experiment_source((HERE/'experiment.c').read_text()))
        board=objd/'board_large.c'
        board_text=(HERE/'board.c').read_text()
        for definition in ('static m4_request rx','static m4_response tx'):
            if board_text.count(definition+';')!=1:raise ValueError('USB mailbox layout changed')
            board_text=board_text.replace(definition+';',definition+' __attribute__((section(".low_usb")));')
        write(board,board_text)
        units[0]=(boot,[]);units[1]=(board,[]);units[-1]=(test,[]);seed.append(linker.read_bytes())
        flags.append('-fstack-usage')
    for u,ff in units:
        stable_flags=[flag.replace(str(src),'<source>').replace(str(objd),'<objects>').replace(str(vendor),'<vendor>') for flag in ff]
        seed.extend([u.read_bytes(),repr(stable_flags).encode()])
    linked_sources=[objd/'vectors.h'] if param else []
    for u in linked_sources:seed.append(u.read_bytes())
    tag=hashlib.sha256(b'\x00'.join(seed)).digest()[:16]
    write(objd/'build_tag.h','#define BUILD_TAG {'+','.join(hex(v)+'u' for v in struct.unpack('<4I',tag))+'}\n')
    write(objd/'sram.ld',linker.read_text().replace('STACK_BYTES',str(stack)))
    inputs=[]
    def compile(v):
        ix,(u,ff)=v; obj=objd/f'{ix:02d}-{u.stem}.o'; dep=obj.with_suffix('.d')
        run([LLVM/'clang.exe',*flags,*ff,'-MMD','-MF',dep,'-c',u,'-o',obj],objd)
        return obj
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex: objs=list(ex.map(compile,enumerate(units)))
    elf=release/(unit+'.elf'); binp=release/(unit+'.bin')
    run([LLVM/'ld.lld.exe','--gc-sections','-T',objd/'sram.ld','-Map='+str(release/(unit+'.map')),*objs,'-o',elf],objd)
    run([LLVM/'llvm-objcopy.exe','-O','binary',elf,binp],objd)
    symtxt=run([LLVM/'llvm-nm.exe','-n',elf],objd);write(objd/'symbols.txt',symtxt)
    syms={s[2]:int(s[0],16) for line in symtxt.splitlines() if len(s:=line.split())==3}
    raw=binp.read_bytes();sp,pc=struct.unpack_from('<II',raw);assert sp==syms['__boot_stack_top'] and 0x20008000<sp<0x20020000 and pc&~1==syms['Reset_Handler']&~1 and pc&1
    assert len(raw)==syms['__load_end']-0x20008000 and syms['__bss_end']<=0x20020000
    data=elf.read_bytes();head=struct.unpack_from('<16sHHIIIIIHHHHHH',data);assert head[2]==40
    for j in range(head[10]):
        typ,off,va,pa,fsize,ms,fl,al=struct.unpack_from('<8I',data,head[5]+j*head[9])
        if typ==1:assert 0x20008000<=va==pa<=va+ms<=0x20020000
    meta=dict(parameter=str(param),strategy=profile,profile=str(profile_id),name=unit,sha256=sha(binp),elf_sha256=sha(elf),tag=tag.hex(),image_bytes=str(len(raw)),main_sram_bytes=str(sp-0x20008000),ccm_bytes=str(syms['__stack_top']-0x10000000),stack_capacity=str(stack),workspace_capacity=str(capacity),clock_hz='168000000')
    if large:
        low=syms['__low_end']-0x20000000
        meta.update(main_sram_bytes=str(sp-0x20008000+low),ccm_bytes=str(syms['__ccm_end']-0x10000000),lower_sram_bytes=str(low),matrix_placement='single-thread lower SRAM and CCM; arithmetic unchanged',kat_expected='SHA3-256 of official expected bytes')
    node=ET.Element('image',meta);ET.ElementTree(node).write(release/(unit+'.xml'),encoding='utf-8',xml_declaration=True)
    print(unit,len(raw),meta['main_sram_bytes'],meta['ccm_bytes'],meta['sha256'],flush=True)
    return objs
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,default=SOURCE);ap.add_argument('--output',type=Path,default=SOURCE/'build/stm32f407');ap.add_argument('--vendor',type=Path,default=HERE/'vendor/libopencm3');ap.add_argument('--param',type=int,default=0);ap.add_argument('--profile',default='probe');ap.add_argument('--all',action='store_true');a=ap.parse_args()
    if not (a.source/'include/latticecore.h').is_file():ap.error('use --source to specify the LatticeCore source root')
    cells=[(p,s) for p in (512,768,1024,44,65,87) for s in ('compact','cached','reference')] if a.all else [(a.param,a.profile)]
    for p,s in cells:build(p,s,a.source,a.output,a.vendor)

