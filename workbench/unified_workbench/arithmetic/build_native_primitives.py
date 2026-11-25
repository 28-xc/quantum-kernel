"""Compile the demonstration sampling and encoding APIs from existing kernel sources."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import os
import sys
from tempfile import TemporaryDirectory

CORE=Path('01_源代码/可参数化格运算内核')
KEM=Path('build/adapted_mlkem')
DSA=Path('src/dsa_compact/build/sign_bitmap_stream_alias/adapted')
MODULE=Path('demo/arithmetic_diagnostic')


def objects(source, output, compiler, target_flags):
    output.mkdir(parents=True,exist_ok=True)
    header=output/'string.h'
    header.write_text('''#include <stddef.h>
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
''',encoding='ascii')
    flags=['-std=c11','-Os','-ffreestanding','-fno-builtin','-ffunction-sections','-fdata-sections',
           '-DNDEBUG','-I'+str(output),'-Iinclude','-Isrc/common','-Itargets/stm32f407/freestanding']
    results=[]

    def compile_unit(path, extra):
        artifact=output/f'{len(results)}-{path.stem}.o'
        subprocess.run([compiler,*target_flags,*flags,*extra,'-c',path,'-o',artifact],cwd=source,check=True)
        results.append(artifact)

    kem_flags=['-I'+str(KEM),'-Iconfigs/hosted','-DMLK_CONFIG_FILE="mlkem_config.h"']
    kem_units=['poly.c','poly_k.c','sampling.c','compress.c','verify.c','fips202/fips202.c',
               'fips202/fips202x4.c','fips202/keccakf1600.c']
    dsa_flags=['-I'+str(DSA),'-Isrc/dsa_packed','-DMLD_CONFIG_FILE="lc_dsa_config.h"',
               '-DMLD_CONFIG_REDUCE_RAM','-DLC_DSA_INPLACE_SAMPLE=2','-DLC_DSA_STREAM_KEYGEN=1']
    dsa_units=['poly.c','poly_kl.c','ct.c','fips202/fips202.c','fips202/fips202x4.c','fips202/keccakf1600.c']
    for parameters, stem, cfg, extra, units, adapter in (
        ((512,768,1024),KEM,'MLK',kem_flags,kem_units,'kem.c'),
        ((44,65,87),DSA,'MLD',dsa_flags,dsa_units,'dsa.c'),
    ):
        for i,param in enumerate(parameters):
            shared='WITH_SHARED' if i==0 else 'NO_SHARED'
            options=[*extra,f'-D{cfg}_CONFIG_PARAMETER_SET={param}',f'-D{cfg}_CONFIG_MULTILEVEL_{shared}']
            for unit in units:
                compile_unit(stem/'src'/unit,options)
            if cfg=='MLD' or i==0:
                compile_unit(MODULE/adapter,options)
    return results


def llvm_bin():
    default = Path(os.environ['LOCALAPPDATA'])/'Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin'
    return Path(os.environ.get('LLVM_BIN',default))


def linux(package,output):
    clang=llvm_bin()/'clang.exe'
    target=['--target=aarch64-linux-gnu','-fPIC','-fno-stack-protector']
    built=objects(package/CORE,output,clang,target)
    exports=output/'exports.txt'
    exports.write_text('{ global: lc_demo_kem; lc_demo_dsa44; lc_demo_dsa65; lc_demo_dsa87; local: *; };',
                       encoding='ascii')
    library=output/'native_primitives_aarch64.so'
    subprocess.run([clang,*target,'-fuse-ld=lld','-nostdlib','-shared','-Wl,--gc-sections,-z,relro,-z,now',
                    '-Wl,--version-script='+str(exports),*built,'-o',library],check=True)
    return library


def stm32(package,output):
    work=Path(__file__).resolve().parent
    ring=package/'02_测试代码与数据/performance/多项式运算/完整环乘实板测量/stm32'
    sys.path.insert(0,str(ring))
    import build_driver as driver
    with TemporaryDirectory() as directory:
        tmp=Path(directory)
        target=['--target=arm-none-eabi','-mcpu=cortex-m4','-mthumb','-mfloat-abi=soft','-mno-unaligned-access']
        built=objects(package/CORE,tmp/'objects',llvm_bin()/'clang.exe',target)
        (tmp/'ring_driver.c').write_bytes((work/'primitive-stm32.c').read_bytes())
        (tmp/'primitive-dispatch.h').write_bytes((work/'primitive-dispatch.h').read_bytes())
        driver.HERE=tmp
        driver.SYMS={}
        driver.FLAGS.extend(['-I'+str(tmp)])
        driver.LD=driver.LD.replace('. += 3200;', '. += 8192;')
        run=driver.run
        def link_with_primitives(command):
            if Path(command[0]).name=='ld.lld.exe':
                command=[*command[:-2],*built,*command[-2:]]
            return run(command)
        driver.run=link_with_primitives
        for profile in (24,32):
            mode=f'{profile}KiB'
            driver.main(mode)
            for ext in ('bin','json'):
                (output/f'stm32-primitives-{profile}.{ext}').write_bytes((tmp/mode/f'driver.{ext}').read_bytes())


def ch32(package,output):
    work=Path(__file__).resolve().parent
    tool=package/CORE/'targets/ch32v307/实板构型/toolchain/bin'
    gcc=tool/'riscv-none-embed-gcc.exe'
    target=['-mabi=ilp32','-march=rv32imacxw','-msmall-data-limit=0','-mno-save-restore']
    with TemporaryDirectory() as directory:
        tmp=Path(directory)
        built=objects(package/CORE,tmp/'objects',gcc,target)
        ld=tmp/'arithmetic.ld'
        ld.write_text("""MEMORY { RAM(rx): ORIGIN = 0x20018000, LENGTH = 0x5800 }
ENTRY(qual_entry)
SECTIONS { .text : { KEEP(*(.text.qual_entry)) *(.text*) *(.rodata*) *(.srodata*) } > RAM }
work = 0x2001d800;
receipt = 0x2001de00;
__qual_stack_top = 0x20020000;
ASSERT(SIZEOF(.text) <= 0x5800, "native arithmetic program exceeds its SRAM range")
""",encoding='ascii')
        elf=tmp/'primitives.elf'
        binary=output/'ch32-primitives.bin'
        subprocess.run([gcc,*target,'-std=c11','-Os','-fno-builtin','-ffreestanding',
                        '-ffunction-sections','-fdata-sections','-nostdlib','-Wl,--no-relax,--gc-sections',
                        '-T',ld,work/'primitive-ch32.c',*built,'-lgcc','-o',elf],check=True)
        subprocess.run([tool/'riscv-none-embed-objcopy.exe','-O','binary',elf,binary],check=True)
        assert binary.stat().st_size <= 0x5800
        return binary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    package,output=args.package.resolve(),args.output.resolve()
    output.mkdir(parents=True,exist_ok=True)
    with TemporaryDirectory() as directory:
        arm=linux(package,Path(directory))
        binary=output/arm.name
        binary.write_bytes(arm.read_bytes())
    rv=ch32(package,output)
    stm32(package,output)
    manifest={file.name:hashlib.sha256(file.read_bytes()).hexdigest() for file in (binary,rv)}
    (output/'primitives.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='ascii')
