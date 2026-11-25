"""Relink each production compact image for an independently selectable FLASH sector.

The script only builds files and never opens a USB device. A 32-KiB SRAM MEMORY
region and a linker ASSERT cover I/O, USB, globals, full arena/guards, stack,
alignment and the small bootstrap stack for every standard parameter.
"""
import argparse,csv,hashlib,struct,xml.etree.ElementTree as ET
from pathlib import Path
from build import HERE,ARM,LLVM,run,sha,write

def relink(param,firmware,src,out,start,strategy='compact'):
    meta=ET.parse(firmware/(f'p{param}-{strategy}.xml')).getroot().attrib
    objd=firmware.parent/'objects'/f'p{param}-{strategy}'
    work=out/'objects'/str(param);work.mkdir(parents=True,exist_ok=True)
    result=out/'firmware';result.mkdir(parents=True,exist_ok=True)
    stack=int(meta['stack_capacity'])
    tag=hashlib.sha256(bytes.fromhex(meta['sha256'])+start.to_bytes(4,'little')+(HERE/'flash.ld.in').read_bytes()).digest()[:16]
    write(work/'build_tag.h','#define BUILD_TAG {'+','.join(hex(w)+'u' for w in struct.unpack('<4I',tag))+'}\n')
    boot=(objd/'startup.S') if strategy=='m4fstack' else (HERE/'startup.S')
    startup=boot.read_text().replace(' ldr r1,=__bss_begin',' ldr r1,=__data_load\n ldr r2,=__data_begin\n ldr r3,=__data_end\n8: cmp r2,r3\n bhs 9f\n ldr r4,[r1],#4\n str r4,[r2],#4\n b 8b\n9: ldr r1,=__bss_begin',1)
    write(work/'startup.S',startup);write(work/'flash.ld',(HERE/'flash.ld.in').read_text().replace('FLASH_START',hex(start)).replace('STACK_BYTES',str(stack)))
    vendors=HERE/'vendor/libopencm3'
    flags=ARM+['-I'+str(HERE/'freestanding'),'-I'+str(src/'targets/include'),'-I'+str(src/'targets/common'),'-I'+str(src/'include'),'-I'+str(vendors/'include'),'-I'+str(HERE),'-I'+str(work),f'-DPARAM={param}','-DPROFILE='+meta['profile'],'-DARENA_BYTES='+meta['workspace_capacity']]
    for source,output in ((work/'startup.S','00-startup.o'),(HERE/'board.c','01-board.o')):
        run([LLVM/'clang.exe',*flags,'-c',source,'-o',work/output],work)
    objects=[work/'00-startup.o',work/'01-board.o']+sorted(p for p in objd.glob('*.o') if p.name[:2] not in ('00','01'))
    unit=f'p{param}-{strategy}-flash32';elf=result/(unit+'.elf');binary=result/(unit+'.bin')
    run([LLVM/'ld.lld.exe','--gc-sections','-T',work/'flash.ld','-Map='+str(result/(unit+'.map')),*objects,'-o',elf],work)
    run([LLVM/'llvm-objcopy.exe','-O','binary',elf,binary],work)
    nmtxt=run([LLVM/'llvm-nm.exe','-n',elf],work)
    sym={r[2]:int(r[0],16) for x in nmtxt.splitlines() if len(r:=x.split())==3}
    nms=run([LLVM/'llvm-nm.exe','-S','--size-sort',elf],work)
    sizes={r[3]:int(r[1],16) for x in nms.splitlines() if len(r:=x.split())==4}
    data=binary.read_bytes(); sp,pc=struct.unpack_from('<II',data)
    if not(sp==sym['__boot_stack_top'] and pc&1 and start<=pc-1<start+len(data) and len(data)==sym['__image_bytes']):raise ValueError('image vector validation failed')
    ram=sym['__reserved_ram'];pool=int(meta['workspace_capacity']);io=sizes['io'];stackguard=64;arenaguard=64
    mutable=sym['__data_end']-sym['__data_begin']
    parts=dict(caller_workspace_bytes=pool,workspace_guard_bytes=arenaguard,op_io_bytes=io,initialized_data_bytes=mutable,stack_capacity_bytes=stack,stack_guard_bytes=stackguard,bootstrap_stack_bytes=128)
    parts['other_bss_usb_and_alignment_bytes']=ram-sum(parts.values())
    if parts['other_bss_usb_and_alignment_bytes']<0 or sum(parts.values())!=ram or ram>32768:raise ValueError('RAM accounting failure')
    row=dict(parameter=param,strategy=strategy,execution='flash32',base=hex(start),entry=hex(pc),used_flash_bytes=len(data),full_reserved_ram_bytes=ram,**parts,ram_budget_bytes=32768,headroom_bytes=32768-ram,sha256=sha(binary),elf_sha256=sha(elf),tag=tag.hex(),clock_hz=168000000)
    ET.ElementTree(ET.Element('image',{a:str(b) for a,b in row.items()})).write(result/(unit+'.xml'),encoding='utf-8',xml_declaration=True)
    return row
if __name__=='__main__':
    from build import SOURCE
    ap=argparse.ArgumentParser();ap.add_argument('--source',type=Path,default=SOURCE);ap.add_argument('--firmware',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--strategy',choices=['compact','m4fstack'],default='compact');ap.add_argument('--address',type=lambda s:int(s,0),default=0x080e0000);args=ap.parse_args()
    if args.address not in range(0x08020000,0x08100000,0x20000):ap.error('must be an entire F407 128 KiB sector')
    rows=[relink(p,args.firmware.resolve(),args.source.resolve(),args.output.resolve(),args.address,args.strategy) for p in (512,768,1024,44,65,87)]
    with (args.output/'flash32-resources.tsv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=rows[0],delimiter='\t',lineterminator='\n');w.writeheader();w.writerows(rows)
    for r in rows:print(r['parameter'],r['used_flash_bytes'],r['full_reserved_ram_bytes'],r['headroom_bytes'],r['sha256'])

