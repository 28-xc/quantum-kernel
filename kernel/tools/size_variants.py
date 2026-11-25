"""Actual parameter-pruned linking and machine-image accounting; no timing."""
from pathlib import Path
import argparse
import datetime
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
import re
import shlex
import shutil
import struct
import subprocess
import sys
import time
from build_variants import CONFIGS

ROOT=Path(__file__).resolve().parents[1]
PUBLIC=['lc_get_sizes','lc_context_init','lc_keypair','lc_encaps','lc_decaps','lc_sign','lc_verify','lc_error_string']
ALL=[512,768,1024,44,65,87]
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def write(path,value):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    Path(path).write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')




def binary_info(path):
    raw=Path(path).read_bytes();sections=[];loads=[]
    if raw[:2]==b'MZ':
        off=struct.unpack_from('<I',raw,60)[0]
        if raw[off:off+4]!=b'PE\0\0':raise ValueError('Invalid PE')
        machine,n=struct.unpack_from('<HH',raw,off+4);opt=off+24;sz=struct.unpack_from('<H',raw,off+20)[0]
        magic=struct.unpack_from('<H',raw,opt)[0];image_base=struct.unpack_from('<Q' if magic==0x20b else '<I',raw,opt+(24 if magic==0x20b else 28))[0]
        symbols,count=struct.unpack_from('<II',raw,off+12);strings=symbols+18*count
        for i in range(n):
            p=opt+sz+i*40;name=raw[p:p+8].split(b'\0')[0].decode('ascii','replace');vsize,addr,filesize,fileoff=struct.unpack_from('<IIII',raw,p+8);flags=struct.unpack_from('<I',raw,p+36)[0]
            if name.startswith('/') and name[1:].isdigit():
                at=strings+int(name[1:]);name=raw[at:raw.index(b'\0',at)].decode('ascii','replace')
            debug=name.startswith(('.debug','.zdebug','.gnu_debug'))
            mapped=bool(flags&0x40000000) and not debug
            sections.append(dict(name=name,address=addr+image_base,memory_bytes=vsize,file_bytes=filesize,file_offset=fileoff,allocated=mapped,writable=bool(flags&0x80000000),executable=bool(flags&0x20000000),nobits=bool(flags&0x80),sha256=hashlib.sha256(raw[fileoff:fileoff+filesize]).hexdigest() if filesize else None))
        kind='PE';span=struct.unpack_from('<I',raw,opt+56)[0];bits=64 if magic==0x20b else 32
    elif raw[:4]==b'\x7fELF':
        bits=64 if raw[4]==2 else 32;endian='<' if raw[5]==1 else '>';machine=struct.unpack_from(endian+'H',raw,18)[0]
        if bits==64:phoff,shoff=struct.unpack_from(endian+'QQ',raw,32);phents,phnum,shents,shnum,shstr=struct.unpack_from(endian+'HHHHH',raw,54);fmt=endian+'IIQQQQIIQQ'
        else:phoff,shoff=struct.unpack_from(endian+'II',raw,28);phents,phnum,shents,shnum,shstr=struct.unpack_from(endian+'HHHHH',raw,42);fmt=endian+'IIIIIIIIII'
        records=[struct.unpack_from(fmt,raw,shoff+i*shents) for i in range(shnum)];strings=records[shstr];names=raw[strings[4]:strings[4]+strings[5]]
        for x in records:
            start=x[0];end=names.find(b'\0',start);name=names[start:end].decode('ascii','replace');size=x[5];filebytes=0 if x[1]==8 else size
            sections.append(dict(name=name,address=x[3],memory_bytes=size,file_bytes=filebytes,file_offset=x[4],allocated=bool(x[2]&2),writable=bool(x[2]&1),executable=bool(x[2]&4),nobits=x[1]==8,sha256=hashlib.sha256(raw[x[4]:x[4]+filebytes]).hexdigest() if filebytes else None))
        for i in range(phnum):
            x=struct.unpack_from(endian+('IIQQQQQQ' if bits==64 else 'IIIIIIII'),raw,phoff+i*phents)
            if x[0]==1:loads.append(dict(address=x[3] if bits==64 else x[2],file_bytes=x[5] if bits==64 else x[4],memory_bytes=x[6] if bits==64 else x[5]))
        kind='ELF';span=max((x['address']+x['memory_bytes'] for x in loads),default=0)-min((x['address'] for x in loads),default=0)
    else:raise ValueError('Expected PE or ELF')
    mapped=[s for s in sections if s['allocated']]
    body=sum(s['memory_bytes'] for s in mapped if not s['writable'])
    return dict(format=kind,bits=bits,machine=machine,file_bytes=len(raw),sha256=sha(path),sections=sections,
        text_bytes=sum(s['memory_bytes'] for s in mapped if s['executable']),
        rodata_bytes=sum(s['memory_bytes'] for s in mapped if not s['executable'] and not s['writable']),
        data_bytes=sum(s['memory_bytes'] for s in mapped if s['writable'] and not s['nobits']),
        bss_bytes=sum(s['memory_bytes'] for s in mapped if s['writable'] and s['nobits']),
        readonly_allocated_bytes=body,all_allocated_section_bytes=sum(s['memory_bytes'] for s in mapped),image_virtual_span_bytes=span,
        load_segments=loads,accounting='Allocated/readable section payload including code/constants/unwind/import/export/relocation tables; debug excluded by resolved name/ELF allocation flag. Discardable PE relocation payload remains charged. PE image span / ELF load segments and total file separately reported.')

def entity_table(nm,info):
    rows=[]
    for line in nm.splitlines():
        m=re.match(r'^([0-9a-fA-F]+)\s+(?:([0-9a-fA-F]+)\s+)?([a-zA-Z])\s+(\S+)$',line)
        if not m:continue
        addr=int(m[1],16);section=next((s for s in info['sections'] if s['address']<=addr<s['address']+s['memory_bytes']),None)
        if not section or not section['allocated']:continue
        name=m[4]
        if name.startswith('.'):continue
        rows.append(dict(symbol=name,address=addr,size_bytes=int(m[2],16) if m[2] else None,type=m[3],section=section['name'],primitive=bool(re.search(r'keccak|shake|sha3|ntt|intt|zeta|qdata|mont|round.?constant|cbd|rej|basemul',name,re.I))))
    addresses={}
    for row in rows:addresses.setdefault(str(row['address']),[]).append(row['symbol'])
    return dict(entities=rows,unique_addresses=len(addresses),aliases={k:v for k,v in addresses.items() if len(v)>1},
                primitive_entities=[r for r in rows if r['primitive']],size_note='ELF symbol sizes when supplied by nm; PE COFF has no reliable per-symbol size here, so null is retained. Distinct addresses are actual retained entities, not source-level deduplication claims.')

def pe_exports(path):
    raw=Path(path).read_bytes();pe=struct.unpack_from('<I',raw,60)[0];opt=pe+24
    magic=struct.unpack_from('<H',raw,opt)[0];directory=opt+(112 if magic==0x20b else 96)
    base=struct.unpack_from('<Q' if magic==0x20b else '<I',raw,opt+(24 if magic==0x20b else 28))[0]
    sections=binary_info(path)['sections']
    def locate(rva):
        for s in sections:
            start=s['address']-base
            if start<=rva<start+max(s['memory_bytes'],s['file_bytes']):return s['file_offset']+rva-start
        raise ValueError('PE export address outside sections')
    table=locate(struct.unpack_from('<I',raw,directory)[0]);count=struct.unpack_from('<I',raw,table+24)[0]
    pointers=locate(struct.unpack_from('<I',raw,table+32)[0]);names=[]
    for i in range(count):
        at=locate(struct.unpack_from('<I',raw,pointers+4*i)[0]);names.append(raw[at:raw.index(b'\0',at)].decode('ascii'))
    return names



def main():
    from configuration_capabilities import validate_pruned_configuration
    from pruning_sources import selected_parameters
    from native_options import add_arm_arguments, arm_values, arm_argv
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--configuration',choices=CONFIGS,required=True)
    p.add_argument('--scope',choices=['all','kem','dsa','512','768','1024','44','65','87'],default='all')
    p.add_argument('--parameters');p.add_argument('--operations');p.add_argument('--probe-workspace',type=int,default=262144)
    p.add_argument('--backend',choices=['portable','aarch64','x86_64'],default='portable')
    p.add_argument('--opt',choices=['O3','Os'],default='Os');p.add_argument('--lto',action='store_true')
    for name,default in [('cc','gcc'),('ar','gcc-ar'),('nm','nm'),('objdump','objdump'),('size','size')]:p.add_argument('--'+name,default=default)
    p.add_argument('--probe-count',type=int,default=100)
    p.add_argument('--extra-defs',nargs='*',default=[])
    p.add_argument('--sanitize',choices=['none','undefined','address,undefined'],default='none')
    add_arm_arguments(p)
    a=p.parse_args();cfg=CONFIGS[a.configuration];validate_pruned_configuration(a.configuration,cfg,backend=a.backend)
    levels=selected_parameters(a.parameters or a.scope);out=a.output.resolve()
    if out.exists() or out.is_relative_to(ROOT) or out in ROOT.parents:raise ValueError('Fresh output outside the source tree required')
    if not 1<=a.probe_count<=10000:raise ValueError('Invalid probe count')
    if any(not re.fullmatch(r'[A-Z][A-Z0-9_]*(?:=[0-9]+)?',v) for v in a.extra_defs):raise ValueError('Only explicit integer feature definitions are supported')
    out.mkdir(parents=True);(out/'tmp').mkdir()
    env=dict(os.environ,TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    logs=[];began=time.monotonic()
    def run(argv,label):
        r=subprocess.run(list(map(str,argv)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
        log=out/(label+'.log');log.write_text(json.capture_text(r.stdout+r.stderr),encoding='utf-8')
        logs.append(dict(argv=list(map(str,argv)),exit_code=r.returncode,log=log.name,log_sha256=sha(log)));write(out/'commands.xml',logs)
        if r.returncode:raise RuntimeError(label+' failed; original log preserved')
        return r.stdout
    try:
        core=out/'core'
        command=[sys.executable,'-B',ROOT/'tools/build_variants.py','--output',core,'--config',a.configuration,'--backend',a.backend,'--parameters',','.join(map(str,levels)),'--opt',a.opt,'--probe-count',str(a.probe_count),'--sanitize',a.sanitize]
        for name in ('cc','ar','nm','size'):command+=['--'+name,getattr(a,name)]
        if a.operations is not None:command+=['--operations',a.operations,'--probe-workspace',str(a.probe_workspace)]
        if a.backend=='aarch64':command+=arm_argv(arm_values(a))
        if a.lto:command.append('--lto')
        if a.extra_defs:command+=['--extra-defs',*a.extra_defs]
        run(command,'unified_build')
        receipt=read(core/'build.xml');windows=receipt['binary']['format']=='PE'
        if receipt['parameters']!=levels or receipt['schedule']!=cfg or not receipt['selected_dispatch']:raise ValueError('Selected build receipt mismatch')
        shared=core/('latticecore.dll' if windows else 'liblatticecore.so')
        archive=core/'liblatticecore.a'
        def inspect(path,label):
            info=binary_info(path)
            symbols=run([a.nm,'-S','--defined-only',path],label+'_nm');entities=entity_table(symbols,info)
            headers=run([a.objdump,'-p',path],label+'_headers')
            dependencies=re.findall(r'DLL Name:\s*(\S+)',headers) if windows else re.findall(r'^\s*NEEDED\s+(\S+)',headers,re.M)
            disasm=run([a.objdump,'-d',path],label+'_disassembly');edges=[];caller=None
            for line in disasm.splitlines():
                match=re.match(r'^([0-9a-fA-F]+) <([^>]+)>:',line)
                if match:caller=match[2]
                branch=re.search(r'\b(?:callq?|bl|b)\s+([0-9a-fA-Fx]+)\s+<([^>]+)>',line)
                if branch and caller:edges.append(dict(caller=caller,target=branch[2],target_address=int(branch[1],16)))
            entities['direct_call_edges']=edges
            write(out/(label+'_entities.xml'),entities)
            info.update(path=path.relative_to(out).as_posix(),dependencies=dependencies,dependency_bytes_included=False,entities_file=label+'_entities.xml',disassembly_sha256=sha(out/(label+'_disassembly.log')))
            return info
        inspections={'shared_library':inspect(shared,'shared')};probes={}
        for linkage in ('shared','static'):
            probe=receipt['public_checks'][linkage]
            rows=[json.loads(line) for line in json.record_lines(probe['stdout']) if line.startswith(('{','<record'))]
            probes[linkage]=dict(exit_code=probe['exit_code'],rows=rows,sha256=probe['sha256'])
            inspections['whole_image_'+linkage]=inspect(core/('probe_'+linkage+('.exe' if windows else '')), 'probe_'+linkage)
        entities=read(out/'shared_entities.xml')['entities'];unselected=[]
        for level in ALL:
            if level not in levels:
                marker='lc_base_mlk'+str(level)+'_' if level>100 else 'lcbase'+str(level)+'_'
                unselected += [row['symbol'] for row in entities if marker in row['symbol']]
        if unselected:raise ValueError('Omitted parameter still retained: '+str(unselected))
        operation_entities=[]
        if receipt.get('operations') is not None:
            from operation_selection import names as operation_names
            for level in levels:
                for operation in operation_names(level):
                    if operation in receipt['operations'][str(level)]:continue
                    prefixes=({'keypair':['keypair_derand'],'encaps':['enc_derand'],'decaps':['dec']} if level>100 else
                              {'keypair':['keypair_internal','keypair'],'sign':['signature_internal','signature'],'verify':['verify_internal','verify','verify_segments']})[operation]
                    base=('lc_base_mlk' if level>100 else 'lcbase')+str(level)+'_'
                    found=[row['symbol'] for row in entities if any(re.match(re.escape(base+stem)+r'(?:\.|$)',row['symbol']) for stem in prefixes)]
                    operation_entities.extend(found)
            if operation_entities:raise ValueError('Omitted operation still retained: '+str(operation_entities))

        names=pe_exports(shared) if windows else [line.split()[0].split('@')[0] for line in run([a.nm,'-D','--defined-only','--format=posix',shared],'exports').splitlines() if line.strip()]
        expected=PUBLIC+(['lc_resource_query','lc_resource_make_plan','lc_resource_algorithm_bytes'] if CONFIGS[a.configuration].get('runtime_cache') else [])
        if sorted(names)!=sorted(expected):raise ValueError('Unexpected public export set')
        sources=dict(receipt['source_hashes']);sources['tools/size_variants.py']=sha(Path(__file__))
        for name,digest in sources.items():
            if sha(ROOT/name)!=digest:raise ValueError('Source changed during selected build: '+name)
        generated={'core/'+name:digest for name,digest in receipt['generated_source_hashes'].items()}
        for name,digest in generated.items():
            if sha(out/name)!=digest:raise ValueError('Generated source changed: '+name)
        write(out/'result.xml',dict(schema='latticecore.pruned-build.v2',status='BUILT_FUNCTIONALLY_CHECKED',configuration=a.configuration,schedule=cfg,parameters=levels,operations=receipt.get('operations'),probe_workspace=receipt.get('probe_workspace'),backend=a.backend,target=receipt['target'],compiler=receipt['compiler'],optimization=a.opt,lto=a.lto,extra_definitions=a.extra_defs,sanitizer=a.sanitize,
            unified_builder_result=dict(path='core/build.xml',sha256=sha(core/'build.xml')),source_hashes=sources,generated_source_hashes=generated,unsupported_status=-8,public_exports=sorted(names),inspections=inspections,
            archive=dict(path='core/liblatticecore.a',file_bytes=archive.stat().st_size,sha256=sha(archive),is_loaded_image=False),public_checks=probes,unselected_named_entities=[],unselected_operation_entities=operation_entities,commands_sha256=sha(out/'commands.xml'),elapsed_seconds=time.monotonic()-began))
        print('Selected unified build, shared/static probes and retained-entity checks passed: '+','.join(map(str,levels)),flush=True)
    except Exception as error:
        write(out/'failure.xml',dict(error=str(error)));raise

if __name__=='__main__':main()
