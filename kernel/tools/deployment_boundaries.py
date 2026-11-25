"""Link exact, insufficient and relaxed image budgets without executing an undersized image."""
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
import argparse, hashlib, record_io as json, re, subprocess

def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,v):Path(p).write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')

def run(build,output):
    build=Path(build).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('Fresh boundary output required')
    record=read(build/'build.xml');commands=read(build/'commands.xml')
    if record['status']!='BUILD_AND_SUBSET_CHECKS_PASSED' or sha(build/'commands.xml')!=record['commands_sha256']:
        raise ValueError('A completed, source-bound target execution is required')
    if sha(build/'latticecore.elf')!=record['elf_sha256']:raise ValueError('Image changed')
    link=next(c['argv'] for c in commands if c['log']=='link.txt')
    original=(build/'image.ld').read_text();memory=record['memory']
    program=memory['code_and_rodata_load_bytes'];rw=memory['writable_image_span_bytes'];total=memory['emulator_image_occupied_ram_bytes']
    cases=[('exact',program,rw,total,True),('program_insufficient',program-1,rw,total,False),
           ('writable_insufficient',program,rw-1,total,False),('total_insufficient',program,rw,total-1,False),
           ('relaxed',program+4096,rw+4096,total+8192,True)]
    output.mkdir(parents=True);results=[]
    for name,p,r,t,accepted in cases:
        folder=output/name;folder.mkdir()
        script=re.sub(r'(CODE \(rx\).*?LENGTH = )\d+',lambda m:m[1]+str(p),original)
        script=re.sub(r'(RAM \(rwx\).*?LENGTH = )\d+',lambda m:m[1]+str(r),script)
        script=re.sub(r'(__code_end - __code_start <= )\d+',lambda m:m[1]+str(p),script)
        script=re.sub(r'(__ram_end - __ram_start\) <= )\d+',lambda m:m[1]+str(t),script)
        (folder/'image.ld').write_text(script,encoding='ascii')
        argv=[str(folder/'image.ld') if x==str(build/'image.ld') else
              str(folder/'latticecore.elf') if x==str(build/'latticecore.elf') else
              '-Wl,-Map,'+str(folder/'latticecore.map') if x.startswith('-Wl,-Map,') else x for x in link]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=120)
        (folder/'link.log').write_text(json.capture_text(result.stdout+result.stderr),encoding='utf-8')
        if (result.returncode==0)!=accepted:raise ValueError('Unexpected link budget result '+name)
        observed=dict(name=name,code_budget=p,writable_budget=r,total_budget=t,argv=argv,
                      link_exit_code=result.returncode,link_log_sha256=sha(folder/'link.log'),executed=False)
        if accepted:
            qemu=[str(folder/'latticecore.elf') if x==str(build/'latticecore.elf') else x for x in record['qemu_command']]
            run_result=subprocess.run(qemu,capture_output=True,text=True,timeout=record['qemu_timeout_seconds'])
            (folder/'console.log').write_text(json.capture_text(run_result.stdout+run_result.stderr),encoding='utf-8')
            from build_targets import parse_run
            checks=parse_run(run_result.stdout,memory,record['vectors'])
            if run_result.returncode:raise ValueError('Legal-capacity run failed')
            observed.update(executed=True,checks=checks,elf_sha256=sha(folder/'latticecore.elf'),console_sha256=sha(folder/'console.log'))
        elif not any(word in result.stderr for word in ('overflow','exceeds','exceed','will not fit')):
            raise ValueError('Rejected build lacks explicit region/budget diagnostic')
        results.append(observed);write(output/'progress.xml',results)
    result=dict(schema='lattice.deployment_boundaries.v1',status='PASS',source_build_sha256=sha(build/'build.xml'),
                source_elf_sha256=record['elf_sha256'],parent_program_bytes=program,parent_writable_bytes=rw,parent_total_ram_bytes=total,
                cases=results,undersized_images_executed=False)
    write(output/'result.xml',result);return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(run(a.build,a.output)['status'])
