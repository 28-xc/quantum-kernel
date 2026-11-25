"""Bounded cgroup-v2 measurements of the project's own complete operations.

Prepare a JSON job list before measurement. This controller changes only its
new project cgroups, preserves every process exit, and never repeats a job.
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
import argparse, datetime, hashlib, record_io as json, os, subprocess, time

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p): return json.loads(Path(p).read_text())
def write(p,x): Path(p).write_text(json.dumps(x,indent=2,allow_nan=False)+'\n')
def text(p):
    try: return p.read_text().strip()
    except FileNotFoundError: return None
def snapshot(group):
    return {n:text(group/n) for n in ('memory.current','memory.peak','memory.max','memory.swap.max','memory.events','memory.stat','cpu.max','cpu.stat','cgroup.events','cgroup.procs')}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--plan',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    if os.geteuid()!=0: raise ValueError('This explicit cgroup controller needs administrator privileges')
    plan=read(a.plan);out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    if len(plan['jobs'])>1000 or not 1<=plan['job_timeout_seconds']<=60: raise ValueError('Unbounded plan')
    for item in plan['artifacts']:
        if sha(item['path'])!=item['sha256']:raise ValueError('Artifact changed')
    for command in [plan['launcher'],plan['workload']]:
        if str(Path(command).resolve())!=command:raise ValueError('Absolute binary path required')
    tag=plan['run_id']
    if not tag.startswith('a127-r3-') or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in tag):raise ValueError('Project run id required')
    parent=Path('/sys/fs/cgroup')/tag
    if parent.exists():raise ValueError('Existing cgroup; inspect rather than repeat')
    available=Path('/sys/fs/cgroup/cgroup.subtree_control').read_text().split()
    if not {'cpu','memory'}<=set(available):raise ValueError('Parent CPU/memory controllers unavailable; no system-wide change made')
    parent.mkdir();(parent/'cgroup.subtree_control').write_text('+cpu +memory')
    uid,gid=plan['uid'],plan['gid'];os.chown(out,uid,gid)
    write(out/'identity.xml',{'plan_sha256':sha(a.plan),'runner_sha256':sha(__file__),'boot_id':text(Path('/proc/sys/kernel/random/boot_id')),'uname':list(os.uname()),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'accounting':'cgroup current sampled every 5ms; kernel memory.peak where available; ru_maxrss separately; no counter reset or dropped slow sample'})
    records=[]
    try:
        for job in plan['jobs']:
            for item in plan['artifacts']:
                if sha(item['path'])!=item['sha256']:raise ValueError('Artifact changed')
            name=job['id']
            if not name.isalnum():raise ValueError('Alphanumeric job id required')
            if job['memory_max_bytes'] not in (262144,524288,1048576,2097152,4194304,8388608,16777216):raise ValueError('Unexpected memory bound')
            if job['cpu_max'] not in ('max 10000','10000 10000','5000 10000','2500 10000'):raise ValueError('Unexpected CPU bound')
            policy=job.get('file_cache_policy','warm_shared_files')
            if policy=='discard_project_file_cache_before_launch':
                # Restrict eviction advice to the two specified project files.
                # Shared system libraries retain the host's normal cache state.
                for path in (plan['workload'],job['library']):
                    with open(path,'rb') as f:
                        os.fsync(f.fileno());os.posix_fadvise(f.fileno(),0,0,os.POSIX_FADV_DONTNEED)
            elif policy!='warm_shared_files':raise ValueError('Unknown file-cache condition')
            group=parent/name;group.mkdir()
            (group/'memory.max').write_text(str(job['memory_max_bytes']))
            (group/'memory.swap.max').write_text('0')
            (group/'cpu.max').write_text(job['cpu_max'])
            before=snapshot(group);raw=out/(name+'.csv')
            cmd=[plan['launcher'],str(group),str(uid),str(gid),plan['workload'],job['library'],str(job['parameter']),str(job['operation']),str(job['samples']),str(job['workspace_bytes']),str(plan['cpu']),str(job['seed']),str(raw)]
            samples=[];start=time.monotonic();timed_out=False
            with (out/(name+'.stdout')).open('wb') as so,(out/(name+'.stderr')).open('wb') as se:
                child=subprocess.Popen(cmd,stdout=so,stderr=se,start_new_session=True)
                while child.poll() is None:
                    current=text(group/'memory.current');samples.append([time.monotonic()-start,int(current)])
                    if time.monotonic()-start>plan['job_timeout_seconds']:
                        import signal
                        os.killpg(child.pid,signal.SIGKILL);child.wait();timed_out=True;break
                    time.sleep(.005)
                code=child.wait()
            after=snapshot(group);meta=None
            try: meta=json.loads((out/(name+'.stdout')).read_text())
            except (ValueError,UnicodeDecodeError):pass
            r={'job':job,'command':cmd,'exit_code':code,'timed_out':timed_out,'elapsed_seconds':time.monotonic()-start,'before':before,'after':after,'sampled_memory_peak_bytes':max((s[1] for s in samples),default=0),'memory_observation_count':len(samples),'workload':meta,'raw_sha256':sha(raw) if raw.exists() else None,'stdout_sha256':sha(out/(name+'.stdout')),'stderr_sha256':sha(out/(name+'.stderr'))}
            write(out/(name+'.memory.xml'),samples);records.append(r);write(out/'progress.xml',records)
            if text(group/'cgroup.procs'):raise RuntimeError('Test process still in cgroup')
            group.rmdir()
            print(name,code,meta.get('status') if meta else 'PROCESS_EXIT',flush=True)
        write(out/'result.xml',{'status':'COLLECTION_COMPLETE','records':records,'plan_sha256':sha(a.plan),'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
    finally:
        if parent.exists() and not list(parent.iterdir()):parent.rmdir()
        # cgroup virtual control files do not prevent rmdir.
        if parent.exists() and not any(p.is_dir() for p in parent.iterdir()):parent.rmdir()
    subprocess.run(['chown','-R',f'{uid}:{gid}',str(out)],check=True)
if __name__=='__main__':main()
