"""Collect an explicit bounded list of complete-operation PMU regions."""
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
import argparse, datetime, hashlib, record_io as json, os, signal, subprocess, time
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def dump(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--plan',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    plan=json.loads(a.plan.read_text());out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    if not 1<=len(plan['jobs'])<=100 or not 1<=plan['job_timeout_seconds']<=60:raise ValueError('Bounded plan required')
    if plan['events']!=['cycles:u','instructions:u','branch-misses:u','cache-references:u','cache-misses:u']:raise ValueError('Unregistered events')
    for f in plan['artifacts']:
        if sha(f['path'])!=f['sha256']:raise ValueError('Artifact mismatch')
    dump(out/'identity.xml',{'plan_sha256':sha(a.plan),'runner_sha256':sha(__file__),'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'events':plan['events'],'boundary':'after 32 warmups, exactly N complete operations and context initializations; PMU enable/disable handshake; post-validation and outputs outside region'})
    records=[]
    for j in plan['jobs']:
        if not j['id'].isalnum():raise ValueError('Alphanumeric id required')
        d=out/j['id'];d.mkdir()
        for name in ['control','ack']:os.mkfifo(d/name,0o600)
        env=os.environ.copy();env.update(A127_PERF_CONTROL=str(d/'control'),A127_PERF_ACK=str(d/'ack'))
        cmd=['perf','stat','-x',',','--no-big-num','--delay=-1','--control=fifo:'+str(d/'control')+','+str(d/'ack'),'-e',','.join(plan['events']),'-o',str(d/'events.csv'),'--',plan['workload'],j['library'],str(j['parameter']),str(j['operation']),str(j['samples']),str(j['workspace_bytes']),str(plan['cpu']),str(j['seed'])]
        start=time.monotonic();timeout=False
        with (d/'stdout.log').open('wb') as so,(d/'stderr.log').open('wb') as se:
            child=subprocess.Popen(cmd,stdout=so,stderr=se,env=env,start_new_session=True)
            try:rc=child.wait(timeout=plan['job_timeout_seconds'])
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);rc=child.wait();timeout=True
        record={'job':j,'command':cmd,'exit_code':rc,'timed_out':timeout,'elapsed_seconds':time.monotonic()-start,'files':{p.name:sha(p) for p in d.iterdir() if p.is_file()},'stdout':(d/'stdout.log').read_text(),'stderr':(d/'stderr.log').read_text()}
        records.append(record);dump(out/'progress.xml',records)
        for name in ['control','ack']:(d/name).unlink()
        print(j['id'],rc,flush=True)
    dump(out/'result.xml',{'records':records,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'plan_sha256':sha(a.plan)})
    if os.geteuid()==0:subprocess.run(['chown','-R',f"{plan['uid']}:{plan['gid']}",str(out)],check=True)
if __name__=='__main__':main()
