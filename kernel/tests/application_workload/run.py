"""Run paired, complete certificate-and-KEM application workloads."""
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
import argparse, csv, hashlib, record_io as json, math, os, platform, random, statistics, subprocess, time

ROOT=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def quantile(a,p):
    a=sorted(a);x=(len(a)-1)*p;i=int(x);return a[i]+(a[min(i+1,len(a)-1)]-a[i])*(x-i)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--config',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--cc',default='gcc');ap.add_argument('--cpu',type=int,default=0)
    ap.add_argument('--blocks',type=int,default=10);ap.add_argument('--samples',type=int,default=200)
    a=ap.parse_args();assert 1<=a.blocks<=30 and 1<=a.samples<=1000
    out=a.output.resolve();assert not out.exists()
    if os.name=='nt':assert out.drive.upper()=='D:'
    out.mkdir(parents=True);(out/'samples').mkdir();(out/'tmp').mkdir();(out/'source').mkdir()
    env=os.environ.copy();env.update(TMP=str(out/'tmp'),TEMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    for name,p in [('enrollment.c',ROOT/'examples/enrollment.c'),('latticecore.h',ROOT/'include/latticecore.h'),('run.py',Path(__file__))]:
        (out/'source'/name).write_bytes(p.read_bytes())
    supplied=json.loads(a.config.read_text(encoding='utf-8'))
    # The public collector serializes the technical configuration only.
    libs=[{k:item[k] for k in ('id','path','sha256','workspace_bytes')} for item in supplied['libraries']]
    cfg={'libraries':libs};assert len({x['id'] for x in libs})==len(libs)
    for lib in libs:assert sha(lib['path'])==lib['sha256']
    exe=out/('enrollment.exe' if os.name=='nt' else 'enrollment')
    command=[a.cc,'-O2','-std=c11','-Wall','-Wextra','-Werror','-fstack-usage','-I'+str(out/'source'),str(out/'source/enrollment.c'),'-o',str(exe)]
    if os.name!='nt':command+=['-ldl']
    q=subprocess.run(command,capture_output=True,text=True,env=env);(out/'compile.log').write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8');assert q.returncode==0
    compiler=subprocess.check_output([a.cc,'--version'],text=True,env=env)
    protocol=dict(schema='lattice.application_protocol.v1',compiler=compiler,compile_command=command,executable_sha256=sha(exe),
        source_sha256={p.name:sha(p) for p in (out/'source').iterdir()},configuration=cfg,blocks=a.blocks,samples=a.samples,
        warmup=16,cpu=a.cpu,platform=platform.platform(),machine=platform.machine(),seed=20260927072,
        workload='Certificate of a fresh ML-KEM public key, ML-DSA verification, encapsulation and decapsulation; sequential authority and device roles.',
        fresh_identity_modes=[False,True],parameter_pairs=[[512,44],[768,65],[1024,87]],
        entropy='Paired deterministic test fixture, identical seed and requests across libraries.',
        latency_scope='Context initialization, optional authority key generation, KEM key generation, certificate signing and verification, encapsulation, decapsulation, shared-secret equality check and secret cleanup.',
        batch_scope='Measured application iterations plus transcript checksum; warmup, result-file writes, key setup for reused identity and library loading are outside.',
        memory_scope='Serialized object buffers are reported separately from library workspace, protected-stack measurements and program sections; benchmark sample arrays belong to measurement infrastructure.')
    save(out/'protocol.xml',protocol);ledger=json.record_stream(out/'tasks.records.xml');results=[];schedule=random.Random(protocol['seed'])
    index=0
    for block in range(a.blocks):
        cells=[(k,d,fresh) for k,d in protocol['parameter_pairs'] for fresh in (0,1)];schedule.shuffle(cells)
        for kem,dsa,fresh in cells:
            order=list(libs);schedule.shuffle(order);expected=None;seed=protocol['seed']+block*1000003+kem*17+fresh
            for lib in order:
                fn=f'{index:05d}.csv';argv=[str(exe),str(Path(lib['path']).resolve()),str(kem),str(dsa),str(lib['workspace_bytes']),str(a.samples),str(fresh),str(seed),str(a.cpu),str(out/'samples'/fn)]
                t=time.time();q=subprocess.run(argv,capture_output=True,text=True,env=env,timeout=120)
                task=dict(index=index,block=block,configuration=lib['id'],kem=kem,dsa=dsa,fresh_identity=bool(fresh),seed=seed,argv=argv,exit_code=q.returncode,stdout=q.stdout,stderr=q.stderr,controller_seconds=time.time()-t)
                ledger.write(json.dumps(task)+'\n');ledger.flush();assert q.returncode==0,task
                result=json.loads(q.stdout);assert result['status']=='PASS'
                identity=(result['transcript_fnv64'],result['entropy_requests'],result['entropy_bytes'])
                if expected is None:expected=identity
                assert expected==identity,(block,kem,dsa,fresh,lib['id'])
                with (out/'samples'/fn).open(newline='') as stream:rows=list(csv.DictReader(stream))
                assert len(rows)==a.samples+16
                values=[int(x['elapsed_ns']) for x in rows if x['phase']=='measurement'];assert len(values)==a.samples
                assert all(0<=int(x['workspace_used_bytes'])<=lib['workspace_bytes'] for x in rows)
                results.append(dict(index=index,block=block,configuration=lib['id'],kem=kem,dsa=dsa,fresh_identity=bool(fresh),
                    result=result,raw_csv='samples/'+fn,raw_sha256=sha(out/'samples'/fn),mean_ns=statistics.mean(values),median_ns=statistics.median(values),p95_ns=quantile(values,.95),p99_ns=quantile(values,.99),applications_per_second=a.samples/(result['batch_wall_ns']*1e-9)))
                index+=1
            print(json.dumps(dict(block=block,kem=kem,dsa=dsa,fresh_identity=bool(fresh),paired_transcripts_match=True)),flush=True)
    ledger.close();save(out/'observations.xml',dict(schema='lattice.application_observations.v1',status='PASS',tasks=index,protocol_sha256=sha(out/'protocol.xml'),ledger_sha256=sha(out/'tasks.records.xml'),records=results))
    print(json.dumps(dict(status='PASS',tasks=index,applications=index*a.samples)))
if __name__=='__main__':main()
