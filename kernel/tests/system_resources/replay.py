"""Prepare or explicitly replay bounded, local Linux system experiments.

prepare only writes a hash-bound job table. build only compiles collectors.
run executes one explicitly selected batch against local, inventory-bound
libraries. The tool has no SSH, cloud, account or remote-control capability.
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
import argparse, collections, hashlib, record_io as json, os, platform, subprocess, sys, time
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text())
def put(p,x):Path(p).write_text(json.dumps(x,indent=2,allow_nan=False)+'\n')
def need(c,m):
 if not c:raise ValueError(m)
def sources():
 lock=read(HERE/'source_lock.xml')
 for r in lock['files']:need(sha(HERE/r['path'])==r['sha256'],'Collector source differs: '+r['path'])
 return lock
def libraries(bundle):
 inventory=read(bundle/'image_inventory.xml');found={}
 for image in inventory['images']:
  if image['kind']!='hosted_library' or image['platform']!='linux_aarch64':continue
  r=image['artifact'];p=(bundle/r['path']).resolve()
  need(p.is_relative_to(bundle),'Image path escapes bundle');need(sha(p)==r['sha256'],'Image identity differs')
  found[r['sha256']]=dict(path=r['path'],sha256=r['sha256'])
 return found
def construct(bundle,overrides):
 lock=sources();images=libraries(bundle)
 tasks=[];input_files=[]
 for data in lock['datasets']:
  p=overrides.get(data['id'],bundle/data['path']);need(sha(p)==data['sha256'],'Published observation identity differs: '+data['id'])
  d=read(p);rows=d.get('jobs',d.get('records'));need(len(rows)==data['jobs'],'Published task count differs')
  input_files.append(dict(id=data['id'],path=data['path'],sha256=sha(p),jobs=len(rows)))
  for ordinal,r in enumerate(rows):
   digest=r['binary_sha256'];need(digest in images,'Required measured library is absent from image inventory: '+digest)
   experiment=r.get('experiment',r.get('study',data['id']))
   task=dict(ordinal=len(tasks),dataset=data['id'],source_record=ordinal,experiment=experiment,configuration=r['configuration'],
    library=images[digest],parameter=r['parameter'],operation=r['operation'],workspace_bytes=r['workspace_bytes'],seed=r['seed'],
    samples=r.get('requested_samples',r.get('samples',(r.get('workload') or {}).get('samples'))),
    cpu=r.get('cpu_logical',(r.get('workload') or {}).get('cpu_logical',2)),
    timeout_seconds=lock['timeouts_seconds'][experiment],
    controller=lock['controller_versions'].get(experiment),
    driver='footprint' if experiment=='process_footprint' else 'pmu' if data['id']=='complete_operation_pmu' else 'workload')
   if 'memory_max_bytes' in r:task.update(memory_max_bytes=r['memory_max_bytes'],cpu_max=r['cpu_max'],file_cache_policy=r['file_cache_policy'])
   need(task['parameter'] in (512,768,1024,44,65,87) and task['operation'] in range(3),'Unsupported public operation')
   need(type(task['samples'])is int and 1<=task['samples']<=100000 and task['seed']>0,'Invalid fixed input count')
   tasks.append(task)
 # Preserve all original dataset and within-study orders; each published
 # experiment fits the original controller's own finite task-count bound.
 batches=[]
 for experiment in dict.fromkeys(t['experiment'] for t in tasks):
  selected=[t['ordinal'] for t in tasks if t['experiment']==experiment]
  need(len(selected)<= (100 if experiment in ('configurations','mechanisms') else 1000),'Controller task bound exceeded')
  batches.append(dict(id=experiment,task_ordinals=selected,jobs=len(selected),maximum_seconds=sum(tasks[i]['timeout_seconds'] for i in selected)))
 result=dict(schema='lattice.system-replay-tasks.v1',source_lock_sha256=sha(HERE/'source_lock.xml'),
  image_inventory_sha256=sha(bundle/'image_inventory.xml'),inputs=input_files,tasks=tasks,batches=batches,
  collection_enabled=False,events=lock['events'])
 return result
def prepare(a):
 result=construct(a.bundle.resolve(),{p.parent.name:p.resolve() for p in a.observations})
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);put(out/'tasks.xml',result)
 print(json.dumps(dict(status='PREPARED',jobs=len(result['tasks']),batches=[(b['id'],b['jobs']) for b in result['batches']],tasks_sha256=sha(out/'tasks.xml'))))
def validate_tasks(tasks,bundle):
 need(tasks==construct(Path(bundle).resolve(),{}),'Fixed task table differs from published scientific inputs')
 return True
def build(a):
 lock=sources();need(platform.system()=='Linux' and platform.machine() in ('aarch64','arm64'),'Native Linux AArch64 collector build required')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);records=[]
 for recipe in lock['recipes']:
  target=out/recipe['output'];cmd=[a.cc,*recipe['flags'],str(HERE/recipe['source']),*recipe['link_flags'],'-o',str(target)]
  p=subprocess.run(cmd,capture_output=True,text=True);(out/(recipe['id']+'.log')).write_text(json.capture_text(p.stdout+p.stderr))
  need(p.returncode==0,'Collector build failed: '+recipe['id'])
  records.append(dict(id=recipe['id'],file=target.name,sha256=sha(target),original_sha256=recipe['measured_binary_sha256'],
   command=cmd,exit_code=p.returncode))
 put(out/'build.xml',dict(schema='lattice.system-collector-build.v1',source_lock_sha256=sha(HERE/'source_lock.xml'),
  platform=platform.machine(),compiler=subprocess.check_output([a.cc,'--version'],text=True).splitlines()[0],records=records))
 print(json.dumps(dict(status='BUILT',collectors=len(records))))
def bound(a):
 need(platform.system()=='Linux' and platform.machine() in ('aarch64','arm64'),'Native Linux AArch64 execution required')
 lock=sources();tasks=read(a.tasks);need(tasks['source_lock_sha256']==sha(HERE/'source_lock.xml'),'Task/source binding differs')
 validate_tasks(tasks,a.bundle)
 built=read(a.build/'build.xml');need(built['source_lock_sha256']==tasks['source_lock_sha256'],'Build/source binding differs')
 images=libraries(a.bundle.resolve());artifacts=[];drivers={}
 for row in built['records']:
  p=(a.build/row['file']).resolve();need(sha(p)==row['sha256'],'Collector binary differs');drivers[row['id']]=str(p);artifacts.append(dict(path=str(p),sha256=row['sha256']))
 for task in tasks['tasks']:
  need(images.get(task['library']['sha256'])==task['library'],'Library locator differs')
  p=(a.bundle/task['library']['path']).resolve();artifacts.append(dict(path=str(p),sha256=task['library']['sha256']))
 return lock,tasks,drivers,list({r['path']:r for r in artifacts}.values())
def run(a):
 lock,tasks,drivers,artifacts=bound(a);batch=next((b for b in tasks['batches'] if b['id']==a.batch),None);need(batch is not None,'Explicit registered batch required')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);selected=[tasks['tasks'][i] for i in batch['task_ordinals']]
 cpu={t['cpu'] for t in selected};timeout={t['timeout_seconds'] for t in selected};need(len(cpu)==len(timeout)==1,'Batch condition split required')
 need(a.uid>=0 and a.gid>=0,'Explicit invoking uid/gid required')
 jobs=[]
 for t in selected:
  j=dict(id='j'+str(t['source_record']).zfill(4),library=str((a.bundle/t['library']['path']).resolve()),
   parameter=t['parameter'],operation=t['operation'],samples=t['samples'],workspace_bytes=t['workspace_bytes'],seed=t['seed'])
  for k in ('memory_max_bytes','cpu_max','file_cache_policy'):
   if k in t:j[k]=t[k]
  jobs.append(j)
 first=selected[0];plan=dict(run_id='a127-r3-replay-'+sha(a.tasks)[:10]+'-'+a.batch.replace('_','-'),uid=a.uid,gid=a.gid,
  cpu=next(iter(cpu)),job_timeout_seconds=next(iter(timeout)),artifacts=artifacts,jobs=jobs,workload=drivers[first['driver']],
  launcher=drivers['launcher'],events=lock['events'])
 put(out/'local-plan.xml',plan)
 if first['controller']:
  if first['driver']=='workload':need(os.geteuid()==0,'cgroup replay requires a locally authorized administrator')
  subprocess.run([sys.executable,'-B',str(HERE/first['controller']),'--plan',str(out/'local-plan.xml'),'--output',str(out/'observations')],check=True)
 else:
  records=[]
  for j in jobs:
   csv=out/(j['id']+'.csv');cmd=[plan['workload'],j['library'],str(j['parameter']),str(j['operation']),str(j['samples']),str(j['workspace_bytes']),str(plan['cpu']),str(j['seed']),str(csv)]
   try:
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=plan['job_timeout_seconds']);stdout,stderr,code,timed_out=p.stdout,p.stderr,p.returncode,False
   except subprocess.TimeoutExpired as e:
    stdout,stderr,code,timed_out=e.stdout or '',e.stderr or '',-9,True
    if isinstance(stdout,bytes):stdout=stdout.decode('utf-8',errors='replace')
    if isinstance(stderr,bytes):stderr=stderr.decode('utf-8',errors='replace')
   (out/(j['id']+'.stdout')).write_text(json.capture_text(stdout));(out/(j['id']+'.stderr')).write_text(stderr)
   records.append(dict(job=j,exit_code=code,timed_out=timed_out,stdout_sha256=sha(out/(j['id']+'.stdout')),stderr_sha256=sha(out/(j['id']+'.stderr')),raw_sha256=sha(csv) if csv.exists() else None))
   put(out/'results.xml',records)
 print(json.dumps(dict(status='COLLECTED',batch=a.batch,jobs=len(jobs))))
def smoke(a):
 lock,tasks,drivers,artifacts=bound(a);out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 # A fresh, explicitly functional run: two calls for each complete operation.
 # The fixed scientific task table stays unchanged.
 records=[];seen=set()
 for t in tasks['tasks']:
  key=(t['parameter'],t['operation'])
  if key in seen:continue
  seen.add(key);csv=out/f'{key[0]}-{key[1]}.csv';cmd=[drivers['workload'],str((a.bundle/t['library']['path']).resolve()),str(key[0]),str(key[1]),'2',str(t['workspace_bytes']),str(t['cpu']),str(t['seed']),str(csv)]
  p=subprocess.run(cmd,capture_output=True,text=True,timeout=30);need(p.returncode==0,'Functional collector failed')
  result=json.loads(p.stdout);need(result['status']=='PASS' and result['samples']==2,'Incomplete functional collector')
  records.append(dict(parameter=key[0],operation=key[1],metadata=result,raw_sha256=sha(csv)))
 need(len(records)==18,'Incomplete functional matrix')
 first=tasks['tasks'][0];library=str((a.bundle/first['library']['path']).resolve())
 csv=out/'footprint.csv';cmd=[drivers['footprint'],library,str(first['parameter']),str(first['operation']),'2',str(first['workspace_bytes']),str(first['cpu']),str(first['seed']),str(csv)]
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=30);need(p.returncode==0,'Footprint functional check failed')
 footprint=[json.loads(line) for line in p.stdout.splitlines()];need(len(footprint)==2 and footprint[1]['status']=='MM_FOOTPRINT','Missing footprint fields')
 put(out/'functional.xml',dict(status='PASS',formal_measurement=False,records=records,footprint=footprint,build_sha256=sha(a.build/'build.xml')))
 print(json.dumps(dict(status='PASS',complete_operations=18,samples_per_operation=2)))
def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
 q=sub.add_parser('prepare');q.add_argument('--bundle',type=Path,required=True);q.add_argument('--observations',type=Path,nargs='*',default=[]);q.add_argument('--output',type=Path,required=True)
 q=sub.add_parser('build');q.add_argument('--cc',default='gcc');q.add_argument('--output',type=Path,required=True)
 for action in ('run','smoke'):
  q=sub.add_parser(action);q.add_argument('--bundle',type=Path,required=True);q.add_argument('--tasks',type=Path,required=True);q.add_argument('--build',type=Path,required=True);q.add_argument('--output',type=Path,required=True)
  if action=='run':q.add_argument('--batch',required=True);q.add_argument('--uid',type=int,required=True);q.add_argument('--gid',type=int,required=True)
 a=p.parse_args();globals()[a.action](a)
if __name__=='__main__':main()
