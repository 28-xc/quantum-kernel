"""Execute a frozen randomized block schedule with a preverified driver.

Every configuration in a block receives the same public test transcript.
All measured rows, including slow rows, are retained. Replicates are blocks.
The manifest is written before the first timing and cannot be overwritten.
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
import argparse, datetime, hashlib, record_io as json, os, platform, random, statistics, subprocess, time
from run import validate_csv

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,x):
 q=p.with_suffix(p.suffix+'.tmp');q.write_text(json.dumps(x,indent=2)+'\n',encoding='utf-8')
 # Windows readers can temporarily deny delete sharing. Only the metadata
 # replacement is retried, after the timed driver has returned. A persistent
 # error still fails the collection and preserves the old target and temp file.
 for attempt in range(20):
  try:
   q.replace(p)
   return
  except PermissionError:
   if attempt==19:raise
   time.sleep(0.05)

def validate_identity(result,cfg,variant,item):
 expected=dict(status='PASS',cpu=cfg['cpu'],samples=cfg['samples'],warmups=cfg['warmups'],backend=variant['provider'],import_pct=variant['pct'],
  parameter=item['parameter'],operation=item['operation'],seed=item['seed'],mode='measure',message_bytes=cfg['message_bytes'],context_bytes=cfg['context_bytes'],
  workspace_reserved=variant['workspace'],openssl_key_reused_across_batch=item['operation']>0,entropy_mode='supplied_test_entropy',provider='default',message_encoding=1,mu=0)
 if any(result.get(k)!=value for k,value in expected.items()):raise ValueError('Driver result differs from complete scheduled identity')

def execute_driver(cmd,env,log,err,timeout=300):
 try:r=subprocess.run(cmd,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
 except subprocess.TimeoutExpired as e:
  for path,value in [(log,e.stdout),(err,e.stderr)]:
   path.write_bytes(value if isinstance(value,bytes) else (value or '').encode('utf-8'))
  raise
 log.write_text(json.capture_text(r.stdout),encoding='utf-8');err.write_text(r.stderr,encoding='utf-8');return r

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--configuration',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--blocks-per-invocation',type=int,default=50,help='Stop only after this many complete blocks; resume the same frozen study explicitly.')
 p.add_argument('--resume',action='store_true')
 a=p.parse_args();cfg=json.loads(a.configuration.read_text(encoding='utf-8'));out=a.output.resolve()
 if not 1<=a.blocks_per_invocation<=50:raise ValueError('Invalid invocation block bound')
 if out.exists()!=a.resume:raise ValueError('Fresh output required, or explicit resume at a verified block boundary')
 if os.name=='nt' and out.drive.upper()!='D:':raise ValueError('Windows output must stay on D:')
 required={'driver','crypto_library','cpu','blocks','samples','warmups','seed','configurations','study_role','message_bytes','context_bytes'}
 if set(cfg)!=required or cfg['study_role'] not in ('development','confirmation'):raise ValueError('Unexpected configuration fields')
 if not 2<=cfg['blocks']<=50 or not 10<=cfg['samples']<=10000 or not 0<=cfg['warmups']<=1000 or not 0<cfg['seed']<2**63:raise ValueError('Invalid study size')
 variants=cfg['configurations'];labels=[v['label'] for v in variants]
 if len(labels)!=len(set(labels)) or not 2<=len(labels)<=30:raise ValueError('Unique configuration labels required')
 files={};driver=Path(cfg['driver']).resolve();crypto=Path(cfg['crypto_library']).resolve()
 for path in [driver,crypto,*[Path(v['library']).resolve() for v in variants]]:
  if not path.is_file():raise ValueError('Missing explicit binary '+str(path))
  files[str(path)]=sha(path)
 for v in variants:
  if set(v)!={'label','library','provider','pct','workspace'} or v['provider'] not in ('lattice','openssl') or v['pct'] not in ('none','random'):raise ValueError('Invalid variant')
  if not v['label'] or not all(c.isalnum() or c in '-_' for c in v['label']):raise ValueError('Invalid label')
  if not 32<=v['workspace']<=262144:raise ValueError('Invalid arena capacity')
 rng=random.Random(cfg['seed']);schedule=[]
 for b in range(cfg['blocks']):
  cells=[(parameter,op) for parameter in [512,768,1024,44,65,87] for op in range(3)];rng.shuffle(cells)
  for parameter,op in cells:
   order=list(range(len(variants)));rng.shuffle(order)
   seed=1+int.from_bytes(hashlib.sha256(f'{cfg["seed"]}/{b}/{parameter}/{op}'.encode()).digest()[:8],'big')%(2**63-1)
   for vi in order:schedule.append(dict(block=b,parameter=parameter,operation=op,variant=vi,seed=seed))
 manifest=dict(schema='latticecore.blocked.v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
  configuration=cfg,binary_sha256=files,runner_sha256=sha(Path(__file__)),validator_sha256=sha(Path(__file__).with_name('run.py')),configuration_sha256=sha(a.configuration),
  host=platform.platform(),machine=platform.machine(),schedule=schedule,replication_unit='randomized complete block',
  timing_environment='exclusive host measurement window; explicit one-core affinity; supplied test entropy',
  measured_boundary='OpenSSL retains an imported key across the batch and creates an operation context per call; latticecore uses its serialized-key API per call; key generation includes encoding for both',
  statistical_rule='retain every row; summarize within blocks; resample complete blocks for paired intervals')
 records=[];paired={};previous_elapsed=0.0
 if a.resume:
  if (out/'result.xml').exists() or (out/'failure.xml').exists():raise ValueError('Completed or failed study cannot be resumed')
  old=json.loads((out/'manifest.xml').read_text(encoding='utf-8'))
  if any(old[k]!=v for k,v in manifest.items() if k!='created_utc'):raise ValueError('Frozen study identity changed')
  checkpoint=json.loads((out/'checkpoint.xml').read_text(encoding='utf-8'))
  if checkpoint.get('status')!='COMPLETE_BLOCK_BOUNDARY' or checkpoint['manifest_sha256']!=sha(out/'manifest.xml') or checkpoint['commands_sha256']!=sha(out/'commands.xml'):raise ValueError('Invalid checkpoint identity')
  records=json.loads((out/'commands.xml').read_text(encoding='utf-8'));previous_elapsed=checkpoint['elapsed_seconds']
  if not records or len(records)>=len(schedule) or len(records)%(18*len(variants)) or checkpoint['completed']!=len(records):raise ValueError('Incomplete block checkpoint')
  journal=list(json.read_records(out/'completed_calls.records.xml'))
  if journal!=records:raise ValueError('Checkpoint journal differs from completed records')
  expected_paths=set()
  for rec,planned in zip(records,schedule,strict=False):
   if any(rec[k]!=planned[k] for k in planned) or rec['exit_code']!=0:raise ValueError('Invalid completed schedule prefix')
   for field,digest in [('raw_csv','raw_sha256'),('log','log_sha256'),('stderr','stderr_sha256')]:
    file=(out/rec[field]).resolve()
    if not file.is_relative_to(out) or sha(file)!=rec[digest]:raise ValueError('Modified checkpoint evidence')
    expected_paths.add(file)
   result=json.loads((out/rec['log']).read_text(encoding='utf-8'));validate_identity(result,cfg,variants[planned['variant']],planned);validate_csv(out/rec['raw_csv'],result)
   key=(rec['block'],rec['parameter'],rec['operation']);identity=(result['input_sequence_sha256'],result['output_sequence_sha256'])
   if key in paired and paired[key]!=identity:raise ValueError('Different transcripts in checkpoint')
   paired[key]=identity
  if {x.resolve() for x in (out/'raw').iterdir()}!=expected_paths:raise ValueError('Unrecorded raw files; preserve and inspect this interrupted study')
 else:
  out.mkdir(parents=True);(out/'raw').mkdir();dump(out/'manifest.xml',manifest)
 manifest_sha=sha(out/'manifest.xml')
 env=os.environ.copy()
 if os.name=='nt':env['PATH']=str(crypto.parent)+os.pathsep+env.get('PATH','')
 else:env['LD_LIBRARY_PATH']=str(crypto.parent)+os.pathsep+env.get('LD_LIBRARY_PATH','')
 started=time.monotonic();first=len(records);limit=min(len(schedule),first+a.blocks_per_invocation*18*len(variants));attempt=None
 try:
  for ordinal in range(first,limit):
   item=schedule[ordinal]
   v=variants[item['variant']];label=f"{ordinal:05d}-b{item['block']:02d}-{item['parameter']}-{item['operation']}-{v['label']}"
   raw=out/'raw'/(label+'.csv');log=out/'raw'/(label+'.xml');err=out/'raw'/(label+'.stderr.txt')
   cmd=[str(driver),str(Path(v['library']).resolve()),v['provider'],str(item['parameter']),str(item['operation']),str(cfg['samples']),str(item['seed']),str(raw),str(v['workspace']),str(cfg['message_bytes']),str(cfg['context_bytes']),v['pct'],str(cfg['cpu']),'measure',str(cfg['warmups']),'3.6.4']
   attempt=dict(ordinal=ordinal,planned=item,label=v['label'],command=cmd,started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),timeout_seconds=300,raw_csv=raw.relative_to(out).as_posix(),log=log.relative_to(out).as_posix(),stderr=err.relative_to(out).as_posix())
   dump(out/'attempt.xml',attempt);t=time.monotonic();r=execute_driver(cmd,env,log,err)
   rec=dict(**item,label=v['label'],command=cmd,exit_code=r.returncode,wall_seconds=time.monotonic()-t,raw_csv=raw.relative_to(out).as_posix(),log=log.relative_to(out).as_posix(),stderr=err.relative_to(out).as_posix())
   records.append(rec)
   if r.returncode:raise RuntimeError('Driver failed: '+label)
   result=json.loads(r.stdout)
   validate_identity(result,cfg,v,item)
   loaded=Path(result['openssl_library']).resolve()
   if not loaded.samefile(crypto) or sha(loaded)!=files[str(crypto)]:raise ValueError('Unexpected OpenSSL library')
   rows=validate_csv(raw,result);key=(item['block'],item['parameter'],item['operation'])
   identity=(result['input_sequence_sha256'],result['output_sequence_sha256'])
   if key in paired and paired[key]!=identity:raise ValueError('Different input/output sequences within matched block')
   paired[key]=identity
   values=[float(row['elapsed_ns']) for row in rows if row['warmup']=='0']
   rec.update(raw_sha256=sha(raw),log_sha256=sha(log),stderr_sha256=sha(err),mean_ns=statistics.mean(values),median_ns=statistics.median(values),min_ns=min(values),max_ns=max(values),input_sequence_sha256=identity[0],output_sequence_sha256=identity[1])
   json.append_record(out/'completed_calls.records.xml',rec)
   dump(out/'progress.xml',dict(completed=len(records),planned=len(schedule),latest=label,elapsed_seconds=previous_elapsed+time.monotonic()-started))
  for path,digest in files.items():
   if sha(Path(path))!=digest:raise ValueError('Binary changed during measurement')
  if sha(out/'manifest.xml')!=manifest_sha:raise ValueError('Schedule changed')
  dump(out/'commands.xml',records)
  elapsed=previous_elapsed+time.monotonic()-started
  if len(records)<len(schedule):
   dump(out/'checkpoint.xml',dict(status='COMPLETE_BLOCK_BOUNDARY',manifest_sha256=manifest_sha,commands_sha256=sha(out/'commands.xml'),completed=len(records),completed_blocks=len(records)//(18*len(variants)),elapsed_seconds=elapsed))
   print(json.dumps(dict(status='COMPLETE_BLOCK_BOUNDARY',completed_blocks=len(records)//(18*len(variants)),total_blocks=cfg['blocks'])))
  else:
   dump(out/'result.xml',dict(status='PASS',manifest_sha256=manifest_sha,commands_sha256=sha(out/'commands.xml'),journal_sha256=sha(out/'completed_calls.records.xml'),completed=len(records),blocks=cfg['blocks'],operation_cells=18,configurations=labels,raw_rows=len(records)*(cfg['samples']+cfg['warmups']),trimmed_rows=0,elapsed_seconds=elapsed))
 except Exception as e:
  dump(out/'commands.xml',records)
  dump(out/'failure.xml',dict(error=str(e),exception_type=type(e).__name__,attempt=attempt,completed=len(records),planned=len(schedule),elapsed_seconds=previous_elapsed+time.monotonic()-started));raise

if __name__=='__main__':main()
