"""Validate complete-operation acquisition and publish byte-exact CSV shards.

The acquisition archive and local identity audit remain separate from the
portable scientific observations. This command executes no binaries.
"""
from pathlib import Path, PurePosixPath
import sys
# The legacy tools/statistics.py is a separate analysis entry point. Exclude
# this script directory before resolving the standard-library module.
TOOL_DIRECTORY=Path(__file__).resolve().parent
sys.path[:]=[p for p in sys.path if Path(p or '.').resolve()!=TOOL_DIRECTORY]
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
import argparse, csv, hashlib, record_io as json, math, os, random, re, shutil, statistics, uuid
from decimal import Decimal
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from publicschemas import pooled_block_model as model, pooled_shards as shards
from publicschemas.pooled_conditions import validate_success_log

MANIFEST_FIELDS=set('schema created_utc configuration binary_sha256 runner_sha256 validator_sha256 configuration_sha256 prepared_sha256 host machine schedule replication_unit timing_environment measured_boundary statistical_rule'.split())
CONFIG_FIELDS=set('driver crypto_library cpu blocks samples warmups seed configurations boundary expected_version prepared message_bytes context_bytes'.split())
RECORD_FIELDS=set('block parameter operation variant seed label command exit_code wall_seconds raw_csv log stderr raw_sha256 log_sha256 stderr_sha256 mean_ns median_ns min_ns max_ns input_sequence_sha256 output_sequence_sha256'.split())
RESULT_FIELDS=set('status manifest_sha256 commands_sha256 journal_sha256 completed blocks operation_cells configurations raw_rows trimmed_rows elapsed_seconds'.split())
LOG_FIELDS=set('status backend parameter operation samples warmups raw_rows mode cpu timer frequency seed message_bytes context_bytes workspace_reserved workspace_observed_test_highwater input_sequence_sha256 output_sequence_sha256 openssl_library import_pct entropy_mode'.split())|model.IMPLEMENTATION_FIELDS
BOUNDARIES={'serialized':('fresh serialized-key service including preparation, operation, encoding and per-call cleanup','fresh_serialized_key_service'),
 'reused':('OpenSSL retains an imported key across the batch and creates an operation context per call; latticecore uses serialized keys per call; key generation includes encoding for both','openssl_retained_key_lattice_serialized_key_service')}
CELLS=[(p,o) for p in (512,768,1024,44,65,87) for o in range(3)]
need=model.need

def unique(items):
 out={}
 for k,v in items:need(k not in out,'Duplicate JSON field: '+k);out[k]=v
 return out
def constant(x):raise ValueError('Nonfinite JSON value: '+x)
def loads(text):return json.loads(text,object_pairs_hook=unique,parse_constant=constant)
def read(path):return loads(Path(path).read_text(encoding='utf-8'))
def sha(path):return shards.sha(path)
def describe(path):return dict(path=str(Path(path).resolve()),sha256=sha(path))
def write(path,value):
 with Path(path).open('x',encoding='utf-8') as f:json.dump(value,f,indent=2,ensure_ascii=False,allow_nan=False);f.write('\n')
PATH_MAP=[]
def located(value):
 text=str(value).replace('\\','/')
 for old,new in PATH_MAP:
  if text==old or text.startswith(old+'/'):
   return (new/text[len(old):].lstrip('/')).resolve()
 return Path(value).resolve()
def configure_path_map(entries):
 global PATH_MAP
 result=[]
 for item in entries:
  old,new=item.split('=',1);old=old.replace('\\','/').rstrip('/')
  need(old and new,'Empty path mapping');result.append((old,Path(new).resolve()))
 need(len({x[0] for x in result})==len(result),'Duplicate path map prefix')
 PATH_MAP=sorted(result,key=lambda x:len(x[0]),reverse=True)
def artifact(path,digest):
 p=located(path);model.digest(digest);need(p.is_file() and sha(p)==digest,'Missing or changed artifact: '+str(p));return p
def relative_file(root,value):
 need(type(value) is str and value and '\\' not in value,'Relative POSIX artifact path required')
 q=PurePosixPath(value);need(not q.is_absolute() and '..' not in q.parts and ':' not in value and q.as_posix()==value,'Unsafe archive path')
 p=(root/q).resolve();need(p.is_relative_to(root) and p.is_file(),'Missing or escaping archive artifact');return p
def token(value):model.token(value);return value
def path_equal(a,b):return located(a)==located(b)

def validate_csv(path,log):
 """Retain original text and independently check its integer clock conversion."""
 ticks=[];values=[];digest=hashlib.sha256();count=0
 with Path(path).open(newline='',encoding='utf-8') as f:
  reader=csv.DictReader(f);need(reader.fieldnames==shards.CSV_FIELDS,'Changed CSV columns')
  for i,r in enumerate(reader):
   need(None not in r and all(v is not None for v in r.values()),'Malformed CSV row')
   need(r['case_id']==f"{log['seed']:016x}-{log['parameter']}-{log['operation']}-{i}",'Changed sample identity/order')
   need(r['warmup']==str(int(i<log['warmups'])) and r['iteration']==str(i-log['warmups']) and r['status']=='0','Failed or reordered sample')
   for k in ('entropy_sha256','message_sha256','context_sha256'):model.digest(r[k]);digest.update(r[k].encode())
   digest.update(r['case_id'].encode())
   if log['mode']=='measure':
    need(re.fullmatch(r'[0-9]+',r['elapsed_ticks']) and re.fullmatch(r'[0-9]+',r['tick_frequency']),'Invalid integer clock')
    t,freq=int(r['elapsed_ticks']),int(r['tick_frequency']);need(freq==log['frequency'] and freq>0,'Changed clock frequency')
    need(re.fullmatch(r'[0-9]+\.[0-9]{3}',r['elapsed_ns']),'Changed elapsed-time representation')
    ns=Decimal(r['elapsed_ns']);need(abs(ns*freq-Decimal(t)*10**9)<=Decimal('0.0005')*freq,'Incorrect clock conversion')
    if i>=log['warmups']:ticks.append(t);values.append(float(ns))
   else:need(log['mode']=='verify' and all(r[k]=='' for k in ('elapsed_ticks','tick_frequency','elapsed_ns')),'Verification unexpectedly timed')
   count+=1
 need(count==log['raw_rows']==log['samples']+log['warmups'],'Incomplete raw sample count')
 return dict(rows=count,input_rows_sha256=digest.hexdigest(),values=values,integer_tick_sum=sum(ticks))

def acquisition_cells(manifest):
 """Validate either complete-operation acquisition format before projection."""
 model.keys(manifest,MANIFEST_FIELDS)
 schema=manifest['schema']
 need(schema in ('latticecore.blocked.v1','private.latticecore.operation_subset.v1'),'Unknown acquisition schema')
 cfg=manifest['configuration']
 model.keys(cfg,CONFIG_FIELDS|({'cells'} if schema=='private.latticecore.operation_subset.v1' else set()))
 if schema=='latticecore.blocked.v1':return CELLS.copy()
 cells=cfg['cells']
 need(type(cells) is list and len(cells)==len(CELLS),'Complete 18 operation cells required')
 need(all(type(row) is list and len(row)==2 and all(type(x) is int for x in row) for row in cells),'Invalid explicit operation cell')
 order=[tuple(row) for row in cells]
 need(len(set(order))==len(CELLS) and set(order)==set(CELLS),'Missing, duplicate or unknown operation cell')
 return order

def verify_acquisition_sources(manifest,source_ids,bindings,collector_source=None,validator_source=None):
 prefix='source_snapshot/bench/complete_operations/'
 need(source_ids.get(prefix+'common.py')==manifest['validator_sha256'],'Prepared validator source differs')
 if manifest['schema']=='latticecore.blocked.v1':
  need(collector_source is None and validator_source is None,'External acquisition sources apply only to the explicit-cell format')
  need(source_ids.get(prefix+'collect.py')==manifest['runner_sha256'],'Prepared collector source differs')
 else:
  need(collector_source is not None and validator_source is not None,'Explicit collector and validator source files required')
  need(prefix+'collect.py' in source_ids,'Missing prepared collector source')
  for path,key in ((collector_source,'runner_sha256'),(validator_source,'validator_sha256')):
   p=artifact(path,manifest[key]);bindings.append(describe(p))

def verify_prepared(cfg,manifest,bindings,collector_source=None,validator_source=None):
 path=artifact(cfg['prepared'],manifest['prepared_sha256']);prep=read(path)
 model.keys(prep,'schema status boundary expected_version driver crypto_library library compiler sources verified_operation_cells all_input_output_sequences_match verification timing_collected commands_sha256'.split())
 need(prep['schema']=='lattice.complete_operation_driver.v1' and prep['status']=='PASS','Unqualified driver preparation')
 need(prep['boundary']==cfg['boundary'] and prep['expected_version']==cfg['expected_version'],'Prepared boundary/version changed')
 need(prep['verified_operation_cells']==18 and prep['all_input_output_sequences_match'] is True and prep['timing_collected'] is False,'Incomplete driver preparation')
 bindings.append(describe(path))
 for name in ('driver','crypto_library','library'):
  model.keys(prep[name],['path','sha256']);p=artifact(prep[name]['path'],prep[name]['sha256']);bindings.append(describe(p))
  if name!='library':need(path_equal(p,cfg[name]),'Different prepared binary')
 source_ids={}
 for item in prep['sources']:
  model.keys(item,['path','sha256']);p=relative_file(path.parent,item['path']);artifact(p,item['sha256']);bindings.append(describe(p));need(item['path'] not in source_ids,'Duplicate prepared source');source_ids[item['path']]=item['sha256']
 verify_acquisition_sources(manifest,source_ids,bindings,collector_source,validator_source)
 pc=artifact(path.parent/'commands.xml',prep['commands_sha256']);bindings.append(describe(pc))
 need(type(read(pc)) is list and all(c.get('exit_code')==0 for c in read(pc)),'Preparation command failure')
 verified=set()
 for row in prep['verification']:
  model.keys(row,['parameter','operation','pct','raw','raw_sha256','summary']);model.parameter(row['parameter'],row['operation'])
  identity=(row['parameter'],row['operation'],row['pct']);need(identity not in verified,'Duplicate preparation cell');verified.add(identity)
  p=relative_file(path.parent,row['raw']);artifact(p,row['raw_sha256']);bindings.append(describe(p))
  s=row['summary'];need(s['status']=='PASS' and s['mode']=='verify' and s['backend']=='compare','Driver functional verification failed')
  need((s['parameter'],s['operation'],s['import_pct'])==identity,'Prepared verification identity changed');validate_csv(p,s)
 need({(p,o) for p,o,_ in verified}==set(CELLS),'Missing prepared operation cell')

def project(root,configuration,labels,dataset_id,platform_id,output,audit,collector_source=None,validator_source=None):
 root=Path(root).resolve();out=Path(output).resolve();audit=Path(audit).resolve();token(dataset_id)
 need(not out.exists() and not audit.exists(),'Fresh output and audit paths required')
 need(not out.is_relative_to(root) and not audit.is_relative_to(out),'Separate acquisition, public output and local audit required')
 need(out!=root and audit!=root,'Distinct output paths required')
 for name in ('failure.xml','checkpoint.xml'):need(not (root/name).exists(),'Incomplete or failed acquisition; keep its original records')
 m=read(root/'manifest.xml');acquisition_order=acquisition_cells(m)
 c=m['configuration'];need(c==read(configuration),'Configuration differs from manifest');artifact(configuration,m['configuration_sha256'])
 need(c['boundary'] in BOUNDARIES and c['expected_version'] in ('3.6.0','3.6.4'),'Unknown operation boundary/version')
 need(m['measured_boundary']==BOUNDARIES[c['boundary']][0] and m['replication_unit']=='randomized complete block','Changed measurement boundary')
 need(m['statistical_rule']=='retain every row; summarize within blocks; resample complete blocks for paired intervals','Changed acquisition rule')
 for key,lo,hi in [('blocks',2,50),('samples',10,10000),('warmups',0,1000),('seed',1,2**63-1),('message_bytes',0,16384),('context_bytes',0,255),('cpu',0,2**20)]:need(type(c[key]) is int and lo<=c[key]<=hi,'Invalid configuration integer: '+key)
 machine=m['machine'];need(platform_id in ('windows_x86_64','linux_aarch64'),'Unknown platform')
 need((platform_id=='windows_x86_64' and machine in ('AMD64','amd64','x86_64') and m['host'].startswith('Windows-')) or (platform_id=='linux_aarch64' and machine in ('aarch64','arm64','ARM64') and m['host'].startswith('Linux-')),'Platform/machine mismatch')
 variants=c['configurations'];need(type(variants) is list and 2<=len(variants)<=30,'Invalid configuration count')
 source_labels=[]
 for v in variants:
  model.keys(v,['label','library','provider','pct','workspace']);token(v['label']);source_labels.append(v['label'])
  need(v['provider'] in ('lattice','openssl') and v['pct'] in ('none','random') and type(v['workspace']) is int and 32<=v['workspace']<=262144,'Invalid provider configuration')
 need(len(set(source_labels))==len(variants),'Duplicate acquisition labels')
 need(type(labels) is dict and set(labels)==set(source_labels),'Explicit one-to-one labels required for every input configuration')
 for v in labels.values():token(v)
 need(len(set(labels.values()))==len(labels),'Duplicate public labels')
 expected_files={located(c[k]) for k in ('driver','crypto_library')}|{located(v['library']) for v in variants}
 need(type(m['binary_sha256']) is dict and len(m['binary_sha256'])==len(expected_files),'Duplicate/missing binary identity')
 binary={};bindings=[]
 for path,digest in m['binary_sha256'].items():
  p=artifact(path,digest);need(p not in binary,'Ambiguous binary path');binary[p]=digest;bindings.append(describe(p))
 need(set(binary)==expected_files,'Unexpected binary identity set');verify_prepared(c,m,bindings,collector_source,validator_source)
 rng=random.Random(c['seed']);schedule=[]
 for block in range(c['blocks']):
  cells=acquisition_order.copy();rng.shuffle(cells)
  for p,o in cells:
   order=list(range(len(variants)));rng.shuffle(order);seed=1+int.from_bytes(hashlib.sha256(f'{c["seed"]}/{block}/{p}/{o}'.encode()).digest()[:8],'big')%(2**63-1)
   schedule.extend(dict(block=block,parameter=p,operation=o,variant=i,seed=seed) for i in order)
 need(m['schedule']==schedule,'Changed randomized complete schedule')
 result=read(root/'result.xml');model.keys(result,RESULT_FIELDS)
 for name,field in [('manifest.xml','manifest_sha256'),('commands.xml','commands_sha256'),('completed_calls.records.xml','journal_sha256')]:artifact(root/name,result[field])
 records=read(root/'commands.xml');journal=list(json.read_records(root/'completed_calls.records.xml'))
 need(type(records) is list and records==journal and len(records)==len(schedule),'Incomplete or changed command journal')
 expected=dict(status='PASS',completed=len(schedule),blocks=c['blocks'],operation_cells=18,configurations=source_labels,raw_rows=len(schedule)*(c['samples']+c['warmups']),trimmed_rows=0)
 need(all(result[k]==v for k,v in expected.items()),'Changed or incomplete completion');model.number(result['elapsed_seconds'])
 configurations=[dict(id=labels[v['label']],provider=v['provider'],import_pct=v['pct'],workspace_reserved=v['workspace'],library_sha256=binary[located(c['crypto_library'] if v['provider']=='openssl' else v['library'])],supplied_lattice_library_sha256=binary[located(v['library'])]) for v in variants]
 data=dict(schema=shards.SCHEMA,dataset_id=dataset_id,platform=platform_id,execution='native',target_machine=machine,driver_sha256=binary[located(c['driver'])],crypto_library_sha256=binary[located(c['crypto_library'])],experiment=dict(blocks=c['blocks'],samples_per_run=c['samples'],warmups_per_run=c['warmups'],seed=c['seed'],message_bytes=c['message_bytes'],context_bytes=c['context_bytes'],cpu_index=c['cpu'],replication_unit='randomized_complete_block',timing_boundary=BOUNDARIES[c['boundary']][1]),configurations=configurations,schedule=[dict(ordinal=i,block=s['block'],parameter=s['parameter'],operation=s['operation'],configuration=configurations[s['variant']]['id'],seed=s['seed']) for i,s in enumerate(schedule)],runs=[],analysis=None,completeness={},sample_format=dict(type='csv',encoding='utf-8',columns=shards.CSV_FIELDS))
 stage=out.with_name(out.name+'.incomplete-'+uuid.uuid4().hex);stage.mkdir(parents=True);(stage/'raw').mkdir();paired={};trace=[];rawfiles=set();rawnames=set();frequencies=set();timers=set()
 for i,(rec,planned) in enumerate(zip(records,schedule,strict=True)):
  model.keys(rec,RECORD_FIELDS);v=variants[planned['variant']]
  need(all(rec[k]==val for k,val in planned.items()) and rec['label']==v['label'] and type(rec['exit_code']) is int and rec['exit_code']==0,'Failed process or changed run identity');model.number(rec['wall_seconds'])
  files={}
  for field,digest in [('raw_csv','raw_sha256'),('log','log_sha256'),('stderr','stderr_sha256')]:
   need(rec[field].startswith('raw/'),'Artifact outside raw directory');p=relative_file(root,rec[field]);artifact(p,rec[digest]);need(p not in rawfiles and rec[field] not in rawnames,'Reused acquisition artifact');rawfiles.add(p);rawnames.add(rec[field]);files[field]=p
  need(files['stderr'].stat().st_size==0,'Nonempty process diagnostic requires inspection')
  log=read(files['log']);need(type(log) is dict and set(log)<=LOG_FIELDS,'Unknown driver fields')
  expected=dict(status='PASS',backend=v['provider'],parameter=planned['parameter'],operation=planned['operation'],samples=c['samples'],warmups=c['warmups'],raw_rows=c['samples']+c['warmups'],mode='measure',cpu=c['cpu'],seed=planned['seed'],import_pct=v['pct'])
  need(all(type(log.get(k)) is type(val) and log[k]==val for k,val in expected.items()),'Driver identity changed')
  validate_success_log(log,c,v,data['experiment']['timing_boundary'])
  need(log.get('negative_checks') is True and log.get('pct_uses_extra_system_rng')==(v['provider']=='openssl' and v['pct']=='random'),'Changed safety/entropy boundary')
  need(path_equal(log['openssl_library'],c['crypto_library']) and log['openssl_version'].startswith('OpenSSL '+c['expected_version']+' '),'Changed loaded OpenSSL')
  need(type(log['workspace_observed_test_highwater']) is int and 0<=log['workspace_observed_test_highwater']<=v['workspace'],'Impossible observed workspace')
  need(log['timer'] in ('QueryPerformanceCounter','QueryPerformanceCounter; verified P-core') if platform_id=='windows_x86_64' else log['timer']=='CLOCK_MONOTONIC_RAW; explicit sched_setaffinity','Changed clock/platform')
  model.integer(log['frequency'],1);frequencies.add(log['frequency']);timers.add(log['timer'])
  for key in ('input_sequence_sha256','output_sequence_sha256'):model.digest(log[key]);need(rec[key]==log[key],'Changed transcript binding')
  command=[str(located(c['driver'])),str(located(v['library'])),v['provider'],str(planned['parameter']),str(planned['operation']),str(c['samples']),str(planned['seed']),str(files['raw_csv']),str(v['workspace']),str(c['message_bytes']),str(c['context_bytes']),v['pct'],str(c['cpu']),'measure',str(c['warmups']),c['expected_version']]
  actual_command=rec['command'].copy()
  for index in (0,1,7):actual_command[index]=str(located(actual_command[index]))
  need(actual_command==command,'Process command differs from frozen invocation')
  observed=validate_csv(files['raw_csv'],log);values=observed.pop('values')
  for key,val in dict(mean_ns=statistics.mean(values),median_ns=statistics.median(values),min_ns=min(values),max_ns=max(values)).items():need(rec[key]==val,'Recorded statistic differs from raw values')
  pair=(planned['block'],planned['parameter'],planned['operation']);identity=(log['input_sequence_sha256'],log['output_sequence_sha256'],observed['input_rows_sha256'])
  need(pair not in paired or paired[pair]==identity,'Unpaired actual input/output sequence');paired[pair]=identity
  relative=f'raw/{i:08d}.csv';dest=stage/relative;shutil.copyfile(files['raw_csv'],dest);artifact(dest,rec['raw_sha256'])
  meta={k:log[k] for k in log if k in model.IMPLEMENTATION_FIELDS and k!='openssl_cflags'}
  data['runs'].append(dict(ordinal=i,driver_exit_code=0,driver_status='PASS',source_csv_sha256=rec['raw_sha256'],source_log_sha256=rec['log_sha256'],source_stderr_sha256=rec['stderr_sha256'],input_sequence_sha256=log['input_sequence_sha256'],output_sequence_sha256=log['output_sequence_sha256'],timer=log['timer'],frequency=log['frequency'],workspace_highwater=log['workspace_observed_test_highwater'],entropy_mode=log['entropy_mode'],implementation_metadata=meta,sample_shard=dict(path=relative,sha256=rec['raw_sha256'],rows=observed['rows'])))
  trace.append(dict(ordinal=i,public_shard=relative,source_artifacts={k:describe(p) for k,p in files.items()},integer_tick_sum=observed['integer_tick_sum'],input_rows_sha256=observed['input_rows_sha256']))
 need(len(frequencies)==len(timers)==1 and len(paired)==c['blocks']*18,'Missing paired cells or inconsistent clock')
 entries=list((root/'raw').iterdir());need({p.relative_to(root).as_posix() for p in entries}==rawnames and all(p.is_file() for p in entries),'Unrecorded/missing raw acquisition files')
 data['completeness']=dict(planned_runs=len(schedule),recorded_runs=len(records),missing_runs=0,sample_rows=result['raw_rows'],failed_sample_rows=0,failed_runs=0,archive_status='COMPLETE')
 shards.validate_manifest(data)
 for item in bindings:artifact(item['path'],item['sha256'])
 for item in trace:
  for bound in item['source_artifacts'].values():artifact(bound['path'],bound['sha256'])
 for name,field in [('manifest.xml','manifest_sha256'),('commands.xml','commands_sha256'),('completed_calls.records.xml','journal_sha256')]:artifact(root/name,result[field])
 write(stage/'observations.xml',data);stage.rename(out)
 audit.parent.mkdir(parents=True,exist_ok=True)
 write(audit,dict(schema='complete_operation_import_audit.v1',source_archive=str(root),configuration=describe(configuration),source_manifest=describe(root/'manifest.xml'),source_completion=describe(root/'result.xml'),public_manifest=describe(out/'observations.xml'),label_mapping=labels,bindings=bindings,raw_mapping=trace,source_code=describe(__file__),recorded_runs=len(records),paired_cells=len(paired),rows_removed=0,rows_reformatted=False,compiler_text='Original hash-bound log retains compiler flags; public scientific metadata excludes build-path-bearing compiler text.'))
 return dict(schema=shards.SCHEMA,dataset_id=dataset_id,recorded_runs=len(records),sample_rows=result['raw_rows'],manifest_sha256=sha(out/'observations.xml'))

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--configuration',type=Path,required=True);p.add_argument('--labels',type=Path,required=True);p.add_argument('--dataset-id',required=True);p.add_argument('--platform',choices=['windows_x86_64','linux_aarch64'],required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--audit',type=Path,required=True)
 p.add_argument('--collector-source',type=Path,help='Actual acquisition collector source for an explicit-cell archive');p.add_argument('--validator-source',type=Path,help='Actual acquisition validator source; must match the prepared validator')
 p.add_argument('--path-map',action='append',default=[],help='Read-only original-prefix=local-prefix artifact mapping; original records remain unchanged')
 a=p.parse_args();configure_path_map(a.path_map);print(json.dumps(project(a.input,a.configuration,read(a.labels),a.dataset_id,a.platform,a.output,a.audit,a.collector_source,a.validator_source)))
if __name__=='__main__':main()
