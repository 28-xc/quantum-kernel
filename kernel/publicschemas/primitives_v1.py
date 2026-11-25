"""Public arithmetic experiments, with exact batch records and typed contracts."""
from pathlib import Path
import csv,math,re,statistics
from .profiling_v1 import need,keys,integer,sha,read,bound

SCHEMA='lattice.arithmetic_batches.v1'
PARAMETERS=(3329,8380417)
FIELDS=('batch','warmup','calls','elapsed_ticks','tick_frequency','batch_mean_ns','checksum','status')
METHOD={'observation':'mean_nanoseconds_per_call_in_one_batch','warmup_batches':10,
 'measured_batches':100,'calls_per_batch':100,'inputs':'100_distinct_states_prepared_and_restored_before_batch_timer',
 'timed_boundary':'arithmetic_loop_over_100_prepared_states',
 'canonical_output':'standard_coefficient_order_and_canonical_residues',
 'archive_output':'native_layout_and_montgomery_scaling','intervals':'descriptive_batch_distribution'}

def digest(s):need(type(s) is str and re.fullmatch(r'[0-9a-f]{64}',s) is not None,'Invalid identity')
def identifier(s):need(type(s) is str and re.fullmatch(r'[a-zA-Z0-9_-]+',s) is not None,'Invalid name')

def expected_cases(component):
 if component=='canonical_research_component':return {(q,op,2) for q in PARAMETERS for op in range(6)}
 need(component=='actual_archive_backend','Unknown representation contract')
 return {(q,op,k) for q in PARAMETERS for op in range(2,6)
  for k in (range(2,5) if q==3329 and op==4 else (2,))}

def quantile7(values,p):
 ordered=sorted(values);h=(len(ordered)-1)*p;lo=math.floor(h);hi=math.ceil(h)
 return ordered[lo]+(h-lo)*(ordered[hi]-ordered[lo])

def recompute(path):
 path=Path(path).resolve();root=path.parent;data=read(path)
 keys(data,('schema','dataset_id','platform','measurement','groups'))
 need(data['schema']==SCHEMA and data['platform'] in ('windows_x86_64','linux_aarch64'),'Wrong arithmetic dataset')
 identifier(data['dataset_id']);need(data['measurement']==METHOD,'Changed measurement contract')
 seen=set();paths=set();results=[];total_rows=0;series={}
 for group in data['groups']:
  keys(group,('id','configuration','round','component','prepared_sha256','plan_sha256','result_sha256',
   'executable_sha256','archive_sha256','oracle','cpu','seed','cases'))
  identifier(group['id']);identifier(group['configuration']);integer(group['round'])
  need(group['id']==group['configuration']+'-round'+f'{group["round"]:02d}','Changed group identity')
  need(group['id'] not in seen,'Duplicate acquisition');seen.add(group['id'])
  for key in ('prepared_sha256','plan_sha256','result_sha256','executable_sha256'):digest(group[key])
  if group['archive_sha256'] is not None:digest(group['archive_sha256'])
  need((group['component']=='actual_archive_backend')==(group['archive_sha256'] is not None),'Wrong archive binding')
  keys(group['oracle'],('cases_per_operation','cases','seed','canaries','reference'))
  integer(group['oracle']['cases_per_operation'],1);integer(group['oracle']['seed'],1)
  need(group['oracle']['canaries'] is True and group['oracle']['reference']=='schoolbook_signed_64_bit', 'Wrong oracle contract')
  expected=expected_cases(group['component']);need(group['oracle']['cases']==len(expected)*group['oracle']['cases_per_operation'],'Incomplete arithmetic oracles')
  integer(group['cpu']);integer(group['seed'],1);found=set()
  series.setdefault(group['configuration'],[]).append(group['round'])
  for cell in group['cases']:
   keys(cell,('q','operation','rank','frequency','checksum','raw'));key=(cell['q'],cell['operation'],cell['rank'])
   need(key in expected and key not in found,'Unexpected or duplicate operation');found.add(key)
   integer(cell['frequency'],1);integer(cell['checksum']);raw=bound(root,cell['raw'],'raw')
   need(cell['raw']['path'] not in paths,'Reused batch data');paths.add(cell['raw']['path'])
   values=[];rows=0;checksum=None
   with raw.open(newline='',encoding='utf-8') as fp:
    reader=csv.DictReader(fp);need(tuple(reader.fieldnames or ())==FIELDS,'Changed arithmetic columns')
    for row in reader:
     keys(row,FIELDS);index=rows-10
     for field in FIELDS:
      if field!='batch_mean_ns':need(re.fullmatch(r'-?\d+',row[field]) is not None,'Invalid batch integer')
     need(int(row['batch'])==index and int(row['warmup'])==int(index<0),'Missing or reordered batch')
     need(int(row['status'])==0 and int(row['calls'])==100 and int(row['elapsed_ticks'])>0,'Failed arithmetic batch')
     need(int(row['tick_frequency'])==cell['frequency'],'Changed batch clock')
     value=int(row['elapsed_ticks'])*1e9/cell['frequency']/100;reported=float(row['batch_mean_ns'])
     need(math.isfinite(reported) and math.isclose(reported,value,rel_tol=1e-12,abs_tol=1e-8),'Batch mean differs from clock')
     checksum=int(row['checksum']);integer(checksum)
     if index>=0:values.append(value)
     rows+=1
   need(rows==110 and len(values)==100 and checksum==cell['checksum'],'Incomplete batch series')
   total_rows+=rows
   results.append(dict(group=group['id'],configuration=group['configuration'],round=group['round'],
    component=group['component'],q=cell['q'],operation=cell['operation'],rank=cell['rank'],
    measured_batches=100,calls_per_batch=100,batch_mean_median_ns=statistics.median(values),
    batch_mean_arithmetic_mean_ns=statistics.mean(values),batch_mean_p95_ns=quantile7(values,.95),
    minimum_batch_mean_ns=min(values),maximum_batch_mean_ns=max(values)))
  need(found==expected,'Missing arithmetic operation')
 need(bool(seen),'Empty arithmetic experiment')
 for rounds in series.values():need(sorted(rounds)==list(range(len(rounds))),'Missing acquisition round')
 need({p.relative_to(root).as_posix() for p in (root/'raw').iterdir()}==paths,'Undeclared arithmetic artifacts')
 return dict(schema='lattice.arithmetic_batch_statistics.v1',observations_sha256=sha(path),dataset_id=data['dataset_id'],
  platform=data['platform'],measurement=METHOD,raw_rows=total_rows,warmup_rows=len(results)*10,
  measured_rows=len(results)*100,deleted_rows=0,cells=results)
