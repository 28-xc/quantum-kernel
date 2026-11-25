"""Validate and summarize batch means from the exact archived arithmetic backends."""
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
import argparse, csv, hashlib, record_io as json, math
from publicschemas.application_v1 import need, keys, integer, digest, read, sha

SCHEMA='lattice.primitive_samples_observations.v1'
SUMMARY='lattice.primitive_samples_statistics.v1'
CONFIGURATIONS=('portable-compact','native-balanced')
CASES=tuple((3329,op,rank) for op,rank in ((2,2),(3,2),(4,2),(4,3),(4,4),(5,2)))+tuple((8380417,op,2) for op in (2,3,4,5))
OPERATIONS={2:'forward_ntt',3:'inverse_ntt_with_montgomery_scale',4:'pointwise_product_or_vector_dot_product',5:'negacyclic_polynomial_product'}
BOOTSTRAP_SEED=20260927941

def validate_observations(data):
 keys(data,('schema','dataset_id','platform','method','configurations','processes'))
 need(data['schema']==SCHEMA and data['platform'] in ('windows_x86_64','linux_aarch64'),'Unknown primitive schema')
 need(data['dataset_id']==data['platform']+'_actual_archive_primitives','Unknown primitive dataset')
 m=data['method'];keys(m,('repetitions','batches','warmup_batches','calls_per_batch','base_seed','seed_increment','cpu','cases','measured_unit','replication_unit','link_scope','bootstrap'))
 need((m['repetitions'],m['batches'],m['warmup_batches'],m['calls_per_batch'])==(7,100,10,100),'Changed primitive design')
 integer(m['base_seed'],1);integer(m['seed_increment'],1)
 need(m['base_seed']+6*m['seed_increment']<2**64,'Primitive seeds exceed the collector domain')
 integer(m['cpu']);need(m['cases']==[dict(q=q,op=op,rank=r) for q,op,r in CASES],'Changed primitive cells')
 need(m['measured_unit']=='mean time per call within a batch of 100 calls' and m['replication_unit']=='independent collector process','Changed timing unit')
 need(m['bootstrap']==dict(seed=BOOTSTRAP_SEED,replicates=10000,generator='PCG64',resampled_unit='whole independent collector process',interval='percentile 95%',quantile_method='linear'),'Changed primitive interval')
 need([x['id'] for x in data['configurations']]==list(CONFIGURATIONS),'Changed primitive configurations')
 for c in data['configurations']:
  keys(c,('id','archive_sha256','build_record_sha256','driver_sha256','prepared_sha256','bindings_sha256','compiler','target','coefficient_order','archive_lto','relink_optimization','driver_compiled_without_lto','linked_entities','build_source_hashes','collector_source_hashes','oracle','negative_control'))
  for name in ('archive_sha256','build_record_sha256','driver_sha256','prepared_sha256','bindings_sha256'):digest(c[name])
  for field in ('build_source_hashes','collector_source_hashes'):
   need(type(c[field]) is dict and len(c[field])>0,'Missing source bindings')
   for name,value in c[field].items():
    need(type(name) is str and '\\' not in name and ':' not in name and not name.startswith('/') and '..' not in name.split('/'),'Unsafe source identity');digest(value)
  need(type(c['linked_entities']) is dict and len(c['linked_entities'])>=11,'Missing actual linked symbols')
  for symbol,value in c['linked_entities'].items():
   need(type(symbol) is str and symbol.startswith(('lcbase_','lc_base_')),'Unexpected linked entity');keys(value,('address','type'));integer(value['address'],1)
   if symbol=='lc_base_mlk_qdata':need(value['type'] in ('R','r'),'Invalid read-only arithmetic constants')
   else:need(value['type'] in ('T','t'),'Invalid linked function')
  need(c['coefficient_order'] in ('bitreversed','avx2_custom') and type(c['archive_lto']) is bool and type(c['driver_compiled_without_lto']) is bool,'Invalid backend representation')
  keys(c['oracle'],('status','component','cases','cases_per_operation','seed','schoolbook_accumulator','canaries','roundtrip_scale'))
  integer(c['oracle']['cases'],1);integer(c['oracle']['cases_per_operation'],1)
  need(c['oracle']['status']=='PASS' and c['oracle']['component']=='actual_archive_backend' and c['oracle']['cases']==10*c['oracle']['cases_per_operation'] and c['oracle']['cases_per_operation'] in (100,200,10000) and c['oracle']['canaries'] is True and c['oracle']['seed']==20260925,'Invalid functional oracle')
  need(c['negative_control']==dict(status='PASS_DETECTED_WRONG_OUTPUT',oracle='independent_schoolbook'),'Missing oracle positive control')
 need(len(data['processes'])==140,'Incomplete primitive collection')
 observed=set()
 for p in data['processes']:
  keys(p,('configuration','repeat','seed','q','op','rank','plan_sha256','results_sha256','prepared_sha256','frequency','checksum','raw'))
  need(p['configuration'] in CONFIGURATIONS and type(p['repeat']) is int and 0<=p['repeat']<7,'Changed process identity')
  need(p['seed']==m['base_seed']+p['repeat']*m['seed_increment'] and (p['q'],p['op'],p['rank']) in CASES,'Changed primitive process condition')
  identity=(p['configuration'],p['repeat'],p['q'],p['op'],p['rank']);need(identity not in observed,'Duplicate primitive process');observed.add(identity)
  for field in ('plan_sha256','results_sha256','prepared_sha256'):digest(p[field])
  need(p['prepared_sha256']==next(x['prepared_sha256'] for x in data['configurations'] if x['id']==p['configuration']),'Changed prepared executable')
  integer(p['frequency'],1);integer(p['checksum']);keys(p['raw'],('path','sha256','bytes','rows'))
  need(p['raw']['path']==f"raw/{p['configuration']}/{p['repeat']}/q{p['q']}_op{p['op']}_rank{p['rank']}.csv" and p['raw']['rows']==110,'Changed primitive sample indexing')
  digest(p['raw']['sha256']);integer(p['raw']['bytes'],1)
 return True

def recompute(path):
 import numpy as np
 path=Path(path).resolve();data=read(path);validate_observations(data);groups={};rows_total=0
 for p in data['processes']:
  source=path.parent/p['raw']['path'];need(source.is_file() and source.stat().st_size==p['raw']['bytes'] and sha(source)==p['raw']['sha256'],'Changed primitive samples')
  with source.open(encoding='utf-8',newline='') as stream:
   reader=csv.DictReader(stream);need(reader.fieldnames==['batch','warmup','calls','elapsed_ticks','tick_frequency','batch_mean_ns','checksum','status'],'Changed primitive columns');rows=list(reader)
  need(len(rows)==110,'Incomplete primitive process');values=[]
  for i,r in enumerate(rows):
   need(set(r)==set(reader.fieldnames) and all(type(x) is str for x in r.values()),'Malformed primitive CSV record')
   batch,warm,calls,ticks,frequency,checksum,status=(int(r[k]) for k in ('batch','warmup','calls','elapsed_ticks','tick_frequency','checksum','status'))
   mean=float(r['batch_mean_ns'])
   need((batch,warm,calls,frequency,status)==(i-10,int(i<10),100,p['frequency'],0) and ticks>0 and checksum>=0,'Changed primitive batch identity')
   need(math.isfinite(mean) and math.isclose(mean,ticks*1e9/frequency/calls,rel_tol=1e-12,abs_tol=6e-10),'Primitive tick conversion mismatch')
   if i>=10:values.append(mean)
  need(int(rows[-1]['checksum'])==p['checksum'],'Changed output checksum')
  groups.setdefault((p['configuration'],p['q'],p['op'],p['rank']),[]).append((p['repeat'],np.asarray(values)));rows_total+=len(rows)
 draws=np.random.Generator(np.random.PCG64(BOOTSTRAP_SEED)).integers(0,7,size=(10000,7));cells=[]
 for key,group in sorted(groups.items()):
  need(sorted(x[0] for x in group)==list(range(7)),'Incomplete independent process repetitions')
  ordered=[v for _,v in sorted(group)];values=np.concatenate(ordered);means=np.asarray([v.mean() for v in ordered]);boot=means[draws].mean(axis=1)
  cells.append(dict(configuration=key[0],q=key[1],operation=OPERATIONS[key[2]],op=key[2],rank=key[3],independent_processes=7,measured_batches=700,calls_per_batch=100,mean_batch_mean_ns=float(values.mean()),median_batch_mean_ns=float(np.median(values)),p95_batch_mean_ns=float(np.quantile(values,.95,method='linear')),p99_batch_mean_ns=float(np.quantile(values,.99,method='linear')),minimum_batch_mean_ns=float(values.min()),maximum_batch_mean_ns=float(values.max()),process_mean_ns=[float(x) for x in means],mean_ci95_low=float(np.quantile(boot,.025,method='linear')),mean_ci95_high=float(np.quantile(boot,.975,method='linear'))))
 return dict(schema=SUMMARY,dataset_id=data['dataset_id'],platform=data['platform'],observations_sha256=sha(path),counts=dict(independent_processes=140,conditions=20,measured_batches=14000,warmup_batches=1400,measured_calls=1400000,warmup_calls=140000,retained_rows=rows_total),statistical_definition='All percentile columns describe 700 batch means per cell. Confidence intervals for the mean resample seven complete independent collector processes; each process contains 100 measured batches of 100 calls.',bootstrap=data['method']['bootstrap'],bootstrap_indices_sha256=hashlib.sha256(draws.astype('<i8').tobytes()).hexdigest(),cells=cells)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('observations',type=Path);p.add_argument('output',type=Path);a=p.parse_args();need(not a.output.exists(),'Fresh output required');result=recompute(a.observations);a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result['counts']))
