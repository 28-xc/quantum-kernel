"""Closed public schema for ordered blocked measurements; no workspace access."""
import math
import re

SCHEMA='lattice.block_observations.v2'
TOKEN=re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
SHA=re.compile(r'[0-9a-f]{64}\Z')
IMPLEMENTATION_FIELDS={'openssl_version','openssl_cflags','openssl_platform','provider','property_query','operation_entropy_bytes','input_transcript_preparation_entropy_bytes','pct_uses_extra_system_rng','message_encoding','mu','negative_checks','fresh_serialized_key_every_call','lattice_context_init_inside_call','openssl_key_context_lifecycle_inside_call'}
IMPLEMENTATION_FIELDS.update({'openssl_key_reused_across_batch','key_import_pct_uses_system_rng_at_setup',
 'openssl_operation_context_lifecycle_inside_call','key_generation_boundary_unchanged','retained_key_import_ticks'})
class BlockDataError(ValueError):pass
def need(ok,message):
 if not ok:raise BlockDataError(message)
def keys(obj,expected):need(type(obj) is dict and set(obj)==set(expected),'Undeclared or missing fields')
def integer(x,minimum=0):need(type(x) is int and x>=minimum,'Invalid integer')
def number(x):need(type(x) in (int,float) and math.isfinite(x) and x>=0,'Invalid measured number')
def token(x):need(type(x) is str and TOKEN.fullmatch(x),'Invalid technical identity')
def digest(x):need(type(x) is str and SHA.fullmatch(x),'Invalid digest')
def parameter(p,op):need(type(p) is int and p in [512,768,1024,44,65,87] and type(op) is int and op in [0,1,2],'Invalid operation')
def validate(data):
 keys(data,['schema','dataset_id','platform','execution','target_machine','driver_sha256','crypto_library_sha256','experiment','configurations','schedule','runs','analysis','completeness'])
 need(data['schema']==SCHEMA,'Wrong schema');token(data['dataset_id']);token(data['platform'])
 need(data['execution']=='native','Emulated execution cannot be native timing')
 need(data['target_machine'] in ['aarch64','arm64','ARM64','x86_64','AMD64','amd64'],'Unregistered architecture')
 digest(data['driver_sha256']);digest(data['crypto_library_sha256'])
 e=data['experiment'];keys(e,['blocks','samples_per_run','warmups_per_run','seed','message_bytes','context_bytes','cpu_index','replication_unit','timing_boundary'])
 for k in ['blocks','samples_per_run']:integer(e[k],1)
 for k in ['warmups_per_run','seed','message_bytes','context_bytes','cpu_index']:integer(e[k])
 need(e['context_bytes']<=255 and e['replication_unit']=='randomized_complete_block' and e['timing_boundary'] in ('fresh_serialized_key_service','openssl_retained_key_lattice_serialized_key_service'),'Unexpected conditions')
 configs=data['configurations'];need(type(configs) is list and len(configs)>=2,'Configurations missing');labels=[]
 for c in configs:
  keys(c,['id','provider','import_pct','workspace_reserved','library_sha256','supplied_lattice_library_sha256']);token(c['id']);labels.append(c['id'])
  need(c['provider'] in ['lattice','openssl'] and c['import_pct'] in ['none','random'],'Unregistered implementation mode');integer(c['workspace_reserved'],32);digest(c['library_sha256']);digest(c['supplied_lattice_library_sha256'])
 need(len(labels)==len(set(labels)),'Duplicate configurations')
 schedule=data['schedule'];need(type(schedule) is list and len(schedule)==e['blocks']*18*len(configs),'Incomplete schedule')
 seen=set()
 for i,s in enumerate(schedule):
  keys(s,['ordinal','block','parameter','operation','configuration','seed']);need(s['ordinal']==i and s['configuration'] in labels,'Schedule identity/order mismatch');integer(s['block']);integer(s['seed'],1);parameter(s['parameter'],s['operation']);need(s['block']<e['blocks'],'Block outside plan')
  ident=(s['block'],s['parameter'],s['operation'],s['configuration']);need(ident not in seen,'Duplicate scheduled cell');seen.add(ident)
 runs=data['runs'];need(type(runs) is list and len(runs)<=len(schedule),'Unexpected run count');sample_count=0;failed_rows=0;failed_runs=0
 for i,r in enumerate(runs):
  keys(r,['ordinal','driver_exit_code','driver_status','source_csv_sha256','source_log_sha256','source_stderr_sha256','input_sequence_sha256','output_sequence_sha256','timer','frequency','workspace_highwater','entropy_mode','implementation_metadata','samples'])
  need(r['ordinal']==i,'Run order changed');integer(r['driver_exit_code'],-2147483648)
  need(r['driver_status'] in [None,'PASS','FAIL','ERROR','INTERRUPTED'],'Invalid reported status')
  for k in ['source_csv_sha256','source_log_sha256','source_stderr_sha256','input_sequence_sha256','output_sequence_sha256']:
   if r[k] is not None:digest(r[k])
  need(r['timer'] in [None,'QueryPerformanceCounter','QueryPerformanceCounter; verified P-core','CLOCK_MONOTONIC_RAW; explicit sched_setaffinity'],'Unregistered timer')
  for k in ['frequency','workspace_highwater']:
   if r[k] is not None:integer(r[k])
  need(r['entropy_mode'] in [None,'supplied_test_entropy'],'Unexpected entropy mode')
  meta=r['implementation_metadata'];need(type(meta) is dict and set(meta)<=IMPLEMENTATION_FIELDS,'Unregistered implementation metadata')
  for k,v in meta.items():
   if k in ['openssl_version','openssl_cflags','openssl_platform','provider','property_query']:need(type(v) is str and len(v)<=4096 and '\0' not in v,'Invalid implementation text')
   elif k in ['operation_entropy_bytes','input_transcript_preparation_entropy_bytes','message_encoding','mu','retained_key_import_ticks']:integer(v)
   else:need(type(v) is bool,'Implementation flag must be boolean')
  if r['driver_status']=='PASS':
   from pooled_conditions import validate_metadata
   validate_metadata(meta,e['timing_boundary'],schedule[i]['operation'])
  samples=r['samples'];need(type(samples) is list and len(samples)<=e['samples_per_run']+e['warmups_per_run'],'Unexpected sample count')
  for j,x in enumerate(samples):
   keys(x,['case_id','iteration','warmup','elapsed_ticks','tick_frequency','elapsed_ns','status','entropy_sha256','message_sha256','context_sha256'])
   s=schedule[i];need(x['case_id']==f"{s['seed']:016x}-{s['parameter']}-{s['operation']}-{j}",'Case identity/order mismatch')
   need(type(x['iteration']) is int and x['iteration']==j-e['warmups_per_run'] and type(x['warmup']) is bool and x['warmup']==(j<e['warmups_per_run']),'Warmup/order changed')
   integer(x['status'],-2147483648);failed_rows+=x['status']!=0
   for k in ['entropy_sha256','message_sha256','context_sha256']:digest(x[k])
   absent=[x[k] is None for k in ['elapsed_ticks','tick_frequency','elapsed_ns']];need(all(absent) or not any(absent),'Partial timing observation')
   if not all(absent):
    integer(x['elapsed_ticks']);integer(x['tick_frequency'],1);number(x['elapsed_ns']);need(abs(x['elapsed_ns']-x['elapsed_ticks']*1e9/x['tick_frequency'])<=.0011,'Timer conversion changed')
    if r['frequency'] is not None:need(x['tick_frequency']==r['frequency'],'Frequency changed within run')
   elif x['status']==0:need(False,'Successful measurement missing its elapsed time')
  sample_count+=len(samples);failed_runs+=(r['driver_exit_code']!=0 or r['driver_status'] not in ['PASS'])
 c=data['completeness'];keys(c,['planned_runs','recorded_runs','missing_runs','sample_rows','failed_sample_rows','failed_runs','archive_status'])
 need(c['planned_runs']==len(schedule) and c['recorded_runs']==len(runs) and c['missing_runs']==len(schedule)-len(runs) and c['sample_rows']==sample_count and c['failed_sample_rows']==failed_rows and c['failed_runs']==failed_runs,'Completeness summary changed')
 complete=len(runs)==len(schedule) and all(len(r['samples'])==e['samples_per_run']+e['warmups_per_run'] for r in runs)
 need(c['archive_status']==('COMPLETE' if complete else 'INCOMPLETE'),'Archive completeness overstated')
 if data['analysis'] is not None:
  need(complete and failed_rows==0 and failed_runs==0,'Successful-only statistics cannot hide failed/missing runs')
  a=data['analysis'];keys(a,['source_summary_sha256','source_table_sha256','analysis_source_sha256','resamples','bootstrap_unit','bootstrap_seed','reference','ratios','cells'])
  for k in ['source_summary_sha256','source_table_sha256','analysis_source_sha256']:digest(a[k])
  integer(a['resamples'],200);integer(a['bootstrap_seed']);need(a['bootstrap_unit']=='complete paired block' and a['reference'] in labels,'Statistics unit/reference changed')
  need(type(a['ratios']) is list and len(a['ratios'])==len(configs) and type(a['cells']) is list and len(a['cells'])==len(configs)*18,'Statistical matrix incomplete')
  need({x.get('configuration') for x in a['ratios']}==set(labels),'Duplicated/missing aggregate configuration')
  need({(x.get('configuration'),x.get('parameter'),x.get('operation')) for x in a['cells']}=={(l,p,o) for l in labels for p in [512,768,1024,44,65,87] for o in range(3)},'Duplicated/missing statistical cell')
  for x in a['ratios']:
   keys(x,['configuration','reference','geometric_mean_ratio','paired_block_bootstrap_ci95']);need(x['configuration'] in labels and x['reference']==a['reference'],'Unknown comparison');number(x['geometric_mean_ratio']);need(type(x['paired_block_bootstrap_ci95']) is list and len(x['paired_block_bootstrap_ci95'])==2,'CI missing')
   for v in x['paired_block_bootstrap_ci95']:number(v)
   need(x['paired_block_bootstrap_ci95'][0]<=x['paired_block_bootstrap_ci95'][1],'Reversed interval')
  for x in a['cells']:
   keys(x,['configuration','parameter','operation','blocks','samples','mean_ns','median_ns','p95_ns','p99_ns','minimum_ns','maximum_ns','reference','ratio','ratio_ci95_low','ratio_ci95_high'])
   need(x['configuration'] in labels and x['reference']==a['reference'],'Unknown cell comparison');parameter(x['parameter'],x['operation']);need(x['blocks']==e['blocks'] and x['samples']==e['blocks']*e['samples_per_run'],'Cell replication changed')
   for k in ['mean_ns','median_ns','p95_ns','p99_ns','minimum_ns','maximum_ns','ratio','ratio_ci95_low','ratio_ci95_high']:number(x[k])
   need(x['ratio_ci95_low']<=x['ratio_ci95_high'],'Reversed cell interval')
 return data
