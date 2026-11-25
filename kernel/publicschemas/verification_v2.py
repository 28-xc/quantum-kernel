"""Public verification observations with explicit case/execution units.

No source discovery, credential access, compilation, timing or acceptance policy.
The records are observations; FAIL and OUTSIDE_PUBLIC_SCOPE remain visible.
"""
from collections import Counter
import re

SCHEMA='lattice.verification_observations.v3'
PARAMETERS=(512,768,1024,44,65,87)
KINDS=('standard_vectors','public_probe','byte_rng_differential','signature_differential',
       'ordinary_regression','detector_control','emulated_target','openssl_interoperation','secret_prefix_cleanup','baseline_boundary','baseline_probe','normal_capacity_recovery')
SCOPES=('frozen_hosted','supplementary_baseline','separate_instrumented_build','instruction_emulation')
OUTCOMES=('PASS','FAIL','ERROR','OUTSIDE_PUBLIC_SCOPE')

def need(test,message):
 if not test:raise ValueError(message)
def keys(x,required,optional=()):
 need(type(x) is dict and set(required)<=set(x) and set(x)<=set(required)|set(optional),'Unexpected or missing public fields')
def integer(x,minimum=0):need(type(x) is int and x>=minimum,'Invalid integer')
def digest(x):need(type(x) is str and re.fullmatch('[0-9a-f]{64}',x),'Invalid SHA-256')
def token(x):need(type(x) is str and re.fullmatch('[A-Za-z0-9_.:+/-]{1,240}',x) and '..' not in x.split('/'),'Invalid technical identifier')
def text(x):
 need(type(x) is str and 0<len(x)<=2048 and '\0' not in x,'Invalid technical text')
 need(not re.search(r'(?i)(?:(?<![A-Za-z0-9])[A-Z]:[\\/]|/home/|/Users/|/internal/|\\Users\\)',x),'Private filesystem path in public text')
def parameter(x):need(x in PARAMETERS and type(x) is int,'Unknown standard parameter')
def booleans(x,names):
 for n in names:need(type(x[n]) is bool,'Boolean observation required')
def ints(x,names):
 for n in names:integer(x[n])
def outcome(x):need(x in OUTCOMES,'Unknown observation outcome')
def count_map(x):
 need(type(x) is dict and x,'Missing counts')
 for k,v in x.items():token(k);integer(v)
def source_map(x):
 need(type(x) is dict and x,'Missing source identities')
 for name,h in x.items():token(name);need(not name.startswith('/'),'Absolute source identity');digest(h)

def record(kind,r):
 if kind=='standard_vectors':
  common=['library_sha256','category','tgId','tcId','parameter','status']
  if r.get('status')=='OUTSIDE_PUBLIC_SCOPE':keys(r,common+['reason']) ;text(r['reason'])
  else:
   keys(r,common+['status_code','workspace_bytes','arena_highwater','canaries'])
   integer(r['status_code'],-2147483648);ints(r,['workspace_bytes','arena_highwater']);booleans(r,['canaries'])
  digest(r['library_sha256']);token(r['category']);parameter(r['parameter']);outcome(r['status']);ints(r,['tgId','tcId'])
  categories=('ML-KEM-keyGen-FIPS203','ML-KEM-encapDecap-FIPS203','ML-KEM-encapDecap-FIPS203-tr1') if r['parameter'] in (512,768,1024) else ('ML-DSA-keyGen-FIPS204','ML-DSA-sigGen-FIPS204','ML-DSA-sigVer-FIPS204')
  need(r['category'] in categories,'Standard category/parameter mismatch')
  if r['status']=='PASS':need(r['canaries'],'PASS standard record with damaged canary')
 elif kind=='public_probe':
  keys(r,['linkage','parameter','calls_per_operation','guard_bytes','random_failure','overlap_rejected','oom_recovery','initial_arena_highwater','status'])
  need(r['linkage'] in ('shared','static'),'Unknown linkage');parameter(r['parameter']);outcome(r['status'])
  ints(r,['calls_per_operation','guard_bytes']);booleans(r,['random_failure','overlap_rejected','oom_recovery'])
  need(type(r['initial_arena_highwater']) is list and len(r['initial_arena_highwater'])==3,'Three operations required')
  for x in r['initial_arena_highwater']:integer(x)
 elif kind=='byte_rng_differential':
  keys(r,['parameter','complete_sequences','outputs_byte_equal','entropy_requests_equal','arena_highwater_equal','arena_observations','last_arena_highwater','aggregate_output_sha256','system_rng_smoke','mutated_input_checked','guards_preserved'])
  parameter(r['parameter']);integer(r['complete_sequences']);digest(r['aggregate_output_sha256'])
  booleans(r,['outputs_byte_equal','entropy_requests_equal','arena_highwater_equal','mutated_input_checked','guards_preserved']);token(r['system_rng_smoke'])
  need(len(r['arena_observations'])==r['complete_sequences'],'Differential case omission')
  for i,c in enumerate(r['arena_observations']):
   keys(c,['case','left','right']);need(c['case']==i,'Differential case order changed')
   for side in ('left','right'):
    need(type(c[side]) is list and len(c[side])==3,'Three operations required')
    for x in c[side]:integer(x)
  need(type(r['last_arena_highwater']) is list and len(r['last_arena_highwater'])==3,'Final operation observations required')
  for x in r['last_arena_highwater']:integer(x)
 elif kind=='signature_differential':
  keys(r,['parameter','count','complete_signatures_byte_equal','same_context_alternating_keys','mutated_signatures_rejected','entropy_bytes_per_signature','signature_aggregate_sha256','cases'])
  parameter(r['parameter']);need(r['parameter'] in (44,65,87),'Signature family mismatch');ints(r,['count','entropy_bytes_per_signature']);digest(r['signature_aggregate_sha256'])
  booleans(r,['complete_signatures_byte_equal','same_context_alternating_keys','mutated_signatures_rejected']);need(r['count']==len(r['cases']),'Signature case omission')
  for i,c in enumerate(r['cases']):
   keys(c,['case','key_id','message_bytes','domain_bytes','arena_peak_pair']);need(c['case']==i,'Signature case order changed');ints(c,['key_id','message_bytes','domain_bytes']);need(c['domain_bytes']<=255,'Invalid domain')
   need(type(c['arena_peak_pair']) is list and len(c['arena_peak_pair'])==2,'Paired arena observations required')
   for x in c['arena_peak_pair']:integer(x)
 elif kind=='normal_capacity_recovery':
  from .normal_capacity import validate_case
  validate_case(r)
 elif kind=='ordinary_regression':
  keys(r,['parameter','seed','sequence_steps','parser_mutations_each','actions','mutated_primary_accepted','mutated_primary_rejected','entropy_calls','transcript_fnv64','status'])
  parameter(r['parameter']);token(r['seed']);ints(r,['sequence_steps','parser_mutations_each','mutated_primary_accepted','mutated_primary_rejected','entropy_calls']);outcome(r['status']);token(r['transcript_fnv64'])
  need(type(r['actions']) is list and len(r['actions'])==12,'Twelve declared action counters required')
  for x in r['actions']:integer(x)
  need(sum(r['actions'])==r['sequence_steps'],'Ordinary action counters disagree')
  need(r['mutated_primary_accepted']+r['mutated_primary_rejected']==r['parser_mutations_each'],'Parser outcome counters disagree')
 elif kind=='baseline_boundary':
  keys(r,['parameter','status','test']);parameter(r['parameter']);outcome(r['status']);text(r['test'])
 elif kind=='baseline_probe':
  keys(r,['linkage','parameter','complete_sequences','status','caller_workspace_used','heap_failure_recovery_tested']);parameter(r['parameter']);outcome(r['status']);need(r['linkage'] in ('shared','static'),'Unknown linkage');integer(r['complete_sequences']);booleans(r,['caller_workspace_used','heap_failure_recovery_tested'])
 elif kind=='detector_control':
  keys(r,['name','detector','detected','exit_code','log_sha256']);token(r['name']);token(r['detector']);need(type(r['detected']) is bool,'Detector observation required');integer(r['exit_code'],-2147483648);digest(r['log_sha256'])
 elif kind=='secret_prefix_cleanup':
  keys(r,['parameter','status','signatures','prefix_bytes','erased_before_free','alternating_keys_same_context','prefix_offset'])
  parameter(r['parameter']);outcome(r['status']);ints(r,['signatures','prefix_bytes','prefix_offset']);booleans(r,['erased_before_free','alternating_keys_same_context'])
 elif kind=='emulated_target':
  keys(r,['event','index','parameter','operation','tcId','kind','rc','ok','arena_highwater_bytes','stack_watermark_bytes','allocation_failures'])
  need(r['event']=='case','Only case events in record sequence');parameter(r['parameter']);need(type(r['operation']) is int and r['operation'] in (0,1,2),'Unknown operation');token(r['kind']);integer(r['rc'],-2147483648);need(type(r['ok']) is bool,'Target case outcome required')
  ints(r,['index','tcId','arena_highwater_bytes','stack_watermark_bytes','allocation_failures'])
 elif kind=='openssl_interoperation':
  keys(r,['parameter','operation','import_pct','cases','failures','exit_code','oracle_sha256','oracle_version','loaded_identity_checked','raw_sha256','samples'])
  parameter(r['parameter']);need(type(r['operation']) is int and r['operation'] in (0,1,2),'Unknown operation');need(r['import_pct'] in ('none','random'),'Unknown import check mode');ints(r,['cases','failures']);integer(r['exit_code'],-2147483648);digest(r['oracle_sha256']);digest(r['raw_sha256']);text(r['oracle_version']);need(type(r['loaded_identity_checked']) is bool,'Actual oracle identity check required')
  need(len(r['samples'])==r['cases'],'Interop sample omission')
  for i,x in enumerate(r['samples']):
   keys(x,['case_id','iteration','status','entropy_sha256','message_sha256','context_sha256']);token(x['case_id']);need(x['iteration']==i,'Interop sample order changed');integer(x['status'],-2147483648)
   for k in ('entropy_sha256','message_sha256','context_sha256'):digest(x[k])
  need(sum(x['status']!=0 for x in r['samples'])==r['failures'],'Interop failure count differs')
 else:raise ValueError('Unknown verification category')

def recompute(d):
 standard=Counter();unique={};signature_design=set();signature_pairs=0;sequence_pairs=0;probe_operations=0;ordinary_records=0;ordinary_steps=0;mutations=0;detected=0;detector_count=0;target_cases=0;target_failures=0;interop=0;interop_failures=0;prefix_signatures=0
 for s in d['suites']:
  kind=s['kind'];scope=s['subject_scope']
  for r in s['records']:
   if kind=='standard_vectors':
    standard[scope+'/'+r['status']]+=1
    k=(s['input_design_sha256'],r['category'],r['tgId'],r['tcId'],r['parameter'])
    unique.setdefault(scope,{}).setdefault(k,set()).add(r['status'])
   elif kind=='signature_differential':
    signature_pairs+=r['count']
    for c in r['cases']:signature_design.add((s['input_design_sha256'],r['parameter'],c['case']))
   elif kind=='byte_rng_differential':sequence_pairs+=r['complete_sequences']
   elif kind=='public_probe':probe_operations+=3*r['calls_per_operation']
   elif kind=='ordinary_regression':ordinary_records+=1;ordinary_steps+=r['sequence_steps'];mutations+=2*r['parser_mutations_each']
   elif kind=='detector_control':detector_count+=1;detected+=r['detected']
   elif kind=='secret_prefix_cleanup':prefix_signatures+=r['signatures']
   elif kind=='emulated_target':target_cases+=1;target_failures+=not r['ok']
   elif kind=='openssl_interoperation':interop+=r['cases'];interop_failures+=r['failures']
 unique_counts={}
 for scope,rows in sorted(unique.items()):
  unique_counts[scope]={'applicable_vector_ids':sum('OUTSIDE_PUBLIC_SCOPE' not in v for v in rows.values()),'outside_scope_vector_ids':sum(v=={'OUTSIDE_PUBLIC_SCOPE'} for v in rows.values()),
   'mlkem_applicable_vector_ids':sum(k[-1] in (512,768,1024) and 'OUTSIDE_PUBLIC_SCOPE' not in v for k,v in rows.items()),
   'mldsa_applicable_vector_ids':sum(k[-1] in (44,65,87) and 'OUTSIDE_PUBLIC_SCOPE' not in v for k,v in rows.items())}
 result=dict(library_images=len(d['libraries']),frozen_hosted_library_images=sum(x['scope']=='frozen_hosted' for x in d['libraries']),
  standard_case_id_counts=unique_counts,standard_record_counts=dict(sorted(standard.items())),
  signature_design_case_ids=len(signature_design),signature_pair_executions=signature_pairs,
  differential_complete_sequence_pair_executions=sequence_pairs,public_probe_operation_executions=probe_operations,
  ordinary_parameter_seed_executions=ordinary_records,ordinary_sequence_step_executions=ordinary_steps,
  ordinary_parser_mutation_executions=mutations,detector_control_executions=detector_count,detector_controls_detected=detected,
  emulated_case_executions=target_cases,emulated_case_failures=target_failures,interop_case_executions=interop,interop_case_failures=interop_failures)
 if any(s['kind']=='secret_prefix_cleanup' for s in d['suites']):result['prefix_cleanup_signature_observations']=prefix_signatures
 if any(s['kind']=='baseline_boundary' for s in d['suites']):result['baseline_boundary_check_executions']=sum(len(s['records']) for s in d['suites'] if s['kind']=='baseline_boundary')
 if any(s['kind']=='baseline_probe' for s in d['suites']):result['baseline_probe_complete_sequence_executions']=sum(r['complete_sequences'] for s in d['suites'] if s['kind']=='baseline_probe' for r in s['records'])
 if any(s['kind']=='normal_capacity_recovery' for s in d['suites']):
  result['normal_capacity_recovery_record_executions']=sum(len(r['records']) for s in d['suites'] if s['kind']=='normal_capacity_recovery' for r in s['records'])
  result['normal_capacity_independent_context_executions']=sum(len(s['records']) for s in d['suites'] if s['kind']=='normal_capacity_recovery')
 return result

def validate(d,check_summary=True):
 keys(d,['schema','dataset_id','core_source_commit','libraries','suites','summary','counting_scope','limits'])
 need(d['schema']==SCHEMA,'Wrong verification schema');token(d['dataset_id']);need(re.fullmatch('[0-9a-f]{40}',d['core_source_commit']),'Core source identity missing')
 hashes=set()
 for a in d['libraries']:
  keys(a,['sha256','configuration','platform','backend','compiler','optimization','lto','scope','source_sha256'])
  digest(a['sha256']);need(a['sha256'] not in hashes,'Duplicate binary');hashes.add(a['sha256']);token(a['configuration']);text(a['platform']);token(a['backend']);text(a['compiler']);need(a['optimization'] in ('O3','Os','instrumented','per_translation_unit_recipe','not_recorded'),'Unknown optimization');need(type(a['lto']) is bool or (a['lto'] is None and a['scope']!='frozen_hosted'),'LTO flag required');need(a['scope'] in SCOPES,'Unknown binary scope');source_map(a['source_sha256'])
 ids=set()
 for s in d['suites']:
  keys(s,['id','kind','subject_scope','library_sha256','status','source_record_sha256','test_source_sha256','input_design_sha256','records','scope'])
  token(s['id']);need(s['id'] not in ids,'Duplicate suite');ids.add(s['id']);need(s['kind'] in KINDS and s['subject_scope'] in SCOPES,'Unregistered suite category');outcome(s['status']);digest(s['source_record_sha256']);source_map(s['test_source_sha256']);digest(s['input_design_sha256']);text(s['scope'])
  need(type(s['library_sha256']) is list and bool(s['library_sha256']),'Actual subject identity missing')
  for h in s['library_sha256']:digest(h);need(h in hashes,'Suite refers to unregistered image')
  need(type(s['records']) is list,'Records must preserve ordered list')
  seen=set()
  for r in s['records']:
   record(s['kind'],r)
   if s['kind']=='standard_vectors':
    need(r['library_sha256'] in s['library_sha256'],'Vector applied to unknown subject');k=(r['library_sha256'],r['category'],r['tgId'],r['tcId']);need(k not in seen,'Repeated vector record');seen.add(k)
  if s['kind']=='normal_capacity_recovery':
   from .normal_capacity import validate_suite
   validate_suite(s['records'])
  if s['status']=='PASS':
   if s['kind'] in ('standard_vectors','public_probe','ordinary_regression','secret_prefix_cleanup'):
    need(all(r['status'] in ('PASS','OUTSIDE_PUBLIC_SCOPE') for r in s['records']),'A failed observation cannot have a PASS suite')
   if s['kind']=='emulated_target':need(all(r['ok'] for r in s['records']),'A failed target case cannot have a PASS suite')
   if s['kind']=='detector_control':need(all(r['detected'] for r in s['records']),'Undetected positive control cannot have a PASS suite')
   if s['kind']=='public_probe':need(all(r['random_failure'] and r['overlap_rejected'] and r['oom_recovery'] for r in s['records']),'Failed public probe check cannot have a PASS suite')
   if s['kind']=='byte_rng_differential':need(all(r['outputs_byte_equal'] and r['entropy_requests_equal'] and r['mutated_input_checked'] and r['guards_preserved'] for r in s['records']),'Failed byte/RNG comparison cannot have a PASS suite')
   if s['kind']=='signature_differential':need(all(r['complete_signatures_byte_equal'] and r['same_context_alternating_keys'] and r['mutated_signatures_rejected'] for r in s['records']),'Failed signature comparison cannot have a PASS suite')
   if s['kind']=='secret_prefix_cleanup':need(all(r['erased_before_free'] and r['alternating_keys_same_context'] for r in s['records']),'Failed erasure observation cannot have a PASS suite')
 for x in d['counting_scope']+d['limits']:text(x)
 expected=recompute(d)
 if check_summary:need(d['summary']==expected,'Derived verification counts do not match records')
 return d
