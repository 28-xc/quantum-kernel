"""Closed complete-operation counting records, separate from sampled profiles."""
from .verification_v2 import keys,need,integer,digest,token,text
SCHEMA='lattice.complete_pmu_observations.v1'
EVENTS=['cycles:u','instructions:u','branch-misses:u','cache-references:u','cache-misses:u']
def validate(d):
 keys(d,['schema','dataset_id','platform','core_source_commit','method','comparisons','records','interrupted_collection','source_plan_hashes','source_result_hashes'])
 need(d['schema']==SCHEMA and d['platform']=='linux_aarch64','Counter platform/schema changed');token(d['dataset_id']);need(len(d['core_source_commit'])==40,'Core identity missing')
 m=d['method'];keys(m,['events','cpu','warmup_operations','message_bytes','context_bytes','workspace_bytes','operations_per_batch','timed_boundary','event_meanings','paired_batches','bootstrap_samples','bootstrap_seed'])
 need(m['events']==EVENTS and m['cpu']==2 and m['warmup_operations']==32 and m['message_bytes']==32 and m['context_bytes']==16 and m['workspace_bytes']==262144 and m['operations_per_batch']==2048,'Counter boundary changed')
 need(m['paired_batches']==5 and m['bootstrap_samples']==50000,'Independent batch count changed');text(m['timed_boundary'])
 comps={c['id']:c for c in d['comparisons']};need(set(comps)=={'fused24','noise4','row4','adaptive87'},'Mechanism set changed');seen=set()
 for c in comps.values():
  keys(c,['id','control','candidate','cells']);token(c['control']);token(c['candidate'])
 for r in d['records']:
  keys(r,['id','study','configuration','parameter','operation','repeat','samples','workspace_bytes','seed','binary_sha256','exit_code','timed_out','events_file','stdout_file','raw_files'])
  token(r['id']);need(r['study'] in comps,'Unknown mechanism');c=comps[r['study']];need(r['configuration'] in [c['control'],c['candidate']],'Unknown comparison arm')
  need([r['parameter'],r['operation']] in c['cells'] and r['repeat'] in range(5),'Unplanned paired cell')
  k=(r['study'],r['configuration'],r['parameter'],r['operation'],r['repeat']);need(k not in seen,'Repeated counter batch');seen.add(k)
  need(r['samples']==2048 and r['workspace_bytes']==262144 and r['exit_code']==0 and r['timed_out'] is False,'Incomplete counter batch');digest(r['binary_sha256']);integer(r['seed'],1)
  for path,h in r['raw_files'].items():need(path.startswith('raw/') and '..' not in path and '\\' not in path and ':' not in path,'Unsafe counter artifact');digest(h)
 expected={(c['id'],a,p,o,i) for c in comps.values() for a in [c['control'],c['candidate']] for p,o in c['cells'] for i in range(5)}
 need(seen==expected and len(seen)==190,'Counter matrix incomplete')
 for source in [d['source_plan_hashes'],d['source_result_hashes']]:
  need(set(source)==set(comps),'Missing counter identity')
  for v in source.values():digest(v)
 x=d['interrupted_collection'];keys(x,['technical_cause','included_in_primary_statistics','raw_files','source_exception_sha256'])
 need(x['included_in_primary_statistics'] is False,'Interfered window entered primary statistics');text(x['technical_cause']);digest(x['source_exception_sha256'])
 for path,h in x['raw_files'].items():need(path.startswith('raw/interrupted/') and '..' not in path,'Unsafe interrupted artifact');digest(h)
 return d
