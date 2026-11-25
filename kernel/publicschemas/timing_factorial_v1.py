"""Closed six-input-family observations for complete ML-KEM decapsulation."""
from .verification_v2 import keys,need,digest,integer,text,token
SCHEMA='lattice.decapsulation_factorial.v1'
def validate(d):
 keys(d,['schema','dataset_id','platform','core_source_commit','libraries','protocol','records','original_screen_observations','sources','source_measurements_sha256','scope'])
 need(d['schema']==SCHEMA and d['platform']=='linux_aarch64','Factorial platform/schema changed');token(d['dataset_id']);need(len(d['core_source_commit'])==40,'Core identity missing')
 need(len(d['libraries'])==2,'Two actual libraries required')
 for x in d['libraries']:
  keys(x,['id','binary_sha256']);token(x['id']);digest(x['binary_sha256'])
 p=d['protocol'];keys(p,['jobs','total_observations','groups_per_block','cpu','timer','workspace_bytes','warmup_groups','combinations','input_semantics','timed_boundary','oracle','statistics','source_protocol_sha256'])
 need(p['cpu']==2 and p['timer']=='CLOCK_MONOTONIC_RAW' and p['workspace_bytes']==262144 and p['warmup_groups']==1000,'Timing boundary changed')
 need(p['groups_per_block']==1000 and p['total_observations']==10920000,'Fixed observation count changed')
 need(p['combinations']=={'0':'FF','1':'RF','2':'FR','3':'RR','4':'FQ','5':'RQ'},'Input families changed');digest(p['source_protocol_sha256'])
 for k in ['input_semantics','timed_boundary','oracle']:text(p[k])
 need(len(p['jobs'])==len(d['records'])==10,'Finite schedule incomplete');seen=set();total=0
 for job,r in zip(p['jobs'],d['records']):
  keys(job,['name','parameter','seed','groups','positive']);token(job['name']);integer(job['seed'],1)
  need(job['parameter'] in (512,768,1024) and type(job['positive']) is bool,'Input identity changed')
  need(job['groups']==(10000 if job['positive'] else 100000),'Finite group count changed')
  keys(r,['job','metadata','artifacts','source_record_sha256']);need(r['job']==job,'Observation order changed');digest(r['source_record_sha256'])
  meta=r['metadata'];keys(meta,['status','standard_keypairs_compared','oracle_calls','groups','observations','warmup_groups','positive','cpu','pool_fnv64','rng_after_pool','checksum','public_bytes_per_key'])
  need(meta['status']=='PASS' and meta['standard_keypairs_compared']==257 and meta['oracle_calls']==3084 and meta['cpu']==2,'Independent oracle missing')
  need(meta['groups']==job['groups'] and meta['observations']==job['groups']*12 and meta['positive']==job['positive'],'Group metadata inconsistent')
  need(meta['warmup_groups']==1000 and meta['public_bytes_per_key']==384*(job['parameter']//256)+64,'Input byte layout changed')
  expected=['.csv','.public.bin','.ct.bin','.sponge.bin']+(['.positive_bits.bin'] if job['positive'] else [])
  keys(r['artifacts'],expected)
  for h in r['artifacts'].values():digest(h)
  if not job['positive']:
   pair=(job['parameter'],job['seed']);need(pair not in seen,'Repeated input cell');seen.add(pair)
  total+=meta['observations']
 need(len(seen)==9 and total==p['total_observations'],'Nine input cells or complete rows missing')
 for s in d['original_screen_observations']:
  keys(s,['library','binary_sha256','protocol_sha256','result_sha256','samples_per_job','threshold_abs_t','records'])
  token(s['library']);digest(s['binary_sha256']);digest(s['protocol_sha256']);digest(s['result_sha256'])
  need(s['samples_per_job']==100000 and s['threshold_abs_t']==4.5 and len(s['records'])==78,'Original finite screen omitted')
  for r in s['records']:
   keys(r,['id','mode','parameter','seed','positive','detected','raw_sha256','history'])
   digest(r['raw_sha256']);need(type(r['detected']) is bool and len(r['history'])==10,'Original threshold history omitted')
   need(r['detected']==any(abs(v['welch_t'])>=4.5 for v in r['history']),'Original flag changed')
 for k,v in d['sources'].items():token(k);digest(v)
 digest(d['source_measurements_sha256'])
 for value in d['scope']:text(value)
 return d
