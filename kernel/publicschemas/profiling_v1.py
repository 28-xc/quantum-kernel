"""Recompute instruction-sample counts from public, hash-bound raw observations."""
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
import collections, csv, hashlib, record_io as json, re

SCHEMA='lattice.instruction_samples.windows.v1'
FIELDS={'schema','dataset_id','platform','measurement','libraries','cells','driver_sha256',
 'crypto_library_sha256','acquisition_manifest_sha256','source_result_sha256'}
CELL_FIELDS={'id','configuration','parameter','operation','iterations','seed','worker_cpu','observer_cpu',
 'timer_period_ms','qpc_frequency','workspace_reserved','samples','core_samples','outside_core_samples',
 'dropped','context_failures','resume_failures','raw'}
RULES=[('encoding_and_representation',r'pack|frombytes|tobytes|compress|encode|decode'),
       ('shake_and_keccak',r'keccak|shake|sha3'),
       ('sampling',r'rej_|cbd|uniform|noise|challenge'),
       ('ntt_and_inverse',r'ntt|invntt'),
       ('cleanup_and_arena',r'zero|arena|memset|wipe'),
       ('polynomial_arithmetic',r'montgomery|reduce|tomont|basemul|mulcache|pointwise|crt|poly_add|poly_sub'),
       ('protocol_and_other_inlined_code',r'.*')]

def need(ok,message):
 if not ok:raise ValueError(message)
def keys(x,names):need(type(x) is dict and set(x)==set(names),'Unexpected fields')
def integer(x,minimum=0):need(type(x) is int and x>=minimum,'Invalid integer')
def sha(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def read(p):
 def pairs(v):
  d={}
  for k,x in v:need(k not in d,'Duplicate JSON key');d[k]=x
  return d
 return json.loads(Path(p).read_text(encoding='utf-8'),object_pairs_hook=pairs,
   parse_constant=lambda x:(_ for _ in ()).throw(ValueError('Nonfinite JSON')))
def bound(root,d,kind):
 keys(d,('path','sha256'));need(re.fullmatch(r'[0-9a-f]{64}',d['sha256']) is not None,'Invalid digest')
 need(type(d['path']) is str and re.fullmatch(kind+r'/[a-zA-Z0-9_-]+\.(?:json|csv)',d['path']) is not None,'Invalid artifact path')
 p=(root/d['path']).resolve();need(p.is_relative_to(root.resolve()) and p.is_file(),'Missing or escaping artifact')
 need(sha(p)==d['sha256'],'Artifact identity changed');return p
def category(label):
 return next(name for name,pattern in RULES if re.search(pattern,label,re.I))

def recompute(path):
 path=Path(path).resolve();root=path.parent;data=read(path);keys(data,FIELDS)
 need(data['schema']==SCHEMA and data['platform']=='windows_x86_64','Unexpected profiling dataset')
 need(type(data['dataset_id']) is str and re.fullmatch(r'[a-zA-Z0-9_-]+',data['dataset_id']) is not None,'Invalid dataset ID')
 for k in ('driver_sha256','crypto_library_sha256','acquisition_manifest_sha256','source_result_sha256'):
  need(type(data[k]) is str and re.fullmatch(r'[0-9a-f]{64}',data[k]) is not None,'Invalid acquisition identity')
 need(data['measurement']=={'method':'suspended_own_worker_instruction_pointer','sample_period_ms':1,
  'quantity':'instruction_sample_count','latency_estimator':False,'sample_trimming':False,
  'label_scope':'exact_disassembly_labels_including_inlined_code','category_rule_version':1,
  'message_bytes':1024,'context_bytes':0,'input_scope':'fixed_key_and_message_fresh_operation_coins'},'Changed sampling method')
 libraries={};artifact_paths=set()
 for lib in data['libraries']:
  keys(lib,('configuration','binary_sha256','mapping'))
  name=lib['configuration'];need(re.fullmatch(r'[a-zA-Z0-9_-]+',name) is not None and name not in libraries,'Invalid/duplicate configuration')
  need(re.fullmatch(r'[0-9a-f]{64}',lib['binary_sha256']) is not None,'Invalid binary identity')
  m=read(bound(root,lib['mapping'],'mapping'));artifact_paths.add(lib['mapping']['path'])
  keys(m,('binary_sha256','image_bytes','instructions'));need(m['binary_sha256']==lib['binary_sha256'],'Mapping binary mismatch')
  integer(m['image_bytes'],1);lookup={}
  for ins in m['instructions']:
   keys(ins,('rva','instruction','disassembly_label','label_rva','same_address_nm_aliases'))
   integer(ins['rva'],1);need(ins['rva']<m['image_bytes'] and ins['rva'] not in lookup,'Invalid/duplicate instruction')
   need(type(ins['instruction']) is str and type(ins['disassembly_label']) is str,'Invalid disassembly label')
   integer(ins['label_rva'],1);need(ins['label_rva']<=ins['rva'],'Label after instruction')
   need(type(ins['same_address_nm_aliases']) is list and all(type(s) is str for s in ins['same_address_nm_aliases']),'Invalid aliases')
   lookup[ins['rva']]=ins
  libraries[name]=(lib,m,lookup)
 result=[];seen=set();totals=collections.Counter()
 for cell in data['cells']:
  keys(cell,CELL_FIELDS);name=cell['configuration'];need(name in libraries,'Unknown configuration')
  need(cell['parameter'] in (512,768,1024,44,65,87) and cell['operation'] in (0,1,2),'Invalid complete operation')
  ident=(name,cell['parameter'],cell['operation']);need(ident not in seen,'Duplicate operation cell');seen.add(ident)
  need(cell['id']==f'{name}_{cell["parameter"]}_{cell["operation"]}','Changed cell identity')
  for key in CELL_FIELDS-{'id','configuration','raw'}:integer(cell[key])
  need(cell['iterations']>0 and cell['qpc_frequency']>0 and cell['workspace_reserved']==262144 and cell['timer_period_ms']==1,'Changed profile conditions')
  need(cell['worker_cpu']!=cell['observer_cpu'],'Observer affinity overlaps worker')
  need(cell['samples']==cell['core_samples']+cell['outside_core_samples'],'Sample total differs')
  need(cell['dropped']==cell['context_failures']==cell['resume_failures']==0,'Incomplete acquisition')
  raw=bound(root,cell['raw'],'raw');need(cell['raw']['path'] not in artifact_paths,'Reused raw artifact');artifact_paths.add(cell['raw']['path'])
  lib,m,lookup=libraries[name];counts=collections.Counter();labels=collections.Counter();groups=collections.Counter();outside=0;previous=-1;size=0
  with raw.open(newline='',encoding='utf-8') as f:
   reader=csv.DictReader(f);need(reader.fieldnames==['sample_id','observer_qpc','core_instruction_rva'],'Changed raw fields')
   for i,row in enumerate(reader):
    keys(row,reader.fieldnames)
    need(int(row['sample_id'])==i,'Reordered/omitted sample');qpc=int(row['observer_qpc']);rva=int(row['core_instruction_rva'])
    need(qpc>=previous and 0<=rva<m['image_bytes'],'Invalid timestamp or instruction offset');previous=qpc;size+=1
    if rva==0:outside+=1;continue
    need(rva in lookup,'Unmapped sampled instruction');ins=lookup[rva];counts[rva]+=1
    labels[(ins['disassembly_label'],ins['label_rva'])]+=1;groups[category(ins['disassembly_label'])]+=1
  need(size==cell['samples'] and outside==cell['outside_core_samples'] and sum(counts.values())==cell['core_samples'],'Raw counts differ')
  groups['outside_core']=outside;totals.update(groups)
  result.append(dict(id=cell['id'],binary_sha256=lib['binary_sha256'],samples=size,core_samples=sum(counts.values()),
    groups=dict(sorted(groups.items())),labels=[dict(label=k[0],label_rva=k[1],samples=v) for k,v in sorted(labels.items())]))
 expected={(name,p,o) for name in libraries for p in (512,768,1024,44,65,87) for o in (0,1,2)}
 need(seen==expected,'Missing complete-operation profile')
 actual={p.relative_to(root).as_posix() for sub in ('raw','mapping') for p in (root/sub).iterdir()}
 need(actual==artifact_paths,'Undeclared or missing public profile artifact')
 return dict(schema='lattice.instruction_samples.recomputed.v1',observations_sha256=sha(path),dataset_id=data['dataset_id'],
   platform=data['platform'],category_rules=[dict(category=n,label_regex=p) for n,p in RULES],cells=result,
   sample_count=sum(totals.values()),group_counts=dict(sorted(totals.items())),scope='Counts of sampled instruction labels; per-cell counts retain acquisition density')
