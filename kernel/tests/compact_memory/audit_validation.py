"""Verify the complete compact-core validation and emulated-target evidence index."""
from pathlib import Path
from collections import Counter
import json as _canonical_json
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
import argparse, hashlib, record_io as json, re, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from publicschemas.application_v1 import read,need,keys,digest,integer,sha

def recompute(path):
 path=Path(path).resolve();root=path.parent;data=read(path)
 keys(data,('schema','platform','production_source_commit','scope','builds','explicit_taint','artifacts'))
 need(data['schema']=='lattice.compact_validation_index.v1' and data['platform']=='linux_aarch64','Unknown compact validation schema')
 artifacts={}
 for x in data['artifacts']:
  keys(x,('path','sha256','bytes','source_sha256','category','projection'));digest(x['sha256']);digest(x['source_sha256']);integer(x['bytes'])
  need(x['path'] not in artifacts and not Path(x['path']).is_absolute() and '..' not in Path(x['path']).parts,'Invalid artifact identity')
  source=root/x['path'];need(source.is_file() and source.stat().st_size==x['bytes'] and sha(source)==x['sha256'],'Changed compact artifact')
  if x['projection']=='original_bytes':need(x['sha256']==x['source_sha256'],'Changed original bytes')
  artifacts[x['path']]=x
 libraries={}
 for item in data['builds']:
  b=read(root/item['id']/'build.xml');need(b['binary']['sha256']==item['library_sha256']==sha(root/item['id']/'liblatticecore.so'),'Library identity mismatch')
  need(hashlib.sha256(_canonical_json.dumps(b['source_hashes'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==item['source_hashes_sha256'],'Source manifest mismatch')
  libraries[item['library_sha256']]=item
  for mode in ('shared','static'):
   p=root/item['id']/('probe_'+mode+'.records.xml')
   probe_text=p.read_text(encoding='utf-8')
   records=[json.loads(line) for line in json.record_lines(probe_text) if line.strip()]
   need(len(records)==6 and {r['parameter'] for r in records}=={512,768,1024,44,65,87},'Incomplete instrumented interface coverage')
   need(all(r['status']=='PASS' and r['random_failure'] and r['overlap_rejected'] and r['oom_recovery'] for r in records),'Failed instrumented functional check')
   captured=b['public_checks'][mode]['stdout']
   different_formats=captured.lstrip().startswith('<record') != probe_text.lstrip().startswith('<record')
   if different_formats:
    captured=json.capture_text(captured)
    probe_text=json.capture_text(probe_text)
   need(b['public_checks'][mode]['exit_code']==0 and captured==probe_text,'Changed instrumented probe output')
 acvp=read(root/'correctness/acvp.xml');counts=dict(Counter(r['status'] for r in acvp['records']))
 need(counts.get('PASS')==2580 and counts.get('OUTSIDE_PUBLIC_SCOPE')==1620 and counts.get('FAIL',0)==0,'Changed ACVP coverage')
 need(all(r['library_sha256'] in libraries for r in acvp['records']),'Unbound ACVP library')
 differences=signatures=capacity=0
 for cfg in ('compact-rate','compact-recompute','compact-rate-shared'):
  diff=read(root/'correctness'/(cfg+'_complete_differential.xml'));sig=read(root/'correctness'/(cfg+'_signatures300.xml'));cap=read(root/'correctness'/(cfg+'_normal_capacity.xml'))
  need(all(x['sha256'] in libraries for x in diff['libraries'].values()),'Unbound differential library')
  need({c['parameter'] for c in diff['cells']}=={512,768,1024,44,65,87} and all(c['complete_sequences']==100 and c['outputs_byte_equal'] and c['entropy_requests_equal'] for c in diff['cells']),'Incomplete full-operation differential checks')
  differences+=sum(c['complete_sequences'] for c in diff['cells'])
  need({r['parameter'] for r in sig['records']}=={44,65,87} and all(r['count']==len(r['cases'])==100 and r['complete_signatures_byte_equal'] and r['mutated_signatures_rejected'] for r in sig['records']),'Incomplete signature differential checks')
  signatures+=sum(r['count'] for r in sig['records'])
  need(cap['status']=='PASS' and cap['library_sha256'] in libraries and cap['total_records']==864 and cap['sequential_concurrent_exact_match'],'Invalid normal-capacity recovery evidence');capacity+=cap['total_records']
 taint_counts=Counter()
 for item in data['explicit_taint']:
  cfg=item['configuration'];need(item['library_sha256'] in libraries and item['exit_code']==item['expected_exit_code'],'Unbound/failed taint observation')
  need(item['harness_sha256']==sha(root/'methods/taint.c'),'Changed explicit secret marking harness')
  text=(root/'taint'/(cfg+'_taint.txt')).read_text();result=read(root/'taint'/(cfg+'_run.log'))
  need(result['status']=='PASS' and result['cases']==96 and result['entropy_requests']==192 and result['secret_key_marked_each_case'],'Incomplete explicit taint workload')
  if cfg=='positive-branch':need(item['exit_code']==77 and 'Conditional jump or move depends on uninitialised value' in text and 'lc_hint_mask.h:2' in text,'Missing secret-branch positive control')
  else:need(item['exit_code']==0 and 'ERROR SUMMARY: 0 errors' in text,'Detected secret-dependent use')
  taint_counts[item['role']]+=1
 base=read(root/'taint_libraries/compact-recompute/build.xml')['source_hashes'];positive=read(root/'taint_libraries/positive-branch/build.xml')['source_hashes']
 delta=[k for k in set(base)|set(positive) if base.get(k)!=positive.get(k)]
 need(delta==['src/dsa_compact/build/sign_bitmap_stream_alias/adapted/src/lc_hint_mask.h'],'Positive control changes exceed the single hint predicate')
 initial=read(root/'ordinary_memcheck/initial_positive_control_attempt.xml');need(initial==[dict(label='positive_control',returncode=0,expected_exit=77)],'Initial unmarked diagnostic must be retained separately')
 targets=[]
 for name in ('m4-rate','m4-recompute','rv32-rate','rv32-recompute'):
  folder=root/'targets'/name;b=read(folder/'build.xml');checks=read(folder/'checks.xml');memory=read(folder/'memory_ledger.xml')
  need(sha(folder/'latticecore.elf')==b['elf_sha256'] and sha(folder/'image.ld')==b['linker_sha256'],'Changed target image/linker')
  candidates=[folder/name for name in ('qemu_console.txt.xml','qemu_console.txt')
              if (folder/name).relative_to(root).as_posix() in artifacts]
  need(len(candidates)==1,'Missing or ambiguous bound target console')
  console=[json.loads(line) for line in json.record_lines(candidates[0].read_text(encoding='utf-8'))
           if line.startswith(('{','<record'))]
  need(console==checks['records'] and console[-1]['event']=='summary' and console[-1]['cases']==117 and console[-1]['failures']==0,'Incomplete target execution')
  need(memory==b['memory'] and memory['writable_image_span_bytes']<=b['configured_writable_ram_bytes']==65536,'Changed target resource ledger')
  targets.append(dict(id=name,image_sha256=b['elf_sha256'],cases=117,writable_image_bytes=memory['writable_image_span_bytes'],maximum_observed_stack_bytes=console[-1]['maximum_observed_test_stack_bytes']))
 return dict(schema='lattice.compact_validation_statistics.v1',observations_sha256=sha(path),status='PASS',artifacts=len(artifacts),instrumented_libraries=len(libraries),acvp_counts=counts,complete_differential_sequences=differences,complete_signature_byte_comparisons=signatures,normal_capacity_records=capacity,explicit_taint=dict(taint_counts),initial_unmarked_positive_control=initial,targets=targets)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('observations',type=Path);p.add_argument('--output',type=Path);a=p.parse_args();r=recompute(a.observations)
 if a.output:need(not a.output.exists(),'Fresh result required');a.output.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(r))
