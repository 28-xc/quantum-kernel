"""Recompute fixed-vector and public-interface qualification from preserved records."""
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
import record_io as json, hashlib, csv, collections, argparse

def _probe_rows(record,declared,label,kind):
 base=label+'/probe_'+kind+'_run.log'
 names=[n for n in (base+'.xml',base) if n in declared]
 assert len(names)==1,('ambiguous or absent probe',base)
 raw=record(names[0]).read_text(encoding='utf8')
 return [json.loads(line) for line in json.record_lines(raw) if line.startswith(('{','<record'))]

def _recompute(root):
 root=Path(root).resolve();h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
 def local(name):
  rel=Path(name)
  assert not rel.is_absolute() and '..' not in rel.parts,name
  p=(root/rel).resolve();assert p.is_relative_to(root),name
  return p
 data=json.loads(local('observations.xml').read_text(encoding='utf-8'));assert data['schema']=='lattice.signing_pipeline_qualification.v1'
 declared={r['path'] for r in data['files']};assert len(declared)==len(data['files'])
 def record(name):
  assert name in declared,('unbound record',name)
  return local(name)
 def read(name):return json.loads(record(name).read_text(encoding='utf-8'))
 for r in data['files']:
  p=local(r['path']);assert p.is_file() and p.stat().st_size==r['bytes'] and h(p)==r['sha256'],r['path']
 out=[];seen=set();prefixes=set()
 for p in data['profiles']:
  platform=p['platform'];configuration=p['configuration'];label=p.get('path_prefix',platform);image=p['production_image_sha256']
  assert platform in ('windows','arm') and configuration and (platform,configuration) not in seen
  assert label not in prefixes;local(label);seen.add((platform,configuration));prefixes.add(label)
  a=read(label+'/acvp.xml');assert a['status']=='PASS' and a['binaries'][0]['sha256']==image
  counts=collections.Counter(x['status']for x in a['records']);assert counts=={'PASS':645,'OUTSIDE_PUBLIC_SCOPE':405} and a['counts']['FAIL']==0
  ids={(x['category'],x['tgId'],x['tcId'])for x in a['records']if x['status']=='PASS'};assert len(ids)==645
  assert all(x['library_sha256']==image for x in a['records']);assert a['used_workspace_erased_for_every_public_case']
  c=read(label+'/complete.xml');assert c['status']=='PASS' and image in [x['sha256']for x in c['libraries'].values()];assert sorted(x['parameter']for x in c['cells'])==[44,65,87,512,768,1024]
  assert all(x['outputs_byte_equal'] and x['entropy_requests_equal']for x in c['cells']);sequences=sum(x['complete_sequences']for x in c['cells']);assert sequences==1200
  s=read(label+'/signatures.xml');assert s['status']=='PASS' and image in [x['sha256']for x in s['libraries']];assert sorted(x['parameter']for x in s['records'])==[44,65,87]
  assert all(x['complete_signatures_byte_equal'] and x['same_context_alternating_keys'] and x['mutated_signatures_rejected']for x in s['records']);n=sum(x['count']for x in s['records']);assert n==900
  o=read(label+'/openssl/prepared.xml');assert o['status']=='PASS' and o['library']['sha256']==image and o['all_input_output_sequences_match']
  csvs=list(local(label+'/openssl').glob('*.csv'));assert len(csvs)==36;cases=[]
  for f in csvs:
   with record(f.relative_to(root).as_posix()).open(newline='')as z:r=list(csv.DictReader(z))
   assert len(r)==100 and all(x['status']=='0' and x['warmup']=='0'for x in r);cases+=r
  assert len(cases)==3600
  cap=read(label+'/capacity.xml');assert cap['status']=='PASS' and cap['library_sha256']==image and cap['sequential_concurrent_exact_match']
  probes={}
  for kind in ['shared','static']:
   rows=_probe_rows(record,declared,label,kind);assert rows and all(x['status']=='PASS'for x in rows);probes[kind]=len(rows)
  build=read(label+'/build.xml');assert build['binary']['sha256']==image
  out.append(dict(platform=platform,configuration=configuration,production_image_sha256=image,applicable_standard_vectors=645,outside_public_scope_records=405,total_vector_records=1050,complete_sequences=sequences,complete_signature_pairs=n,openssl_cross_comparisons=len(cases),public_probe_records=probes,capacity_and_recovery='PASS'))
 assert out
 return dict(schema='lattice.signing_pipeline_qualification_summary.v1',status='PASS',profiles=out,files_checked=len(data['files']))

SCHEMA='lattice.signing_pipeline_qualification.v1'
def recompute(observations_path):
 observations_path=Path(observations_path)
 d=_recompute(observations_path.parent)
 d.update(dataset_id='signing-pipeline-qualification',observations_sha256=hashlib.sha256(observations_path.read_bytes()).hexdigest())
 return d
