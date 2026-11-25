"""Validate completed bounded regressions and compare deterministic observations."""
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
import argparse, hashlib, record_io as json
LEVELS=[512,768,1024,44,65,87]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def validate(folder):
 p=folder/'result.xml';r=json.loads(p.read_text(encoding='utf-8'))
 if r['status']!='PASS' or r['formal_timing']:raise ValueError('Not a completed correctness regression: '+str(folder))
 if sha(folder/'commands.xml')!=r['commands_sha256'] or sha(folder/'sequence.exe')!=r['exe_sha256']:raise ValueError('Artifact hash differs')
 commands=json.loads((folder/'commands.xml').read_text(encoding='utf-8'))
 for c in commands:
  if sha(folder/c['log'])!=c['log_sha256']:raise ValueError('Log hash differs')
  allowed=c['log'] in ['compiler.log','positive_control.log'] and r['mode']!='release'
  if c['exit_code'] and not allowed:raise ValueError('Unexpected failed command')
 if r['mode']=='release':
  if sha(folder/'latticecore.dll')!=r['package']['dll_sha256']:raise ValueError('Staged DLL hash differs')
 else:
  pc=r['positive_control']
  if not pc['detected'] or pc['exit_code']==0 or sha(folder/'positive_control.log')!=pc['log_sha256']:raise ValueError('Missing detected positive control')
  if sha(folder/'positive_control.c')!=pc['source_sha256']:raise ValueError('Positive source hash differs')
  text=(folder/'positive_control.log').read_text(encoding='utf-8')
  required=['AddressSanitizer','heap-buffer-overflow'] if r['mode']=='asan' else ['runtime error','signed integer overflow']
  if any(s not in text for s in required):raise ValueError('Positive diagnostic missing')
 keys=[(s,p) for s in r['seeds'] for p in LEVELS]
 if [(x['seed'],x['parameter']) for x in r['records']]!=keys:raise ValueError('Missing, duplicated or reordered records')
 for x in r['records']:
  if x['status']!='PASS' or x['sequence_steps']!=r['sequence_count'] or x['parser_mutations_each']!=r['mutation_count_each_parser']:raise ValueError('Count mismatch')
  if len(x['actions'])!=12 or min(x['actions'])<=0 or sum(x['actions'])!=x['sequence_steps']:raise ValueError('Action coverage mismatch')
  if x['mutated_primary_accepted']+x['mutated_primary_rejected']!=x['parser_mutations_each']:raise ValueError('Parser count mismatch')
 return r
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--inputs',nargs='+',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if a.output.exists():raise ValueError('Refuse evidence overwrite')
 rows=[];control=None
 for path in a.inputs:
  path=path.resolve();r=validate(path)
  if control is None:control=r['records']
  if r['records']!=control:raise ValueError('Deterministic regression observations differ: '+str(path))
  rows.append({'path':str(path),'result_sha256':sha(path/'result.xml'),'mode':r['mode'],'identity':r.get('package',r.get('instrumented_configuration')),'records':len(r['records']),'positive_control':r.get('positive_control')})
 summary={'schema':'latticecore.robustness.r2.summary.v1','status':'PASS','groups':rows,'parameters':LEVELS,
  'records':sum(x['records'] for x in rows),'sequence_steps':sum(x['sequence_steps'] for x in control)*len(rows),
  'parser_mutation_inputs':sum(x['parser_mutations_each']*2 for x in control)*len(rows),
  'same_deterministic_observations':True,'comparison_scope':'Exact equality of action counts, accepted/rejected counts, callback counts and noncryptographic FNV64 transcript digest. Full signature byte comparisons and standards oracles are separate.',
  'limitations':['Bounded fixed-seed regression, not coverage-guided fuzzing or exhaustive verification.','Separate portable sanitizer executables do not instrument the released native GCC DLL or assembly.','ASan does not identify every internal arena suballocation boundary.','No constant-time, performance, embedded full-RAM or standards-certification claim follows.'],'formal_timing':False}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');print(json.dumps({k:summary[k] for k in ('status','records','sequence_steps','parser_mutation_inputs')}))
if __name__=='__main__':main()
