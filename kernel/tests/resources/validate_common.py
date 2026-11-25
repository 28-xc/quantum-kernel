"""Recheck the raw six-parameter common-context witness without executing it."""
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
import argparse, collections, copy, record_io as json
from controller import read,require,sha
from run_common import classify,ORDERS

def check(root,resource_path,library=None):
 r=read(root/'result.xml');resource=read(resource_path)
 require(r['status']==resource['status']=='PASS' and r['source_resource']['sha256']==sha(resource_path),'Changed/failed source resource')
 require(r['library']['sha256']==resource['dll_sha256'],'Different resource and common-witness binaries')
 if library is not None:require(sha(library)==resource['dll_sha256'],'Actual target bytes differ')
 for name in ('commands','trials'):require(sha(root/(name+'.xml'))==r[name+'_sha256'],'Changed '+name)
 for n,h in r['source_sha256'].items():require(Path(n).name==n and sha(root/'sources'/n)==h,'Changed/unsafe instrument source')
 exe=root/('common_probe.exe' if (root/'common_probe.exe').exists() else 'common_probe');require(sha(exe)==r['probe_sha256'],'Changed common probe')
 for c in read(root/'commands.xml'):
  require(c['exit_code']==0 and sha(root/Path(c['log']['path']).name)==c['log']['sha256'],'Changed/failed instrument command')
 cells=list(resource['cells'].values());require(len(cells)==18,'Incomplete resource scope')
 w=max(c['workspace_bytes'] for c in cells);s=max(c['stack_bytes'] for c in cells)
 require((r['workspace_common_bytes'],r['stack_common_bytes'])==(w,s),'Wrong fixed common W/S')
 parts=[w,s]
 for k in ('external_context_bytes','globals_bytes','outside_heap_bytes'):
  values={c[k] for c in cells};require(len(values)==1 and r[k] in values,'Changed metadata charge');parts.append(r[k])
 require(sum(parts)==r['full_reserved_core_budget_bytes'] and r['physical_RAM_measured'] is False and r['simultaneous_observed_peak_bytes'] is None,'Budget or physical/observed-peak overclaim')
 require(r['same_context_init_once_per_sequence'] and r['orders']==[list(x) for x in ORDERS] and r['seeds_per_order']>=24,'Changed common sequence method')
 trials=read(root/'trials.xml');require(len(trials)==r['trial_count'] and [t['id'] for t in trials]==list(range(len(trials))),'Incomplete/reordered raw trials')
 counts=collections.Counter();seeds={0:set(),1:set()};control_seen=[];checks=set();lower=set();budgets=[]
 for t in trials:
  cap,stack,seed,order,count,control=map(int,t['argv'][2:]);events=[json.loads(x) for x in json.record_lines(t['stdout']) if x.startswith(('{','<record'))]
  starts=[e for e in events if e.get('event')=='common_start'];require(len(starts)==1 and [starts[0][k] for k in ('arena_bytes','stack_bytes','seed','order','parameter_count','control')]==[cap,stack,seed,order,count,control],'Command/start identity mismatch')
  if t['classification']=='WINDOWS_ACCESS_OR_STACK_EXIT':
   require(t['exit_code']&0xffffffff in (0xc0000005,0xc00000fd) and not any(e.get('event')=='common_result' for e in events),'Wrong Windows abnormal exit');kind='WINDOWS_ACCESS_OR_STACK_EXIT';parsed=None
  else:kind,parsed=classify(t['exit_code'],events,cap,stack,order,count,control)
  require(kind==t['classification'] and parsed==t['result'],'Raw common classification differs');counts[kind]+=1
  purpose=t['purpose']
  if purpose=='instrument_control':control_seen.append((control,stack,kind));require(cap==262144,'Changed control arena')
  else:
   require(control==0 and stack==s,'Actual operation uses another stack')
   require(parsed['outside_heap_peak_requested_bytes']==r['outside_heap_bytes'],'Observed heap exceeds resource model')
  if purpose=='common_fixed_reservation':
   require(cap==w and count==6 and kind=='SUCCESS' and seed not in seeds[order],'Invalid/repeated common confirmation');seeds[order].add(seed)
  elif purpose=='interleaving_selfcheck':
   require(cap==w and kind=='SUCCESS' and (count,order) not in checks,'Bad selfcheck');checks.add((count,order))
  elif purpose=='lower_common_arena_oom':
   require(cap==w-32 and count==6 and kind=='WORKSPACE_OOM' and order not in lower,'Bad lower-capacity witness');lower.add(order)
  elif purpose=='fixed_total_budget':budgets.append(t['id']);require(count==6 and kind in ('SUCCESS','WORKSPACE_OOM'),'Bad budget witness')
  else:require(purpose=='instrument_control','Unexpected raw-trial purpose')
 require(control_seen[:1]==[(1,4096,'SUCCESS')] and len(control_seen)==4 and control_seen[1][0:2]==(2,4096) and control_seen[1][2] in ('PROTECTED_STACK_FAULT','WINDOWS_ACCESS_OR_STACK_EXIT') and control_seen[2:]==[(2,65536,'SUCCESS'),(3,16384,'SUCCESS')],'Missing/changed instrument controls')
 require(trials[3]['result']['outside_heap_peak_requested_bytes']==96 and trials[3]['result']['outside_heap_calls']>0,'Missing heap positive')
 require(checks=={(3,0),(3,1),(6,0),(6,1)} and lower=={0,1},'Incomplete interleaved/negative tests')
 require(all(len(x)==r['seeds_per_order'] for x in seeds.values()) and seeds[0]==seeds[1],'Incomplete paired confirmation seeds')
 require(len(r['budget_trials'])==10 and sorted(budgets)==sorted(b['trial'] for b in r['budget_trials']),'Missing budget trials')
 seen=set()
 for b in r['budget_trials']:
  t=trials[b['trial']];key=(b['budget_bytes'],b['order']);require(key not in seen,'Repeated budget trial');seen.add(key)
  cap=(b['budget_bytes']-sum(parts[1:]))//32*32
  require(b['arena_bytes']==int(t['argv'][2])==cap and b['charged_core_bytes']==cap+sum(parts[1:])<=b['budget_bytes'] and b['status']==t['classification'],'Misbound total budget')
 require(seen=={(x,o) for x in (16384,32768,65536,131072,262144) for o in (0,1)},'Changed budget grid')
 normal=next(t for t in trials if t['purpose']=='common_fixed_reservation');negative=[]
 for k,v in [('context_init_calls',2),('context_and_arena_identity_stable',False),('completed_operations',17),('canaries_ok',False),('same_context_reinitialized_recovery_ok',False),('heap_errors',1)]:
  bad=copy.deepcopy(normal['result']);bad[k]=v
  try:classify(0,[bad],w,s,0,6,0)
  except ValueError:negative.append(k)
  else:raise ValueError('Corrupted common record accepted '+k)
 return {'status':'PASS','source_result_sha256':sha(root/'result.xml'),'source_resource_sha256':sha(resource_path),'binary_sha256':resource['dll_sha256'],'trials':len(trials),'classification_counts':dict(counts),'negative_record_rejections':negative,'single_context_initialization_per_measured_sequence':True,'six_parameter_sequences':sum(map(len,seeds.values())),'physical_RAM_measured':False}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('measurement',type=Path);p.add_argument('--resource',type=Path,required=True);p.add_argument('--library',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();require(not a.output.exists(),'Fresh audit path required');d=check(a.measurement,a.resource,a.library);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(d,indent=2)+'\n');print('PASS',d['trials'])
if __name__=='__main__':main()
