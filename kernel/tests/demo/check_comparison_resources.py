"""Check actual published resource joins, budget decisions and identity rejection."""
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
import argparse, copy, hashlib, record_io as json, sys, tempfile
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from publicschemas import comparison_resources as model

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--view',type=Path,required=True)
 parser.add_argument('--output',type=Path,required=True)
 a=parser.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 view=a.view.resolve();data=model.load(view);checks=[]
 def test(name,action):
  action();checks.append(name)
 def rejected(action):
  try:action()
  except (ValueError,KeyError,AssertionError):return
  raise AssertionError('Invalid identity was accepted')
 # The time driver's larger arena must not replace measured algorithm memory.
 stats={}
 for s in data['studies']:
  p=model.checked(view.parent,s['statistics']);d=model.read(p);stats[d['dataset_id']]=d
 profiles={'schema':'lattice.deployment_profiles.v2','profiles':[
  dict(platform=p['platform'],configuration=p['configuration'],binary_sha256=p['binary_sha256'],workspace_bytes=p['reserved_components']['workspace_bytes'])
  for p in data['points'] if p['deployment_recipe']], 'scope':'Exact qualified deployment images.'}
 for p in data['points']:
  if not p['deployment_recipe']:continue
  request=dict(platform=p['platform'],timing_dataset=p['statistics_dataset'],ram_bytes=p['core_reserved_bytes'],program_bytes=p['program_bytes'])
  def accepted():
   r=model.select(data,stats[p['statistics_dataset']],request,profiles)
   assert r['selected']['binary_sha256']==p['binary_sha256']
   assert r['selected']['measurement_workspace_bytes']==p['measurement_workspace_bytes']
   assert r['selected']['workspace_bytes']==p['reserved_components']['workspace_bytes']
  test(p['platform']+' exact budget and distinct timing capacity',accepted)
  for field in ('ram_bytes','program_bytes'):
   r=dict(request);r[field]-=1
   test(p['platform']+' '+field+' below exact requirement',lambda r=r: (None if model.select(data,stats[p['statistics_dataset']],r,profiles)['selected'] is None else (_ for _ in ()).throw(AssertionError('Insufficient budget accepted'))))
 # Alter only the wrapper. External files remain immutable and hashes are checked.
 original=model.read(view)
 with tempfile.TemporaryDirectory(prefix='resource-identity-',dir=view.parent) as temp:
  out=Path(temp)/'view.xml'
  # Copy the small wrapper next to the original so all relative descriptors retain
  # their intended meaning; the separate temporary filename prevents overwrite.
  sibling=view.parent/(Path(temp).name+'.xml')
  try:
   def invalid(name,mutate):
    d=copy.deepcopy(original);mutate(d);sibling.write_text(json.dumps(d),encoding='utf-8')
    test(name,lambda:rejected(lambda:model.load(sibling)))
   invalid('changed statistics hash',lambda d:d['studies'][0]['statistics'].__setitem__('sha256','0'*64))
   invalid('changed resource hash',lambda d:d['studies'][0]['resources'].__setitem__('sha256','0'*64))
   invalid('changed observations hash',lambda d:d['studies'][0]['observations'].__setitem__('sha256','0'*64))
   invalid('deployment image substitution',lambda d:d['deployment_configurations'][0].__setitem__('binary_sha256','0'*64))
   invalid('common context image substitution',lambda d:d['deployment_configurations'][0].__setitem__('common_context',d['deployment_configurations'][1]['common_context']))
   invalid('parent-directory traversal',lambda d:d['studies'][0]['resources'].__setitem__('path','../outside.xml'))
   invalid('duplicate study',lambda d:d['studies'].append(copy.deepcopy(d['studies'][0])))
  finally:sibling.unlink(missing_ok=True)
 result=dict(status='PASS',view_sha256=hashlib.sha256(view.read_bytes()).hexdigest(),checks=checks,points=len(data['points']),source_sha256=hashlib.sha256(Path(model.__file__).read_bytes()).hexdigest())
 (a.output/'result.xml').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(dict(status='PASS',checks=len(checks),points=len(data['points']))))
if __name__=='__main__':main()
