"""Independent application-latency and primitive-batch reproduction checks."""
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
import argparse, copy, importlib, record_io as json, shutil, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from publicschemas.application_v1 import read, need, sha

def negative_tests(module,path,output):
 need(not output.exists(),'Fresh test output directory required');output.mkdir(parents=True)
 original=read(path);collection='jobs' if 'jobs' in original else 'processes';checks=[]
 def reject(name,action):
  try:action()
  except ValueError as error:checks.append(dict(case=name,status='PASS_REJECTED',reason=str(error)))
  else:raise ValueError('Altered evidence accepted: '+name)
 for name in ('missing_record','changed_library','unknown_field'):
  data=copy.deepcopy(original)
  if name=='missing_record':data[collection].pop()
  elif name=='changed_library':data[collection][0]['configuration']='unknown-library'
  else:data['unlisted_management_field']='not part of the scientific schema'
  reject(name,lambda data=data:module.validate_observations(data))
 from publicschemas.application_v1 import loads
 field='<field><name>schema</name><integer>1</integer></field>'
 for name,wire,body in [('duplicate_json_key','{"schema":1,"schema":2}',field+field),
                        ('nonfinite_json','{"x":NaN}','<field><name>x</name><number>NaN</number></field>'),
                        ('overflowing_float','{"x":1e9999}','<field><name>x</name><number>1e9999</number></field>')]:
  try:loads(wire)
  except ValueError:pass
  else:raise ValueError('Invalid transport value accepted: '+name)
  target=output/(name+'.xml')
  target.write_text('<record format="typed-xml-v1"><object>'+body+'</object></record>',encoding='utf-8')
  reject(name,lambda target=target:read(target))
 for name in ('changed_sample_byte','deleted_sample_with_updated_hash','changed_time_with_updated_hash'):
  directory=output/name;directory.mkdir();data=copy.deepcopy(original);descriptor=data[collection][0]['raw'];target=directory/descriptor['path'];target.parent.mkdir(parents=True);shutil.copyfile(path.parent/descriptor['path'],target)
  raw=target.read_bytes();lines=raw.splitlines(keepends=True)
  if name=='changed_sample_byte':target.write_bytes(raw+b'\n')
  elif name=='deleted_sample_with_updated_hash':target.write_bytes(b''.join(lines[:-1]))
  else:
   # An impossible duration preserves the SHA check while challenging the numeric contract.
   parts=lines[1].decode().rstrip('\r\n').split(',');parts[2 if collection=='jobs' else 5]='-1';lines[1]=(','.join(parts)+'\n').encode();target.write_bytes(b''.join(lines))
  if name!='changed_sample_byte':descriptor.update(sha256=sha(target),bytes=target.stat().st_size)
  obs=directory/'observations.xml';obs.write_text(json.dumps(data),encoding='utf-8');reject(name,lambda obs=obs:module.recompute(obs))
 result=dict(status='PASS',observations_sha256=sha(path),cases=checks);(output/'result.xml').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kind',choices=['application-latency','primitive-batches'],required=True);p.add_argument('observations',type=Path);p.add_argument('--statistics',type=Path);p.add_argument('--output',type=Path);p.add_argument('--negative-tests',type=Path);a=p.parse_args()
 module=importlib.import_module('publicschemas.'+{'application-latency':'application_latency_v1','primitive-batches':'primitive_samples_v1'}[a.kind]);computed=module.recompute(a.observations)
 if a.statistics:need(computed==read(a.statistics),'Published statistics differ from independent recomputation')
 if a.output:
  need(not a.output.exists(),'Fresh statistics output required');a.output.write_text(json.dumps(computed,indent=2)+'\n',encoding='utf-8')
 if a.negative_tests:negative_tests(module,a.observations.resolve(),a.negative_tests)
 print(json.dumps(dict(status='PASS',counts=computed['counts'],negative_tests=9 if a.negative_tests else 0)))
if __name__=='__main__':main()
