"""Fixed rejection cases derived from an explicitly supplied completed archive.

The copies below are altered validator fixtures, never measurement results.
No binaries are run and the supplied original archive is read-only.
"""
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
import argparse, copy, importlib.util, record_io as json, shutil, subprocess, sys
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('import_complete',ROOT/'tools/import_complete_operations.py');tool=importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--study',type=Path,required=True);p.add_argument('--configuration',type=Path,required=True);p.add_argument('--labels',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve();out.mkdir(exist_ok=False,parents=True);source=a.study.resolve();labels=tool.read(a.labels)
 original_manifest=tool.read(source/'manifest.xml');original_records=tool.read(source/'commands.xml');original_result=tool.read(source/'result.xml')
 cases=['duplicate_json_key','unknown_configuration_field','unknown_manifest_field','changed_boundary','incomplete_run','nonzero_exit','csv_hash_changed','csv_missing','relative_escape','absolute_raw_path','wrong_clock_conversion','failed_sample','changed_output_pair','changed_workspace','unknown_driver_field','nonempty_stderr','duplicate_public_label','private_audit_inside_output']
 results=[]
 for name in cases:
  folder=out/name;folder.mkdir();(folder/'raw').mkdir();m=copy.deepcopy(original_manifest);records=copy.deepcopy(original_records);result=copy.deepcopy(original_result)
  # Two first records are sufficient for all fixed rejection locations below.
  for rec in records:
   rec['command'][7]=str((folder/rec['raw_csv']).resolve())
  for rec in records[:2]:
   for key in ('raw_csv','log','stderr'):shutil.copyfile(source/rec[key],folder/rec[key])
  first=records[0];logpath=folder/first['log'];log=tool.read(logpath);mapping=dict(labels);audit=folder/'audit.xml';target=out/(name+'-public')
  if name=='unknown_configuration_field':m['configuration']['study_role']='altered_fixture'
  elif name=='unknown_manifest_field':m['unexpected']='altered_fixture'
  elif name=='changed_boundary':m['measured_boundary']='operation-only'
  elif name=='incomplete_run':result['completed']-=1
  elif name=='nonzero_exit':first['exit_code']=7
  elif name=='csv_hash_changed':first['raw_sha256']='0'*64
  elif name=='csv_missing':(folder/first['raw_csv']).unlink()
  elif name=='relative_escape':first['raw_csv']='raw/../manifest.xml'
  elif name=='absolute_raw_path':first['raw_csv']=str((source/original_records[0]['raw_csv']).resolve())
  elif name in ('wrong_clock_conversion','failed_sample'):
   path=folder/first['raw_csv'];lines=path.read_text().splitlines(keepends=True);row=lines[1].rstrip('\r\n').split(',')
   row[5]='999999999.000' if name=='wrong_clock_conversion' else row[5]
   if name=='failed_sample':row[6]='-6'
   lines[1]=','.join(row)+'\n';path.write_text(''.join(lines));first['raw_sha256']=tool.sha(path)
  elif name=='changed_output_pair':
   second=records[1];path=folder/second['log'];v=tool.read(path);v['output_sequence_sha256']='0'*64;second['output_sequence_sha256']='0'*64;path.write_text(json.dumps(v));second['log_sha256']=tool.sha(path)
  elif name=='changed_workspace':log['workspace_reserved']+=32
  elif name=='unknown_driver_field':log['unexpected']='altered_fixture'
  elif name=='nonempty_stderr':path=folder/first['stderr'];path.write_text('fixed negative diagnostic\n');first['stderr_sha256']=tool.sha(path)
  elif name=='duplicate_public_label':keys=list(mapping);mapping[keys[1]]=mapping[keys[0]]
  elif name=='private_audit_inside_output':audit=target/'audit.xml'
  if name in ('changed_workspace','unknown_driver_field'):logpath.write_text(json.dumps(log));first['log_sha256']=tool.sha(logpath)
  (folder/'manifest.xml').write_text(json.dumps(m));(folder/'commands.xml').write_text(json.dumps(records));(folder/'completed_calls.records.xml').write_text(''.join(json.dumps(r)+'\n' for r in records))
  if name=='duplicate_json_key':path=folder/'manifest.xml';s=path.read_text();path.write_text(s[:-1]+',"schema":"latticecore.blocked.v1"}')
  result.update(manifest_sha256=tool.sha(folder/'manifest.xml'),commands_sha256=tool.sha(folder/'commands.xml'),journal_sha256=tool.sha(folder/'completed_calls.records.xml'))
  (folder/'result.xml').write_text(json.dumps(result))
  try:tool.project(folder,a.configuration,mapping,'fixed-negative-fixture','windows_x86_64',target,audit)
  except (ValueError,OSError) as error:
   assert not target.exists() and not audit.exists(),name
   expected={'duplicate_json_key':'Duplicate JSON field','unknown_configuration_field':'Undeclared or missing fields','unknown_manifest_field':'Undeclared or missing fields','changed_boundary':'Changed measurement boundary','incomplete_run':'Changed or incomplete completion','nonzero_exit':'Failed process or changed run identity','csv_hash_changed':'Missing or changed artifact','csv_missing':'Missing or escaping archive artifact','relative_escape':'Unsafe archive path','absolute_raw_path':'Artifact outside raw directory','wrong_clock_conversion':'Incorrect clock conversion','failed_sample':'Failed or reordered sample','changed_output_pair':'Unpaired actual input/output sequence','changed_workspace':'Missing or changed successful driver condition','unknown_driver_field':'Unknown driver fields','nonempty_stderr':'Nonempty process diagnostic','duplicate_public_label':'Duplicate public labels','private_audit_inside_output':'Separate acquisition, public output and local audit required'}
   assert expected[name] in str(error),(name,str(error),expected[name])
   results.append(dict(case=name,rejected=True,error_type=type(error).__name__,message=str(error)))
  else:raise AssertionError('Accepted negative case: '+name)
 # Exercise the documented direct script entry from its own tools directory.
 # A module-only import does not expose sibling names shadowing the stdlib.
 cli_output=out/'cli-observations';cli_audit=out/'cli-audit.xml'
 argv=[sys.executable,'-X','utf8','-B',str(ROOT/'tools/import_complete_operations.py'),'--input',str(source),'--configuration',str(a.configuration.resolve()),'--labels',str(a.labels.resolve()),'--dataset-id','direct-cli-check','--platform','windows_x86_64','--output',str(cli_output),'--audit',str(cli_audit)]
 cli=subprocess.run(argv,cwd=ROOT/'tools',capture_output=True,text=True,encoding='utf-8',timeout=180)
 (out/'cli.stdout.txt').write_text(json.capture_text(cli.stdout),encoding='utf-8');(out/'cli.stderr.txt').write_text(cli.stderr,encoding='utf-8')
 assert cli.returncode==0 and not cli.stderr,cli.stderr
 direct=json.loads(cli.stdout);assert direct['recorded_runs']==len(original_records) and direct['sample_rows']==original_result['raw_rows']
 assert direct['manifest_sha256']==tool.sha(cli_output/'observations.xml')
 tool.write(out/'result.xml',dict(status='PASS',scope='Fixed altered acquisition fixtures and direct CLI success; no benchmark or cryptographic execution.',original_manifest=tool.describe(source/'manifest.xml'),tool=tool.describe(ROOT/'tools/import_complete_operations.py'),test=tool.describe(__file__),cases=results,direct_cli=dict(command=argv,exit_code=cli.returncode,summary=direct,stdout=tool.describe(out/'cli.stdout.txt'),stderr=tool.describe(out/'cli.stderr.txt'),audit=tool.describe(cli_audit))))
 print(json.dumps(dict(status='PASS',fixed_rejections=len(results),result_sha256=tool.sha(out/'result.xml'))))
if __name__=='__main__':main()
