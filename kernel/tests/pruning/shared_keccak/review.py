"""Append-only linked-image review; count actual addresses, not spellings."""
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
import argparse, record_io as json, re, subprocess, sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from size_variants import sha,read,write,binary_info

def main():
 p=argparse.ArgumentParser();p.add_argument('--candidate',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--objdump',default='objdump');a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);rows=[]
 for folder in a.candidate:
  folder=folder.resolve();r=read(folder/'result.xml');control=Path(r['control']['result']).parent;c=read(control/'result.xml');name='lto' if r['lto'] else 'nolto'
  if sha(folder/'latticecore.dll')!=r['candidate']['sha256'] or sha(control/'latticecore.dll')!=r['control']['library_sha256']:raise ValueError('Image changed')
  control_entities=read(control/'shared_entities.xml')['entities'];candidate_entities=read(folder/'inspection/entities.xml')['entities']
  def core(es):
   selected=[x for x in es if re.fullmatch(r'(mlk|mld)_keccakf1600_permute_c',x['symbol'])]
   return {'symbols':selected,'unique_machine_addresses':len({x['address'] for x in selected})}
  co=core(control_entities);ca=core(candidate_entities)
  if ca['unique_machine_addresses']!=1:raise ValueError('No single actual retained core')
  constant=lambda es:[x for x in es if 'KeccakF_RoundConstants' in x['symbol']]
  candidate_static=binary_info(folder/'probe_static.exe');control_static=c['inspections']['whole_image_static'];head=subprocess.run([a.objdump,'-p',str(folder/'probe_static.exe')],capture_output=True,text=True,check=True)
  header=out/(name+'_static_headers.txt');header.write_text(json.capture_text(head.stdout),encoding='utf-8');candidate_static['dependencies']=re.findall(r'DLL Name:\s*(\S+)',head.stdout);candidate_static['dependency_bytes_included']=False
  sections={x['name']:x['memory_bytes'] for x in r['control_image']['sections'] if x['allocated']};changed=[]
  for s in r['candidate_image']['sections']:
   if s['allocated'] and s['memory_bytes']!=sections.get(s['name'],0):changed.append({'section':s['name'],'control':sections.get(s['name'],0),'candidate':s['memory_bytes'],'delta':s['memory_bytes']-sections.get(s['name'],0)})
  rows.append({'lto':r['lto'],'optimization':r['optimization'],'prototype_result':{'path':str(folder/'result.xml'),'sha256':sha(folder/'result.xml')},'control_result':{'path':str(control/'result.xml'),'sha256':sha(control/'result.xml')},'control_core':co,'candidate_core':ca,'control_constants':constant(control_entities),'candidate_constants':constant(candidate_entities),'candidate_shared_wrapper':r['shared_entity'],'actual_cross_family_references':r['actual_cross_family_references'],'shared_ro_bytes':{'control':r['control_image']['readonly_allocated_bytes'],'candidate':r['candidate_image']['readonly_allocated_bytes'],'delta':r['readonly_delta_bytes']},'changed_loaded_sections':changed,'static_whole_image':{'control':control_static,'candidate':candidate_static,'readonly_delta':candidate_static['readonly_allocated_bytes']-control_static['readonly_allocated_bytes']},'correctness':{key:{'path':str(folder/key),'sha256':sha(folder/key)} for key in ['primitive_oracle.xml','acvp.xml','differential.xml','shared_probe_run.log','static_probe_run.log']},'interpretation':'The LTO control already has aliases at one core address; explicit sharing has no code-saving claim.' if co['unique_machine_addresses']==1 else 'The control has distinct core addresses; the candidate removes one retained core and shares one round-constant object. Net image reduction, not symbol count, is the size result.'})
 write(out/'review.xml',{'status':'LINKED_ENTITY_AND_SIZE_REVIEW_COMPLETE','rows':rows,'script_sha256':sha(__file__),'scope':['Actual PE images on this Windows compiler configuration; AArch64 not executed.','No equality of symbol count or source text is treated as equality of machine-code entities.','Static whole-image includes test caller and linked core; external runtime/OS DLL bytes remain separate.','Correctness is bounded oracle, published applicable vectors and interface tests, not formal proof.','Call costs require a separate paired whole-API experiment.']})
 print('Actual-address and loaded-section review complete')
if __name__=='__main__':main()
