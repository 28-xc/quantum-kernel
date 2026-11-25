"""Execute complete applications under explicit total mutable-memory budgets.

The reservation includes serialized objects, application state, shared workspace,
the qualified whole-call stack, globals/TLS, and reserved external heap. Every
attempt retains its process output, followed by a normal-capacity recovery run.
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
import argparse, record_io as json, os
import application_owner as owner
from application_timing import checked,read,valid_ids,ref

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--build',type=Path,required=True);p.add_argument('--config',type=Path,required=True)
 p.add_argument('--budgets',default='32768,49152,65536,98304,131072')
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 budgets=[int(v) for v in a.budgets.split(',')]
 owner.require(budgets==sorted(set(budgets)) and all(4096<=v<=1048576 and v%32==0 for v in budgets),'Use increasing distinct 32-byte-aligned budgets')
 build,_=owner.loaded_build(a.build);cfg=read(a.config);owner.require(set(cfg)=={'libraries'},'Unexpected configuration fields');valid_ids([v['id']for v in cfg['libraries']])
 out=owner.fresh(a.output);runner=owner.Runner(out);rows=[];bindings=[]
 for v in cfg['libraries']:
  owner.require(set(v)=={'id','library','resources'},'Unexpected library fields');lib=checked(v['library']);resource=checked(v['resources']);d=read(resource)
  owner.require(d['status']=='PASS' and d['core']['sha256']==owner.sha(lib) and d['application']['sha256']==owner.sha(owner.app_module(build)),'Unbound application resources')
  bindings.append(dict(id=v['id'],library=ref(lib),resources=ref(resource)))
  for cell in d['cells']:
   fixed=cell['charged_bytes']-cell['workspace_bytes'];stack=cell['stack_reserved_bytes'];globals_=cell['library_globals_tls_bytes'];heap=cell['heap_reserved_bytes'];module=cell['application_module_globals_bytes']
   def execute(label,work,seed):
    argv=[owner.executable(build,'resource_probe'),lib,cell['kem'],cell['dsa'],cell['layout'],1,work,stack,globals_,seed,2,0,0,heap,module]
    extra={'LD_PRELOAD':str(build/'heap_audit.so')}if os.name!='nt'else None
    rec=runner.run(label,argv,extra_env=extra);result=next(x for x in rec['events']if 'status'in x);h=next(x for x in rec['events']if x.get('event')=='heap_lifetime')
    owner.require(result['status']in ('PASS','WORKSPACE_INSUFFICIENT') and result['cleared'] and result['guards_ok'] and not result['timed'] and result['heap_errors']==0,'Invalid bounded application result')
    owner.require(result['stack_watermark_bytes']<=stack and result['workspace_high_water']<=work and h['unsupported']==0 and h['tls_slot_allocations']==0 and h['peak_requested']<=heap,'Reservation violated')
    if result['status']=='PASS':owner.require(result['rc']==0 and result['completed_flows']==2 and result['transcript_matches'],'Incomplete application')
    else:owner.require(result['rc']==-5,'Unexpected capacity result')
    return result
   for budget in budgets:
    for repeat in range(2):
     seed=202610075109+104729*repeat+cell['kem']
     work=((budget-fixed)//32)*32
     row=dict(configuration=v['id'],kem=cell['kem'],dsa=cell['dsa'],layout=cell['layout'],budget_bytes=budget,fixed_bytes=fixed,seed=seed)
     if work<32:
      row.update(status='RESERVATION_INSUFFICIENT',executed=False,minimum_charged_bytes=fixed+32)
     else:
      observed=execute('bounded',work,seed);owner.require(observed['charged_bytes']<=budget and observed['charged_bytes']==fixed+work,'Budget arithmetic mismatch')
      row.update(status=observed['status'],executed=True,workspace_bytes=work,observed=observed)
     restored=execute('restored',cell['workspace_bytes'],seed);owner.require(restored['status']=='PASS','Normal-capacity recovery failed');row['restoration']=restored;rows.append(row)
     owner.write(out/'progress.xml',rows)
 owner.loaded_build(build)
 for v in bindings:checked(v['library']);checked(v['resources'])
 result=dict(schema='lattice.application_budget.v1',status='PASS',budgets=budgets,libraries=bindings,application_build=ref(build/'build.xml'),tool_sha256=owner.sha(__file__),commands_sha256=owner.sha(out/'commands.xml'),cells=rows,timing_collected=False,scope='Two fixed complete application flows per bounded execution; insufficient workspace returns through normal cleanup. Normal-capacity restoration is a separate execution with its own recorded reservation.')
 owner.write(out/'result.xml',result);print(json.dumps(dict(status='PASS',trials=len(rows),budgets=budgets,successful=sum(x['status']=='PASS'for x in rows),result=owner.reference(out/'result.xml'))))

if __name__=='__main__':main()
