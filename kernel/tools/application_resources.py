"""Measure normal fixed-pool application resources on Windows or Linux/AArch64.

Application construction, lifecycle and error recovery have a separate check
entry. An operation-level workspace failure is collected only when requested.
The original build tool and all compiled application inputs remain unchanged.
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
from application_owner import (ROOT,EXPORTS,PAIRS,require,workspace,loaded_build,
 reference,inventory,app_module,fresh,Runner,executable,sha,write)

def probe_import_support(core_image,app_image,build):
    """Account for additional handlers in the frozen Windows application probe."""
    require(not app_image['unhandled_allocator_imports'],'Unsupported application allocator import')
    pending=core_image['unhandled_allocator_imports']
    support=[]
    if pending and os.name=='nt':
        header=build/'source/tests/resources_pq/windows_heap_audit.h'
        text=header.read_text(encoding='utf-8')
        known={('msvcrt.dll','_strdup'):('audit_real_strdup=(audit_strdup_fn)*slot;replacement=(void*)audit_strdup;',
                                      'audit_add(p,strlen(s)+1,'),
               ('kernel32.dll','TlsAlloc'):('audit_real_tlsalloc=(audit_tlsalloc_fn)*slot;replacement=(void*)audit_tlsalloc;',
                                           'audit_tlsalloc_calls++')}
        for item in pending:
            key=(item['module'].lower(),item['name'])
            require(key in known,'Unsupported core allocator import')
            require(all(token in text for token in known[key]),'Missing compiled probe allocator handler')
            support.append(dict(module=item['module'],name=item['name'],handler_source_sha256=sha(header)))
    else:
        require(not pending,'Unsupported core allocator import')
    return support

def resources(args):
    require(256<=args.stack_bytes<=262144 and args.stack_bytes%16==0,'Stack must be a multiple of16 in256..262144')
    require(0<=args.heap_bound<=1048576,'Heap reservation outside supported range')
    if args.failure_workspace is not None:
        require(args.failure_workspace < args.workspace,'Failure workspace must be smaller than the normal workspace')
    b,manifest=loaded_build(args.build);core=args.library.resolve();core_id=reference(core)
    core_image=inventory(core,['lc_get_sizes','lc_context_init','lc_keypair','lc_encaps','lc_decaps','lc_sign','lc_verify','lc_error_string']);app_image=inventory(app_module(b),EXPORTS)
    probe_supported=probe_import_support(core_image,app_image,b)
    module_globals=app_image['writable_image_plus_single_thread_tls_bytes']
    globals_=core_image['writable_image_plus_single_thread_tls_bytes'];out=fresh(args.output);runner=Runner(out)
    def trial(label,k,d,layout,fresh_,seed,work,stack,flows=4,control=0,allowed=(0,)):
        argv=[executable(b,'resource_probe'),core,k,d,layout,fresh_,work,stack,globals_,seed,flows,0,control,args.heap_bound,module_globals]
        extra={'LD_PRELOAD':str(b/'heap_audit.so')} if os.name!='nt' else None
        row=runner.run(label,argv,allowed,extra_env=extra);events=row['events'];result=next((x for x in events if 'status' in x),None);heap=next((x for x in events if x.get('event')=='heap_lifetime'),None)
        return row,result,heap
    # Both controls run with a legal roomy stack; no intentional overflow is executed.
    controls=((1,16384),(3,16384))
    for control,stack in controls:
        row,result,heap=trial('instrument-control',512,44,0,1,6179,args.workspace,stack,1,control)
        require(result is not None and result['status']=='PASS','Instrument control failed')
        if control==3:require(result['outside_heap_peak']==96,'Heap positive control failed')
    normal=[];recovery=[]
    for seed_index in range(4):
        for k,d in PAIRS:
            for fresh_ in (0,1):
                pair=[]
                for layout in (0,1):
                    row,result,heap=trial('normal',k,d,layout,fresh_,202610031612+seed_index*104729+k,args.workspace,args.stack_bytes)
                    require(result['status']=='PASS' and result['guards_ok'] and result['cleared'] and result['transcript_matches'] and result['completed_flows']==4,'Application resource check failed')
                    require(not result['timed'] and result['batch_ticks']==0 and result['stack_watermark_bytes']<=args.stack_bytes and result['workspace_high_water']<=args.workspace,'Invalid resource boundary')
                    require(result['heap_errors']==0 and heap['unsupported']==0 and heap['tls_slot_allocations']==0 and heap['peak_requested']<=args.heap_bound,'Invalid heap/resource accounting')
                    normal.append(result);pair.append(result)
                require(pair[0]['transcript']==pair[1]['transcript'],'Layout transcript mismatch')
    if args.failure_workspace is not None:
        for k,d in PAIRS:
            for layout in (0,1):
                row,failed,heap=trial('insufficient',k,d,layout,1,202610041615+k,args.failure_workspace,args.stack_bytes,1)
                require(failed['status']=='WORKSPACE_INSUFFICIENT' and failed['rc']==-5 and failed['cleared'] and failed['guards_ok'],'Capacity failure handling changed')
                row,restored,heap=trial('restored-capacity',k,d,layout,1,202610041615+k,args.workspace,args.stack_bytes,1)
                require(restored['status']=='PASS' and restored['cleared'] and restored['guards_ok'],'Restored capacity failed')
                recovery.append(dict(kem=k,dsa=d,layout=layout,failure=failed,restored=restored,same_process=False))
    cells=[]
    for k,d in PAIRS:
        for layout in (0,1):
            group=[x for x in normal if x['kem']==k and x['layout']==layout];require(len(group)==8,'Incomplete resource cell')
            keys=('pool_bytes','application_state_bytes','serialized_owner_bytes','workspace_bytes','stack_reserved_bytes','library_globals_tls_bytes','application_globals_bytes','application_module_globals_bytes','charged_bytes')
            for key in keys:require(len({x[key] for x in group})==1,'Inconsistent charged resources')
            cells.append(dict(kem=k,dsa=d,layout=layout,**{key:group[0][key] for key in keys},maximum_stack_watermark=max(x['stack_watermark_bytes'] for x in group),maximum_workspace_high_water=max(x['workspace_high_water'] for x in group),maximum_observed_heap=max(x['outside_heap_peak'] for x in group),heap_reserved_bytes=args.heap_bound,flows=32))
    require(reference(core)==core_id,'Core identity changed');loaded_build(b)
    result=dict(schema='lattice.application_resources.v1',status='PASS',core=core_id,application=reference(app_module(b)),build=reference(b/'build.xml'),core_image=core_image,application_image=app_image,program_bytes=core_image['program_non_debug_image_bytes']+app_image['program_non_debug_image_bytes'],cells=cells,normal_batches=48,normal_flows=192,capacity_recovery=recovery,capacity_recovery_count=len(recovery),capacity_recovery_scope='Explicit operation-level insufficient-workspace and fresh-process restoration' if recovery else 'Collected separately by application functional and interface checks; no operation-level shortage is assumed for this core',positive_controls=len(controls),commands_sha256=sha(out/'commands.xml'),inventory_tool_sha256=sha(ROOT/'tests/resources/image_inventory.py'),resource_tool_sha256=sha(Path(__file__)),timing_collected=False,scope='Fixed complete workflows with both serialized-owner layouts. Charged memory includes the state/object/workspace pool, protected full-application stack, library globals/TLS, application control globals and reserved external heap. Stack watermarks describe the executed inputs.')
    result['additional_probe_supported_imports']=probe_supported
    write(out/'result.xml',result);print(json.dumps(dict(status='PASS',result=reference(out/'result.xml'),program_bytes=result['program_bytes'],cells=[dict(kem=x['kem'],dsa=x['dsa'],layout=x['layout'],charged_bytes=x['charged_bytes']) for x in cells])))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True)
    p.add_argument('--library',type=Path,required=True)
    p.add_argument('--workspace',type=workspace,required=True)
    p.add_argument('--stack-bytes',type=int,required=True)
    p.add_argument('--heap-bound',type=int,default=0)
    p.add_argument('--failure-workspace',type=workspace,
                   help='Optional operation-level insufficient capacity, below normal capacity; omit when the core has no such workspace requirement')
    p.add_argument('--output',type=Path,required=True)
    resources(p.parse_args())

if __name__=='__main__':main()
