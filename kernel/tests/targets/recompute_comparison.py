"""Recompute the matched Cortex-M4 memory comparison from complete consoles."""
from pathlib import Path
import argparse
import hashlib
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
import record_io as json
import re

SCHEMA='lattice.m4_matched_memory.v1'
PROFILES=('pqm4','rate','recompute')
PARAMETERS=(44,65,87)
WRITABLE={'rng_state','active','cases','context','dlen','entropy_bytes','entropy_calls',
          'entropy_error','entropy_position','failed','generated','max_stack','max_workspace',
          'mlen','operation','signature_length','work','pk','msg','dom','sig','sk'}


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))


def recompute(path):
    path=Path(path).resolve();root=path.parent;data=read(path)
    need(data['schema']==SCHEMA and data['target']=='mps2-an386/cortex-m4','Unexpected target')
    need(data['source_core_commit']=='1df22ecdfa7ff762dae87cca3d83c4f633b4a156','Changed core identity')
    need(data['pqm4_commit']=='5e5cc76d0b072ee7077e58afcbc619a1a67a53b4' and
         data['mupq_commit']=='ddcccedb2db9d0250856bd58ee5c46c61e506c5d','Changed independent baseline')
    need(len(data['images'])==9 and data['timing_collected'] is False,'Changed experiment size or type')
    matched={};summaries=[]
    for image,(profile,parameter) in zip(data['images'],((p,k) for p in PROFILES for k in PARAMETERS),strict=True):
        need((image['implementation'],image['parameter'])==(profile,parameter),'Reordered target image')
        artifacts={}
        for key in ('console','symbols','memory_ledger','linker','image'):
            descriptor=image[key];file=(root/descriptor['path']).resolve()
            need(file.is_relative_to(root) and file.is_file() and file.stat().st_size==descriptor['bytes'] and sha(file)==descriptor['sha256'],'Changed target artifact')
            artifacts[key]=file
        records=[]
        for line in json.record_lines(artifacts['console'].read_text(encoding='utf-8')):
            if not line.strip():continue
            need(line.startswith(('{','<record')),'Unrecognized console output')
            records.append(json.loads(line))
        begin=[r for r in records if r.get('event')=='begin']
        controls=[r for r in records if r.get('event')=='watermark_positive_control']
        rows=[r for r in records if r.get('event')=='case']
        end=[r for r in records if r.get('event')=='summary']
        need(len(begin)==len(controls)==len(end)==1 and len(rows)==76 and len(records)==79,'Incomplete target execution')
        need(begin[0]['parameter']==parameter and begin[0]['pointer_bits']==32 and
             begin[0]['timing_collected'] is False and controls[0]['ok'] is True,'Changed target or instrumentation')
        need(end[0]['cases']==76 and end[0]['failures']==0 and end[0]['timing_collected'] is False,'Target failures')
        generated=[r for r in rows if r['kind']=='fixed_seed_roundtrip']
        standard=[r for r in rows if r['kind'] in ('acvp_positive','acvp_negative')]
        need(len(generated)==72 and len(standard)==4 and
             {(r['index'],r['operation']) for r in generated}=={(i,o) for i in range(24) for o in range(3)},'Target input coverage differs')
        need({(r['operation'],r['kind']) for r in standard}==
             {(0,'acvp_positive'),(1,'acvp_positive'),(2,'acvp_positive'),(2,'acvp_negative')},
             'Missing standard operation or negative signature')
        for r in rows:
            need(r['parameter']==parameter and r['ok'] is True and r['operation'] in range(3), 'Failed target case')
            need(r['rc']==(-1 if r['kind']=='acvp_negative' else 0),'Changed target return code')
            key=(parameter,r['kind'],r['index'],r['operation'])
            value=tuple(r[k] for k in ('rc','ok','entropy_requests','entropy_bytes','public_output_hex'))
            if profile=='pqm4':matched[key]=value
            else:need(matched[key]==value,'Different public output or entropy transcript')
            need(re.fullmatch(r'(?:[0-9a-f]{2})*',r['public_output_hex']) is not None,'Invalid public byte encoding')
            if r['kind']=='fixed_seed_roundtrip':
                expected={44:(1312,2420),65:(1952,3309),87:(2592,4627)}[parameter]
                need(len(r['public_output_hex'])==(2*expected[r['operation']] if r['operation']<2 else 0),'Incomplete public output')
            need(0<=r['stack_watermark_bytes']<16384-32,'Target stack guard crossed')
        stack=[max(r['stack_watermark_bytes'] for r in rows if r['operation']==o) for o in range(3)]
        workspace=[max(r['workspace_bytes'] for r in rows if r['operation']==o) for o in range(3)]
        need(end[0]['operation_stack_watermarks']==stack and end[0]['operation_workspace_peaks']==workspace,'Summary differs from complete target cases')
        symbols={}
        for line in artifacts['symbols'].read_text().splitlines():
            match=re.fullmatch(r'([0-9a-fA-F]+)\s+([A-Za-z?])\s+(\S+)',line)
            if match:symbols[match[3]]=(int(match[1],16),match[2])
        writable={name for name,(_,kind) in symbols.items() if kind in ('d','b','D','B') and not name.startswith('__')}
        need(writable<=WRITABLE,'Additional writable entity requires explicit accounting')
        api=('lc_get_sizes','lc_context_init','lc_keypair','lc_sign','lc_verify','lc_encaps','lc_decaps','lc_error_string')
        need(image['retained_public_entries']==sorted(name for name in api if name in symbols),'Retained public-entry scope differs from the actual image')
        if profile=='pqm4':need('context' not in symbols and 'work' not in symbols,'Unexpected baseline workspace');context=0
        else:
            need(symbols['dlen'][0]-symbols['context'][0]==32,'Changed Cortex-M context size')
            context=32
        ledger=read(artifacts['memory_ledger'])
        need(ledger['test_stack_reservation_bytes']==16384 and ledger['control_stack_reservation_bytes']==2048,'Changed reserved stack')
        need(ledger['emulator_image_occupied_ram_bytes']==ledger['writable_image_span_bytes']+ledger['code_and_rodata_load_bytes'],'Changed mapped image accounting')
        components=sum(ledger[k] for k in ('data_bytes','bss_excluding_arena_io_stacks_bytes','arena_reservation_with_guards_bytes','caller_io_reservation_with_guards_bytes','test_stack_reservation_bytes','control_stack_reservation_bytes','alignment_gap_bytes'))
        need(components==ledger['writable_image_span_bytes'],'Memory segments do not sum')
        capacity=0 if profile=='pqm4' else ledger['arena_reservation_with_guards_bytes']-64
        need(max(workspace)==capacity,'Target caller workspace differs from measured common peak')
        summaries.append(dict(implementation=profile,parameter=parameter,image_sha256=image['image']['sha256'],
            observations=76,workspace_peaks_by_operation=workspace,stack_watermarks_by_operation=stack,
            common_workspace_bytes=capacity,maximum_observed_stack_bytes=max(stack),context_bytes=context,
            persistent_algorithm_globals_bytes=0,workspace_plus_observed_stack_and_context_bytes=capacity+max(stack)+context,
            caller_io_with_guards_bytes=ledger['caller_io_reservation_with_guards_bytes'],
            test_stack_reserved_bytes=16384,control_stack_reserved_bytes=2048,
            writable_image_reserved_bytes=ledger['writable_image_span_bytes'],
            code_and_rodata_including_test_vectors_bytes=ledger['code_and_rodata_load_bytes'],
            complete_emulator_mapped_bytes=ledger['emulator_image_occupied_ram_bytes']))
    need(len(matched)==228,'Missing matched inputs')
    return dict(schema='lattice.m4_matched_memory_statistics.v1',observations_sha256=sha(path),
        images=9,executed_records=684,paired_inputs=228,generated_public_outputs_compared=144,
        standard_cases_per_implementation=12,timing_collected=False,rows=summaries)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('observations',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();need(not args.output.exists(),'Fresh output required')
    result=recompute(args.observations)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:value for key,value in result.items() if key!='rows'}))
