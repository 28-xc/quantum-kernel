"""Recompute bounded complete applications from process records, without execution."""
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
import hashlib, record_io as json

SCHEMA='lattice.application_budget_observations.v1'
CONFIGURATIONS={'lattice-compact-native','lattice-cache40-native','lattice-cache56-native',
                'lattice-speed32-native','lattice-sign-pipeline-native','native-lowram-lto','native-full-lto'}
METHOD_CONTROL='lattice-separated32-control'
ADDITIONAL_CONFIGURATIONS={'lattice-cache48-native','native-lowram-os-lto'}
PAIRS={(512,44),(768,65),(1024,87)}
BUDGETS=[32768,49152,65536,98304,131072]

def recompute(observations_path):
    observations_path=Path(observations_path).resolve();root=observations_path.parent
    def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
    observed=json.loads(observations_path.read_text(encoding='utf8'))
    assert observed['schema']==SCHEMA and observed['platform'] in ('windows_x86_64','linux_aarch64')
    files={r['path']:r for r in observed['files']};assert len(files)==len(observed['files'])
    def path(name):
        rel=Path(name);assert not rel.is_absolute() and '..' not in rel.parts
        p=(root/rel).resolve();assert p.is_relative_to(root) and p.is_file()
        assert name in files and sha(p)==files[name]['sha256'] and p.stat().st_size==files[name]['bytes']
        return p
    def read(name):return json.loads(path(name).read_text(encoding='utf8'))
    def binary(name,measured):
        p=path(name)
        if sha(p)==measured:return
        from .deployment_image import verify_deployment_image
        receipt_name=observed['derivations'][name]
        verify_deployment_image(p.read_bytes(),read(receipt_name),measured_sha256=measured)
    for name in files:path(name)
    result=read('result.xml');commands=read('commands.xml')
    assert result['schema']=='lattice.application_budget.v1' and result['status']=='PASS'
    assert result['budgets']==BUDGETS and result['timing_collected'] is False
    assert result['commands_sha256']==sha(path('commands.xml'))
    build=read(result['application_build']['path'])
    assert sha(path(result['application_build']['path']))==result['application_build']['sha256']
    for n,h in build['artifacts'].items():binary('application/'+n,h)
    for s in build['sources']:assert sha(path('application/source/'+s['path']))==s['sha256']
    assert sha(path('measurement.py'))==result['tool_sha256']
    libraries={v['id']:v for v in result['libraries']};assert set(libraries) in (CONFIGURATIONS, CONFIGURATIONS | {METHOD_CONTROL}, CONFIGURATIONS | {METHOD_CONTROL} | ADDITIONAL_CONFIGURATIONS)
    resources={}
    for ident,lib in libraries.items():
        binary(lib['library']['path'],lib['library']['sha256'])
        record=read(lib['resources']['path']);assert sha(path(lib['resources']['path']))==lib['resources']['sha256']
        assert record['status']=='PASS' and record['core']['sha256']==lib['library']['sha256']
        resources[ident]={(c['kem'],c['dsa'],c['layout']):c for c in record['cells']}
        assert set(resources[ident])=={(k,d,l) for k,d in PAIRS for l in (0,1)}
    for command in commands:
        assert command['exit_code']==0
        for field in ('stdout','stderr'):
            f=path(command[field]['path']);assert sha(f)==command[field]['sha256']
        assert not path(command['stderr']['path']).read_text(encoding='utf8')
        events=[json.loads(s) for s in path(command['stdout']['path']).read_text(encoding='utf8').splitlines() if s.startswith('{')]
        assert events==command['events']
    cursor=0;seen=set();summary=[]
    def consume(label,value,work,stack,heap_bound):
        nonlocal cursor
        command=commands[cursor];cursor+=1;assert command['label']==label
        argv=command['command'];assert len(argv)==15
        assert argv[0].startswith('application/') and path(argv[0]).name in build['artifacts']
        assert argv[1]==libraries[ident]['library']['path']
        assert [int(v) for v in argv[2:]]==[k,d,layout,1,work,stack,value['library_globals_tls_bytes'],trial['seed'],2,0,0,heap_bound,value['application_module_globals_bytes']]
        event=next(x for x in command['events'] if 'status' in x)
        heap=next(x for x in command['events'] if x.get('event')=='heap_lifetime')
        assert event==value and event['guards_ok'] and event['cleared'] and event['heap_errors']==0
        assert event['timed'] is False or event['timed']==0
        assert event['workspace_high_water']<=work and event['stack_watermark_bytes']<=stack
        assert heap['unsupported']==0 and heap['tls_slot_allocations']==0 and heap['peak_requested']<=heap_bound
        if event['status']=='PASS':assert event['completed_flows']==2 and event['transcript_matches'] and event['rc']==0
        else:assert event['status']=='WORKSPACE_INSUFFICIENT' and event['rc']==-5
    for trial in result['cells']:
        ident=trial['configuration'];k=trial['kem'];d=trial['dsa'];layout=trial['layout'];budget=trial['budget_bytes']
        assert ident in libraries and (k,d) in PAIRS and layout in (0,1) and budget in BUDGETS
        assert trial['seed'] in {202610075109+k,202610075109+104729+k}
        key=(ident,k,d,layout,budget,trial['seed']);assert key not in seen;seen.add(key)
        resource=resources[ident][k,d,layout]
        fixed=resource['charged_bytes']-resource['workspace_bytes'];work=((budget-fixed)//32)*32
        assert trial['fixed_bytes']==fixed
        if work<32:
            assert trial['executed'] is False and trial['status']=='RESERVATION_INSUFFICIENT' and trial['minimum_charged_bytes']==fixed+32
        else:
            assert trial['executed'] is True and trial['workspace_bytes']==work
            assert trial['status']==trial['observed']['status']
            assert trial['observed']['charged_bytes']==fixed+work<=budget
            consume('bounded',trial['observed'],work,resource['stack_reserved_bytes'],resource['heap_reserved_bytes'])
        consume('restored',trial['restoration'],resource['workspace_bytes'],resource['stack_reserved_bytes'],resource['heap_reserved_bytes'])
        assert trial['restoration']['status']=='PASS' and trial['restoration']['charged_bytes']==resource['charged_bytes']
        summary.append(dict(configuration=ident,kem=k,dsa=d,layout=layout,budget_bytes=budget,seed=trial['seed'],status=trial['status']))
    expected=2*len(PAIRS)*2*len(BUDGETS)*len(libraries)
    assert len(seen)==expected and cursor==len(commands)
    return dict(schema='lattice.application_budget_summary.v1',dataset_id=observed['dataset_id'],platform=observed['platform'],
        observations_sha256=sha(observations_path),status='PASS',trials=expected,normal_capacity_restorations=expected,
        process_records=len(commands),successful=sum(x['status']=='PASS' for x in summary),
        configurations=[dict(id=x,library_sha256=libraries[x]['library']['sha256']) for x in sorted(libraries)],cells=summary)
