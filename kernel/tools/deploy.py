"""Compile required parameter/operation sets and admit the actual image to explicit budgets.

Hosted budgets count the static deployment test image's allocated read-only plus
initialized bytes (P), and all writable image bytes (RAM), including its arena,
I/O, context and legal 64 KiB call-stack reservation exactly once. OS loader and
control-thread storage are separate. Target budgets count the complete emulator
image, including published input/expected constants and both target stacks.
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
import argparse, hashlib, record_io as json, os, shutil, subprocess, sys
from operation_selection import normalize,PARAMETERS
from public_recipes import RECIPES

ROOT=Path(__file__).resolve().parents[1]
TARGETS=('windows-x86_64','linux-aarch64','m4','rv32')
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,v):Path(p).write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

def validate(value):
    required={'schema','platform','parameters','operations','budgets'}
    optional={'workspace_bytes','recipes','test_stack_bytes','control_stack_bytes','tools','boundary_checks'}
    if not isinstance(value,dict) or set(value)-required-optional or required-set(value) or value['schema']!='lattice.deployment_request.v1':
        raise ValueError('Explicit deployment request schema required')
    if value['platform'] not in TARGETS:raise ValueError('Unsupported platform')
    parameters=value['parameters']
    if not isinstance(parameters,list) or not parameters or len(set(parameters))!=len(parameters) or not set(parameters)<=set(PARAMETERS):
        raise ValueError('Required parameters must be distinct standard parameters')
    operations=normalize(value['operations'],parameters)
    if operations is None:raise ValueError('Every required operation must be explicit')
    budget=value['budgets'];expected={'program_bytes','ram_bytes'}
    if value['platform'] in ('m4','rv32'):expected.add('writable_ram_bytes')
    if set(budget)!=expected or any(type(v)!=int or v<=0 for v in budget.values()):raise ValueError('All platform budget dimensions must be positive integers')
    value=dict(value)
    value.setdefault('recipes',['compact-rate','compact-recompute'])
    value.setdefault('workspace_bytes',12288 if all(x in ('compact-rate','compact-recompute') for x in value['recipes']) else 131072)
    w=value['workspace_bytes']
    if type(w)!=int or not 32<=w<=1048576 or w%32:raise ValueError('Workspace must be a 32-byte multiple')
    recipes=value['recipes']
    if not isinstance(recipes,list) or not recipes or len(recipes)>4 or len(recipes)!=len(set(recipes)):raise ValueError('Use one to four distinct, ordered supported recipes')
    for name in recipes:
        if name not in RECIPES or not RECIPES[name]['algorithm'].get('modified'):raise ValueError('Deployment requires a public kernel recipe')
        backend=RECIPES[name]['defaults']['backend']
        if value['platform'] in ('m4','rv32') and name not in ('compact-rate','compact-recompute'):raise ValueError('Target recipe is unsupported')
        if value['platform']=='windows-x86_64' and backend not in ('portable','x86_64'):raise ValueError('Recipe platform differs')
        if value['platform']=='linux-aarch64' and backend not in ('portable','aarch64'):raise ValueError('Recipe platform differs')
    for key in ('test_stack_bytes','control_stack_bytes'):
        if key in value and (type(value[key])!=int or value[key]<2048 or value[key]%32):raise ValueError('Legal aligned stack reservation required')
        if key in value and value['platform'] not in ('m4','rv32'):raise ValueError('Hosted validation reserves its fixed legal 64 KiB call stack')
    if value.get('boundary_checks') and value['platform'] not in ('m4','rv32'):raise ValueError('Linker boundary checks require a target image')
    return dict(value,parameters=[p for p in PARAMETERS if p in parameters],operations=operations)

def execute(request,output):
    request=validate(request);output=Path(output).resolve()
    if output.exists() or output==ROOT or output.is_relative_to(ROOT):raise ValueError('Fresh independent deployment directory required')
    output.mkdir(parents=True);write(output/'request.xml',request)
    records=[];attempts=[];python=[sys.executable,'-B']
    def run(argv,label,allow_failure=False):
        result=subprocess.run(list(map(str,argv)),cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace')
        log=output/(label+'.log');log.write_text(json.capture_text(result.stdout+result.stderr),encoding='utf-8')
        records.append(dict(argv=list(map(str,argv)),exit_code=result.returncode,log=log.name,log_sha256=sha(log)))
        write(output/'commands.xml',records)
        if result.returncode and not allow_failure:raise RuntimeError(label+' failed; retained log '+str(log))
        return result.returncode
    try:
        for index,recipe in enumerate(request['recipes']):
            directory=output/('configuration-'+str(index));parameters=','.join(map(str,request['parameters']))
            operations=json.dumps(request['operations'],separators=(',',':'));budget=request['budgets']
            if request['platform'] in ('m4','rv32'):
                command=python+[ROOT/'tools/build_targets.py','--target',request['platform'],'--profile',recipe.removeprefix('compact-'),
                    '--parameters',parameters,'--operations',operations,'--output',directory,'--workspace-bytes',request['workspace_bytes'],
                    '--stack-bytes',request.get('test_stack_bytes',4096),'--control-stack-bytes',request.get('control_stack_bytes',2048),
                    '--ram-bytes',budget['writable_ram_bytes'],'--code-bytes',budget['program_bytes'],'--total-image-ram-bytes',budget['ram_bytes'],'--run','--timeout-seconds','120']
                rc=run(command,'build-'+str(index),allow_failure=True)
                if rc:
                    log=directory/'link.txt'
                    rejected=log.is_file() and any(s in log.read_text(encoding='utf-8',errors='replace') for s in
                        ('code and data load exceed program budget','whole emulator image exceeds physical RAM budget',
                         'writable image exceeds configured RAM window','will not fit in region','overflowed by'))
                    if not rejected:raise RuntimeError('Target build or function check failed; see retained build log')
                    attempts.append(dict(recipe=recipe,parameters=request['parameters'],operations=request['operations'],budgets=budget,
                        accepted=False,reason='Actual target linker rejected the requested budget',
                        link_log=dict(path=log.relative_to(output).as_posix(),sha256=sha(log)),executed=False))
                    write(output/'attempts.xml',attempts);continue
                result=read(directory/'build.xml');memory=result['memory']
                resources=dict(program_bytes=memory['code_and_rodata_load_bytes'],ram_bytes=memory['emulator_image_occupied_ram_bytes'],
                    writable_ram_bytes=memory['writable_image_span_bytes'],accounting=memory)
                image=directory/'latticecore.elf';receipt=directory/'build.xml'
            else:
                plan=output/('plan-'+str(index)+'.xml')
                command=python+[ROOT/'tools/build.py','plan','--mode','pruned','--configuration',recipe,'--parameters',parameters,
                    '--operations',operations,'--probe-workspace',request['workspace_bytes'],'--probe-count','1','--output',plan]
                for key,val in request.get('tools',{}).items():
                    if key not in ('cc','ar','nm','objdump','size'):raise ValueError('Unknown tool override')
                    command+=['--'+key,val]
                run(command,'plan-'+str(index));run(python+[ROOT/'tools/build.py','build','--plan',plan,'--output',directory],'build-'+str(index))
                receipt=directory/'artifacts/result.xml';result=read(receipt);inspection=result['inspections']['whole_image_static']
                triple=result['target'];is_windows=any(x in triple for x in ('mingw','windows','w64'))
                if request['platform']=='windows-x86_64' and (not is_windows or 'x86_64' not in triple):raise ValueError('Actual compiler target differs from required platform')
                if request['platform']=='linux-aarch64' and not ('linux' in triple and 'aarch64' in triple):raise ValueError('Actual compiler target differs from required platform')
                resources=dict(program_bytes=inspection['readonly_allocated_bytes']+inspection['data_bytes'],ram_bytes=inspection['data_bytes']+inspection['bss_bytes'],
                    accounting=dict(scope='static managed image; host OS/loader/control stack separate',sections=inspection['sections'],
                        workspace_bytes=request['workspace_bytes'],call_stack_reservation_bytes=65536,components_already_in_writable_sections=True,
                        static_probe_checks=result['public_checks']['static']['rows']))
                image=directory/'artifacts'/inspection['path']
            accepted=all(resources[k]<=v for k,v in budget.items())
            item=dict(recipe=recipe,parameters=request['parameters'],operations=request['operations'],resources=resources,budgets=budget,
                accepted=accepted,build=dict(path=receipt.relative_to(output).as_posix(),sha256=sha(receipt)),image=dict(path=image.relative_to(output).as_posix(),sha256=sha(image)))
            attempts.append(item);write(output/'attempts.xml',attempts)
            if accepted:
                package=output/'deployment';package.mkdir()
                exports=[image]
                if request['platform'] not in ('m4','rv32'):
                    core=directory/'artifacts/core'
                    exports += [core/'liblatticecore.a',core/('latticecore.dll' if request['platform']=='windows-x86_64' else 'liblatticecore.so')]
                for path in exports:shutil.copyfile(path,package/path.name)
                for path in (ROOT/'include/latticecore.h',ROOT/'configs/pruned/latticecore_pruned.h'):shutil.copyfile(path,package/path.name)
                feature_lines=['/* Generated from the accepted deployment requirements. */','#ifndef LC_DEPLOYMENT_CAPABILITIES_H','#define LC_DEPLOYMENT_CAPABILITIES_H']
                from operation_selection import names
                for parameter in PARAMETERS:
                    for operation in names(parameter):
                        enabled=parameter in request['parameters'] and operation in request['operations'].get(str(parameter),[])
                        feature_lines.append('#define LC_DEPLOY_'+str(parameter)+'_'+operation.upper()+' '+str(int(enabled)))
                feature_lines+=['#define LC_DEPLOY_WORKSPACE_BYTES '+str(request['workspace_bytes']),'#endif']
                (package/'deployment_capabilities.h').write_text('\n'.join(feature_lines)+'\n',encoding='ascii')
                write(package/'requirements.xml',request);write(package/'resources.xml',resources)
                if request.get('boundary_checks'):
                    if request['platform'] not in ('m4','rv32'):raise ValueError('Executable linker boundary checks are available for target images')
                    run(python+[ROOT/'tools/deployment_boundaries.py','--build',directory,'--output',output/'boundary-checks'],'boundaries')
                result=dict(schema='lattice.deployment_result.v1',status='BUILT_VERIFIED_AND_WITHIN_BUDGET',request=request,selected=item,attempts=attempts,
                    operations_removed=[dict(parameter=p,operation=n) for p in request['parameters'] for n in __import__('operation_selection').names(p) if n not in request['operations'][str(p)]],
                    deployment_files=[dict(path=p.relative_to(output).as_posix(),sha256=sha(p),bytes=p.stat().st_size) for p in sorted(package.iterdir())],
                    commands_sha256=sha(output/'commands.xml'),timing_collected=False)
                write(output/'result.xml',result);return result
        raise ValueError('No requested recipe fits all budgets; required parameters and operations were preserved')
    except Exception as error:
        write(output/'failure.xml',dict(status='NOT_DEPLOYED',error=str(error),request=request,attempts=attempts));raise

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--request',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(execute(read(args.request),args.output)['status'])
