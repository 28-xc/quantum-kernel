"""Build six-parameter libraries, parameter subsets and arithmetic components."""
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
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from build_variants import CONFIGS
from native_options import add_arm_arguments, arm_values, arm_argv, ARM_OPTION_NAMES
from public_recipes import RECIPES, apply_plan_defaults
PARAMETERS = [512, 768, 1024, 44, 65, 87]

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(value, ensure_ascii=False, indent=2) + '\n'
    if not path.exists() or path.read_text(encoding='utf-8') != text:
        path.write_text(text, encoding='utf-8')

def source_path(name):
    path = Path(name)
    if path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
        raise ValueError('Normalized relative source path required')
    path = ROOT / path
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(ROOT):
        raise ValueError('Missing or indirect source: ' + name)
    return path

def source_manifest():
    from statistics_source_manifest import verify as verify_statistics_sources
    verify_statistics_sources(read(ROOT / 'publicschemas/pooled_provenance.xml'), ROOT)
    inventory = read(ROOT / 'configs/source_files.xml')
    if set(inventory) != {'schema', 'paths'} or inventory['schema'] != 'lattice.source_paths.v1':
        raise ValueError('Invalid source inventory')
    names = inventory['paths']
    if names != sorted(set(names)) or 'tools/build.py' not in names or 'configs/source_files.xml' not in names:
        raise ValueError('Incomplete or duplicate source inventory')
    return [dict(path=n, sha256=sha(source_path(n)), bytes=source_path(n).stat().st_size) for n in names]

def selected(text):
    groups = {'all': PARAMETERS, 'kem': PARAMETERS[:3], 'dsa': PARAMETERS[3:]}
    values = groups[text] if text in groups else [int(x) for x in text.split(',')]
    if not values or len(values) != len(set(values)) or not set(values) <= set(PARAMETERS):
        raise ValueError('Select a nonempty set of distinct standard parameters')
    return [p for p in PARAMETERS if p in values]

def request(args):
    parameters = selected(args.parameters)
    if args.mode != 'canonical' and args.configuration not in CONFIGS:
        raise ValueError('Unknown algorithm configuration')
    if args.mode != 'canonical':
        from configuration_capabilities import validate_pruned_configuration
        validate_pruned_configuration(args.configuration, CONFIGS[args.configuration], backend=args.backend)
    if args.mode != 'canonical' and CONFIGS[args.configuration].get('public_a_session') and args.mode != 'hosted':
        raise ValueError('Session recipes currently require the complete hosted interface')
    if args.mode == 'hosted' and parameters != PARAMETERS:
        raise ValueError('Parameter subsets use pruned mode')
    if args.mode == 'canonical' and (args.backend != 'portable' or parameters != PARAMETERS or
                                    args.configuration != 'canonical' or args.opt != 'O3' or args.lto):
        raise ValueError('Canonical component uses portable, all, canonical, O3 and no LTO')
    if not 1 <= args.probe_count <= 10000:
        raise ValueError('Functional probe count must be between 1 and 10000')
    from operation_selection import normalize
    operations=normalize(getattr(args,'operations',None),parameters)
    if operations is not None and args.mode!='pruned':raise ValueError('Operation requirements use pruned mode')
    native={'native_options':arm_values(args)} if args.backend=='aarch64' else {}
    if operations is not None:native.update(operations=operations,probe_workspace=getattr(args,'probe_workspace',262144))
    return dict(**native, mode=args.mode, configuration=args.configuration, backend=args.backend,
                parameters=parameters, optimization=args.opt, lto=args.lto, probe_count=args.probe_count,
                tools={k: getattr(args, k) for k in ('cc', 'ar', 'nm', 'objdump', 'size')})

def plan(args):
    apply_plan_defaults(args)
    body = dict(request=request(args), sources=source_manifest())
    output = dict(schema='lattice.build_plan.v1', **body, identity=identity(body))
    write(args.output, output)
    if args.cmake_dependencies:
        text = 'set(LC_SOURCE_DEPENDENCIES\n' + ''.join(
            '  "${CMAKE_SOURCE_DIR}/' + x['path'] + '"\n' for x in output['sources']) + ')\n'
        if not args.cmake_dependencies.exists() or args.cmake_dependencies.read_text(encoding='utf-8') != text:
            args.cmake_dependencies.write_text(text, encoding='utf-8')
    print(output['identity'])

def child_command(recipe, output):
    tools = recipe['tools']; pairs = lambda names: sum((['--'+n, tools[n]] for n in names), [])
    if recipe['mode'] == 'canonical':
        return [sys.executable, '-B', str(ROOT/'tools/build_primitives.py'), 'prepare', '--mode', 'canonical',
                '--output', str(output), '--cases', str(recipe['probe_count']), *pairs(('cc','ar','nm','objdump'))]
    pruned = recipe['mode'] == 'pruned'
    command = [sys.executable, '-B', str(ROOT/'tools'/('size_variants.py' if pruned else 'build_variants.py')),
               '--output', str(output), '--configuration' if pruned else '--config', recipe['configuration'],
               '--backend', recipe['backend'], '--opt', recipe['optimization'],
               '--probe-count', str(recipe['probe_count']), *pairs(('cc','ar','nm'))]
    if pruned: command += ['--parameters', ','.join(map(str,recipe['parameters'])), *pairs(('objdump',))]
    else: command += pairs(('size',))
    if recipe.get('operations') is not None:command+=['--operations',json.dumps(recipe['operations'],separators=(',',':')),'--probe-workspace',str(recipe['probe_workspace'])]
    if recipe['backend']=='aarch64':command+=arm_argv(recipe['native_options'])
    if recipe['lto']: command.append('--lto')
    return command

def build(args):
    data = read(args.plan)
    if set(data) != {'schema','request','sources','identity'} or data['schema'] != 'lattice.build_plan.v1':
        raise ValueError('Invalid build plan')
    if identity({k:data[k] for k in ('request','sources')}) != data['identity'] or source_manifest() != data['sources']:
        raise ValueError('Source or plan changed; generate a new plan')
    recipe = data['request']; output = args.output.resolve()
    normalized = dict(recipe, parameters=','.join(map(str,recipe['parameters'])), opt=recipe['optimization'], **recipe['tools'])
    normalized.update(recipe.get('native_options',{}))
    if request(argparse.Namespace(**normalized)) != recipe:
        raise ValueError('Invalid build request')
    if output.exists() or output.is_relative_to(ROOT) or output in ROOT.parents:
        raise ValueError('Choose a fresh build directory')
    output.mkdir(parents=True); (output/'tmp').mkdir(); write(output/'plan.xml',data)
    command = child_command(recipe, output/'artifacts')
    env = dict(os.environ, TEMP=str(output/'tmp'), TMP=str(output/'tmp'), TMPDIR=str(output/'tmp'), PYTHONDONTWRITEBYTECODE='1')
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, encoding='utf-8', errors='replace')
    (output/'build.log').write_text(json.capture_text(result.stdout+result.stderr), encoding='utf-8')
    write(output/'command.xml',dict(argv=command,exit_code=result.returncode,log_sha256=sha(output/'build.log')))
    if result.returncode: raise RuntimeError('Compilation or functional check failed; see build.log')
    if source_manifest() != data['sources']: raise ValueError('Source changed while building')
    leaf = {'hosted':'build.xml','pruned':'result.xml','canonical':'prepared.xml'}[recipe['mode']]
    artifact = output/'artifacts'/leaf; receipt = read(artifact)
    approved = {x['path']:x['sha256'] for x in data['sources']}; used = {}; generated = {}
    for name,digest in receipt.get('source_hashes',{}).items():
        path = Path(name); path = ((ROOT/path) if not path.is_absolute() else path).resolve()
        if path.is_relative_to(output): generated[path.relative_to(output).as_posix()] = digest
        elif path.is_relative_to(ROOT):
            relative = path.relative_to(ROOT).as_posix()
            if approved.get(relative) != digest: raise ValueError('Compiler used an unlisted or changed source: '+relative)
            used[relative] = digest
        else: raise ValueError('Project dependency outside the source and output directories')
    for name,digest in receipt.get('generated_source_hashes',{}).items():
        path=(artifact.parent/name).resolve()
        if not path.is_relative_to(output) or not path.is_file() or sha(path)!=digest:raise ValueError('Generated source changed or escaped output: '+name)
        generated[path.relative_to(output).as_posix()]=digest
    if recipe['mode'] == 'canonical':
        for entry in receipt['sources']:
            relative = Path(entry['path']).resolve().relative_to(ROOT).as_posix()
            if approved.get(relative) != entry['sha256']: raise ValueError('Unlisted component source')
            used[relative] = entry['sha256']
    write(output/'result.xml',dict(schema='lattice.source_build.v1',status='PASS',plan_identity=data['identity'],
          request=recipe,builder_result=dict(path=artifact.relative_to(output).as_posix(),sha256=sha(artifact)),
          compiler_project_dependencies=used,generated_dependencies=generated))
    print(output/'result.xml')

def bundle(args):
    output=args.output.resolve(); manifest=source_manifest()
    if output.exists() or output == ROOT or output.is_relative_to(ROOT): raise ValueError('Fresh independent directory required')
    output.mkdir(parents=True)
    for item in manifest:
        target=output/item['path']; target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source_path(item['path']),target)
        if sha(target) != item['sha256']: raise ValueError('Source copy mismatch')
    write(output/'source_inventory.xml',dict(schema='lattice.source_inventory.v1',files=manifest))
    print(output/'source_inventory.xml')

def main():
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('plan'); p.add_argument('--mode',choices=['hosted','pruned','canonical'],default='hosted')
    p.add_argument('--configuration',default='compact-rate'); p.add_argument('--backend',choices=['portable','aarch64','x86_64'],default=None)
    p.add_argument('--operations');p.add_argument('--probe-workspace',type=int,default=262144)
    p.add_argument('--parameters',default='all'); p.add_argument('--opt',choices=['O3','Os'],default=None)
    p.add_argument('--lto',action=argparse.BooleanOptionalAction,default=None); p.add_argument('--probe-count',type=int,default=100)
    for name,default in [('cc','gcc'),('ar','gcc-ar'),('nm','nm'),('objdump','objdump'),('size','size')]:p.add_argument('--'+name,default=default)
    add_arm_arguments(p)
    p.set_defaults(**{name:None for name in ARM_OPTION_NAMES})
    p.add_argument('--output',type=Path,required=True);p.add_argument('--cmake-dependencies',type=Path)
    p=sub.add_parser('build');p.add_argument('--plan',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('bundle');p.add_argument('--output',type=Path,required=True)
    sub.add_parser('recipes')
    args=parser.parse_args(); {'plan':plan,'build':build,'bundle':bundle,'recipes':lambda _:print(json.dumps(RECIPES,indent=2))}[args.action](args)

if __name__ == '__main__':main()
