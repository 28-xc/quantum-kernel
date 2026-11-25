"""Collect and replay paired complete fixed-pool application batches.

Preparation binds qualified images and resource records. Collection stores every
process output before validating it. Analysis executes no application binaries.
"""
from pathlib import Path
import argparse
import datetime
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
import math
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time
import application_owner as owner

SCHEMA = 'lattice.application_owner_timing.v2'
SEED = 20261011154201
PAIRS = ((512, 44), (768, 65), (1024, 87))
IDS = ('lattice-native', 'pqclean-reference')
RESERVATION_FIELDS = ('workspace_bytes', 'stack_reserved_bytes', 'library_globals_tls_bytes',
                      'application_module_globals_bytes', 'heap_reserved_bytes')
ACCOUNTING_FIELDS = ('pool_bytes', 'application_state_bytes', 'serialized_owner_bytes',
                     'workspace_bytes', 'stack_reserved_bytes', 'library_globals_tls_bytes',
                     'application_globals_bytes', 'application_module_globals_bytes', 'charged_bytes')
CELL_FIELDS = set(('kem', 'dsa', 'maximum_stack_watermark', 'maximum_workspace_high_water',
                  'maximum_observed_heap', 'heap_reserved_bytes', 'flows', 'layout') + ACCOUNTING_FIELDS)
RESULT_FIELDS = set('status kem dsa layout fresh_identity rc iterations completed_flows last_flow_operations transcript transcript_matches seed pool_bytes workspace_bytes guards_ok cleared timed batch_ticks frequency cpu heap_instrumented final_close_included'.split())
DRIVER_SOURCE = Path(__file__).resolve().parents[1] / 'bench/application_owner/timing.c'
DRIVER_SCHEMA = 'lattice.application_timing_driver.v1'
STATISTICS = dict(bootstrap_seed=20261011154203, replicates=50000, generator='PCG64',
                  interval='percentile 95%', resampled_unit='paired complete blocks',
                  ratio='ratio of arithmetic mean batch times')
DESIGN = dict(blocks=9, seed=SEED, timeout_seconds=30, total_timeout_seconds=600,
              timed_scope='app_open and context initialization, app_prepare, complete app_flow calls, app_finish and final app_close clearing the entire fixed pool',
              outside_scope='module loading, symbol lookup, physical pool allocation and release, wide-workspace transcript oracle, post-call whole-pool zero and memory-guard checks',
              entropy='Deterministic common inputs paired within each block, parameter pair, identity mode and flow count',
              layouts={'0': 'separate serialized objects', '1': 'public key view in the KEM secret key; signature storage first receives the generated public key and later holds ciphertext and shared secrets'},
              replication_unit='randomized complete block of 48 independent application batches',
              sample_scope='one complete initialized and cleared application batch per process; all 432 batches retained',
              instrument='ordinary application timing driver without heap hooks or stack-resource instrumentation; reservations come from separately qualified identical application/core images',
              statistics=STATISTICS)
PLAN_FIELDS = set(DESIGN) | {'schema', 'state', 'platform', 'cpu', 'clock', 'config', 'libraries', 'build', 'bindings', 'jobs', 'driver'}
ROW_FIELDS = {'index', 'block', 'configuration', 'kem', 'dsa', 'fresh_identity', 'flows', 'layout', 'seed',
              'command', 'exit_code', 'timed_out', 'execution_error', 'started_utc', 'elapsed_controller_seconds',
              'stdout', 'stderr', 'result'}
require = owner.require


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def keys(value, expected, message):
    require(type(value) is dict and set(value) == set(expected), message)


def exact(left, right):
    return json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(right, sort_keys=True, separators=(',', ':'), allow_nan=False)


def integer(value, low=0, high=2**64-1):
    require(type(value) is int and low <= value <= high, 'Invalid integer')


def json_text(text):
    def unique(items):
        value = {}
        for key, item in items:
            require(key not in value, 'Duplicate JSON field')
            value[key] = item
        return value
    def constant(value):
        raise ValueError('Nonfinite JSON value: ' + value)
    return json.loads(text, object_pairs_hook=unique, parse_constant=constant)


def read(path):
    return json_text(Path(path).read_text(encoding='utf-8'))


def save(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.writing')
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def ref(path):
    path = Path(path).resolve()
    return dict(path=str(path), sha256=owner.sha(path))


def checked(item):
    keys(item, ('path', 'sha256'), 'Invalid file reference')
    require(type(item['path']) is str and type(item['sha256']) is str and
            re.fullmatch('[0-9a-f]{64}', item['sha256']), 'Invalid file identity')
    path = Path(item['path']).resolve()
    require(path.is_file() and owner.sha(path) == item['sha256'], 'Changed input identity: ' + str(path))
    return path


def host_platform():
    machine = platform.machine().lower()
    if os.name == 'nt' and machine in ('amd64', 'x86_64'):
        return 'windows_x86_64'
    require(platform.system() == 'Linux' and machine in ('aarch64', 'arm64'), 'Unsupported execution platform')
    return 'linux_aarch64'


def valid_ids(ids):
    require(2 <= len(ids) <= 10 and len(set(ids)) == len(ids) and all(type(x) is str and re.fullmatch('[a-z0-9][a-z0-9_-]*', x) for x in ids), 'Two to ten distinct library identities required')


def design(ids):
    valid_ids(ids)
    return dict(DESIGN, total_timeout_seconds=300*len(ids),
                replication_unit=f'randomized complete block of {24*len(ids)} independent application batches',
                sample_scope=f'one complete initialized and cleared application batch per process; all {216*len(ids)} batches retained')


def schedule(ids, blocks=9):
    valid_ids(ids)
    require(type(blocks) is int and blocks == 9, 'Changed paired design')
    rng = random.Random(SEED)
    rows = []
    for block in range(blocks):
        cells = [(k, d, fresh, count) for k, d in PAIRS for fresh in (0, 1) for count in (1, 200)]
        rng.shuffle(cells)
        for k, d, fresh, count in cells:
            arms = [(name, layout) for name in ids for layout in (0, 1)]
            rng.shuffle(arms)
            seed = SEED + block * 104729 + k * 97 + fresh * 7919 + count * 31
            for name, layout in arms:
                rows.append(dict(index=len(rows), block=block, configuration=name, kem=k,
                                 dsa=d, fresh_identity=fresh, flows=count, layout=layout, seed=seed))
    return rows


def input_libraries(config, build):
    value = read(config)
    keys(value, ('libraries',), 'Unexpected configuration fields')
    require(type(value['libraries']) is list, 'Explicit libraries required')
    valid_ids([x.get('id') for x in value['libraries']])
    output = []
    for row in value['libraries']:
        keys(row, ('id', 'library', 'resources'), 'Unexpected library fields')
        library = checked(row['library'])
        resource_path = checked(row['resources'])
        resource = read(resource_path)
        require(resource['schema'] == 'lattice.application_resources.v1' and resource['status'] == 'PASS', 'Invalid application resources')
        require(resource['core'] == owner.reference(library), 'Resource/core mismatch')
        require(resource['application'] == owner.reference(owner.app_module(build)), 'Resource/application mismatch')
        require(resource['build'] == owner.reference(build / 'build.xml'), 'Resource/build mismatch')
        require(type(resource['normal_batches']) is int and resource['normal_batches'] == 48 and
                type(resource['normal_flows']) is int and resource['normal_flows'] == 192 and
                resource['timing_collected'] is False, 'Incomplete normal resource qualification')
        commands = checked(dict(path=str(resource_path.parent / 'commands.xml'), sha256=resource['commands_sha256']))
        cells = resource['cells']
        require(type(cells) is list and len(cells) == 6, 'Incomplete resource cells')
        observed = set()
        for cell in cells:
            keys(cell, CELL_FIELDS, 'Changed resource cell fields')
            for name, number in cell.items():
                integer(number)
            identity = cell['kem'], cell['dsa'], cell['layout']
            require(identity not in observed, 'Duplicate resource cell')
            observed.add(identity)
            require(cell['flows'] == 32, 'Incomplete normal resource cell')
            require(32 <= cell['workspace_bytes'] <= 1048576 and cell['workspace_bytes'] % 32 == 0 and
                    256 <= cell['stack_reserved_bytes'] <= 262144 and cell['stack_reserved_bytes'] % 16 == 0 and
                    cell['heap_reserved_bytes'] <= 1048576, 'Invalid resource reservation')
            require(cell['maximum_stack_watermark'] <= cell['stack_reserved_bytes'] and
                    cell['maximum_workspace_high_water'] <= cell['workspace_bytes'] and
                    cell['maximum_observed_heap'] <= cell['heap_reserved_bytes'], 'Resource reserve exceeded')
            require(cell['charged_bytes'] == sum(cell[n] for n in ('pool_bytes', 'stack_reserved_bytes',
                    'library_globals_tls_bytes', 'application_globals_bytes', 'application_module_globals_bytes', 'heap_reserved_bytes')), 'Inconsistent resource charge')
        require(observed == {(k, d, layout) for k, d in PAIRS for layout in (0, 1)}, 'Incomplete resource cells')
        for field in RESERVATION_FIELDS:
            require(len({c[field] for c in cells}) == 1, 'Inconsistent whole-application reservation')
        integer(resource['program_bytes'], 1)
        output.append(dict(id=row['id'], library=ref(library), resources=ref(resource_path),
                           resource_commands=ref(commands), reservation={field: cells[0][field] for field in RESERVATION_FIELDS},
                           program_bytes=resource['program_bytes'], cells=cells))
    return output


def build_bindings(build, manifest):
    paths = [build / name for name in manifest['artifacts']]
    paths += [build / 'build.xml', build / 'commands.xml', Path(__file__), Path(owner.__file__)]
    paths += [build / 'source' / row['path'] for row in manifest['sources']]
    return [ref(path) for path in paths]


def build_driver(args):
    build, _ = owner.loaded_build(args.build)
    platform_id = host_platform()
    out = owner.fresh(args.output)
    (out / 'source').mkdir()
    sources = []
    for source in (DRIVER_SOURCE, build / 'source/application.h', build / 'source/latticecore.h'):
        destination = out / 'source' / source.name
        shutil.copyfile(source, destination)
        sources.append(dict(original=ref(source), copied=ref(destination)))
    application = owner.app_module(build)
    copied = out / application.name
    shutil.copyfile(application, copied)
    compiler = Path(shutil.which(str(args.cc)) or str(args.cc)).resolve()
    require(compiler.is_file(), 'Missing compiler')
    executable = out / ('application_timing.exe' if os.name == 'nt' else 'application_timing')
    command = [str(compiler), '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
               '-I' + str(out / 'source'), str(out / 'source/timing.c')]
    command += [str(build / 'libapplication.dll.a')] if os.name == 'nt' else [str(copied), '-Wl,-rpath,$ORIGIN', '-ldl']
    command += ['-o', str(executable)]
    started = utc()
    try:
        process = subprocess.run(command, capture_output=True, timeout=120, cwd=out)
    except (subprocess.TimeoutExpired, OSError) as error:
        (out / 'compile.stdout').write_bytes(getattr(error, 'stdout', None) or b'')
        (out / 'compile.stderr').write_bytes(getattr(error, 'stderr', None) or b'')
        save(out / 'failure.xml', dict(status='FAILED_BUILD', command=command, error=repr(error),
                                      stdout=ref(out / 'compile.stdout'), stderr=ref(out / 'compile.stderr')))
        raise
    (out / 'compile.stdout').write_bytes(json.capture_bytes(process.stdout))
    (out / 'compile.stderr').write_bytes(process.stderr)
    command_record = dict(command=command, exit_code=process.returncode, started_utc=started, ended_utc=utc(),
                          stdout=ref(out / 'compile.stdout'), stderr=ref(out / 'compile.stderr'))
    save(out / 'commands.xml', [command_record])
    require(process.returncode == 0, 'Timing driver compilation failed; logs retained')
    value = dict(schema=DRIVER_SCHEMA, status='PASS_BUILD_ONLY', platform=platform_id,
                 application_build=ref(build / 'build.xml'), application=ref(application),
                 copied_application=ref(copied), sources=sources, compiler=ref(compiler),
                 commands=ref(out / 'commands.xml'), executable=ref(executable), collector=ref(__file__),
                 timing_collected=False)
    save(out / 'driver.xml', value)
    print(json.dumps(dict(status='PASS_BUILD_ONLY', driver=ref(out / 'driver.xml'))))


def loaded_driver(path, build, platform_id):
    path = Path(path).resolve()
    value = read(path)
    keys(value, ('schema', 'status', 'platform', 'application_build', 'application', 'copied_application',
                 'sources', 'compiler', 'commands', 'executable', 'collector', 'timing_collected'), 'Changed driver fields')
    require(value['schema'] == DRIVER_SCHEMA and value['status'] == 'PASS_BUILD_ONLY' and
            value['platform'] == platform_id and value['timing_collected'] is False, 'Invalid timing driver')
    require(value['collector'] == ref(__file__) and value['application_build'] == ref(build / 'build.xml') and
            value['application'] == ref(owner.app_module(build)), 'Changed application/collector identity')
    require(value['copied_application']['sha256'] == value['application']['sha256'], 'Different application copy')
    for name in ('application_build', 'application', 'copied_application', 'compiler', 'commands', 'executable', 'collector'):
        checked(value[name])
    require(Path(value['executable']['path']).parent == path.parent and
            Path(value['copied_application']['path']).parent == path.parent, 'Unexpected driver deployment path')
    expected = [ref(DRIVER_SOURCE), ref(build / 'source/application.h'), ref(build / 'source/latticecore.h')]
    require(type(value['sources']) is list and len(value['sources']) == 3, 'Incomplete driver source closure')
    for item, original in zip(value['sources'], expected):
        keys(item, ('original', 'copied'), 'Changed driver source fields')
        require(item['original'] == original and item['copied']['sha256'] == original['sha256'], 'Changed driver source')
        checked(item['original']); checked(item['copied'])
    commands = read(value['commands']['path'])
    require(type(commands) is list and len(commands) == 1 and commands[0]['exit_code'] == 0, 'Failed driver build')
    checked(commands[0]['stdout']); checked(commands[0]['stderr'])
    return value


def prepare(args):
    build, manifest = owner.loaded_build(args.build)
    platform_id = host_platform()
    integer(args.cpu, 0, 2**20)
    require(args.cpu == 2 if os.name == 'nt' else args.cpu in os.sched_getaffinity(0), 'Unsupported processor affinity')
    libraries = input_libraries(args.config, build)
    loaded_driver(args.driver, build, platform_id)
    plan = dict(schema=SCHEMA, state='prepared', platform=platform_id, cpu=args.cpu,
                clock='QueryPerformanceCounter' if os.name == 'nt' else 'CLOCK_MONOTONIC_RAW',
                config=ref(args.config), libraries=libraries, build=str(build), driver=ref(args.driver),
                bindings=build_bindings(build, manifest), jobs=schedule([x['id'] for x in libraries]), **design([x['id'] for x in libraries]))
    out = owner.fresh(args.output)
    save(out / 'plan.xml', plan)
    print(json.dumps(dict(status='PREPARED', plan=ref(out / 'plan.xml'), tasks=len(plan['jobs']))))


def load_plan(path, execution=False):
    plan = read(path)
    keys(plan, PLAN_FIELDS, 'Changed plan fields')
    require(plan['schema'] == SCHEMA and plan['state'] == 'prepared', 'Unknown plan')
    for name, value in design([x['id'] for x in plan['libraries']]).items():
        require(type(plan[name]) is type(value) and exact(plan[name], value), 'Changed protocol field: ' + name)
    require(plan['platform'] in ('windows_x86_64', 'linux_aarch64'), 'Unknown platform')
    integer(plan['cpu'], 0, 2**20)
    require(plan['clock'] == ('QueryPerformanceCounter' if plan['platform'] == 'windows_x86_64' else 'CLOCK_MONOTONIC_RAW'), 'Changed timer')
    if plan['platform'] == 'windows_x86_64':
        require(plan['cpu'] == 2, 'The qualified Windows probe requires logical CPU 2')
    if execution:
        require(plan['platform'] == host_platform(), 'Plan/host mismatch')
        if os.name != 'nt':
            require(plan['cpu'] in os.sched_getaffinity(0), 'Planned CPU is unavailable')
    # The plan's bound build and resources are re-read; derived reservations are
    # never accepted solely from mutable values embedded in the plan.
    build, manifest = owner.loaded_build(Path(plan['build']))
    require(plan['bindings'] == build_bindings(build, manifest), 'Changed or incomplete build/source closure')
    for item in plan['bindings']:
        checked(item)
    require(exact(plan['libraries'], input_libraries(checked(plan['config']), build)), 'Changed resource or library derivation')
    loaded_driver(checked(plan['driver']), build, plan['platform'])
    require(exact(plan['jobs'], schedule([x['id'] for x in plan['libraries']])), 'Changed paired schedule')
    return plan, build


def invocation(plan, build, job, timed=True):
    lib = next(x for x in plan['libraries'] if x['id'] == job['configuration'])
    driver = read(plan['driver']['path'])
    return list(map(str, [driver['executable']['path'], Path(lib['library']['path']), job['kem'], job['dsa'],
                         job['layout'], job['fresh_identity'], lib['reservation']['workspace_bytes'],
                         job['seed'], job['flows'], plan['cpu'], int(timed)]))


def observe(plan, build, job, out, timeout, timed=True):
    command = invocation(plan, build, job, timed)
    env = os.environ.copy()
    for name in ('LD_PRELOAD', 'LD_AUDIT'):
        env.pop(name, None)
    start = time.monotonic()
    row = dict(**job, command=command, exit_code=None, timed_out=False, execution_error=None,
               started_utc=utc(), elapsed_controller_seconds=0, stdout=None, stderr=None, result=None)
    stdout, stderr = b'', b''
    try:
        process = subprocess.run(command, capture_output=True, timeout=timeout, env=env, cwd=build)
        row['exit_code'] = process.returncode
        stdout, stderr = process.stdout, process.stderr
    except subprocess.TimeoutExpired as error:
        row['timed_out'] = True
        row['execution_error'] = repr(error)
        stdout, stderr = error.stdout or b'', error.stderr or b''
    except OSError as error:
        row['execution_error'] = repr(error)
    row['elapsed_controller_seconds'] = time.monotonic() - start
    # No parsing or success assertion precedes these durable raw records.
    for name, contents in (('stdout', stdout), ('stderr', stderr)):
        relative = f'raw/{job["index"]:04d}.{name}' + ('.xml' if name=='stdout' else '')
        if name=='stdout':
            try: contents=json.dumps(json.loads(contents)).encode('utf-8')
            except ValueError: contents=json.dumps(contents.decode('utf-8',errors='replace')).encode('utf-8')
        file = out / relative
        with file.open('xb') as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        row[name] = dict(path=relative, sha256=owner.sha(file))
    return row


def raw_output(out, row, name):
    item = row[name]
    keys(item, ('path', 'sha256'), 'Invalid raw output reference')
    require(item['path'] == f'raw/{row["index"]:04d}.{name}' + ('.xml' if name=='stdout' else ''), 'Changed raw output indexing')
    file = Path(out) / item['path']
    require(file.is_file() and owner.sha(file) == item['sha256'], 'Changed raw output')
    return file.read_bytes()


def decode_record(out, row):
    require(raw_output(out, row, 'stderr') == b'', 'Unexpected process diagnostic')
    text = raw_output(out, row, 'stdout').decode('utf-8')
    lines = [text]
    require(isinstance(json.loads(text),dict), 'Expected exactly one application event')
    result = json_text(lines[0])
    keys(result, RESULT_FIELDS, 'Changed application result fields')
    return result


def verify_record(plan, build, row, timed=True):
    keys(row, ROW_FIELDS, 'Changed process record fields')
    integer(row['index'], 0, len(plan['jobs'])-1)
    job = plan['jobs'][row['index']]
    require(all(type(row[k]) is type(v) and row[k] == v for k, v in job.items()), 'Changed process identity')
    require(row['command'] == invocation(plan, build, job, timed), 'Changed process command')
    require(row['timed_out'] is False and row['execution_error'] is None and type(row['exit_code']) is int and row['exit_code'] == 0,
            'Application execution failed')
    require(type(row['elapsed_controller_seconds']) in (int, float) and math.isfinite(row['elapsed_controller_seconds']) and
            0 <= row['elapsed_controller_seconds'] <= plan['timeout_seconds'], 'Invalid process elapsed time')
    x = row['result']
    keys(x, RESULT_FIELDS, 'Missing application result')
    for name, value in x.items():
        if name not in ('status', 'transcript', 'transcript_matches', 'guards_ok', 'cleared', 'timed', 'heap_instrumented', 'final_close_included'):
            integer(value)
    for name in ('transcript_matches', 'guards_ok', 'cleared', 'final_close_included'):
        require(x[name] is True, 'Application correctness or cleanup boundary failed')
    require(x['heap_instrumented'] is False and x['timed'] is timed, 'Changed instrumentation or timing mode')
    require(x['status'] == 'PASS' and x['rc'] == 0 and x['frequency'] > 0, 'Invalid complete-batch result')
    require(x['batch_ticks'] > 0 if timed else x['batch_ticks'] == 0, 'Invalid timer boundary')
    require(x['cpu'] == plan['cpu'], 'Changed processor affinity')
    if plan['platform'] == 'linux_aarch64':
        require(x['frequency'] == 10**9, 'Changed POSIX clock frequency')
    require(type(x['transcript']) is str and re.fullmatch('[0-9a-f]{16}', x['transcript']), 'Invalid output transcript')
    require((x['kem'], x['dsa'], x['layout'], x['fresh_identity'], x['seed'], x['iterations'], x['completed_flows']) ==
            (job['kem'], job['dsa'], job['layout'], job['fresh_identity'], job['seed'], job['flows'], job['flows']), 'Changed process inputs')
    require(x['last_flow_operations'] == 5 + job['fresh_identity'], 'Incomplete application operation sequence')
    lib = next(y for y in plan['libraries'] if y['id'] == job['configuration'])
    cell = next(c for c in lib['cells'] if (c['kem'], c['dsa'], c['layout']) == (job['kem'], job['dsa'], job['layout']))
    require(x['pool_bytes'] == cell['pool_bytes'] and x['workspace_bytes'] == cell['workspace_bytes'], 'Changed fixed-pool reservation')


def paired_transcript(expected, row):
    pair = tuple(row[k] for k in ('block', 'kem', 'dsa', 'fresh_identity', 'flows'))
    transcript = row['result']['transcript']
    require(expected.setdefault(pair, transcript) == transcript, 'Paired full-output transcript mismatch')


def collect(args):
    plan_path = args.plan.resolve()
    plan, build = load_plan(plan_path, execution=True)
    out = owner.fresh(args.output)
    (out / 'raw').mkdir()
    original_affinity = None
    if os.name != 'nt':
        original_affinity = os.sched_getaffinity(0)
        os.sched_setaffinity(0, {plan['cpu']})
    records = []; start = time.monotonic(); expected = {}; frequency = None
    plan_identity = ref(plan_path)
    save(out / 'progress.xml', dict(state='running', started_utc=utc(), completed=0, total=len(plan['jobs']), plan=plan_identity))
    try:
        for job in plan['jobs']:
            remaining = plan['total_timeout_seconds'] - (time.monotonic() - start)
            require(remaining > 0, 'Bounded application collection exceeded')
            row = observe(plan, build, job, out, min(plan['timeout_seconds'], remaining))
            records.append(row)
            save(out / 'records.xml', records)
            # Timeout and malformed-output records are already preserved here.
            require(not row['timed_out'] and row['execution_error'] is None, 'Process failed or exceeded time bound')
            row['result'] = decode_record(out, row)
            save(out / 'records.xml', records)
            verify_record(plan, build, row)
            paired_transcript(expected, row)
            current = row['result']['frequency']
            require(frequency is None or frequency == current, 'Changed process timer frequency')
            frequency = current
            require(time.monotonic() - start <= plan['total_timeout_seconds'], 'Bounded application collection exceeded')
            save(out / 'progress.xml', dict(state='running', completed=len(records), total=len(plan['jobs']), updated_utc=utc(), plan=plan_identity))
        require(len(expected) == 108 and ref(plan_path) == plan_identity, 'Changed plan or missing paired cell')
        load_plan(plan_path)
        require(time.monotonic() - start <= plan['total_timeout_seconds'], 'Final identity validation exceeded time bound')
        result = dict(schema=SCHEMA, status='PASS', plan=plan_identity, records=ref(out / 'records.xml'),
                      processes=len(records), target_flows=sum(x['flows'] for x in records),
                      oracle_flows=sum(x['flows'] for x in records), trimmed_processes=0,
                      elapsed_controller_seconds=time.monotonic() - start, ended_utc=utc())
        save(out / 'result.xml', result)
        save(out / 'progress.xml', dict(state='completed', completed=len(plan['jobs']), total=len(plan['jobs']), result=ref(out / 'result.xml')))
        print(json.dumps(result))
    except BaseException as error:
        save(out / 'progress.xml', dict(state='failed', completed=len(records), total=len(plan['jobs']), plan=plan_identity,
                                      error=repr(error), updated_utc=utc()))
        raise
    finally:
        if original_affinity is not None:
            os.sched_setaffinity(0, original_affinity)


def analyze(args):
    import numpy as np
    root = args.input.resolve()
    result = read(root / 'result.xml')
    keys(result, ('schema', 'status', 'plan', 'records', 'processes', 'target_flows', 'oracle_flows',
                  'trimmed_processes', 'elapsed_controller_seconds', 'ended_utc'), 'Changed completion fields')
    require(result['schema'] == SCHEMA and result['status'] == 'PASS' and result['trimmed_processes'] == 0 and
            type(result['processes']) is int and 432 <= result['processes'] <= 2160, 'Incomplete application batch')
    plan, build = load_plan(checked(result['plan']))
    require(checked(result['records']) == root / 'records.xml', 'Observation record is outside the acquisition')
    records = read(root / 'records.xml')
    require(type(records) is list and len(records) == result['processes'] == len(plan['jobs']), 'Incomplete observations')
    integer(result['target_flows'], 1); integer(result['oracle_flows'], 1)
    require(type(result['elapsed_controller_seconds']) in (int, float) and math.isfinite(result['elapsed_controller_seconds']) and 0 <= result['elapsed_controller_seconds'] <= plan['total_timeout_seconds'], 'Changed total time bound')
    require(result['target_flows'] == result['oracle_flows'] == sum(job['flows'] for job in plan['jobs']), 'Changed flow counts')
    grouped = {}; expected = {}; frequencies = set(); files = set()
    for index, row in enumerate(records):
        require(row['index'] == index, 'Changed process order')
        decoded = decode_record(root, row)
        require(decoded == row['result'], 'Stored result differs from raw process output')
        verify_record(plan, build, row)
        paired_transcript(expected, row)
        frequencies.add(row['result']['frequency'])
        for name in ('stdout', 'stderr'):
            files.add((root / row[name]['path']).resolve())
        key = tuple(row[k] for k in ('configuration', 'layout', 'kem', 'dsa', 'fresh_identity', 'flows'))
        values = grouped.setdefault(key, {})
        require(row['block'] not in values, 'Duplicate paired block')
        values[row['block']] = row['result']['batch_ticks'] * 1e9 / row['result']['frequency']
    require(len(expected) == 108 and len(frequencies) == 1, 'Incomplete pairing or inconsistent timer')
    require(set((root / 'raw').iterdir()) == files, 'Missing or unrecorded process output')
    draws = np.random.Generator(np.random.PCG64(STATISTICS['bootstrap_seed'])).integers(0, 9, size=(STATISTICS['replicates'], 9))
    absolute = []; vectors = {}
    for key, values in sorted(grouped.items()):
        require(sorted(values) == list(range(9)), 'Missing independent block')
        vector = np.asarray([values[b] for b in range(9)]); vectors[key] = vector
        boot = vector[draws].mean(axis=1)
        absolute.append(dict(zip(('configuration', 'layout', 'kem', 'dsa', 'fresh_identity', 'flows'), key),
                             independent_batches=9, mean_batch_ns=float(vector.mean()),
                             ci95_batch_ns=np.quantile(boot, [.025, .975]).tolist(),
                             complete_flows_per_second=key[-1] * 1e9 / float(vector.mean()), block_batch_ns=vector.tolist()))
    comparisons = []
    arms = [(lib['id'], layout) for lib in plan['libraries'] for layout in (0, 1)]
    for k, d in PAIRS:
        for fresh in (0, 1):
            for count in (1, 200):
                for index, a in enumerate(arms):
                    for b in arms[index+1:]:
                        u = vectors[(*a, k, d, fresh, count)]; v = vectors[(*b, k, d, fresh, count)]
                        ratios = u[draws].mean(axis=1) / v[draws].mean(axis=1)
                        comparisons.append(dict(numerator=dict(configuration=a[0], layout=a[1]),
                                                denominator=dict(configuration=b[0], layout=b[1]),
                                                kem=k, dsa=d, fresh_identity=fresh, flows=count,
                                                mean_time_ratio=float(u.mean()/v.mean()),
                                                ci95=np.quantile(ratios, [.025, .975]).tolist()))
    require(len(absolute) == 24*len(plan['libraries']) and len(comparisons) == 12*len(arms)*(len(arms)-1)//2, 'Incomplete application statistics')
    out = owner.fresh(args.output)
    save(out / 'statistics.xml', dict(schema='lattice.application_owner_statistics.v1',
                 result=ref(root / 'result.xml'), plan=result['plan'], records=result['records'],
                 collector=ref(__file__), method=STATISTICS,
                 bootstrap_indices_sha256=hashlib.sha256(draws.astype('<i8').tobytes()).hexdigest(),
                 cells=absolute, comparisons=comparisons, retained_processes=len(records), retained_target_flows=result['target_flows']))
    print(json.dumps(dict(status='PASS', cells=len(absolute), comparisons=len(comparisons), statistics=ref(out / 'statistics.xml'))))


def check(args):
    plan_path = args.plan.resolve()
    plan, build = load_plan(plan_path, execution=True)
    # One block covers every image/layout/condition; a distinct seed separates
    # this functional preflight from the registered measurement inputs.
    jobs = [dict(job, seed=202610045709 + job['kem'] * 97 + job['fresh_identity'] * 7919 + job['flows'] * 31)
            for job in plan['jobs'][:24*len(plan['libraries'])]]
    checked_plan = dict(plan, jobs=jobs)
    out = owner.fresh(args.output); (out / 'raw').mkdir()
    records = []; expected = {}; start = time.monotonic()
    try:
        for job in jobs:
            remaining = plan['total_timeout_seconds'] - (time.monotonic() - start)
            require(remaining > 0, 'Functional preflight exceeded time bound')
            row = observe(checked_plan, build, job, out, min(30, remaining), timed=False)
            records.append(row); save(out / 'records.xml', records)
            require(not row['timed_out'] and row['execution_error'] is None, 'Preflight process failed')
            row['result'] = decode_record(out, row); save(out / 'records.xml', records)
            verify_record(checked_plan, build, row, timed=False); paired_transcript(expected, row)
        require(len(expected) == 12, 'Incomplete preflight pairing')
        load_plan(plan_path)
        result = dict(schema='lattice.application_timing_check.v1', status='PASS', plan=ref(plan_path),
                      records=ref(out / 'records.xml'), processes=len(jobs), paired_conditions=12,
                      target_flows=sum(j['flows'] for j in jobs), timing_collected=False,
                      full_pool_cleanup=True, final_close_included=True)
        save(out / 'result.xml', result); print(json.dumps(result))
    except BaseException as error:
        save(out / 'failure.xml', dict(status='FAILED', completed=len(records), error=repr(error), plan=ref(plan_path)))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest='action', required=True)
    b = sub.add_parser('build-driver'); b.add_argument('--build', type=Path, required=True); b.add_argument('--cc', required=True); b.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('prepare'); p.add_argument('--build', type=Path, required=True); p.add_argument('--config', type=Path, required=True)
    p.add_argument('--driver', type=Path, required=True); p.add_argument('--cpu', type=int, default=2); p.add_argument('--output', type=Path, required=True)
    c = sub.add_parser('collect'); c.add_argument('--plan', type=Path, required=True); c.add_argument('--output', type=Path, required=True)
    q = sub.add_parser('check'); q.add_argument('--plan', type=Path, required=True); q.add_argument('--output', type=Path, required=True)
    a = sub.add_parser('analyze'); a.add_argument('--input', type=Path, required=True); a.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); {'build-driver': build_driver, 'prepare': prepare, 'check': check, 'collect': collect, 'analyze': analyze}[args.action](args)


if __name__ == '__main__':
    main()
