"""Real session application calls. No timing, retained secret, or synthetic result."""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import importlib.util
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
import platform
import sys

V, N, I, U = C.c_void_p, C.c_size_t, C.c_int, C.c_uint64
PAIR = {44: 512, 65: 768, 87: 1024}
MODES = {'cold1': (1, 0), 'reuse200': (200, 0), 'fresh200': (200, 1)}
APP_HEADER = '7f9876eb90f6ae59f015951b564ed0c9b8d2a1bba0a3a7cab16c3308d136446c'
FUNCTIONS = ('lc_context_init', 'lc_get_sizes', 'lc_keypair', 'lc_encaps',
             'lc_decaps', 'lc_sign', 'lc_verify', 'lc_a_session_cache_bytes',
             'lc_a_session_workspace_bound', 'lc_a_session_init',
             'lc_a_session_prepare', 'lc_a_session_sign', 'lc_a_session_verify',
             'lc_a_session_close')

def check(ok, text):
    if not ok:
        raise ValueError(text)

def read(path):
    def pairs(items):
        result = {}
        for key, value in items:
            check(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    def bad(value):
        raise ValueError('Nonfinite JSON')
    return json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=pairs, parse_constant=bad)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def artifact(base, item):
    check(type(item) is dict and set(item) == {'path', 'sha256'}, 'Invalid artifact reference')
    path = (base / item['path']).resolve()
    check(sha(path) == item['sha256'], 'Artifact fingerprint differs')
    return path

def execution_image(base, item, measured_sha256, derivation=None):
    path = artifact(base, item)
    if item['sha256'] != measured_sha256:
        check(derivation is not None, 'Measured and deployment image identities differ')
        receipt = artifact(base, derivation)
        from publicschemas.deployment_image import verify_deployment_image
        verify_deployment_image(path.read_bytes(), read(receipt), measured_sha256=measured_sha256)
    elif derivation is not None:
        # Even an optional receipt is an explicit identity assertion.
        from publicschemas.deployment_image import verify_deployment_image
        verify_deployment_image(path.read_bytes(), read(artifact(base, derivation)), measured_sha256=measured_sha256)
    return path

class Context(C.Structure):
    _fields_ = [('workspace', V), ('workspace_bytes', N), ('random', V), ('random_user', V),
                ('arena_high_water', N), ('allocations', N), ('allocation_failures', N), ('last_error', I)]

class Sizes(C.Structure):
    _fields_ = [(k, N) for k in ('public_key', 'secret_key', 'ciphertext', 'shared_secret', 'signature')]

class Session(C.Structure):
    _fields_ = [('cache', V), ('capacity', N), ('cache_bytes', N), ('rho', C.c_ubyte * 32),
                ('magic', C.c_uint32), ('ready', C.c_uint32), ('parameter', I), ('format_tag', C.c_uint32)]

class Api(C.Structure):
    _fields_ = [(name, V) for name in FUNCTIONS]

class State(C.Structure):
    _fields_ = [('api', Api), ('context', Context), ('k', Sizes), ('d', Sizes),
                ('session', Session), ('public_cache', V), ('cache_bytes', N), ('authority_high', N),
                ('objects', V), ('work', V), ('object_bytes', N), ('workspace_bytes', N),
                ('pool_bytes', N), ('high', N)] + [(k, I) for k in (
                    'kem', 'dsa', 'layout', 'fresh', 'identity_ready', 'rc', 'completed', 'phase',
                    'fault', 'fault_stage', 'entropy_failure')] + [(k, U) for k in (
                    'entropy', 'requests', 'entropy_bytes', 'flows', 'transcript')] + [
                    ('observer', V), ('observer_user', V)]

def resource_entry(base, config, selected, public_model=None):
    path = artifact(base, selected['resources']); data = read(path)
    measured_library = selected.get('measured_library_sha256', selected['library']['sha256'])
    measured_application = config.get('measured_application_sha256', config['application']['sha256'])
    public = data.get('schema') == 'lattice.public_a_workflows.v1'
    if public:
        check(public_model is not None, 'Public workflow validator is required')
        public_model.validate_observations(data)
        matches = [r for r in data['configurations'] if r['id'] == selected['resource_id']]
        check(len(matches) == 1, 'Ambiguous public resource identity')
        row = matches[0]; cells = row['resource_cases']
        image = {'sha256': row['library_sha256']}
        app_image = {'sha256': data['identities']['application_sha256']}
    elif data.get('schema') == 'private.session_resources.v2':
        check(data.get('status') == 'PASS', 'Resource qualification did not pass')
        check(data.get('complete') is True, 'Resource study incomplete')
        matches = [r for r in data['items'] if r['id'] == selected['resource_id']]
        check(len(matches) == 1, 'Ambiguous resource identity')
        row = matches[0]; cells = row['fixed']; image = row['image']
        app_image = data['application_image']
        check(row['library']['sha256'] == measured_library, 'Different resource library')
    else:
        check(data.get('status') == 'PASS', 'Resource qualification did not pass')
        # Original finite-input resource record, retained without changing any observation.
        check(set(data) == {'status', 'scope', 'libraries', 'application', 'cells', 'commands_sha256'},
              'Unsupported resource model')
        image = data['libraries'][selected['resource_id']]; app_image = data['application']
        cells = [r for r in data['cells'] if r['label'] == selected['resource_id'] + '-enforced']
    check(image['sha256'] == measured_library, 'Different resource image')
    check(app_image['sha256'] == measured_application, 'Different application image')
    check(cells, 'No fixed resource observations')
    out = {}
    for d, k in PAIR.items():
        rows = [r for r in cells if r['dsa'] == d and r['kem'] == k]
        check({r['fresh_identity'] for r in rows} == {0, 1}, 'Incomplete lifecycle resource coverage')
        for r in rows:
            check((public or r['status'] == 'PASS') and r['guards_ok'] and r['cleared'] and r['outside_heap_peak'] == 0,
                  'Resource boundaries failed')
            check(r['state_bytes' if public else 'application_state_bytes'] == C.sizeof(State), 'Application state ABI differs')
            total = sum(r[f] for f in ('pool_bytes', 'stack_reserved_bytes', 'library_globals_tls_bytes',
                                      'application_globals_bytes', 'application_module_globals_bytes'))
            check(total == r['charged_bytes'] and total <= 81920, 'Application exceeds 80 KiB')
        fields = ('pool_bytes', 'workspace_bytes', 'stack_reserved_bytes', 'charged_bytes',
                  'library_globals_tls_bytes', 'application_globals_bytes', 'application_module_globals_bytes')
        check(len({tuple(r[f] for f in fields) for r in rows}) == 1, 'Resource reservation varies by lifecycle')
        out[d] = {f: rows[0][f] for f in fields}
    return out

class Configuration:
    def __init__(self, path):
        self.path = Path(path).resolve(); self.base = self.path.parent; self.data = read(self.path)
        check(self.data.get('schema') == 'lattice.session_demo.v1', 'Invalid session configuration')
        check(self.data.get('budget_bytes') == 81920, 'Explicit 80 KiB budget required')
        header = artifact(self.base, self.data['application_header'])
        check(sha(header) == APP_HEADER and C.sizeof(State) == 504, 'Unsupported application ABI')
        self.public_model = None
        if 'workflow_model' in self.data:
            validator = artifact(self.base, self.data['workflow_model'])
            spec = importlib.util.spec_from_file_location('session_public_workflow_model', validator)
            self.public_model = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.public_model)
        self.measured_application = self.data.get('measured_application_sha256', self.data['application']['sha256'])
        self.app = execution_image(self.base, self.data['application'], self.measured_application,
                                   self.data.get('application_derivation'))
        self.entries = {}; self.paths = {}; self.resources = {}
        for row in self.data['configurations']:
            check(row['id'] not in self.entries and type(row['title']) is str, 'Duplicate configuration')
            self.paths[row['id']] = execution_image(self.base, row['library'],
                row.get('measured_library_sha256', row['library']['sha256']), row.get('library_derivation'))
            self.resources[row['id']] = resource_entry(self.base, self.data, row, self.public_model)
            self.entries[row['id']] = row
        check(self.entries, 'No session configurations')
        self.downloads = {}
        # Study references are downloadable originals. Their content is not presented as live latency.
        for i, study in enumerate(self.data.get('studies', [])):
            if study.get('kind') == 'public-a-workflows-v1':
                check(self.public_model is not None, 'Public workflow validator is required')
                observations = artifact(self.base, study['observations'])
                raw = artifact(self.base, study['raw']); summary = artifact(self.base, study['summary'])
                p = read(observations); s = read(summary)
                self.public_model.validate_summary(s, p, sha(observations))
                check(p['raw']['sha256'] == sha(raw) and p['raw']['bytes'] == raw.stat().st_size,
                      'Public workflow raw binding differs')
                measured = {v['library_sha256'] for v in p['configurations']}
                local_platforms = {e['platform'] for e in self.entries.values()}
                if p['platform'] in local_platforms:
                    check(p['identities']['application_sha256'] == self.measured_application,
                          'Public study uses a different application')
                    check(all(e.get('measured_library_sha256', e['library']['sha256']) in measured
                              for e in self.entries.values() if e['platform'] == p['platform']),
                          'Public study omits a demonstration image')
                    check('data_only_deployment' not in study, 'Local study must bind live images')
                else:
                    # A foreign-platform study is data-only. Bind its own application and
                    # every actual measured core; never compare its ELF identity to a PE.
                    deployment = study.get('data_only_deployment')
                    check(type(deployment) is dict and set(deployment) ==
                          {'platform', 'application', 'application_derivation', 'libraries'},
                          'Foreign study requires complete deployment bindings')
                    check(deployment['platform'] == p['platform'] and p['platform'] in
                          {'windows_x86_64', 'linux_aarch64'}, 'Foreign study platform differs')
                    execution_image(self.base, deployment['application'],
                                    p['identities']['application_sha256'],
                                    deployment['application_derivation'])
                    rows = deployment['libraries']
                    expected = {v['id']: v['library_sha256'] for v in p['configurations']}
                    check(type(rows) is list and len(rows) == len(expected) and
                          all(type(r) is dict and set(r) == {'id', 'library', 'derivation'} for r in rows)
                          and {r['id'] for r in rows} == set(expected),
                          'Foreign study omits or duplicates a measured core')
                    for row in rows:
                        execution_image(self.base, row['library'], expected[row['id']], row['derivation'])
                for kind, file in [('plan', observations), ('raw', raw), ('summary', summary)]:
                    self.downloads[f'{i}-{kind}'] = (file, sha(file))
                continue
            plan = artifact(self.base, study['plan']); raw = artifact(self.base, study['raw'])
            summary = artifact(self.base, study['summary']); p = read(plan); s = read(summary)
            appsha = p.get('app_sha256') or p.get('application', {}).get('sha256')
            check(appsha == self.measured_application, 'Study uses a different application')
            check(s.get('raw_sha256', s.get('raw', {}).get('sha256')) == sha(raw), 'Study raw binding differs')
            if 'plan' in s: check(s['plan']['sha256'] == sha(plan), 'Study plan binding differs')
            entries = p.get('libraries', p.get('library', {}))
            # The supported old/private and current reproducible study plans retain exact image fingerprints.
            measured = entries.values() if type(entries) is dict else entries
            identities = {v['sha256'] for v in measured}
            check(all(e.get('measured_library_sha256', e['library']['sha256']) in identities for e in self.entries.values()), 'Study omits a demonstration image')
            for kind, file in [('plan', plan), ('raw', raw), ('summary', summary)]:
                self.downloads[f'{i}-{kind}'] = (file, sha(file))

    def catalog(self):
        return dict(schema='lattice.session_demo_catalog.v1', budget_bytes=81920,
            configurations=[dict(id=k, title=v['title'], platform=v['platform'],
                resources=self.resources[k], maximum_charged_bytes=max(r['charged_bytes'] for r in self.resources[k].values()))
                for k, v in self.entries.items()],
            studies=[dict(id=i, title=v['title']) for i, v in enumerate(self.data.get('studies', []))],
            live_scope='现场运行检查固定池、完整流程与清理；栈、全局区和程序大小对应相同库的独立保护实验。浏览器及演示宿主另计。')

def execute(config, identifier, dsa, mode):
    check(type(dsa) is int and dsa in PAIR and mode in MODES and identifier in config.entries, 'Invalid session preset')
    selected = config.entries[identifier]
    host = 'windows_x86_64' if sys.platform == 'win32' and platform.machine().lower() in ('amd64', 'x86_64') else 'linux_aarch64' if sys.platform.startswith('linux') and platform.machine().lower() in ('aarch64', 'arm64') else None
    check(selected['platform'] == host, 'Library architecture is not available on this host')
    from demo import host_cpu
    from publicschemas.cpu_features import availability
    probe = artifact(config.base, config.data['host_probe']) if 'host_probe' in config.data else None
    check(availability(selected['execution'], host_cpu.query(probe))['available'], 'CPU capability is unavailable')
    # Validate both files again in the worker immediately before loading.
    measured_library = selected.get('measured_library_sha256', selected['library']['sha256'])
    core = C.CDLL(str(execution_image(config.base, selected['library'], measured_library, selected.get('library_derivation'))))
    module = C.CDLL(str(execution_image(config.base, config.data['application'], config.measured_application,
                                       config.data.get('application_derivation'))))
    api = Api(*[C.cast(getattr(core, name), V).value for name in FUNCTIONS])
    signatures = {
        'app_pool_bytes': (N, [C.POINTER(Api), I, I, I, N]),
        'app_open': (V, [V, N, C.POINTER(Api), I, I, I, I, N, U]),
        'app_prepare': (I, [V]), 'app_flow': (I, [V]), 'app_temporaries_clear': (I, [V]),
        'app_finish': (None, [V]), 'app_close': (None, [V])}
    for name, (ret, args) in signatures.items():
        fn = getattr(module, name); fn.restype = ret; fn.argtypes = args
    r = config.resources[identifier][dsa]; n, fresh = MODES[mode]; kem = PAIR[dsa]
    size = module.app_pool_bytes(C.byref(api), kem, dsa, 1, r['workspace_bytes'])
    check(size == r['pool_bytes'], 'Live application owner differs from the qualified resource model')
    raw = C.create_string_buffer(size + 96); start = (C.addressof(raw) + 63) & ~31
    C.memset(raw, 0xa5, len(raw)); C.memset(start, 0xcc, size)
    pointer = None; events = [0] * 7; observer_error = []
    callback_type = C.CFUNCTYPE(None, V, C.c_uint, V)
    @callback_type
    def observe(user, stage, state):
        if stage < 7: events[stage] += 1
        else: observer_error.append(stage)
    result = dict(schema='lattice.session_functional_observation.v1', performance_measurement=False,
                  library=identifier, kem=kem, dsa=dsa, mode=mode, requested_flows=n,
                  application_sha256=config.data['application']['sha256'], library_sha256=selected['library']['sha256'],
                  measured_application_sha256=config.measured_application, measured_library_sha256=measured_library,
                  entropy_source='host_os_csprng', resource_evidence_sha256=selected['resources']['sha256'],
                  resources=r, workspace_guarded=True, stack_scope='independently qualified reservation; no live browser-host stack claim')
    try:
        # A zero test seed selects the actual OS CSPRNG in the unchanged application.
        pointer = module.app_open(start, size, C.byref(api), kem, dsa, 1, fresh, r['workspace_bytes'], 0)
        check(pointer == start, 'Application failed to initialize')
        state = C.cast(pointer, C.POINTER(State)).contents
        state.observer = C.cast(observe, V).value
        check(not state.context.random and not state.context.random_user, 'Live demo must use the OS CSPRNG')
        rc = module.app_prepare(pointer); clear = True
        if rc == 0:
            for _ in range(n):
                rc = module.app_flow(pointer)
                clear = clear and module.app_temporaries_clear(pointer) == 1
                if rc: break
        result.update(return_code=rc, completed_flows=state.flows,
                      observed_workspace_peak=state.high, authority_workspace_peak=state.authority_high,
                      public_cache_bytes=state.cache_bytes, temporary_secrets_cleared=clear,
                      operation_counts=dict(zip(('identity_keygen', 'kem_keygen', 'sign', 'verify', 'encaps', 'decaps', 'prepare_public_matrix'), events)),
                      public_transcript=f'{state.transcript:016x}')
        expected = [n if fresh else 1, n, n, n, n, n, n if fresh else 1]
        result['functional_checks_passed'] = rc == 0 and state.flows == n and events == expected and clear and not observer_error
    finally:
        if pointer:
            module.app_finish(pointer)
            module.app_close(pointer)
        result['pool_cleared'] = not any(C.string_at(start, size))
        result['canaries_ok'] = C.string_at(start - 32, 32) == b'\xa5' * 32 and C.string_at(start + size, 32) == b'\xa5' * 32
        C.memset(start, 0, size)
    result['functional_checks_passed'] &= result['pool_cleared'] and result['canaries_ok']
    return result

def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--config', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--library', required=True); p.add_argument('--dsa', type=int, choices=PAIR, required=True)
    p.add_argument('--mode', choices=MODES, required=True); a = p.parse_args()
    try:
        sys.path.insert(0, str(a.source.resolve()))
        result = execute(Configuration(a.config), a.library, a.dsa, a.mode)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0 if result['functional_checks_passed'] else 1
    except Exception:
        print(json.dumps({'schema':'lattice.session_functional_error.v1', 'error':'完整会话流程未完成'}, ensure_ascii=False))
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
