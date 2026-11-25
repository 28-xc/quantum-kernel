"""Run device enrollment tests."""
import ctypes as C
import platform
import sys

from .crypto import digest

STEPS = ('生成签发方密钥', '生成设备密钥', '签署设备公钥', '验证公钥签名', '封装共享秘密', '解封装共享秘密')


def run(config, req, *, report=None):
    import session_runtime as rt
    from demo import host_cpu
    from publicschemas.cpu_features import availability
    kem, dsa = req.get('kem'), req.get('dsa')
    scenario, fresh, count = req.get('scenario', 'normal'), req.get('fresh', True), req.get('count', 1)
    if (type(kem) is not int or kem not in (512, 768, 1024) or type(dsa) is not int or dsa not in (44, 65, 87)
            or scenario not in ('normal', 'signature', 'capacity') or type(fresh) is not bool
            or type(count) is not int or count not in (1, 2)):
        raise ValueError('请选择接入参数和场景。')
    selected = config.entries['project']
    if sys.platform != 'win32' or platform.machine().lower() not in ('amd64','x86_64'):
        raise ValueError('设备接入不可用。')
    probe = rt.artifact(config.base, config.data['host_probe'])
    if not availability(selected['execution'], host_cpu.query(probe))['available']:
        raise ValueError('本机处理器不支持设备接入。')
    lib_path = rt.execution_image(config.base, selected['library'], selected.get('measured_library_sha256',
                                  selected['library']['sha256']), selected.get('library_derivation'))
    app_path = rt.execution_image(config.base, config.data['application'], config.measured_application,
                                  config.data.get('application_derivation'))
    core, app = C.CDLL(str(lib_path)), C.CDLL(str(app_path))
    api = rt.Api(*[C.cast(getattr(core, name), rt.V).value for name in rt.FUNCTIONS])
    for name, ret, args in (
        ('app_pool_bytes',rt.N,[C.POINTER(rt.Api),rt.I,rt.I,rt.I,rt.N]),
        ('app_open',rt.V,[rt.V,rt.N,C.POINTER(rt.Api),rt.I,rt.I,rt.I,rt.I,rt.N,rt.U]),
        ('app_prepare',rt.I,[rt.V]), ('app_flow',rt.I,[rt.V]), ('app_temporaries_clear',rt.I,[rt.V]),
        ('app_finish',None,[rt.V]), ('app_close',None,[rt.V])):
        fn = getattr(app, name); fn.argtypes = args; fn.restype = ret
    capacity = config.resources['project'][dsa]['workspace_bytes']
    pool_bytes = app.app_pool_bytes(C.byref(api), kem, dsa, 1, capacity)
    if not pool_bytes:
        raise ValueError('不支持这组接入参数。')
    raw = C.create_string_buffer(pool_bytes + 96)
    start = (C.addressof(raw) + 63) & ~31
    C.memset(raw, 0xa5, len(raw)); C.memset(start, 0, pool_bytes)
    stages = []
    captured = {}
    @C.CFUNCTYPE(None, rt.V, C.c_uint, rt.V)
    def observe(user, index, ptr):
        if index > 5:
            return
        # Match the struct in examples/public_a_session/application.c.
        state = C.cast(ptr, C.POINTER(rt.State)).contents
        k, d = state.k, state.d
        key = state.objects + k.secret_key - k.public_key - 64
        authority = state.objects + k.secret_key
        signature = authority + d.public_key + d.secret_key
        pub = {0:(authority,d.public_key), 1:(key,k.public_key), 2:(signature,d.signature),
               3:(key,k.public_key), 4:(signature,k.ciphertext)}.get(index)
        if pub:
            captured[index] = {'bytes': pub[1], 'sha256': digest(C.string_at(*pub))}
        stages.append(index)
        if report: report(f'{STEPS[index]} · 已完成')
    pointer = app.app_open(start, pool_bytes, C.byref(api), kem, dsa, 1, int(fresh), capacity, 0)
    if pointer != start:
        C.memset(raw, 0, len(raw))
        raise ValueError('无法启动设备接入。')
    rounds = []
    try:
        state = C.cast(pointer, C.POINTER(rt.State)).contents
        state.observer = C.cast(observe, rt.V).value
        if state.context.random or state.context.random_user:
            raise ValueError('无法取得随机数。')
        state.fault, state.fault_stage = {'normal':(0,0), 'signature':(3,3), 'capacity':(2,2)}[scenario]
        if report: report('正在准备接入')
        rc = app.app_prepare(pointer)
        for index in range(count):
            if index:
                stages.clear(); captured.clear()
            if rc == 0:
                if report: report(f'正在执行第 {index + 1} 次接入' if count > 1 else '正在执行接入')
                rc = app.app_flow(pointer)
                if report and rc == 0 and state.flows == index + 1: report('双方共享秘密一致')
            failed_at = state.phase if rc else None
            steps = []
            for ordinal, label in enumerate(STEPS):
                used_identity = index > 0 and ordinal == 0 and not fresh and state.identity_ready
                done = ordinal in stages or used_identity
                step = {'step': ordinal + 1, 'operation': label,
                        'status': '复用本批签发方身份' if used_identity else '已完成' if done else
                                  ('验签失败' if rc == -6 else '工作区不足' if rc == -5 else '失败')
                                  if ordinal == failed_at else '未执行',
                        'return_code': 0 if done else rc if ordinal == failed_at else None}
                if ordinal in captured:
                    step['public_output'] = captured[ordinal]
                steps.append(step)
            rounds.append(dict(steps=steps, return_code=rc,
                               shared_secret_equal=(rc == 0 and state.flows == index + 1) if 5 in stages else None,
                               temporary_secrets_cleared=bool(app.app_temporaries_clear(pointer))))
            if rc:
                break
        flows = int(state.flows)
    finally:
        app.app_finish(pointer); app.app_close(pointer)
        cleared = not any(C.string_at(start, pool_bytes))
        guarded = C.string_at(start-32,32) == b'\xa5'*32 and C.string_at(start+pool_bytes,32) == b'\xa5'*32
        C.memset(raw, 0, len(raw))
    expected = {'normal':0, 'signature':-6, 'capacity':-5}[scenario]
    ok = rc == expected and guarded and cleared and all(x['temporary_secrets_cleared'] for x in rounds)
    ok = ok and (flows == count if scenario == 'normal' else flows == 0 and rounds[-1]['steps'][4]['status'] == '未执行')
    return dict(verified=ok, return_code=rc, summary=('双方共享秘密一致' if rc == 0 else
                '验签失败，接入已停止' if rc == -6 else '工作区不足' if rc == -5 else '流程失败'),
                build_id=config.data['application']['sha256'], library_sha256=selected['library']['sha256'],
                application_profile='Windows 完整接入应用 · project', kem=kem, dsa=dsa, scenario=scenario,
                fresh_authority=fresh, requested_flows=count, attempted_flows=len(rounds), completed_flows=flows,
                failed_flows=len(rounds)-flows, rounds=rounds, steps=rounds[-1]['steps'], shared_secret_length=32,
                pool_cleared=cleared, canaries_ok=guarded, domain='A1-27 device enrollment v2',
                source_path='01_源代码/可参数化格运算内核/examples/public_a_session/application.c')
