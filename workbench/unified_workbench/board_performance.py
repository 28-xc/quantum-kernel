"""Time the board API with reviewed inputs and capture public bytes from those calls."""
import struct

from . import crypto, security_checks, vectors


def measure(runtime, target, profile, plan, report, append, *, stop=None):
    board = runtime.live.providers['stm32f407' if target=='stm32f407' else 'ch32']
    role = None if target=='stm32f407' else ('高性能' if profile=='80' else '低内存')
    fixtures = []
    for parameter, operation in plan:
        family = 'ML-KEM' if parameter > 100 else 'ML-DSA'
        index = crypto.OPERATIONS[family].index(operation)
        fixture = next(case for case in vectors.board_cases(runtime.root,parameter,role)
                       if case['operation']==index and case['accepted'])
        inputs, expected = vectors.board_case_data(runtime.source,fixture)
        fixtures.append((fixture, inputs, expected))
    if not fixtures:
        return {}
    profile_row = runtime.remote_row(target,profile)
    clock = 168000000 if role is None else profile_row.get('clock_hz')
    if type(clock) is not int or clock <= 0:
        raise ValueError('设备没有提供当前固件的计时频率。')
    capacities = {}

    def start(index, *_):
        parameter, operation = plan[index]
        name = 'ML-KEM' if parameter > 100 else 'ML-DSA'
        report(f'{name}-{parameter} · {crypto.NAMES[operation]} · 正在执行板端计时')

    def receive(index, reply, actual):
        fixture, inputs, expected = fixtures[index]
        parameter, operation = plan[index]
        if role is None:
            code = struct.unpack('<i',struct.pack('<I',reply[24]))[0]
            peak, cycles = reply[29], reply[32]
            guards = reply[28] == 1 and reply[30] == 0 and reply[31] == 1 and reply[33] == 1
            strategy = 'compact' if profile == '24' else 'cached'
            capacity = board.images[parameter,strategy]['workspace_capacity']
        else:
            code, peak = reply[3], reply[5]
            cycles = reply[9] | reply[10] << 32
            require_timer = reply[11] == 5
            if not require_timer:
                raise ValueError('CH32 板端周期计数器未处于已验证的时钟模式。')
            guards = reply[2] & 39 == 39
            capacity = capacities[index]
        if not 0 < cycles < 2**53 or not 0 <= peak <= capacity:
            raise ValueError('板端周期或工作区读数无效。')

        outputs = {key:value for key,value in zip(expected, actual)}
        checks = {key: outputs.get(key) == bytes.fromhex(value) for key,value in expected.items()}
        verified = code == 0 and guards and all(checks.values())
        display_inputs = public_data({key:bytes.fromhex(value) for key,value in inputs.items()})
        display_outputs = public_data(outputs)
        if operation == 'verify':
            verified = verified and not any(actual)
        summary = ('K = K′' if operation == 'decaps' else '验签通过' if operation == 'verify' else '成功') \
            if verified else '检查失败'
        append(dict(operation=operation, parameter=parameter, return_code=code, verified=verified, summary=summary,
                    cycles=cycles, duration_ms=cycles*1000/clock, workspace_bytes=capacity, workspace_used_bytes=peak,
                    checks=dict(operation_verified=verified), function=crypto.FUNCTIONS[operation],
                    inputs=display_inputs, public_outputs=display_outputs, input_fixture=vectors.board_case_id(fixture)))

    if role is None:
        items = [(fixture['parameter'],fixture['operation'],fixture['tcId'],security_checks.fixture_fields(inputs))
                 for fixture, inputs, _ in fixtures]
        board.run_acvp_bytes(items,report=report,on_start=start,on_reply=receive,stop=stop)
        identity = board.engine.resident.identity
        resources = {'static_ram_bytes': identity['static_ram_bytes'], 'flash_bytes': identity['image_bytes']}
        build_id = identity['firmware_sha256']
    else:
        cases = [(fixture['parameter'],fixture['operation'],fixture['tcId']) for fixture, _, _ in fixtures]

        def capacity(index, packet):
            capacities[index] = struct.unpack_from('<I',packet,16)[0]

        runtime.live.ch32_strategy.run_acvp(profile,cases,on_start=start,on_reply=receive,
                                           edit_fixture=capacity,timed=True,stop=stop)
        runtime.connect_ch32(profile)
        resources = {key:profile_row[key] for key in ('static_ram_bytes','flash_bytes') if type(profile_row.get(key)) is int}
        build_id = profile_row['binary_sha256']
    return dict(clock_hz=clock,timing_method='板端周期计数 · 公开向量逐项调用',
                firmware_resources=resources,build_id=build_id)


def public_data(values):
    public_fields = ('public_key', 'ciphertext', 'signature', 'message', 'context')
    output = {key:crypto.object_info(value) for key,value in values.items() if key in public_fields}
    for key,label in (('secret_key','secret_key_length'),('secret','shared_secret_length')):
        if key in values:
            output[label] = len(values[key])
    return output

