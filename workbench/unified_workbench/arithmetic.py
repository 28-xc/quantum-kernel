"""Public-input diagnostics for the project's portable Windows arithmetic build.

The DLL performs the displayed operation. Integer and SHAKE functions below
are independent checks and never provide an execution result to the UI.
"""
from ctypes import CDLL, POINTER, c_int, c_int32, c_uint8, c_uint32
from functools import lru_cache
from hashlib import sha256, shake_128, shake_256
import json
import os
import platform
from pathlib import Path
from secrets import randbelow, randbits, token_bytes
from demo import platform_protocol as wire
from time import perf_counter_ns


HERE = Path(__file__).resolve().parent
DIAG = HERE / 'arithmetic'
PROJECT = Path('01_源代码/可参数化格运算内核')
POLY_SOURCE = PROJECT / 'src/backends/canonical.c'
ADAPTER_SOURCE = PROJECT / 'demo/arithmetic_diagnostic'
KEM, DSA = 'ML-KEM', 'ML-DSA'
POLYNOMIAL = ('add', 'sub', 'mul', 'ntt', 'intt')
UNARY = ('ntt', 'intt')
PARAMETERS = {KEM: (512, 768, 1024), DSA: (44, 65, 87)}
MODULI = {KEM: 3329, DSA: 8380417}
ETA = {512: 3, 768: 2, 1024: 2, 44: 2, 65: 4, 87: 2}
TAU = {44: 39, 65: 49, 87: 60}
CHALLENGE = {44: 32, 65: 48, 87: 64}
DIMENSION = {512: (2, 2), 768: (3, 3), 1024: (4, 4), 44: (4, 4), 65: (6, 5), 87: (8, 7)}
VECTOR = c_int32 * 256
BUFFER = c_uint8 * 384
SEED = c_uint8 * 64
FORMAL_OPS = {'matrix': 0, 'noise': 1, 'secret': 1, 'mask': 2, 'challenge': 3,
              'encode': 4, 'decode': 5, 'compress': 6, 'decompress': 7, 'reduce': 8}
OPERATIONS = (
    ('add', '多项式加法', 'poly', 'pair', (KEM, DSA)),
    ('sub', '多项式减法', 'poly', 'pair', (KEM, DSA)),
    ('reduce', '系数模约减', 'poly', 'scalar', (KEM, DSA)),
    ('mul', '完整多项式环乘', 'poly', 'pair', (KEM, DSA)),
    ('ntt', 'NTT', 'poly', 'poly', (KEM, DSA)),
    ('intt', 'INTT', 'poly', 'poly', (KEM, DSA)),
    ('matrix', '公开矩阵采样', 'sample', 'seed', (KEM, DSA)),
    ('noise', 'ML-KEM 噪声采样', 'sample', 'seed', (KEM,)),
    ('secret', 'ML-DSA 秘密系数采样', 'sample', 'seed', (DSA,)),
    ('mask', 'ML-DSA 签名掩码采样', 'sample', 'seed', (DSA,)),
    ('challenge', 'ML-DSA 挑战采样', 'sample', 'seed', (DSA,)),
    ('encode', '系数编码', 'codec', 'poly', (KEM, DSA)),
    ('decode', '系数解码', 'codec', 'bytes', (KEM, DSA)),
    ('compress', 'ML-KEM 密文量化压缩', 'codec', 'poly', (KEM,)),
    ('decompress', 'ML-KEM 密文量化解压', 'codec', 'bytes', (KEM,)),
)


ALL_OPERATIONS = tuple(item[0] for item in OPERATIONS)


def catalog(root):
    operations = []
    for identifier, title, group, kind, algorithms in OPERATIONS:
        item = dict(id=identifier, title=title, group=group, algorithms=algorithms, input=kind)
        if group == 'sample':
            item['hint'] = '留空使用默认种子。'
            item['seed_bytes'] = {'matrix': 32, 'noise': 32, 'secret': 64, 'mask': 64,
                                  'challenge': CHALLENGE}[identifier]
        if identifier in ('compress', 'decompress'):
            item['widths'] = {512: [4, 10], 768: [4, 10], 1024: [5, 11]}
        operations.append(item)
    linux = is_linux_arm()
    native = (DIAG / ('native_arithmetic_aarch64.so' if linux else 'native_arithmetic.dll')).is_file()
    return dict(operations=operations, available=native and (os.name == 'nt' or linux))


def is_linux_arm():
    return platform.system() == 'Linux' and platform.machine().lower() in ('aarch64','arm64')


def arm_build_hash():
    return json.loads((DIAG / 'arithmetic-aarch64.json').read_text(encoding='utf-8'))['binary_sha256']


@lru_cache(maxsize=1)
def linux_adapter():
    if not is_linux_arm():
        raise ValueError('算术模块需要 Linux AArch64。')
    path = DIAG / 'native_arithmetic_aarch64.so'
    digest = arm_build_hash()
    if sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError('Linux 算术模块校验失败。')
    dll = CDLL(str(path))
    _bind_polynomial(dll)
    return dll, digest


def primitive_digest():
    return json.loads((DIAG/'primitives.json').read_text(encoding='ascii'))['native_primitives_aarch64.so']


@lru_cache(maxsize=1)
def linux_primitives():
    if not is_linux_arm():
        raise ValueError('算术模块需要 Linux AArch64。')
    path = DIAG/'native_primitives_aarch64.so'
    digest = primitive_digest()
    if sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError('Linux 原语模块校验失败。')
    dll=CDLL(str(path))
    _bind_primitive(dll)
    return dll,digest


def _bind_polynomial(dll):
    coefficients = POINTER(c_int32)
    for name in POLYNOMIAL:
        fn = getattr(dll, 'lc_poly_' + name)
        fn.argtypes = [c_uint32, coefficients] if name in UNARY else [
            c_uint32, coefficients, coefficients, coefficients]
        fn.restype = c_int


@lru_cache(maxsize=1)
def _adapter():
    path = DIAG / 'native_arithmetic.dll'
    evidence = json.loads((DIAG / 'build.json').read_text(encoding='utf-8'))
    if sha256(path.read_bytes()).hexdigest() != evidence['dll_sha256']:
        raise ValueError('算术模块校验失败。')
    dll = CDLL(str(path))
    _bind_polynomial(dll)
    _bind_primitive(dll)
    return dll, evidence


def _bind_primitive(dll):
    coefficients, buffer = POINTER(c_int32), POINTER(c_uint8)
    dll.lc_demo_kem.argtypes = [c_int, c_int, coefficients, buffer, buffer, *([c_uint32]*4)]
    dll.lc_demo_kem.restype = c_int
    for parameter in PARAMETERS[DSA]:
        fn = getattr(dll, f'lc_demo_dsa{parameter}')
        fn.argtypes = [c_int, coefficients, buffer, buffer, *([c_uint32]*3)]
        fn.restype = c_int


def _integer(value, low, high, field):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{field}需为 {low} 到 {high} 的整数')
    return value


def _hex(value, length, field):
    if not isinstance(value, str) or len(value) > 3*length:
        raise ValueError(f'{field}需要 {length} 字节十六进制数据')
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f'{field}含非法十六进制字符') from error
    if len(data) != length:
        raise ValueError(f'{field}需要 {length} 字节十六进制数据')
    return data


def _coefficients(request, name, low, high, preset, monomial, scalar=False):
    if preset == 'import':
        items = request.get(name)
        if scalar and type(items) is int:
            items = [items]
        if not isinstance(items, list) or len(items) not in ((1, 256) if scalar else (256,)):
            raise ValueError('约减需要1或256个整数' if scalar else '需要256个系数')
        return [_integer(item, low, high, '系数') for item in items]
    if preset == 'random':
        return [low + randbelow(high-low+1) for _ in range(256)]
    if preset == 'boundary':
        return [low, high]*128
    result = [0]*256
    if preset == 'monomial':
        result[monomial] = 1
    if preset == 'unit':
        result[0] = 1
    return result


def _multiply(a, b, q):
    value = [0]*256
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            index = i+j
            value[index % 256] += x*y if index < 256 else -x*y
    return [x % q for x in value]


def _forward(values, algorithm, q):
    stride, primitive, bits = (2, 17, 7) if algorithm == KEM else (1, 1753, 8)
    result = []
    for index in range(256 // stride):
        exponent = int(f'{index:0{bits}b}'[::-1], 2)*2+1
        point = pow(primitive, exponent, q)
        for column in range(stride):
            evaluated = 0
            for coefficient in values[column::stride][::-1]:
                evaluated = (evaluated*point + coefficient) % q
            result.append(evaluated)
    return result


def _inverse(values, algorithm, q):
    stride, primitive, bits = (2,17,7) if algorithm == KEM else (1,1753,8)
    domain = 1 << bits
    scale = pow(domain,-1,q)
    result = [0] * 256
    for index in range(domain):
        exponent = int(f'{index:0{bits}b}'[::-1],2)*2+1
        reciprocal = pow(primitive,-exponent,q)
        power = scale
        for offset in range(0,256,stride):
            for column in range(stride):
                result[offset+column] = (result[offset+column] + values[index*stride+column]*power) % q
            power = power*reciprocal % q
    return result


def _pack(values, width):
    word = sum(value << (i * width) for i, value in enumerate(values))
    return word.to_bytes(32 * width, 'little')


def _unpack(data, width):
    value, mask = int.from_bytes(data, 'little'), (1 << width) - 1
    return [(value >> (i * width)) & mask for i in range(256)]


def _matrix_check(seed, row, column, algorithm, q):
    xof = shake_128(seed + bytes((column, row)))
    candidates = []
    size = 768
    while len(candidates) < 256:
        stream = xof.digest(size)
        candidates.clear()
        for i in range(0, size, 3):
            n = int.from_bytes(stream[i:i+3], 'little')
            digits = (n & 4095, n >> 12) if algorithm == KEM else (n & 8388607,)
            candidates.extend(value for value in digits if value < q)
        size *= 2
    return candidates[:256]


def _eta_check(seed, index, parameter, algorithm):
    eta = ETA[parameter]
    if algorithm == KEM:
        stream = shake_256(seed + bytes((index,))).digest(64 * eta)
        bits = [(byte >> i) & 1 for byte in stream for i in range(8)]
        return [sum(bits[i:i+eta]) - sum(bits[i+eta:i+2*eta])
                for i in range(0, len(bits), 2*eta)]

    xof = shake_256(seed + index.to_bytes(2, 'little'))
    size, values = 256, []
    while len(values) < 256:
        values.clear()
        for byte in xof.digest(size):
            for nibble in (byte & 15, byte >> 4):
                if eta == 2 and nibble < 15:
                    values.append(2-nibble % 5)
                elif eta == 4 and nibble < 9:
                    values.append(4-nibble)
        size *= 2
    return values[:256]


def _challenge_check(seed, parameter):
    # Read signs and rejection positions from a single public XOF stream.
    stream = shake_256(seed)
    size = 256
    data = stream.digest(size)
    signs, cursor = int.from_bytes(data[:8], 'little'), 8
    output = [0]*256
    for i in range(256-TAU[parameter], 256):
        while True:
            if cursor == size:
                size *= 2
                data = stream.digest(size)
            position = data[cursor]
            cursor += 1
            if position <= i:
                break
        output[i], output[position] = output[position], 1-2*(signs & 1)
        signs >>= 1
    return output


def polynomial_inputs(request, operation, q, preset):
    lower = 1-q if preset == 'import' else 0
    inputs = {}
    fields = [('a',255)] if operation in UNARY else [('a',255),('b',1)]
    for side,monomial in fields:
        submitted = _coefficients(request, side, lower, q-1, preset, monomial)
        inputs[side] = [x % q for x in submitted]
        if inputs[side] != submitted:
            inputs['submitted_'+side] = submitted
    return inputs


def native_polynomial(dll, operation, q, a, b=None):
    fn = getattr(dll, 'lc_poly_' + operation)
    input_a = VECTOR(*a)
    if operation in UNARY:
        output, arguments = input_a, (input_a,)
    else:
        output = VECTOR()
        arguments = (output, input_a, VECTOR(*b))
    started = perf_counter_ns()
    status = fn(q, *arguments)
    return status,list(output),perf_counter_ns() - started


def check_polynomial(operation, algorithm, q, inputs, output):
    a = inputs['a']
    if operation == 'ntt':
        actual, expected = output, _forward(a, algorithm, q)
        method = '独立求值 · 标准位逆序分量'
    elif operation == 'intt':
        actual, expected = output, _inverse(a, algorithm, q)
        method = '独立单位根插值 · 标准位逆序分量'
    elif operation == 'mul':
        actual, expected = output, _multiply(a, inputs['b'], q)
        method = '独立整数朴素负循环卷积 · 比对全部256项'
    else:
        sign = 1 if operation == 'add' else -1
        actual, expected = output, [(x+sign*y) % q for x,y in zip(a,inputs['b'])]
        method = '独立整数模运算 · 比对全部256项'
    return sum(x == y for x,y in zip(actual,expected)), method, expected


def _run_poly(dll, request, operation, algorithm, q, preset, report):
    inputs = polynomial_inputs(request,operation,q,preset)
    if report: report('正在计算')
    status,output,elapsed = native_polynomial(dll,operation,q,inputs['a'],inputs.get('b'))
    if report and status == 0: report('已收到计算结果，正在核对系数')
    matches,method,expected = check_polynomial(operation,algorithm,q,inputs,output)
    return status, output, matches, method, inputs, elapsed, expected


def execute_linux(request, exchange=None, *, report=None):
    operation, algorithm = request.get('operation'), request['algorithm']
    preset = request.get('preset')
    if operation not in POLYNOMIAL or preset not in ('monomial','zero','unit','boundary','random','import'):
        raise ValueError('请选择 Linux 支持的运算和输入类型。')
    q = MODULI[algorithm]
    if report: report('正在准备输入')
    if exchange is None:
        dll,digest = linux_adapter()
        status,output,matched,method,inputs,elapsed,expected = _run_poly(dll,request,operation,algorithm,q,preset,report)
    else:
        from demo import platform_protocol as wire
        digest = arm_build_hash()
        inputs = polynomial_inputs(request,operation,q,preset)
        if report: report('正在向 Linux 发送算术请求')
        reply = exchange(operation,q,inputs['a']+inputs.get('b',[]))
        if reply['binary_sha256'] != digest:
            raise ValueError('Linux 返回的算术模块标识与当前软件不匹配。')
        status,elapsed = reply['status'],reply['duration_ns']
        output = wire.decode_polynomials(reply['coefficients'],256,q)
        if report: report('已收到 Linux 结果，正在核对系数')
        matched,method,expected = check_polynomial(operation,algorithm,q,inputs,output)
        wire.observe_frame('本机','HOST',b'',f'{matched}/256 个系数与独立计算结果一致')
    return dict(verified=status == 0 and matched == 256,status_code=status,inputs=inputs,output=output,
                modulus=q,duration_ns=elapsed,backend='Linux AArch64 · 规范多项式 API',build_id=digest,
                source_path=POLY_SOURCE.as_posix(),check=method,expected_output=expected,
                function='lc_poly_'+operation,
                summary=f'{matched}/256 个系数与独立计算结果一致')


def call_primitive(dll,packet):
    _,parameter,op,index,row,column,width,*data=wire.PRIMITIVE_INPUT.unpack(packet)
    coefficients=VECTOR(*data[:256])
    encoded=BUFFER(*data[256])
    seed=SEED(*data[257])
    if parameter in PARAMETERS[KEM]:
        function=dll.lc_demo_kem
        args=[parameter,op,coefficients,encoded,seed,index,row,column,width]
    else:
        function=getattr(dll, f'lc_demo_dsa{parameter}')
        args=[op,coefficients,encoded,seed,index,row,column]
    started=perf_counter_ns()
    status=function(*args)
    elapsed=perf_counter_ns()-started
    return status,wire.PRIMITIVE_OUTPUT.pack(*coefficients,bytes(encoded)),elapsed


def _run_binding(dll, request, operation, algorithm, parameter, q, preset, kind, report, exchange=None):
    coefficients, encoded, seed = [], b'', b''
    index, row, column, width = 0, 0, 0, 0
    eta = ETA[parameter]
    inputs = {}
    if kind == 'seed':
        seed_length = 32 if operation in ('noise', 'matrix') else CHALLENGE[parameter] if operation == 'challenge' else 64
        raw = request.get('seed_hex')
        if not raw and preset == 'import':
            raise ValueError('导入采样需要填写公开测试种子')
        if raw:
            seed = _hex(raw, seed_length, '公开种子')
        elif preset == 'random':
            seed = token_bytes(seed_length)
        else:
            seed = bytes(range(seed_length))
        inputs['public_seed_hex'] = seed.hex()
        if operation == 'matrix':
            rows, columns = DIMENSION[parameter]
            row = _integer(request.get('row', 0), 0, rows-1, '矩阵行号')
            column = _integer(request.get('column', 0), 0, columns-1, '矩阵列号')
            inputs.update(row=row, column=column)
        elif operation != 'challenge':
            index = _integer(request.get('index', 0), 0, 65535 if operation == 'mask' else 255, '采样索引')
            inputs['index'] = index

    if operation == 'reduce':
        low, high = (-32768, 32767) if algorithm == KEM else (-(1 << 31), (1 << 31)-1-(1 << 22))
        coefficients = _coefficients(request, 'a', low, high, preset, 0, scalar=True)
    if operation in ('encode', 'decode', 'compress', 'decompress'):
        low, high = (-eta, eta) if algorithm == DSA else (0, q-1)
        if operation in ('compress', 'decompress'):
            valid = (5, 11) if parameter == 1024 else (4, 10)
            width = request.get('width', valid[0])
            if type(width) is not int or width not in valid:
                raise ValueError(f'这个参数的密文位宽为 {valid[0]} 或 {valid[1]}')
        else:
            width = 12 if algorithm == KEM else 4 if eta == 4 else 3
        inputs['width'] = width
        if kind == 'bytes':
            if preset == 'import':
                encoded = _hex(request.get('data_hex'), 32*width, '编码输入')
            else:
                values = _coefficients(request, 'a', low, high, preset, 0)
                if operation == 'decompress':
                    values = [((x*(1 << width)+q//2)//q) % (1 << width) for x in values]
                elif algorithm == DSA:
                    values = [eta-x for x in values]
                encoded = _pack(values, width)
            expected_unpacked = _unpack(encoded, width)
            if operation == 'decode' and any(x > (q-1 if algorithm == KEM else 2*eta) for x in expected_unpacked):
                raise ValueError('输入含无效的系数编码')
            inputs['data_hex'] = encoded.hex()
        else:
            coefficients = _coefficients(request, 'a', low, high, preset, 0)
    if coefficients:
        inputs['a'] = coefficients

    packet=wire.PRIMITIVE_INPUT.pack(randbits(32),parameter,FORMAL_OPS[operation],index,row,column,width,
                                     *coefficients,*([0]*(256-len(coefficients))),encoded,seed)
    if report: report('正在计算')
    if exchange is None:
        status,output,elapsed=call_primitive(dll,packet)
    else:
        label=next(title for key,title,*_ in OPERATIONS if key==operation)
        status,output,elapsed,image=exchange(packet,label=label,report=report)
        if request.get('platform')=='arm' and image!=primitive_digest():
            raise ValueError('Linux 返回的原语模块标识与当前软件不匹配。')
    if report and status == 0: report('已收到计算结果，正在校验')

    data=wire.PRIMITIVE_OUTPUT.unpack(output)
    actual=list(data[:256])
    native_bytes=data[256]
    if operation == 'matrix':
        expected = _matrix_check(seed, row, column, algorithm, q)
        method = '独立 SHAKE128 与拒绝采样逐系数核验'
    elif operation in ('noise', 'secret'):
        expected = _eta_check(seed, index, parameter, algorithm)
        method = '独立 SHAKE256 与标准取样规则逐系数核验'
    elif operation == 'mask':
        gamma = 1 << (17 if parameter == 44 else 19)
        bits = 18 if parameter == 44 else 20
        data = shake_256(seed + index.to_bytes(2, 'little')).digest(32*bits)
        expected = [gamma-n for n in _unpack(data, bits)]
        method = '独立 SHAKE256 与掩码分量解码'
    elif operation == 'challenge':
        expected = _challenge_check(seed, parameter)
        method = f'独立 SHAKE256 与抽样位置逐项核验，非零项数 {TAU[parameter]}'
    elif operation == 'reduce':
        actual = actual[:len(coefficients)]
        expected = [n % q for n in coefficients]
        matches = sum(n % q == target for n,target in zip(actual, expected))
        return status, actual, matches, '比较标准代表元 · 输出保留内核实际代表元', inputs, elapsed, expected
    elif operation == 'compress':
        digits = [((x*(1 << width)+q//2)//q) % (1 << width) for x in coefficients]
        expected = _pack(digits, width)
        actual = bytes(native_bytes[:len(expected)])
        method = '独立标准量化及位串比对'
    elif operation == 'decompress':
        expected = [(q*x+(1 << (width-1))) >> width for x in expected_unpacked]
        method = '独立标准反量化逐系数核验'
    elif operation == 'encode':
        expected = _pack(coefficients if algorithm == KEM else [eta-x for x in coefficients], width)
        actual = bytes(native_bytes[:len(expected)])
        method = '独立小端位串逐字节核验'
    else:
        expected = expected_unpacked if algorithm == KEM else [eta-x for x in expected_unpacked]
        method = '独立小端位串解码逐系数核验'
    matches = sum(x == y for x,y in zip(actual, expected))
    return status, actual, matches, method, inputs, elapsed, expected


def execute_primitive(request, exchange=None, *, report=None):
    algorithm,parameter=request['algorithm'],request['parameter']
    operation,preset=request['operation'],request['preset']
    option=next((row for row in OPERATIONS if row[0]==operation and algorithm in row[4]),None)
    if option is None or operation in POLYNOMIAL or preset not in ('monomial','zero','unit','boundary','random','import'):
        raise ValueError('当前参数不支持此算术运算或输入类型。')
    board=request.get('source_kind')=='live_board'
    dll=linux_primitives()[0] if exchange is None else None
    status,output,matched,method,inputs,elapsed,expected=_run_binding(
        dll,request,operation,algorithm,parameter,MODULI[algorithm],preset,option[3],report,exchange)
    encoded=isinstance(output,bytes)
    unit='字节' if encoded else '个系数'
    summary=('运算失败' if status else f'{matched}/{len(output)} {unit}与独立计算结果一致')
    result=dict(verified=status==0 and matched==len(output),status_code=status,inputs=inputs,check=method,
                summary=summary,modulus=MODULI[algorithm],
                source_path=(ADAPTER_SOURCE/('kem.c' if algorithm==KEM else 'dsa.c')).as_posix(),
                function='lc_demo_kem' if algorithm==KEM else f'lc_demo_dsa{parameter}')
    if encoded:
        result.update(output_hex=output.hex(),expected_output_hex=expected.hex())
    else:
        result.update(output=output,expected_output=expected)
    result['cycles' if board else 'duration_ns']=elapsed
    if operation=='reduce':
        result['canonical_output']=[x%MODULI[algorithm] for x in output]
    return result


def execute(root, request, *, report=None):
    if os.name != 'nt' or request.get('platform', 'windows') != 'windows' or request.get('source_kind', 'live_host') != 'live_host':
        raise ValueError('请切换到 Windows 本机。')
    algorithm, parameter = request.get('algorithm'), request.get('parameter')
    if algorithm not in PARAMETERS or type(parameter) is not int or parameter not in PARAMETERS[algorithm]:
        raise ValueError('算法与参数不匹配')
    operation = request.get('operation')
    option = next((row for row in OPERATIONS if row[0] == operation and algorithm in row[4]), None)
    if option is None:
        raise ValueError('当前参数不支持此算术运算')
    preset = request.get('preset', 'monomial')
    if preset not in ('monomial', 'zero', 'unit', 'boundary', 'random', 'import'):
        raise ValueError('请选择输入类型。')
    q = MODULI[algorithm]
    if report: report('正在准备输入')
    dll, evidence = _adapter()
    expected = None
    if operation in POLYNOMIAL:
        status, value, matches, method, inputs, elapsed, expected = _run_poly(dll, request, operation, algorithm, q, preset, report)
        source = POLY_SOURCE
    else:
        status, value, matches, method, inputs, elapsed, expected = _run_binding(
            dll, request, operation, algorithm, parameter, q, preset, option[3], report)
        source = ADAPTER_SOURCE / ('kem.c' if algorithm == KEM else 'dsa.c')
    verified = status == 0 and matches == len(value)
    encoded = isinstance(value, bytes)
    if status != 0:
        summary = '运算失败'
    elif operation == 'intt':
        summary = f'{matches}/{len(value)} 个系数通过独立插值校验'
    elif operation == 'reduce':
        summary = f'{matches}/{len(value)} 个系数的模 q 结果一致'
    else:
        unit = '字节' if encoded else '个系数'
        summary = f'{matches}/{len(value)} {unit}与独立计算结果一致'
    result = dict(verified=verified, status_code=status, check=method, inputs=inputs,
                  summary=summary,
                  source_kind='live_host', backend=evidence['component'], build_id=evidence['dll_sha256'],
                  source_path=source.as_posix(), modulus=q, duration_ns=elapsed,
                  measurement_kind='本机诊断调用墙钟时长')
    result['output_hex' if encoded else 'output'] = value.hex() if encoded else value
    if operation in POLYNOMIAL:
        result.update(expected_output=expected,function='lc_poly_'+operation)
    elif isinstance(expected,bytes):
        result['expected_output_hex']=expected.hex()
    else:
        result['expected_output']=expected
    if operation == 'reduce':
        result['canonical_output'] = [x % q for x in value]
    return result


def execute_board(request, run_ring, *, report=None):
    operation = request.get('operation')
    if operation not in (*POLYNOMIAL,'reduce'):
        raise ValueError('当前开发板未提供该运算。')
    algorithm = request['algorithm']
    q = MODULI[algorithm]
    preset = request.get('preset')
    if preset not in ('monomial','zero','unit','boundary','random','import'):
        raise ValueError('请选择输入类型。')
    if report: report('正在准备输入')
    if operation == 'reduce':
        low,high = (-32768,32767) if algorithm == KEM else (-(1<<31),(1<<31)-1-(1<<22))
        inputs = {'a': _coefficients(request,'a',low,high,preset,0,scalar=True)}
    else:
        inputs = polynomial_inputs(request,operation,q,preset)
    a = inputs['a']
    transmitted = a + [0]*(256-len(a))
    output,cycles = run_ring(transmitted,inputs.get('b',[0]*256),q,operation=operation,report=report)
    if len(output) != 256:
        raise ValueError('板端输出系数无效。')
    if report: report(f'正在核对 {len(a)} 个系数')
    raw = output[:len(a)]
    output = raw
    if operation == 'reduce':
        expected = [value % q for value in a]
        matched = sum(value % q == reference for value,reference in zip(raw,expected))
        method = '板端约减结果与主机逐项比较模 q 代表元'
    else:
        if operation == 'ntt':
            output = [value % q for value in raw]
        elif operation == 'intt':
            inverse_radix = pow(1 << (16 if algorithm == KEM else 32), -1, q)
            output = [value * inverse_radix % q for value in raw]
        matched,method,expected = check_polynomial(operation,algorithm,q,inputs,output)
        if operation == 'intt':
            method = '板端输出去 Montgomery 因子 · '+method
    function = {'mul':'完整环乘诊断','ntt':'Flash NTT','intt':'Flash INTT','reduce':'Flash 约减',
                'add':'lc_poly_add','sub':'lc_poly_sub'}[operation]
    result = dict(verified=matched == len(a),status_code=0,inputs=inputs,output=output,modulus=q,
                  check=method,cycles=cycles,function=function,expected_output=expected,
                  summary=f'{matched}/{len(a)} 个系数与独立计算结果一致')
    if output != raw:
        result['native_output'] = raw
    if operation == 'reduce':
        result['canonical_output'] = [value % q for value in raw]
    return result
