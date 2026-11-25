"""Run local crypto tests without returning secrets."""
import ctypes as C
import hashlib
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from demo.server import Context, Sizes


PARAMETERS = {'ML-KEM': (512, 768, 1024), 'ML-DSA': (44, 65, 87)}
OPERATIONS = {'ML-KEM': ('keygen', 'encaps', 'decaps'), 'ML-DSA': ('keygen', 'sign', 'verify')}
NAMES = {'keygen': '生成密钥', 'encaps': '封装', 'decaps': '解封装', 'sign': '签名', 'verify': '验签',
         'decaps-modified': '修改密文再试', 'verify-modified': '修改消息再试',
         'verify-modified-signature': '签名篡改测试'}
FUNCTIONS = {op: 'lc_' + op for op in ('encaps', 'decaps', 'sign', 'verify')} | {
    'keygen': 'lc_keypair', 'decaps-modified': 'lc_decaps', 'verify-modified': 'lc_verify',
    'verify-modified-signature': 'lc_verify'}
MATERIALS = {'public_key': '公钥', 'secret_key': '私钥', 'ciphertext': '密文', 'signature': '签名'}
CODES = {0: '成功', -1: '参数错误', -2: '输入长度错误', -3: '缓冲区重叠', -4: '随机数获取失败',
         -5: '工作区不足', -6: '输入校验未通过', -7: '内部错误', -8: '此配置不可用'}
RNG = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)


def now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sizes(lib, parameter):
    result = Sizes()
    if lib.lc_get_sizes(parameter, C.byref(result)):
        raise ValueError('内核不支持此参数')
    return result


def message_bytes(req):
    text, context = req.get('message', ''), req.get('context', '')
    if not isinstance(text, str) or not isinstance(context, str):
        raise ValueError('消息和上下文需要文本')
    if 'message_hex' in req:
        value = req['message_hex']
        if not isinstance(value, str) or len(value) > 131072:
            raise ValueError('文件超过 65,536 字节')
        try:
            message = bytes.fromhex(value)
        except ValueError:
            raise ValueError('文件编码错误') from None
    else:
        message = text.encode('utf-8')
    domain = context.encode('utf-8')
    if len(message) > 65536 or len(domain) > 255:
        raise ValueError('消息上限 65,536 B，上下文上限 255 B')
    return message, domain


@contextmanager
def arena(lib, capacity, entropy=None):
    raw = C.create_string_buffer(capacity + 96)
    address = (C.addressof(raw) + 63) & ~31
    C.memset(raw, 0xa5, len(raw))
    C.memset(address, 0, capacity)
    context = Context()
    if lib.lc_context_init(C.byref(context), address, capacity, entropy, None):
        raise ValueError('工作区初始化失败')
    try:
        yield context, address
    finally:
        C.memset(raw, 0, len(raw))


def guard_status(ctx, address, capacity):
    high = ctx.arena_high_water
    return {'canaries_ok': C.string_at(address - 32, 32) == b'\xa5'*32 and
            C.string_at(address + capacity, 32) == b'\xa5'*32,
            'used_workspace_erased': high <= capacity and C.string_at(address, high) == bytes(high),
            'workspace_used_bytes': high}


def object_info(data, *, content=True):
    result = {'length': len(data), 'sha256': digest(data)}
    if content:
        result['hex'] = data.hex()
    return result


class Objects:
    def __init__(self, lib, profile, parameter):
        lengths = sizes(lib, parameter)
        self.profile, self.parameter = profile, parameter
        self.id = secrets.token_hex(12)
        self.pk = C.create_string_buffer(lengths.public_key)
        self.sk = C.create_string_buffer(lengths.secret_key)
        self.payload = C.create_string_buffer(lengths.ciphertext or lengths.signature)
        self.secret = C.create_string_buffer(32)
        self.decapsulated_secret = C.create_string_buffer(32)
        self.has_public = self.has_secret = self.has_payload = self.has_shared = False
        self.has_decapsulated_secret = False
        self.payload_field = 'ciphertext' if lengths.ciphertext else 'signature'
        self.revision = 0
        self.key_record = self.payload_record = self.check_record = None
        self.signed_input = None

    def clear_decapsulated_secret(self):
        C.memset(self.decapsulated_secret, 0, len(self.decapsulated_secret))
        self.has_decapsulated_secret = False

    def close(self):
        for buf in (self.pk, self.sk, self.payload, self.secret):
            C.memset(buf, 0, len(buf))
        self.has_public = self.has_secret = self.has_payload = self.has_shared = False
        self.clear_decapsulated_secret()
        self.revision += 1
        self.key_record = self.payload_record = self.check_record = None
        self.signed_input = None

    def slots(self):
        return {'public_key': (self.pk, self.has_public), 'secret_key': (self.sk, self.has_secret),
                self.payload_field: (self.payload, self.has_payload)}

    def view_slots(self):
        return self.slots() | {'shared_secret': (self.secret, self.has_shared),
                               'decapsulated_secret': (self.decapsulated_secret, self.has_decapsulated_secret)}

    def state(self):
        return {'id': self.id,
                'lengths': {key: len(buf) for key,(buf,loaded) in self.view_slots().items() if loaded},
                'can_retest': bool(self.check_record and (self.has_shared if self.parameter > 100 else self.signed_input))}


def check_key(lib, cap, obj, field, candidate):
    p = obj.parameter
    pk = candidate if field == 'public_key' else obj.pk if obj.has_public else None
    sk = candidate if field == 'secret_key' else obj.sk if obj.has_secret else None
    scratch = [C.create_string_buffer(len(obj.payload)), C.create_string_buffer(32), C.create_string_buffer(32)]
    test, shared, other = scratch
    try:
        with arena(lib, cap) as (ctx, _):
            args = C.byref(ctx), p
            if p > 100:
                if sk is not None:
                    size = len(obj.pk)
                    offset = len(sk) - size - 64
                    embedded = (C.c_char * size).from_buffer(sk, offset)
                    if pk is not None and not secrets.compare_digest(pk.raw, embedded.raw):
                        raise ValueError('公钥和私钥不匹配。请先清除当前数据。')
                    pk = embedded
                    for b in range(0, offset, 3):
                        a, mid, c = C.string_at(C.addressof(sk) + b, 3)
                        if (a | ((mid & 15) << 8)) >= 3329 or ((mid >> 4) | (c << 4)) >= 3329:
                            raise ValueError('私钥格式错误。')
                rc = lib.lc_encaps(*args, test, len(test), shared, len(shared), pk, len(pk))
                if rc:
                    raise ValueError('公钥格式错误。' if rc == -6 else CODES.get(rc, '公钥检查失败。'))
                if sk is not None:
                    rc = lib.lc_decaps(*args, other, len(other), test, len(test), sk, len(sk))
                    if rc or not secrets.compare_digest(shared, other):
                        raise ValueError('私钥校验失败。')
            elif sk is not None:
                # ML-DSA 公钥的定长编码占满位串。私钥编码由签名入口检查。
                rc = lib.lc_sign(*args, test, len(test), b'', 0, b'', 0, sk, len(sk))
                if rc:
                    raise ValueError('私钥格式错误。' if rc == -6 else CODES.get(rc, '私钥检查失败。'))
                if pk is not None and lib.lc_verify(*args, test, len(test), b'', 0, b'', 0, pk, len(pk)):
                    raise ValueError('公钥和私钥不匹配。请先清除当前数据。')
    finally:
        for buf in scratch:
            C.memset(buf, 0, len(buf))


def import_material(lib, cap, obj, field, encoded):
    slots = obj.slots()
    if field not in slots:
        raise ValueError('请选择当前算法的文件。')
    dest, _ = slots[field]
    label = MATERIALS[field]
    if not isinstance(encoded, str) or len(encoded) != 2 * len(dest):
        raise ValueError(f'{label}应为 {len(dest)} 字节，请检查文件和参数。')
    try:
        raw = bytes.fromhex(encoded)
    except ValueError:
        raise ValueError(f'{label}文件格式错误。') from None
    if len(raw) != len(dest):
        raise ValueError(f'{label}文件格式错误。')
    candidate = C.create_string_buffer(raw, len(raw))
    try:
        keep_shared = obj.has_shared and obj.has_public and (
            field == 'secret_key' or (field == 'public_key' and secrets.compare_digest(dest.raw, raw)))
        if field in ('public_key', 'secret_key'):
            check_key(lib, cap, obj, field, candidate)
            obj.key_record = None
            if field == 'public_key':
                obj.has_public = True
            else:
                obj.has_secret = True
        else:
            obj.has_payload = True
            obj.payload_record = None
        C.memmove(dest, candidate, len(dest))
        if not keep_shared:
            C.memset(obj.secret, 0, len(obj.secret))
            obj.has_shared = False
        obj.clear_decapsulated_secret()
        obj.check_record = obj.signed_input = None
        obj.revision += 1
    finally:
        C.memset(candidate, 0, len(candidate))


def replacement_checks(sk, ss, cipher, peer):
    oracle = hashlib.shake_256()
    oracle.update(C.string_at(C.addressof(sk) + len(sk) - 32, 32))
    oracle.update(cipher)
    return {'replacement_matches_fips203': secrets.compare_digest(oracle.digest(32), peer),
            'differs_from_original': not secrets.compare_digest(ss, peer)}


def measure_operation(lib, cap, profile, parameter, selected, report=None):
    family = 'ML-KEM' if parameter in PARAMETERS['ML-KEM'] else 'ML-DSA'
    operations = OPERATIONS[family]
    if selected not in operations:
        raise ValueError('当前参数不支持此操作。')
    message = b'\0' * 32 if family == 'ML-DSA' else b''
    objects = Objects(lib, profile, parameter)
    try:
        for op in operations:
            if report:
                report(f'{family}-{parameter} · {NAMES[op]} · 正在执行')
            row = operation(lib, cap, objects, op, message, detail=(op == selected))
            if op == selected:
                data = {'message': message, 'context': b'', 'public_key': objects.pk.raw}
                if op in ('decaps', 'verify'):
                    data['ciphertext' if op == 'decaps' else 'signature'] = objects.payload.raw
                row['inputs'] = {key: object_info(data[key]) for key in row['inputs'] if key in data}
                if op in ('sign', 'decaps'):
                    row['inputs']['secret_key_length'] = len(objects.sk)
                return row
            if not row['verified']:
                raise ValueError(f"{NAMES[op]}准备失败。{row['summary']}")
    finally:
        objects.close()


def operation(lib, cap, objects, op, message=b'', context=b'', detail=True):
    p = objects.parameter
    family = 'ML-KEM' if p in PARAMETERS['ML-KEM'] else 'ML-DSA'
    if op not in OPERATIONS[family]:
        if op == ('decaps-modified' if family == 'ML-KEM' else 'verify-modified'):
            return retest(lib, cap, objects, op)
        raise ValueError('当前参数不支持此操作')
    if op in ('encaps', 'verify') and not objects.has_public:
        raise ValueError('请先生成或导入公钥。')
    if op in ('sign', 'decaps') and not objects.has_secret:
        raise ValueError('请先生成或导入私钥。')
    if op in ('verify', 'decaps') and not objects.has_payload:
        raise ValueError('请先签名或封装。')
    pk, sk, payload, ss = objects.pk, objects.sk, objects.payload, objects.secret
    public = {}
    inputs = {'key_record': objects.key_record} if op != 'keygen' else {}
    checks = {}
    if op in ('sign', 'verify'):
        inputs.update(message=object_info(message, content=False), context=object_info(context, content=False))
    if op in ('encaps', 'verify'):
        inputs['public_key'] = object_info(pk.raw, content=False)
    if op in ('verify', 'decaps'):
        inputs['payload_record'] = objects.payload_record
        inputs['signature' if op == 'verify' else 'ciphertext'] = object_info(payload.raw, content=False)
    with arena(lib, cap) as (ctx, addr):
        args = (C.byref(ctx), p)
        started = now()
        tick = time.perf_counter_ns()
        if op == 'keygen':
            objects.close()
            rc = lib.lc_keypair(*args, pk, len(pk), sk, len(sk))
        elif op == 'encaps':
            objects.has_payload = objects.has_shared = False
            objects.clear_decapsulated_secret()
            objects.revision += 1
            objects.payload_record = objects.check_record = None
            rc = lib.lc_encaps(*args, payload, len(payload), ss, len(ss), pk, len(pk))
        elif op == 'decaps':
            objects.clear_decapsulated_secret()
            objects.check_record = None
            peer = objects.decapsulated_secret
            rc = lib.lc_decaps(*args, peer, len(peer), payload, len(payload), sk, len(sk))
            if objects.has_shared:
                checks['shared_secret_equal'] = rc == 0 and secrets.compare_digest(ss, peer)
        elif op == 'sign':
            objects.has_payload = False
            objects.revision += 1
            objects.payload_record = objects.check_record = None
            objects.signed_input = None
            rc = lib.lc_sign(*args, payload, len(payload), message, len(message), context, len(context), sk, len(sk))
        else:
            rc = lib.lc_verify(*args, payload, len(payload), message, len(message), context, len(context), pk, len(pk))
        duration = (time.perf_counter_ns() - tick) / 1000000
        finish = now()
        guards = guard_status(ctx, addr, cap)
    if op == 'keygen' and rc == 0:
        objects.has_public = objects.has_secret = True
        public.update(public_key=object_info(pk.raw, content=detail), secret_key_length=len(sk))
    if op in ('sign', 'encaps') and rc == 0:
        objects.has_payload = True
        public['signature' if op == 'sign' else 'ciphertext'] = object_info(payload.raw, content=detail)
        if op == 'sign':
            objects.signed_input = message, context
    if op in ('encaps', 'decaps') and rc == 0:
        public['shared_secret_length'] = 32
    ok = rc == 0 and all(checks.values()) and guards['canaries_ok'] and guards['used_workspace_erased']
    if op == 'encaps':
        objects.has_shared = ok
        if not ok:
            C.memset(ss, 0, len(ss))
    elif op == 'decaps':
        if rc == 0 and guards['canaries_ok'] and guards['used_workspace_erased']:
            objects.has_decapsulated_secret = True
        else:
            objects.clear_decapsulated_secret()
    if ok and op == 'verify':
        objects.signed_input = message, context
    success = {'keygen': '已生成密钥', 'encaps': '已生成密文', 'sign': '已生成签名',
               'verify': '验签通过', 'decaps': '共享秘密一致' if objects.has_shared else '已解封装'}
    summary = success[op] if ok else (
        '共享秘密不一致' if checks.get('shared_secret_equal') is False and rc == 0 else
        '验签失败' if op == 'verify' and rc == -6 else CODES.get(rc, '检查失败') if rc else '检查失败')
    return dict(operation=op, parameter=p, started_at=started, finished_at=finish, return_code=rc, verified=ok,
                summary=summary, public_outputs=public, inputs=inputs, checks=checks, object_ref=objects.id,
                duration_ms=duration, function=FUNCTIONS[op], **guards)


def security_input(field, original, test, *, source='fresh', reference=None):
    if isinstance(original, bytes):
        original, test = original.hex(), test.hex()
    result = dict(field=field, before=original, after=test, source=source)
    if reference:
        result['reference'] = reference
    return result


def retest(lib, cap, objects, op, *, baseline_verified=False, modified_secret=None):
    if not objects.has_payload or not (baseline_verified or objects.state()['can_retest']):
        raise ValueError('请先完成正常解封装或验签。')
    pk, sk, payload, ss = objects.pk, objects.sk, objects.payload, objects.secret
    checks, details = {}, {}
    started = now()
    with arena(lib, cap) as (ctx, addr):
        args = C.byref(ctx), objects.parameter
        tick = time.perf_counter_ns()
        if op == 'decaps-modified':
            original = payload.raw
            changed = bytearray(original)
            changed[0] ^= 1
            cipher = bytes(changed)
            details = {'case': 'ciphertext', 'ciphertext_test': {
                'original_bytes': len(original), 'modified_bytes': len(cipher),
                'changed_bytes': sum(a != b for a,b in zip(original, cipher)),
                'uses_current_ciphertext': not baseline_verified,
            }}
            peer = C.create_string_buffer(32)
            try:
                original_rc = lib.lc_decaps(*args, peer, len(peer), original, len(original), sk, len(sk))
                details['ciphertext_test']['original_return_code'] = original_rc
                checks['original_shared_secret_equal'] = original_rc == 0 and secrets.compare_digest(ss, peer)
                C.memset(peer, 0, len(peer))
                rc = lib.lc_decaps(*args, peer, len(peer), cipher, len(cipher), sk, len(sk))
                if rc == 0:
                    checks.update(replacement_checks(sk, ss, cipher, peer))
                    if modified_secret is not None:
                        C.memmove(modified_secret, peer, len(peer))
            finally:
                C.memset(peer, 0, len(peer))
            case, modified = 'ciphertext', cipher
            expected, success = 0, '隐式拒绝正确：替代共享秘密符合预期，与原共享秘密不同。'
        else:
            message, domain = objects.signed_input
            original_rc = lib.lc_verify(*args, payload, len(payload), message, len(message), domain, len(domain), pk, len(pk))
            checks['original_signature_verified'] = original_rc == 0
            candidate, observed = payload, message
            expected = -6
            if op == 'verify-modified-signature':
                case, original = 'signature', payload.raw
                candidate = bytes([original[0] ^ 1]) + original[1:]
                modified = candidate
                check, success = 'modified_signature_rejected', '修改签名后，验签失败'
            else:
                case, original = 'message', message
                observed = bytes([message[0] ^ 1]) + message[1:] if message else b'\x01'
                modified = observed
                check, success = 'modified_message_rejected', '修改消息后，验签失败'
            details = {'case': case, f'{case}_test': {
                'original_bytes': len(original), 'modified_bytes': len(modified),
                'original_return_code': original_rc,
                'changed_bytes': sum(a != b for a, b in zip(original, modified)) + abs(len(original) - len(modified)),
                'uses_current_signature': not baseline_verified,
            }}
            rc = lib.lc_verify(*args, candidate, len(candidate), observed, len(observed), domain, len(domain), pk, len(pk))
            checks[check] = rc == expected
        duration = (time.perf_counter_ns() - tick) / 1000000
        guards = guard_status(ctx, addr, cap)
    ok = rc == expected and all(checks.values()) and guards['canaries_ok'] and guards['used_workspace_erased']
    inputs = dict(key_record=objects.key_record, payload_record=objects.payload_record,
                  check_record=objects.check_record)
    evidence = security_input(case, original, modified, source='fresh' if baseline_verified else 'current',
                              reference=(objects.check_record if case == 'message' else objects.payload_record))
    return dict(operation=op, parameter=objects.parameter, started_at=started, finished_at=now(),
                return_code=rc, expected_return_code=expected, original_return_code=original_rc,
                security_input=evidence, verified=ok, summary=success if ok else '异常复测失败',
                public_outputs={}, inputs=inputs, checks=checks, object_ref=objects.id,
                duration_ms=duration, function=FUNCTIONS[op], **details, **guards)


def security(lib, cap, profile, p, case, current=None, *, modified_secret=None, report=None):
    family = 'ML-KEM' if p > 100 else 'ML-DSA'
    supported = {'capacity', 'length', 'encoding', 'random'} | (
        {'ciphertext'} if family == 'ML-KEM' else {'signature', 'message'})
    if case not in supported:
        raise ValueError('此测试与当前参数不匹配')
    retest_op = {'ciphertext': 'decaps-modified', 'message': 'verify-modified',
                 'signature': 'verify-modified-signature'}.get(case)
    if retest_op and current is not None and current.state()['can_retest']:
        if report is not None:
            report(f'使用当前密码流程输入 · 执行原始与修改后的 {FUNCTIONS[retest_op]}')
        return retest(lib, cap, current, retest_op, modified_secret=modified_secret)
    obj = Objects(lib, profile, p)
    message, domain = (b'This is a test message.', b'') if case in ('message', 'signature') else (b'A1-27 public demonstration', b'A1-27')
    def step(op):
        return operation(lib, cap, obj, op, message, domain, detail=False)
    try:
        if report is not None:
            report('生成正常输入并执行基线检查')
        base = [step(op) for op in OPERATIONS[family]]
        if not all(e['verified'] for e in base):
            return dict(verified=False, summary='正常输入测试失败。', baseline=base)
        if retest_op:
            if report is not None:
                report(f'执行原始与修改后的 {FUNCTIONS[retest_op]}')
            return retest(lib, cap, obj, retest_op, baseline_verified=True, modified_secret=modified_secret) | {'baseline': base}
        pk, sk, pay, ss = obj.pk, obj.sk, obj.payload, obj.secret
        actual_cap = 32 if case == 'capacity' else cap
        requested = 0
        if report is not None:
            if case == 'capacity':
                report(f'将工作区从 {cap:,} B 限制为 {actual_cap:,} B · 调用 lc_keypair')
            elif case == 'random':
                report('随机源回调返回失败 · 调用 lc_keypair')
            else:
                report('构造本次异常输入并调用密码接口')

        @RNG
        def unavailable_random(user, output, count):
            nonlocal requested
            requested += count
            return -1
        with arena(lib, actual_cap, unavailable_random if case == 'random' else None) as (ctx, address):
            args = (C.byref(ctx), p)
            diagnostic = {}
            if case in ('capacity', 'random'):
                C.memset(pk, 0xa5, len(pk)); C.memset(sk, 0xa5, len(sk))
                rc = lib.lc_keypair(*args, pk, len(pk), sk, len(sk))
                expected = -5 if case == 'capacity' else -4
                diagnostic['failure_output_zero'] = not any(pk.raw) and not any(sk.raw)
                op = 'keygen'
                evidence = (security_input('workspace_bytes', cap, actual_cap) if case == 'capacity' else
                            security_input('entropy_bytes', requested, 0))
            elif family == 'ML-KEM' and case == 'length':
                original = pay.raw
                short = original[:-1]
                evidence = security_input('ciphertext', original, short)
                op = 'decaps'
                peer = C.create_string_buffer(32)
                try:
                    rc = lib.lc_decaps(*args, peer, len(peer), short, len(short), sk, len(sk))
                    expected = -2
                finally:
                    C.memset(peer, 0, 32)
            elif family == 'ML-KEM':
                original = pk.raw
                damaged = b'\xff\xff' + original[2:]
                evidence = security_input('public_key', original, damaged)
                op = 'encaps'
                rc = lib.lc_encaps(*args, pay, len(pay), ss, 32, damaged, len(damaged))
                expected = -6
            else:
                original = pay.raw
                signed = original[:-1] + (b'\xff' if case == 'encoding' else b'')
                evidence = security_input('signature', original, signed)
                op = 'verify'
                rc = lib.lc_verify(*args, signed, len(signed), message, len(message),
                                   domain, len(domain), pk, len(pk))
                expected = -2 if case == 'length' else -6
            guards = guard_status(ctx, address, actual_cap)
        if report is not None and case in ('capacity', 'random'):
            report('恢复正常条件 · 重新调用 lc_keypair')
        recovery = step('keygen') if case in ('capacity', 'random') else None
        ok = rc == expected and all(diagnostic.values()) and guards['canaries_ok'] and guards['used_workspace_erased']
        ok = ok and (recovery is None or recovery['verified'])
        return dict(verified=ok, summary='结果符合预期' if ok else '检查失败', case=case,
                    return_code=rc, expected_return_code=expected, baseline=base, checks=diagnostic,
                    original_return_code=next(row['return_code'] for row in base if row['operation']==op),
                    recovery_return_code=recovery['return_code'] if recovery else None,
                    security_input=evidence, recovered=recovery, function=FUNCTIONS[op], **guards)
    finally:
        obj.close()
