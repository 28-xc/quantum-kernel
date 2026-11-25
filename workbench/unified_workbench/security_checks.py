"""Run bounded abnormal-input checks through the resident board API."""
import hashlib
import secrets
import struct

from . import crypto, vectors

BOARD_CASES = ('length', 'encoding', 'random', 'capacity', 'message', 'ciphertext', 'signature')


def finding(label, value, verified):
    return dict(label=label, value=value, verified=verified)


def code_text(code):
    if code is None or code == -127:
        return '未执行'
    reason = crypto.CODES.get(code)
    return f'{code}（{reason}）' if reason else str(code)


def measured_step(label, step):
    function = f"（{step['function']}）" if step.get('function') else ''
    timing = f" · {step['duration_ms']:.3f} ms" if step.get('duration_ms') is not None else ''
    return f"{label}{function} · 返回码 {code_text(step.get('return_code'))}{timing} · {step['summary']}"


def result_log(result):
    for step in result.get('baseline', ()):
        yield measured_step('正常输入 · ' + crypto.NAMES[step['operation']], step)

    evidence = result.get('security_input')
    if evidence:
        field, before, after = (evidence[key] for key in ('field', 'before', 'after'))
        labels = {'ciphertext': '密文', 'signature': '签名', 'message': '消息', 'public_key': '公钥',
                  'workspace_bytes': '工作区容量', 'entropy_bytes': '随机源字节数'}
        source = {'current': '当前密码流程', 'fresh': '本次生成', 'fixture': '公开测试向量', 'firmware': '当前固件'}
        reference = f" · 用例 {evidence['reference']}" if evidence.get('reference') else ''
        yield f"输入来源 · {source.get(evidence['source'], evidence['source'])}{reference}"
        label = labels[field]
        if isinstance(before, int):
            yield f'调整{label} · 正常 {before:,} B → 本次 {after:,} B'
        else:
            yield f'检查对象 · {label} · 原始 {len(before)//2:,} B → 本次 {len(after)//2:,} B'
            changes = []
            count = 0
            for offset in range(0, max(len(before), len(after)), 2):
                original, actual = before[offset:offset+2].upper(), after[offset:offset+2].upper()
                if original != actual:
                    count += 1
                    if len(changes) < 8:
                        changes.append(f"{offset//2}：{original or '无'} → {actual or '无'}")
            if count:
                yield f"变更 {count:,} 字节 · 字节偏移（从 0 开始）与 HEX 值 · " + '、'.join(changes) + ('…' if count > 8 else '')

    if result.get('original_return_code') is not None and (not result.get('baseline') or 'duration_ms' in result):
        yield f"原始输入 · 返回码 {code_text(result['original_return_code'])}"
    if 'return_code' in result:
        function = result.get('function') or '设备检查'
        actual = code_text(result['return_code'])
        expected = code_text(result.get('expected_return_code'))
        yield f'异常输入 · {function} · 实际返回码 {actual} · 预期返回码 {expected}'
    if result.get('cycles') is not None:
        yield f"异常调用 · {result['cycles']:,} 周期"
    if result.get('duration_ms') is not None:
        yield f"原始与修改后对照 · {result['duration_ms']:.3f} ms"

    checks = {
        'original_shared_secret_equal': '原始共享秘密一致',
        'differs_from_original': '替代共享秘密与原值不同',
        'replacement_matches_fips203': '替代共享秘密独立核验',
        'original_signature_verified': '原始签名验签',
        'modified_signature_rejected': '修改签名后拒绝验签',
        'modified_message_rejected': '修改消息后拒绝验签',
        'failure_output_zero': '失败输出清零',
        'canaries_ok': '缓冲区边界检查',
        'used_workspace_erased': '已用工作区清理',
    }
    values = result.get('checks', {}) | {
        key: result[key] for key in ('canaries_ok', 'used_workspace_erased') if key in result
    }
    for key, label in checks.items():
        if isinstance(values.get(key), bool):
            yield f"核验 · {label} · {'通过' if values[key] else '失败'}"
    for item in result.get('findings', ()):
        status = '通过' if item['verified'] is True else '失败' if item['verified'] is False else ''
        suffix = f' · {status}' if status and status != item['value'] else ''
        yield f"核验 · {item['label']} · {item['value']}{suffix}"
    if result.get('workspace_used_bytes') is not None:
        yield f"已用工作区峰值 · {result['workspace_used_bytes']:,} B"
    if result.get('recovered'):
        yield measured_step('恢复正常条件后重试', result['recovered'])
    elif result.get('recovery_return_code') is not None:
        yield f"恢复正常条件后重试 · 返回码 {code_text(result['recovery_return_code'])}"


def fixture_fields(inputs):
    fields = {key: bytes.fromhex(value) for key, value in inputs.items()}
    fields['coins'] = fields.pop('seed', fields.pop('randomness', b''))
    return fields


def changed_fields(parameter, case, fields):
    if case == 'capacity':
        return 'coins', fields['coins']
    if case == 'random':
        return 'coins', b''
    if case == 'length':
        key = 'ciphertext' if parameter > 100 else 'signature'
        return key, fields[key][:-1]
    if case == 'encoding':
        if parameter > 100:
            return 'public_key', b'\xff\xff' + fields['public_key'][2:]
        return 'signature', fields['signature'][:-1] + b'\xff'
    if case in ('message', 'ciphertext', 'signature') and fields[case]:
        original = fields[case]
        return case, bytes([original[0] ^ 1]) + original[1:]
    raise ValueError('异常测试缺少适用输入。')


def ch32_edit(profile, data, key, changed, capacity):
    fields = ('coins', 'public_key', 'secret_key', 'ciphertext', 'signature', 'message', 'context')
    descriptor = (5 if profile == '80' else 6) + 2 * fields.index(key)
    offset, size = struct.unpack_from('<2I', data, 4 * descriptor)
    start = offset - 0x2000f6e0 if profile == '80' else offset + 96
    if len(changed) > size or not 0 <= start <= start + size <= len(data):
        raise ValueError('板上诊断输入长度无效。')
    data[start:start + len(changed)] = changed
    struct.pack_into('<I', data, 4 * (descriptor + 1), len(changed))
    if capacity:
        struct.pack_into('<I', data, 16, 32)


def board_check(runtime, target, profile, parameter, case, expected_code, report):
    recovery = case in ('random', 'capacity')
    operation = 0 if recovery else 1 if case == 'encoding' and parameter > 100 else 2
    role = ('高性能' if profile == '80' else '低内存') if target == 'ch32v307' else None
    fixture = next(row for row in vectors.board_cases(runtime.root, parameter, role)
                   if row['operation'] == operation and row['accepted'])
    inputs, expected = vectors.board_case_data(runtime.source, fixture)
    original = fixture_fields(inputs)
    key, value = changed_fields(parameter, case, original)
    changed = original | {key: value}
    tc = fixture['tcId']
    ident = parameter, operation, tc
    phases = ('异常输入', '恢复后重试') if recovery else ('原始输入', '异常输入')
    abnormal_index = 0 if recovery else 1
    receipts = []
    selected_capacity = None

    def capture(index, code, output, ready, **extra):
        cycles = extra.get('cycles')
        timing = f' · {cycles:,} 周期' if cycles is not None else ''
        report(f"板端应答 · {phases[index]} · 返回码 {code_text(code)}{timing}")
        receipts.append(dict(return_code=code, ready=ready, output=output, **extra))

    report(f'已载入公开测试向量 {vectors.board_case_id(fixture)} · 准备发送板端请求')
    if target == 'stm32f407':
        items = [(*ident, fields) for fields in ([changed, original] if recovery else [original, changed])]

        def receive(index, reply, output):
            code = struct.unpack('<i', struct.pack('<I', reply[24]))[0]
            capture(index, code, output, reply[28] == 1 and reply[33] == 1, cycles=reply[32])

        runtime.live.providers[target].run_acvp_bytes(items, report=report, on_reply=receive)
    else:
        def alter(index, packet):
            nonlocal selected_capacity
            if index == abnormal_index:
                selected_capacity = struct.unpack_from('<I', packet, 16)[0]
                ch32_edit(profile, packet, key, value, case == 'capacity')

        def receive(index, reply, output):
            capture(index, reply[3], output, bool(reply[2] & 1))

        runtime.live.ch32_strategy.run_acvp(profile, [ident, ident], on_reply=receive, edit_fixture=alter)
        runtime.connect_ch32(profile)

    normal = receipts[1 - abnormal_index]
    abnormal = receipts[abnormal_index]
    normal_ok = (normal['ready'] and normal['return_code'] == 0 and
                 [output for output in normal['output'] if output] ==
                 [bytes.fromhex(value) for value in expected.values()])
    code = abnormal['return_code']
    passed = abnormal['ready'] and code == expected_code
    abnormal_row = finding('异常输入返回码', code, passed)
    normal_row = finding(phases[1 - abnormal_index], '通过' if normal_ok else '失败', normal_ok)
    findings = [abnormal_row, normal_row] if recovery else [normal_row, abnormal_row]
    if recovery:
        zero = len(abnormal['output']) == 2 and all(output and not any(output) for output in abnormal['output'])
        findings.append(finding('失败输出清零', '通过' if zero else '失败', zero))
    if case == 'ciphertext':
        replacement = hashlib.shake_256(original['secret_key'][-32:] + value).digest(32)
        actual = abnormal['output'][0]
        differs = len(actual) == 32 and not secrets.compare_digest(actual, normal['output'][0])
        match = secrets.compare_digest(actual, replacement)
        findings.extend([finding('替代共享秘密与原值比较', '不同' if differs else '未确认不同', differs),
                         finding('替代共享秘密独立核验', '通过' if match else '失败', match)])
    field, before, after = key, original[key], value
    if case == 'capacity':
        field, before, after = 'workspace_bytes', selected_capacity, 32
    elif case == 'random':
        field, before, after = 'entropy_bytes', len(before), len(after)
    family = 'ML-KEM' if parameter > 100 else 'ML-DSA'
    return dict(verified=all(row['verified'] for row in findings), findings=findings, return_code=code,
                expected_return_code=expected_code, cycles=abnormal.get('cycles'), remote_test=case,
                original_return_code=normal['return_code'] if not recovery else None,
                recovery_return_code=normal['return_code'] if recovery else None,
                function=crypto.FUNCTIONS[crypto.OPERATIONS[family][operation]],
                security_input=crypto.security_input(field, before, after, source='fixture',
                                                     reference=vectors.board_case_id(fixture)))

