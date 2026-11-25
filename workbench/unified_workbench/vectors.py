"""Run ACVP and Wycheproof cases."""
import ctypes as C
import csv
from functools import lru_cache
from struct import unpack
from xml.etree import ElementTree as ET

import record_io
from .crypto import OPERATIONS, RNG, arena, digest, guard_status, sizes


@lru_cache(maxsize=8)
def corpus(source, suite, parameter):
    rows = {}
    family = 'ML-KEM' if parameter > 100 else 'ML-DSA'
    folder = source/'tests/vectors'/suite
    if suite == 'acvp':
        for path in sorted(folder.glob(f'{family}-*/prompt.xml')):
            prompt = record_io.loads(path.read_bytes())
            expected_path = path.with_name('expectedResults.xml')
            expected = record_io.loads(expected_path.read_bytes())
            wanted = {t['tcId']:t for g in expected['testGroups'] for t in g['tests']}
            for g in prompt['testGroups']:
                if int(g['parameterSet'].split('-')[-1]) != parameter or g.get('preHash') == 'preHash' or g.get('signatureInterface') == 'internal':
                    continue
                for t in g['tests']:
                    key = f"{path.parent.name}/g{g['tgId']}/tc{t['tcId']}"
                    rows[key] = (prompt['mode'],g,t,wanted[t['tcId']],path,expected_path)
    elif suite == 'wycheproof':
        prefix = 'mlkem' if parameter > 100 else 'mldsa'
        for path in sorted((folder/'testvectors_v1').glob(f'{prefix}_{parameter}_*.xml')):
            data = record_io.loads(path.read_bytes())
            for index,g in enumerate(data['testGroups']):
                for t in g['tests']:
                    if 'Internal' in t.get('flags',[]) or (parameter < 100 and 'msg' not in t):
                        continue
                    seed = g.get('privateSeed',t.get('seed'))
                    if seed is not None and len(bytes.fromhex(seed)) != (64 if parameter > 100 else 32):
                        continue
                    key = f"{path.stem}/g{index}/tc{t['tcId']}"
                    rows[key] = (path.stem,g,t,t,path,path)
    else:
        raise ValueError('测试集无效')
    return rows


def run_case(lib, cap, p, suite, entry, root, *, captured=None, on_start=None):
    mode, group, tc, target, prompt_path, expected_path = entry
    z = sizes(lib,p)
    entropy = [b'',0]
    @RNG
    def supply(user, out, n):
        data, at = entropy
        if n > len(data)-at:
            return -1
        C.memmove(out, data[at:at+n], n); entropy[1] += n
        return 0
    def seed(value):
        entropy[:] = [bytes.fromhex(value), 0]
    def decode(key, default=None):
        return bytes.fromhex(tc.get(key,default)) if key in tc or default is not None else None
    outputs = [C.create_string_buffer(n) for n in (z.public_key,z.secret_key,z.ciphertext,z.signature,32)]
    pk,sk,ct,sig,ss = outputs
    public, comparisons, output_lengths = {}, {}, {}
    operation, input_lengths = None, {}
    function = group.get('function')
    check_category = function if function in ('encapsulationKeyCheck','decapsulationKeyCheck') else None
    def describe(name, **fields):
        nonlocal operation, input_lengths
        operation = name
        if on_start:
            on_start(check_category if name in ('encaps','decaps') and check_category else name,tc['tcId'])
        input_lengths = {key: len(value) for key, value in fields.items()}
        if captured is not None:
            captured['inputs'] = {key: bytes(value) for key, value in fields.items()}
    def compare(identifier, actual, expected):
        a,b = bytes(actual),bytes.fromhex(expected)
        # Compare secret bytes locally.
        if identifier in ('public_key','ciphertext','signature'):
            public[identifier] = {'actual_sha256':digest(a), 'expected_sha256':digest(b), 'length':len(a)}
        match = a == b
        comparisons[identifier] = comparisons.get(identifier, True) and match
        output_lengths[identifier] = len(a)
        if captured is not None:
            captured['outputs'].append((identifier, a, b))
        return match
    try:
        with arena(lib,cap,supply) as (ctx,addr):
            args = (C.byref(ctx),p)
            def keygen():
                describe('keygen', seed=entropy[0])
                return lib.lc_keypair(*args,pk,len(pk),sk,len(sk))
            def encaps(public_key):
                describe('encaps', public_key=public_key, randomness=entropy[0])
                return lib.lc_encaps(*args,ct,len(ct),ss,32,public_key,len(public_key))
            def decaps(cipher,key):
                describe('decaps', ciphertext=cipher, secret_key=key)
                return lib.lc_decaps(*args,ss,32,cipher,len(cipher),key,len(key))
            def sign(message,context,key):
                describe('sign', message=message, context=context, secret_key=key, randomness=entropy[0])
                return lib.lc_sign(*args,sig,len(sig),message,len(message),context,len(context),key,len(key))
            def verify(signature,message,context,key, *, describe_input=True):
                if describe_input:
                    describe('verify', signature=signature, message=message, context=context, public_key=key)
                return lib.lc_verify(*args,signature,len(signature),message,len(message),context,len(context),key,len(key))
            expected_status = target.get('testPassed',True) if suite == 'acvp' else tc['result'] == 'valid'
            checked = []
            if suite == 'acvp':
                if mode == 'keyGen':
                    kem = p > 100
                    seed(tc['d']+tc['z'] if kem else tc['seed'])
                    rc = keygen()
                    checked.extend((compare('public_key',pk,target['ek' if kem else 'pk']),
                                    compare('secret_key',sk,target['dk' if kem else 'sk'])))
                elif mode == 'encapDecap':
                    function = group['function']
                    if function in ('encapsulation','encapsulationKeyCheck'):
                        seed(tc.get('m','00'*32)); rc = encaps(decode('ek'))
                        if 'c' in target:
                            checked.extend((compare('ciphertext',ct,target['c']),compare('secret',ss,target['k'])))
                    else:
                        key = decode('dk')
                        if key is None:
                            seed(tc['d']+tc['z'])
                            if keygen() != 0:
                                raise ValueError('生成测试密钥失败。')
                            key = sk
                        rc = decaps(decode('c','00'*z.ciphertext),key)
                        if 'k' in target:
                            checked.append(compare('secret',ss,target['k']))
                elif mode == 'sigGen':
                    seed(tc.get('rnd','00'*32))
                    rc = sign(decode('message'), decode('context',''), decode('sk'))
                    checked.append(compare('signature',sig,target['signature']))
                else:
                    rc = verify(decode('signature'),decode('message'),decode('context',''),decode('pk'))
            else:
                vector_seed = group.get('privateSeed',tc.get('seed'))
                if vector_seed is not None:
                    seed(vector_seed)
                    if keygen() != 0:
                        raise ValueError('生成测试密钥失败。')
                    for tag, buf, value in (('public_key',pk,group.get('publicKey')),('public_key',pk,tc.get('ek')),
                                             ('secret_key',sk,tc.get('dk'))):
                        if value:
                            checked.append(compare(tag,buf,value))
                if p > 100:
                    if 'keygen_seed' in mode:
                        rc = 0
                    elif 'encaps' in mode:
                        seed(tc['m']); rc=encaps(decode('ek'))
                        if expected_status:
                            checked.extend((compare('ciphertext',ct,tc['c']),compare('secret',ss,tc['K'])))
                    else:
                        rc=decaps(decode('c'),sk if vector_seed is not None else decode('dk'))
                        if expected_status:
                            checked.append(compare('secret',ss,tc['K']))
                else:
                    m,ctx_data = decode('msg'),decode('ctx','')
                    pub = bytes.fromhex(group['publicKey']) if group.get('publicKey') is not None else None
                    if 'verify' in mode:
                        rc=verify(decode('sig'),m,ctx_data,pub)
                    else:
                        seed(tc.get('rnd','00'*32))
                        rc=sign(m,ctx_data,sk if vector_seed is not None else bytes.fromhex(group['privateKey']))
                        if expected_status:
                            checked.append(compare('signature',sig,tc['sig']))
                            if rc == 0:
                                checked.append(verify(sig,m,ctx_data,pub,describe_input=False) == 0)
            guards = guard_status(ctx,addr,cap)
            rc_matches = (rc == 0) if expected_status else rc in (-1,-2,-6)
            ok = rc_matches and all(checked) and guards['canaries_ok'] and guards['used_workspace_erased']
            category = check_category or operation
            return dict(verified=ok, return_code=rc, expected_accept=expected_status, actual_accept=rc==0,
                        comparisons=len(checked), output_checks=comparisons, public_outputs=public, **guards,
                        tested_operation=operation, tested_category=category, input_lengths=input_lengths,
                        output_lengths=output_lengths, case_description=tc.get('comment'),
                        source_path=prompt_path.relative_to(root).as_posix(),
                        expected_path=expected_path.relative_to(root).as_posix(), tc_id=tc['tcId'])
    finally:
        for buf in outputs:
            C.memset(buf,0,len(buf))


CH32_RECORDS = '02_测试代码与数据/correctness/CH32V307/标准向量与存储核验'
STM32_OUTPUTS = ('02_测试代码与数据/performance/完整密码操作/STM32F407/'
                 '正式固件和同板对照/defensive')


def board_case_id(case):
    return f"{case['category']}/g{case['tgId']}/tc{case['tcId']}"


@lru_cache(maxsize=18)
def board_cases(root, parameter, role=None):
    manifest = (root/CH32_RECORDS/role/'向量来源.xml' if role else
                root/'02_测试代码与数据/correctness/embedded/linking-validation/targets/m4-all/vectors.xml')
    if not role and not manifest.is_file():
        manifest = root/'workbench/fixtures/acvp-cases.xml'
    data = record_io.loads(manifest.read_bytes())
    cases = [row for row in data['cases'] if row['parameter'] == parameter]
    return sorted(cases,key=lambda row:(row['operation'],not row['accepted']))


def board_case_data(source, case):
    parameter, op = case['parameter'], case['operation']
    _, _, tc, expected, _, _ = corpus(source, 'acvp', parameter)[board_case_id(case)]
    kem = parameter > 100
    if op == 0:
        inputs = {'seed':tc['d']+tc['z'] if kem else tc['seed']}
        outputs = dict(public_key=expected['ek' if kem else 'pk'],secret_key=expected['dk' if kem else 'sk'])
    elif kem and op == 1:
        inputs = dict(public_key=tc['ek'],randomness=tc['m'])
        outputs = dict(ciphertext=expected['c'],secret=expected['k'])
    elif kem:
        inputs = dict(secret_key=tc['dk'],ciphertext=tc['c'])
        outputs = dict(secret=expected['k'])
    elif op == 1:
        inputs = dict(secret_key=tc['sk'],message=tc['message'],context=tc.get('context',''),randomness=tc['rnd'])
        outputs = dict(signature=expected['signature'])
    else:
        inputs = dict(public_key=tc['pk'],message=tc['message'],context=tc.get('context',''),signature=tc['signature'])
        outputs = {}
        if expected['testPassed'] != case['accepted']:
            raise ValueError('预期验签结果与用例清单不符。')
    return inputs, outputs


def board_result_row(case, inputs, outputs, code, passed, checks, **measurements):
    family = 'ML-KEM' if case['parameter'] > 100 else 'ML-DSA'
    return dict(case_id=board_case_id(case),tc_id=case['tcId'],parameter=case['parameter'],
                tested_operation=OPERATIONS[family][case['operation']],
                verified=passed,return_code=code,expected_accept=case['accepted'],
                actual_accept=None if code is None else code==0,output_checks=checks,
                input_lengths={name:len(data)//2 for name,data in inputs.items()},
                output_lengths={name:len(data)//2 for name,data in outputs.items()},**measurements)


def ch32_case(root, source, role, case):
    directory = root/CH32_RECORDS/role/f"p{case['parameter']}-op{case['operation']}-tc{case['tcId']}"
    descriptor = ET.parse(directory/'向量.xml').getroot()
    if (descriptor.get('category'),descriptor.get('group'),descriptor.get('case')) != (
            case['category'],str(case['tgId']),str(case['tcId'])):
        raise ValueError('板上用例记录与清单不符。')
    inputs, outputs = board_case_data(source, case)
    raw = {field.get('name'): (field.text or '').lower() for field in descriptor.findall('bytes')}
    input_keys = {'seed':'coins','randomness':'coins','message':'message','context':'domain','ciphertext':'ct',
                  'public_key':'pk','secret_key':'sk','signature':'sig'}
    if any(raw[input_keys[field]] != value.lower() for field,value in inputs.items()):
        raise ValueError('板上输入与 ACVP 用例不符。')
    magic, tc, mask, code, _, arena, failures, n0, n1 = unpack('<3Ii5I',(directory/'result.bin').read_bytes())
    expected_mask = 63 if role == '低内存' else 39
    if (magic,tc) != (0x51444f4e,case['tcId']) or (n0,n1) != tuple(len(raw[f'expected{i}'])//2 for i in range(2)):
        raise ValueError('板上应答与用例不符。')
    checks, values = {}, []
    for i, (field, expected) in enumerate(outputs.items()):
        if expected.lower() != raw[f'expected{i}']:
            raise ValueError('板上预期输出与 ACVP 用例不符。')
        item = dict(field=field,expected=expected)
        saved = directory/f'actual-output{i}.bin'
        if role == '高性能' and saved.is_file():
            actual = saved.read_bytes().hex()
            item['actual'] = actual
            checks[field] = actual == expected.lower()
        elif role == '低内存':
            checks[field] = bool(mask & (8 << i))
        values.append(item)
    verified = mask==expected_mask and code==(0 if case['accepted'] else -6) and not failures
    verified = verified and len(checks)==len(outputs) and all(checks.values())
    row = board_result_row(case,inputs,outputs,code,verified,checks,workspace_used_bytes=arena)
    return row, {'inputs':inputs,'outputs':values}


def stm32_archive(root, parameter, profile):
    revision = {'24':'P','32':'Q'}.get(profile)
    if revision is None:
        raise ValueError('请选择 24 KiB 或 32 KiB。')
    folder = root/STM32_OUTPUTS/revision
    fields = ['full_keypair','full_ciphertext_or_signature','shared_secret_or_cross_verification']
    if parameter > 100:
        fields.append('implicit_rejection')
    with (folder/f'oracle/p{parameter}.tsv').open(encoding='utf-8-sig',newline='') as handle:
        rows = [dict(strategy={'compact':'低内存','cached':'高性能'}[row['strategy']],
                     checks=[row[key] == 'PASS' for key in fields])
                for row in csv.DictReader(handle,delimiter='\t') if int(row['parameter'])==parameter]
    return rows


def execute_acvp(lib, workspace, source, root, cases, image, *, on_start=None, on_result=None):
    rows, details = [], {}
    for index,(parameter,identifier) in enumerate(cases,1):
        captured = {'inputs':{},'outputs':[]}
        entry = corpus(source,'acvp',parameter)[identifier]
        start = (lambda operation,tc: on_start(index,parameter,operation,tc)) if on_start else None
        row = run_case(lib,workspace,parameter,'acvp',entry,root,captured=captured,on_start=start)
        row.update(case_id=identifier,parameter=parameter)
        rows.append(row)
        if on_result: on_result(row)
        details[identifier] = {'inputs':{key:data.hex() for key,data in captured['inputs'].items()},
                               'outputs':[dict(field=field,actual=actual.hex(),expected=expected.hex())
                                          for field,actual,expected in captured['outputs']]}
    return dict(binary_sha256=image,rows=rows,details=details)


def ch32_live_case(source, case, reply, actual, profile):
    _,_,mask,code,_,arena,failures,_,_=reply
    inputs, expected = board_case_data(source,case)
    checks = {field:actual[i].hex()==value.lower() for i,(field,value) in enumerate(expected.items())}
    verified = (mask==(39 if profile=='80' else 63) and code==(0 if case['accepted'] else -6)
                and not failures and all(checks.values()) and not any(actual[len(expected):]))
    row = board_result_row(case,inputs,expected,code,verified,checks,workspace_used_bytes=arena)
    detail = {'inputs':inputs,'outputs':[
        dict(field=field,expected=value,actual=actual[i].hex()) for i,(field,value) in enumerate(expected.items())]}
    return row,detail
