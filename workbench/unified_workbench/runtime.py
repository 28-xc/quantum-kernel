"""Manage device connections and save test results."""
from collections import deque
import ctypes as C
import csv
import hashlib
from functools import lru_cache
import struct
import json
import platform
import re
import secrets
import threading
from time import monotonic
from datetime import datetime
from pathlib import Path

from demo import board_representatives, platform_config, platform_protocol as wire
from demo.platform_providers import ProviderError
from demo.spreadsheet_export import workbook
from . import arithmetic, board_performance, crypto, onboarding, security_checks, vectors

NAMES = {'windows':'Windows x64','arm':'Linux AArch64','stm32f407':'STM32F407','ch32v307':'CH32V307',
         'qemu-m4':'Cortex-M4 QEMU','qemu-rv32':'RV32IM QEMU'}
PROFILES = {'windows':('low-memory','performance'), 'arm':('low-memory','performance'), 'stm32f407':('24','32'),
            'ch32v307':('28','80'), 'qemu-m4':('saved',), 'qemu-rv32':('saved',)}
PROVIDER = {'ch32v307':'ch32','arm':'arm','stm32f407':'stm32f407'}
SOURCE = {'windows':'live_host','arm':'live_host','stm32f407':'live_board','ch32v307':'live_board'}
REMOTE_TESTS = {'ciphertext': '密文篡改测试', 'signature': '签名篡改测试', 'message': '消息篡改测试',
                'capacity': '工作区不足与恢复', 'random': '随机数异常与恢复',
                'length': '错误长度', 'encoding': '非法编码'}
ACVP_TEST = 'ACVP 测试'
PERFORMANCE_BATCH = '18 项性能测试'


def executable_text(image):
    if image.startswith(b'MZ'):
        pe_offset, = struct.unpack_from('<I', image, 0x3c)
        if image[pe_offset:pe_offset + 4] != b'PE\0\0':
            raise ValueError('算法库 PE 文件头无效。')
        count, = struct.unpack_from('<H', image, pe_offset + 6)
        optional_size, = struct.unpack_from('<H', image, pe_offset + 20)
        offset = pe_offset + 24 + optional_size
        for index in range(count):
            section = offset + index * 40
            name, length = struct.unpack_from('<8sI', image, section)
            if name.rstrip(b'\0') == b'.text':
                return length
        raise ValueError('算法库 PE 缺少 .text 段。')

    formats = {
        b'\x7fELF\x01\x01': ('<16sHHIIIIIHHHHHH', '<10I'),
        b'\x7fELF\x02\x01': ('<16sHHIQQQIHHHHHH', '<IIQQQQIIQQ'),
    }
    if image[:6] not in formats:
        raise ValueError('当前构建的可执行文件格式无效。')
    header, section = formats[image[:6]]
    fields = struct.unpack_from(header, image)
    offset = fields[6]
    size, count, names_index = fields[11:14]
    if size != struct.calcsize(section) or not 0 < names_index < count or offset + size * count > len(image):
        raise ValueError('当前构建的 ELF 节表无效。')
    sections = [struct.unpack_from(section, image, offset + size * index) for index in range(count)]
    names = sections[names_index]
    strings = image[names[4]:names[4] + names[5]]
    for name, _, flags, _, _, length, *_ in sections:
        if flags & 6 == 6 and strings[name:].split(b'\0', 1)[0] == b'.text':
            return length
    raise ValueError('当前构建的 ELF 缺少 .text 段。')


def ignore_progress(_message):
    pass


def operation_progress(parameter, operation):
    family = 'ML-KEM' if parameter > 100 else 'ML-DSA'
    return f'{family}-{parameter} {crypto.NAMES[operation]}'


def report_remote_steps(steps, report, offset=None):
    for index, step in enumerate(steps, 1):
        label = operation_progress(step['parameter'],step['operation'])
        prefix = f'{offset + index}/18 ' if offset is not None else ''
        report(f"{prefix}{label} · {step['summary']}")

EXPORT_KINDS = {
    'crypto': ('correctness', '密码测试'),
    'board-suite': ('correctness', '板上测试'),
    'vectors': ('correctness', '标准向量'),
    'arithmetic': ('performance', '算术测试'),
    'onboarding': ('performance', '设备接入'),
    'performance': ('performance', '性能测试'),
    'security': ('security', '安全检查'),
}
DOCS = ('REPRODUCE.md','01_源代码/可参数化格运算内核/include/latticecore.h',
        '01_源代码/可参数化格运算内核/src/common/public_api.c',
        '01_源代码/可参数化格运算内核/examples/public_a_session/application.c',
        '03_复现环境与运行程序/scripts/replay.ps1','03_复现环境与运行程序/scripts/verify.ps1',
        '03_复现环境与运行程序/host/Windows/README.md','03_复现环境与运行程序/host/AArch64/README.md',
        '03_复现环境与运行程序/firmware/CH32V307/运行说明.md','03_复现环境与运行程序/firmware/STM32F407/README.md',
        '03_复现环境与运行程序/firmware/STM32F407/运行.txt',
        '03_复现环境与运行程序/仿真/Cortex-M4_QEMU/运行说明.md','03_复现环境与运行程序/仿真/RV32IM_QEMU/运行说明.md',
        '03_复现环境与运行程序/软件演示程序/入口/unified_workbench/arithmetic/build.json')
BUILD_DOCS=('02_测试代码与数据/复算数据/artifacts/windows-low-memory-public/build/command.xml',
            '02_测试代码与数据/复算数据/artifacts/windows-low-memory-public/build/result.xml',
            '02_测试代码与数据/correctness/windows/deployment-validation/current-images.xml',
            '03_复现环境与运行程序/完整设备接入应用/Windows/最终实验驱动/commands.xml')


EXPORT_INTERNAL_FIELDS = {
    'request_id', 'run_id', 'device_run_id', 'session_id', 'input_id',
    'build_id', 'build_tag', 'object_ref', 'key_record', 'payload_record',
    'uid', 'response_file', 'record_path', 'source_path', 'expected_path', 'check_record',
    'schema', 'protocol', 'sequence', 'source_kind', 'platform_id', 'hex', 'materials',
}
PUBLIC_FILES = {'public_key': '公钥', 'ciphertext': '密文', 'signature': '签名'}
CHECK_NAMES = {
    'shared_secret_equal': '共享秘密一致',
    'replacement_matches_fips203': '替代共享秘密符合计算结果',
    'differs_from_original': '替代共享秘密与原结果不同',
    'modified_message_rejected': '修改消息后验签失败',
}
VECTOR_OPERATIONS = {**crypto.NAMES, 'encapsulationKeyCheck':'封装密钥检查',
                     'decapsulationKeyCheck':'解封装密钥检查'}
VECTOR_FIELDS = {**crypto.MATERIALS, 'secret':'共享秘密', 'message':'消息',
                 'context':'上下文', 'seed':'种子', 'randomness':'随机输入'}

def parameter_name(parameter):
    return f"{'ML-KEM' if parameter > 100 else 'ML-DSA'}-{parameter}"


def vector_case_name(operation, case_id):
    title = VECTOR_OPERATIONS.get(operation,'用例')
    return f'{title} tc{case_id}'


def vector_log_line(index, total, parameter, operation, case_id, status):
    return f'{index}/{total} {parameter_name(parameter)} {vector_case_name(operation,case_id)} · {status}'


def vector_result_log(index, total, row):
    operation = row.get('tested_category') or row.get('tested_operation')
    status = '失败'
    if row['verified']:
        status = '通过（按预期拒绝）' if row.get('expected_accept') is False else '通过'
    return vector_log_line(index,total,row['parameter'],operation,row['tc_id'],status)


def flat(value, prefix=''):
    if isinstance(value,dict):
        for key,item in value.items():
            label=str(key).lower().replace('-', '')
            if key in EXPORT_INTERNAL_FIELDS or 'sha256' in label or 'sha3_256' in label:
                continue
            yield from flat(item, (prefix+'.' if prefix else '')+str(key))
    elif isinstance(value,list):
        if all(isinstance(v,(int,float)) for v in value):
            yield [prefix, ', '.join(map(str,value))]
        else:
            for i,item in enumerate(value,1):
                yield from flat(item, f'{prefix}[{i}]')
    else:
        yield [prefix, value]


class Workbench:
    def __init__(self,current,live,sessions,source,root,output,*,local_platform='windows'):
        self.current,self.live,self.sessions = current,live,sessions
        self.local_platform = local_platform
        self.source,self.root,self.output = map(Path,(source,root,output))
        self.folder = self.output/'workbench'
        self.folder.mkdir(exist_ok=True)
        self.lock = threading.RLock()
        self.jobs_lock = threading.Lock()
        self.objects, self.history, self.jobs, self.files = {}, [], {}, {}
        self.downloads = {}
        self.modified_secret = C.create_string_buffer(32)
        self.modified_secret_ref = None
        self.selected_sources = {}
        self.evidence_path=self.root/'04_实验结果与验证材料/演示证据索引.json'
        self.evidence=json.loads(self.evidence_path.read_text(encoding='utf-8-sig')) if self.evidence_path.is_file() else {}
        if self.evidence.get('resources'):
            self.load_resource_builds()
        for group in ('resources','operations','microbench','coverage','security'):
            for row in self.evidence.get(group,[]):
                for key in ('source_path','board_record','evidence'):
                    path=row.get(key,'').split('#',1)[0]
                    if path: self.register_file(path)
        for path in [*DOCS,*BUILD_DOCS,*self.evidence.get('downloads',{}).values()]:
            self.register_file(path)
        base = self.source.relative_to(self.root).as_posix()
        for rel in ('demo/f407_provider.py','demo/ch32_strategy.py','demo/platform_providers.py',
                    'src/backends/canonical.c','demo/arithmetic_diagnostic/kem.c',
                    'demo/arithmetic_diagnostic/dsa.c','examples/public_a_session/application.c'):
            self.register_file(f'{base}/{rel}')
        app = Path(__file__).parent.relative_to(self.root).as_posix()
        for name in ('arithmetic','runtime','crypto','vectors','onboarding','security_checks','board_performance'):
            self.register_file(f'{app}/{name}.py')
        ring = '02_测试代码与数据/performance/多项式运算/完整环乘实板测量'
        for rel in ('stm32/24KiB/ring_driver.c','stm32/32KiB/ring_driver.c','ch32/measure_ring.c'):
            self.register_file(f'{ring}/{rel}')
        for name in ('transform-stm32.c','transform-ch32.c','primitive-stm32.c',
                     'primitive-ch32.c','stm32-acvp.c'):
            self.register_file(f'{app}/arithmetic/{name}')
        compiler_path=Path(__file__).parent/'arithmetic/build.json'
        self.diagnostic_build=json.loads(compiler_path.read_text(encoding='utf-8')) if compiler_path.is_file() else {}
        for profile, title in (('low-memory','低内存策略'),('performance','高性能策略')):
            self.register_file('03_复现环境与运行程序/host/Windows/'+title+'/运行说明.md')
        self.parameters = self.parameter_catalog()

    def register_file(self, rel):
        if not isinstance(rel,str) or not rel:
            return
        f=(self.root/rel).resolve()
        if f.is_relative_to(self.root) and f.is_file() and f.suffix.lower() in ('.xlsx','.xml','.md','.txt','.c','.h','.py','.ps1','.json','.tsv'):
            self.files[rel]=f

    def parameter_catalog(self):
        result = {}
        lib=next(iter(self.current.libs.values()),None)
        for family,params in crypto.PARAMETERS.items():
            for p in params:
                if lib is not None:
                    z=crypto.sizes(lib,p)
                    fields={k:getattr(z,k) for k,_ in z._fields_}
                    origin='lc_get_sizes'
                else:
                    body=(self.source/'src/common/public_api.c').read_text(encoding='utf-8')
                    match=re.search(rf'case\s+{p}\s*:(.*?);break;',body)
                    if not match: continue
                    fields={k:int(v) for k,v in re.findall(r's->(\w+)=(\d+)',match.group(1))}
                    if p>100: fields['shared_secret']=32
                    origin='src/common/public_api.c · 归档参数表'
                result[str(p)]=dict(**fields, algorithm=family, modulus=3329 if p>100 else 8380417,
                    ntt_layers=7 if p>100 else 8, source=origin, operations=crypto.OPERATIONS[family])
        return result

    def available(self,target,profile):
        if target==self.local_platform:
            return profile in self.current.libs
        ident=PROVIDER.get(target)
        provider=self.live.providers.get(ident)
        if not provider or provider.state!='connected':
            return False
        return self.remote_row(target,profile) is not None

    def remote_row(self,target,profile):
        ident=PROVIDER.get(target)
        rows=self.live.remote_rows.get(ident,())
        selected={'stm32f407':{'24':'stm32f407-compact','32':'stm32f407-cached'},
                  'ch32v307':{'28':'ch32-finals-low','80':'ch32-finals-high'},
                  'arm':{'low-memory':'arm-low-memory','performance':'arm-performance'}}.get(target,{}).get(profile)
        if target=='stm32f407':
            cap=getattr(self.live.providers.get(ident),'capabilities',{})
            if str(cap.get('deployment_kib',''))!=profile:
                return None
        return next((r for r in rows if r['id']==selected and r.get('execution_available',False)),None)

    def catalog(self):
        targets=[]
        for key,label in NAMES.items():
            if key.startswith('qemu') or (self.local_platform == 'arm' and key != 'arm'):
                continue
            choices=[dict(id=p, available=self.available(key,p), operation_timing=False) for p in PROFILES[key]]
            if key==self.local_platform:
                for item in choices:
                    desc=self.current.descriptors.get(item['id'],{})
                    item['operation_timing'] = item['available']
                    item.update(workspace_bytes=desc.get('workspace_bytes'), build_id=desc.get('binary_sha256'),
                                detail=desc.get('execution_reason',''))
                    if key=='arm':
                        item['board_vectors']=item['available']
                        if arithmetic.is_linux_arm() and arithmetic.catalog(self.root)['available']:
                            item['linux_operations']=arithmetic.ALL_OPERATIONS
            elif key in PROVIDER:
                for item in choices:
                    row = self.remote_row(key, item['id']) if item['available'] else None
                    item['presets'] = row.get('run_presets', {}) if row else {}
                    if key == 'stm32f407' and row:
                        item['board_vectors'] = self.live.providers['stm32f407'].can_run_kat()
                        item['board_ring'] = item['board_vectors']
                    if key == 'ch32v307' and row:
                        item['board_vectors'] = item['board_ring'] = getattr(self.live,'ch32_strategy',None) is not None
                    if key in ('stm32f407', 'ch32v307') and row:
                        item['operation_timing'] = True
                    if item.get('board_ring'):
                        item['board_operations'] = arithmetic.ALL_OPERATIONS
                        item['security_checks'] = True
                    if key == 'arm' and row:
                        capability = self.live.providers['arm'].capabilities.get(row['id'],{})
                        item['operation_timing'] = capability.get('operation_timing') is True
                        item['board_vectors'] = capability.get('acvp') is True
                        item['security_checks'] = capability.get('security_checks') is True
                        if capability.get('arithmetic_sha256') == arithmetic.arm_build_hash():
                            extended = capability.get('primitive_sha256') == arithmetic.primitive_digest()
                            item['linux_operations'] = arithmetic.ALL_OPERATIONS if extended else arithmetic.POLYNOMIAL
            can_deploy = (key == 'stm32f407' and key in self.live.providers or
                          key == 'ch32v307' and getattr(self.live, 'ch32_strategy', None) is not None)
            targets.append(dict(id=key,title=label,profiles=choices,can_deploy=can_deploy,
                    configured=key==self.local_platform or PROVIDER.get(key) in self.live.providers))
        return dict(platforms=targets,local_platform=self.local_platform,parameters=self.parameters,arithmetic=arithmetic.catalog(self.root),
                    acvp_cases={str(p):[dict(id=vectors.board_case_id(case),tc=case['tcId'],operation=crypto.OPERATIONS[family][case['operation']],
                                             accepted=case['accepted']) for case in vectors.board_cases(self.root,p)]
                                for family,params in crypto.PARAMETERS.items() for p in params},
                    evidence=self.evidence,files=list(self.files),host=platform.platform(),processor=platform.processor() or platform.machine(),
                    output=str(self.folder),history=self.history[-64:][::-1],build_docs=[p for p in BUILD_DOCS if p in self.files],
                    diagnostic_build={k:self.diagnostic_build.get(k) for k in ('component','compiler','build_configuration')})

    def validate(self,q,live=True,*,allow_stm32_dfu=False):
        if not isinstance(q,dict): raise ValueError('参数对象错误')
        family,p,t,profile=(q.get(k) for k in ('algorithm','parameter','platform','profile'))
        if family not in crypto.PARAMETERS or type(p) is not int or p not in crypto.PARAMETERS[family]:
            raise ValueError('算法与参数不匹配')
        if t not in PROFILES or profile not in PROFILES[t]:
            raise ValueError('平台与配置不匹配')
        if live:
            if q.get('source_kind') != SOURCE.get(t):
                raise ValueError('当前配置无法运行。')
            if t == 'stm32f407':
                with self.lock:
                    provider = self.live.providers.get(t)
                    if not (allow_stm32_dfu and provider and provider.observed_mode()=='dfu'
                            and provider.can_run_kat() and self.available(t,profile)):
                        self.ensure_stm32_ready(profile)
            if not self.available(t,profile):
                raise ValueError('当前配置无法运行。')
        return family,p,t,profile

    def prepare_record(self,q,operation,kind='crypto',ident=None):
        ident=ident or secrets.token_hex(10)
        return {k:q.get(k) for k in ('algorithm','parameter','platform','profile','source_kind')} | {
            'request_id':ident,'operation':operation,'kind':kind,'export_folder':EXPORT_KINDS[kind][0],
            'started_at':crypto.now(),'status':'运行中',
            'build_id':self.current.descriptors.get(q.get('profile'),{}).get('binary_sha256') if q.get('platform')==self.local_platform else None,
            'record_path':'workbench/'+ident+'.json'}

    def finish(self,record,result):
        if record['kind']=='performance':
            result=dict(result,resource_usage=self.performance_resources(record,result))
        record=dict(record)
        record.update(result=result,finished_at=crypto.now(),status=result.get('status') or ('检查通过' if result.get('verified') else '检查失败'),
                      verification=result.get('verified'), input_id=result.get('case_id') or result.get('input_id') or record['request_id'])
        if result.get('build_id'): record['build_id']=result['build_id']
        collector = wire.RUN_TRAFFIC.get()
        if collector is not None:
            lines = collector.snapshot()
            if lines['frames']:
                record['traffic'] = lines
        path=self.folder/(record['request_id']+'.json')
        with path.open('x',encoding='utf-8') as handle:
            json.dump(record,handle,ensure_ascii=False,allow_nan=False,separators=(',',':'))
        self.history.append({k:v for k,v in record.items() if k not in ('result','traffic')})
        return record

    def get_record(self,ident):
        if not re.fullmatch(r'[0-9a-f]{20}',ident):
            raise ValueError('运行编号无效')
        path=self.folder/(ident+'.json')
        if not path.is_file(): raise ValueError('运行记录不存在')
        record = json.loads(path.read_text(encoding='utf-8'))
        if record.get('operation') == '板上正确性测试':
            record['operation'] = ACVP_TEST
        return record

    def load_resource_builds(self):
        index = board_representatives.load_index(self.root)
        for config in self.evidence['resources']:
            key = 'ch32' if config['platform'] == 'ch32v307' else config['platform']
            role = 'low' if config['profile'] in ('24', '28') else 'high'
            pin = index[key,role]
            binary = board_representatives.resolve(self.root, pin.get('bin'))
            elf = binary.with_suffix('.elf')
            data = elf.read_bytes()
            elf_hash = hashlib.sha256(data).hexdigest()
            if (elf_hash != pin.get('elf_sha256') or pin.get('bin_sha256') != config['image_sha256']
                    or int(pin.get('flash')) != config['flash_bytes']
                    or int(pin.get('ram')) != config['complete_ram']):
                raise ValueError('正式资源记录与固件构建身份不符。')
            path = elf.relative_to(self.root).as_posix()
            config.update(code_bytes=executable_text(data), elf_sha256=elf_hash, elf_path=path,
                          firmware_tag=pin.get('build_id'))
            # Only the four hash-verified build artifacts enter the download list.
            self.files[path]=elf

    @staticmethod
    def read_tsv(path):
        with path.open(encoding='utf-8-sig',newline='') as source:
            return list(csv.DictReader(source,delimiter='\t'))

    @lru_cache(maxsize=4)
    def operation_samples(self, platform, profile):
        source=self.root/'02_测试代码与数据'
        samples=[]
        if platform=='stm32f407':
            base=source/'performance/完整密码操作/STM32F407/正式固件和同板对照'
            folder=base/'runs'/('fixedkem24-p' if profile=='24' else 'endpoint-q32-q')
            frames=(folder/'responses.bin').read_bytes()
            for row in self.read_tsv(folder/'schedule.tsv'):
                if row['scope']!='measurement' or row['strategy']!=('compact' if profile=='24' else 'cached'):
                    continue
                p=int(row['parameter'])
                words=struct.unpack_from('<64I',frames,int(row['order'])*256)
                if words[12]!=p or words[23]!=639:
                    raise ValueError('STM32 的计时记录与采样表不符。')
                family='ML-KEM' if p>100 else 'ML-DSA'
                for i,op in enumerate(crypto.OPERATIONS[family]):
                    samples.append((p,op,int(row['block']),int(row['pair']),words[28+i],0))
        else:
            base=source/'resources/CH32V307/六固件成对测量'/('low' if profile=='28' else 'high')
            for block in range(8):
                folder=base/f'区组{block+1:02d}'
                frames=(folder/'串口应答.bin').read_bytes()
                for row in self.read_tsv(folder/'事务.tsv'):
                    if row['phase']!='measure':
                        continue
                    offset=int(row['offset'])+20
                    p=int(row['parameter'])
                    if struct.unpack_from('<I',frames,offset+32)[0]!=p:
                        raise ValueError('CH32 的计时记录与采样表不符。')
                    family='ML-KEM' if p>100 else 'ML-DSA'
                    for i,op in enumerate(crypto.OPERATIONS[family]):
                        _,code,cycles=struct.unpack_from('<IiQ',frames,offset+128+32*i)
                        samples.append((p,op,block,int(row['repeat']),cycles,code))
        return samples

    def arithmetic_sample_file(self, row):
        source=self.root/'02_测试代码与数据/performance'
        poly=source/'多项式运算'
        if row['operation']=='环乘':
            folder=poly/'完整环乘实板测量'
            if row['platform']=='stm32f407':
                return folder/'stm32'/f"{row['profile']}KiB"/'raw-cycles.tsv'
            return folder/'ch32/raw-cycles.tsv'
        if row['platform']=='stm32f407':
            name='P' if row['profile']=='24' else 'Q'
            return source/'完整密码操作/STM32F407/正式固件和同板对照/defensive'/name/'lab/primitive.tsv'
        return poly/'CH32V307/实板原语测量/raw-cycles.tsv'

    def arithmetic_samples(self,row):
        data=self.read_tsv(self.arithmetic_sample_file(row))
        if row['operation']=='环乘':
            if row['platform']=='stm32f407':
                return [[int(x['input']),int(x['repeat']),int(x['cycles']),int(x['empty_cycles']),'']
                        for x in data if x['operation']==row['algorithm']]
            name='retired-response87' if row['profile']=='28' else 'wire80-eight'
            q=3329 if row['algorithm']=='ML-KEM' else 8380417
            return [[int(x['input']),int(x['repeat']),int(x['inclusive_cycles']),int(x['empty_cycles']),'']
                    for x in data if x['profile']==name and int(x['q'])==q]
        if row['platform']=='stm32f407':
            return [[int(x['case']),int(x['block']),int(x['cycles']),'',int(x['iterations'])]
                    for x in data if x['operation']==row['operation']]
        name='retired-response87' if row['profile']=='28' else 'wire80-eight'
        prefix='kem' if row['algorithm']=='ML-KEM' else 'dsa'
        op={'NTT':f'{prefix}_forward','INTT':f'{prefix}_inverse',
            'Montgomery pointwise':'dsa_pointwise','矩阵内积':'kem_dot'}[row['operation']]
        return [[int(x['independent_input']),int(x['within_input_repeat']),int(x['inclusive_ticks']),
                 int(x['empty_envelope_ticks']),''] for x in data
                if x['image']==name and x['operation']==op and int(x['KEM_columns'])==(row.get('columns') or 0)]

    def performance_tables(self, ident, view):
        entries = [(group,row) for group in ('resources','operations','microbench')
                   for row in self.evidence[group] if row['id']==ident]
        if len(entries)!=1 or view not in ('operations','micro','memory'):
            raise ValueError('测试记录不存在。')
        group, row = entries[0]
        same = lambda item:(item['platform'],item['profile'])==(row['platform'],row['profile'])
        config = next(item for item in self.evidence['resources'] if same(item))
        clock=config['platform_clock_mhz']
        timer='DWT 周期计数' if config['platform']=='stm32f407' else 'SysTick 周期计数'
        board=f"{config['board']} {config['profile']} KiB"
        summary=[['设备','测试项目','结果']]
        details=[]
        if group=='operations' or group=='resources' and view=='operations':
            selected = [row] if group=='operations' else [item for item in self.evidence['operations'] if same(item)]
            raw=self.operation_samples(config['platform'],config['profile'])
            details=[['参数','操作','区组','输入编号','周期','耗时（ms）','返回码']]
            for item in selected:
                selected_samples=[(block,i,cycles,rc) for p,op,block,i,cycles,rc in raw
                                  if (p,op)==(item['parameter'],item['operation'])]
                if len(selected_samples)!=item['samples_per_parameter'] or abs(
                    sum(c for _,_,c,_ in selected_samples)/(clock*1000*len(selected_samples))-item['mean_ms'])>1e-8:
                    raise ValueError('逐次样本与正式耗时不符。')
                summary.append([board,item['algorithm']+' '+item['operation_label'],item['mean_ms']])
                details.extend([item['algorithm'],item['operation_label'],block+1,i+1,c,c/(clock*1000),rc]
                               for block,i,c,rc in selected_samples)
        elif group=='microbench' or group=='resources' and view=='micro':
            selected = [row] if group=='microbench' else [item for item in self.evidence['microbench'] if same(item)]
            details=[['算法','运算','输入编号','重复编号或区组','周期','空调用周期','批内调用次数']]
            for item in selected:
                label=item['operation']+(f"（{item['columns']} 列）" if item.get('columns') else '')
                summary.append([board,item['algorithm']+' '+label,item['cycles']])
                details.extend([item['algorithm'],label,*sample] for sample in self.arithmetic_samples(item))
        else:
            details=[['项目','字节数'],['RAM 预算',config['budget_bytes']],['完整 RAM',config['complete_ram']],
                     ['临时缓冲区容量（工作区）',config['workspace_reserved']],
                     ['临时缓冲区实测峰值（工作区）',config.get('observed_peak_bytes')],
                     ['Flash 占用',config['flash_bytes']],['代码段（ELF .text）',config['code_bytes']]]
            summary.append([board,'资源占用','正式配置'])
        info=[['设备',board],['记录','正式实板测量'],['固件配置',config['strategy']],
              ['处理器频率（MHz）',clock],['计时方式',timer]]
        if view=='micro':
            sources=dict.fromkeys(self.arithmetic_sample_file(item) for item in selected)
            info.extend(['原始样本文件',path.relative_to(self.root).as_posix()] for path in sources)
        elif view=='operations':
            info.append(['原始测量目录','完整密码操作/STM32F407/正式固件和同板对照'
                         if config['platform']=='stm32f407' else 'CH32V307/六固件成对测量'])
        info.extend([['固件标识',config['firmware_tag']],['固件 SHA-256',config['image_sha256']],
                     ['ELF 路径',config['elf_path']],['ELF SHA-256',config['elf_sha256']]])
        if view=='memory':
            info.append(['临时缓冲区峰值采样范围',config['peak_scope']])
        if row.get('statistic') and view=='micro':
            info.append(['汇总方法',row['statistic']])
        if group=='operations' or view=='operations':
            info.extend([['输入数（每组参数）',64],
                         ['测试安排','4 个区组，每组 16 个输入' if config['platform']=='stm32f407' else '8 个区组，每组 8 个输入'],
                         ['计时范围','完整密码 API']])
        return summary,details,info,board

    def performance_samples(self, ident):
        view = next((view for group,view in (('operations','operations'),('microbench','micro'))
                     if any(row['id']==ident for row in self.evidence[group])),None)
        if view is None:
            raise ValueError('原始样本不存在。')
        _,details,_,_ = self.performance_tables(ident,view)
        return dict(header=details[0],rows=details[1:])

    def performance_archive(self, ident, view):
        summary,details,info,board = self.performance_tables(ident,view)
        return workbook([('测试汇总',summary),('逐项数据',details),('测试信息',[['项目','记录'],*info])],
                        filters=('逐项数据',)), f'{board}-测试结果.xlsx'

    def run_performance(self,q,*,report=ignore_progress):
        family,p,target,profile=self.validate(q)
        operation=q.get('operation')
        if operation not in crypto.OPERATIONS[family]:
            raise ValueError('当前设备无法运行此项测试。')
        record=self.prepare_record(q,operation,kind='performance')
        log=[]
        def record_progress(message):
            log.append(message)
            report(message)
        try:
            with self.lock:
                self.validate(q)
                if target in ('stm32f407','ch32v307'):
                    if q.get('performance_input') == 'vector':
                        rows = []
                        observed = board_performance.measure(self,target,profile,[(p,operation)],record_progress,rows.append)
                        row = rows[0]
                        result = dict(observed,verified=row['verified'],steps=rows,duration_ms=row['duration_ms'],summary=row['summary'])
                    else:
                        result=self.measure_board_operation(q,target,profile,p,operation,record_progress)
                else:
                    result=self.measure_host_operation(target,profile,p,operation,record_progress)
        except (ValueError,OSError,KeyError,RuntimeError) as error:
            message=str(error) if isinstance(error,ValueError) else self.remote_error(error)
            result=dict(verified=False,status='未完成',summary=message)
        return self.finish(record,dict(result,log=log))

    @staticmethod
    def timed_resources(result):
        values=dict(result.get('firmware_resources',{}))
        rows=[row for row in result.get('steps',[]) if row.get('return_code') is not None]
        for key in ('workspace_bytes','workspace_used_bytes'):
            readings=[row[key] for row in rows if type(row.get(key)) is int]
            if readings:
                values[key]=max(readings)
        return values

    def performance_resources(self, record, result):
        usage = self.timed_resources(result)
        target, profile = record['platform'], record['profile']
        build_id = result.get('build_id') or record.get('build_id')
        if not build_id or not result.get('steps'):
            return usage
        if target in ('stm32f407', 'ch32v307'):
            for config in self.evidence.get('resources', ()):
                if (config['platform'], config['profile']) != (target, profile):
                    continue
                if build_id in (config['image_sha256'], config['elf_sha256']):
                    for name, key in (('ram_budget_bytes', 'budget_bytes'),
                                      ('static_ram_bytes', 'complete_ram'),
                                      ('firmware_workspace_bytes', 'workspace_reserved'),
                                      ('flash_bytes', 'flash_bytes'), ('code_bytes', 'code_bytes')):
                        usage.setdefault(name, config[key])
                break
            return usage

        platform_path = {'windows': ('Windows', 'latticecore.dll'), 'arm': ('AArch64', 'liblatticecore.so')}
        if target not in platform_path or profile not in ('low-memory', 'performance'):
            return usage
        folder, filename = platform_path[target]
        variant = '低内存策略' if profile == 'low-memory' else '高性能策略'
        path = self.root / '03_复现环境与运行程序/host' / folder / variant / filename
        try:
            image = path.read_bytes()
            if hashlib.sha256(image).hexdigest() == build_id:
                usage['library_bytes'] = len(image)
                usage['code_bytes'] = executable_text(image)
        except (OSError, ValueError, struct.error):
            pass
        return usage

    def measure_board_operation(self,q,target,profile,parameter,operation,report):
        report(f'{NAMES[target]} {profile} KiB · {operation_progress(parameter,operation)}')
        raw=self.remote_run(target,profile,parameter,q)
        measured=self.board_timing_rows(raw,parameter)
        row=next(item for item in measured['steps'] if item['operation']==operation)
        if row['duration_ms'] is None:
            raise ValueError('开发板没有返回这项操作的周期。')
        return dict(measured,verified=row['verified'],steps=[row],duration_ms=row['duration_ms'],
                    summary=row['summary'],raw_response=raw)

    def board_timing_rows(self,raw,parameter):
        clock=raw.get('clock_hz') or raw.get('device_metrics',{}).get('timer',{}).get('frequency_hz')
        if not isinstance(clock,int) or clock<=0:
            raise ValueError('未收到本次计时使用的处理器频率。')
        steps=self.remote_steps(raw,parameter)
        operations={row['operation']:row for row in raw['operations']}
        resources=raw.get('device_metrics',{}).get('resources',{})
        firmware_resources={}
        for key,value in (
            ('flash_bytes',resources.get('flash_bytes') if resources else
                           raw.get('image_bytes') if raw.get('image_storage')=='flash' else None),
            ('static_ram_bytes',resources.get('static_ram_bytes',raw.get('static_ram_bytes'))),
        ):
            if type(value) is int:
                firmware_resources[key]=value
        for row in steps:
            observed=operations.get(row['operation'],{})
            row['workspace_bytes']=raw.get('workspace_bytes')
            row['workspace_used_bytes']=observed.get('arena_high_water_bytes')
            row['duration_ms']=row['cycles']*1000/clock if row['cycles'] is not None else None
            row['checks']={'operation_verified':row['verified']}
            check={'decaps':'shared_secret_equal','verify':'signature_verified'}.get(row['operation'])
            if check and check in raw['checks']:
                row['checks'][check]=raw['checks'][check]
            if 'canaries_ok' in raw:
                row['checks']['canaries_ok']=raw['canaries_ok']
            if row['return_code'] is not None and not all(row['checks'].values()):
                row['verified']=False
                if row['checks'].get('canaries_ok') is False:
                    row['summary']='缓冲区保护检查失败'
        return dict(steps=steps,clock_hz=clock,timing_method='板端周期计数',
                    firmware_resources=firmware_resources,
                    build_id=raw.get('binary_sha256') or raw.get('firmware_sha256') or raw.get('build_tag'))

    def measure_host_operation(self,target,profile,parameter,operation,report):
        if target==self.local_platform:
            desc=self.current.descriptors[profile]
            build_id=desc['binary_sha256']
            row=crypto.measure_operation(self.current.libs[profile],desc['workspace_bytes'],
                                         profile,parameter,operation,report)
            row['workspace_bytes']=desc['workspace_bytes']
        else:
            library=self.remote_row(target,profile)
            provider=self.live.providers[PROVIDER[target]]
            if not library or provider.capabilities.get(library['id'],{}).get('operation_timing') is not True:
                raise ValueError('Linux 端运行程序尚未提供操作计时。')
            report(f'{NAMES[target]} · {operation_progress(parameter,operation)}')
            measured=provider.run_performance(library['id'],parameter,operation)
            row=dict(operation=operation,parameter=parameter,return_code=measured['return_code'],
                     verified=measured['verified'],duration_ms=measured['duration_ns']/1_000_000,
                     summary='通过' if measured['verified'] else '检查失败',
                     function=crypto.FUNCTIONS[operation])
            row.update((key,measured[key]) for key in ('workspace_bytes','workspace_used_bytes','inputs','public_outputs')
                       if key in measured)
            build_id=measured['binary_sha256']
        return dict(verified=row['verified'],steps=[row],duration_ms=row['duration_ms'],
                    timing_method='执行主机单调时钟',summary=row['summary'],build_id=build_id)

    def run_performance_job(self,job,record,q,target,profile):
        started=monotonic()
        collector=wire.RUN_TRAFFIC.set(job['traffic']) if 'traffic' in job else None
        metadata={}
        raw_responses={}
        error=None
        def remember(observed):
            for key in ('clock_hz','timing_method','build_id','firmware_resources'):
                if key not in observed:
                    continue
                value=observed[key]
                if key in metadata and metadata[key]!=value:
                    raise ValueError('批量运行期间计时条件或构建身份发生变化。')
                metadata[key]=value
        try:
            with self.lock:
                started=monotonic()
                if target in ('stm32f407','ch32v307') and q.get('performance_input') == 'vector':
                    self.validate(q)
                    observed = board_performance.measure(self,target,profile,job['plan'],job['log'].append,
                        lambda row: self.append_performance_row(job,row),stop=job['cancel'].is_set)
                    remember(observed)
                else:
                    for parameter in (p for group in crypto.PARAMETERS.values() for p in group):
                        if job['cancel'].is_set():
                            break
                        family='ML-KEM' if parameter>100 else 'ML-DSA'
                        self.validate(dict(q,algorithm=family,parameter=parameter))
                        operations=crypto.OPERATIONS[family]
                        if target in ('stm32f407','ch32v307'):
                            job['current']=[parameter,'完整流程']
                            job['log'].append(f'{parameter_name(parameter)} · 等待板端应答')
                            raw=self.remote_run(target,profile,parameter,q)
                            observed=self.board_timing_rows(raw,parameter)
                            remember(observed)
                            raw_responses[str(parameter)]=raw
                            for row in observed['steps']:
                                self.append_performance_row(job,row)
                        else:
                            for operation in operations:
                                if job['cancel'].is_set():
                                    break
                                job['current']=[parameter,operation]
                                observed=self.measure_host_operation(target,profile,parameter,operation,job['log'].append)
                                row=observed['steps'][0]
                                remember(observed)
                                self.append_performance_row(job,row)
        except (ValueError,OSError,TypeError,KeyError,RuntimeError) as failure:
            error=str(failure) if isinstance(failure,ValueError) else self.remote_error(failure)
        rows=job['rows']
        executed=sum(row['return_code'] is not None for row in rows)
        passed=sum(row['verified'] for row in rows)
        total=len(job['plan'])
        cancelled=len(rows)<total and job['cancel'].is_set()
        status='未完成' if error else '已取消' if cancelled else '检查通过' if passed==total else '检查失败'
        result=dict(metadata,verified=not error and passed==total,steps=rows,status=status,total=total,executed=executed,
                    passed=passed,failed=executed-passed,elapsed_ms=(monotonic()-started)*1000,
                    summary=error or f'通过 {passed}/{total} 项',log=list(job['log']))
        if raw_responses:
            result['raw_responses']=raw_responses
        try:
            job['result']=self.finish(record,result)
        except (OSError,ValueError):
            job['result']=dict(record,verification=False,status='未完成',
                               result=dict(result,summary='未能保存运行记录。'))
        finally:
            if collector is not None:
                wire.RUN_TRAFFIC.reset(collector)
        job['state']=job['result']['status']
        job['current']=None

    @staticmethod
    def append_performance_row(job,row):
        job['rows'].append(row)
        label=operation_progress(row['parameter'],row['operation'])
        timing=f" · {row['duration_ms']:.3f} ms" if row['duration_ms'] is not None else ''
        job['log'].append(f"{len(job['rows'])}/{len(job['plan'])} {label} · {row['summary']}{timing}")

    def traffic_file(self, ident):
        record = self.get_record(ident)
        log = record.get('traffic')
        if not log:
            raise ValueError('这次运行没有通信记录。')
        lines = []
        for frame in log['frames']:
            lines.append(f"{frame['direction']} {frame['link']} · {frame['description']} ({frame['bytes']} B)")
            if frame['hex']:
                lines.append(frame['hex'])
        if log['omitted']:
            lines.append(f"还有 {log['omitted']} 条超出记录上限。")
        return '\n'.join(lines)+'\n', f"{NAMES[record['platform']]}-通信日志.txt"

    def job_traffic(self, ident, start):
        job = self.jobs.get(ident)
        if job is None or 'traffic' not in job:
            return dict(frames=[],omitted=0)
        return job['traffic'].snapshot(start)

    def export_name(self,record):
        label=EXPORT_KINDS.get(record.get('kind'),EXPORT_KINDS['crypto'])[1]
        if record['result'].get('board_vectors'):
            label = f"{NAMES[record['platform']]}-{ACVP_TEST}"
        if record['platform'] == 'arm' and record.get('kind') == 'board-suite':
            label = '密码测试'
        timestamp=datetime.fromisoformat(record['finished_at']).astimezone().strftime('%Y%m%d-%H%M%S-%f')
        prefix = f"{NAMES[record['platform']]}-" if 'raw_response' in record['result'] or record['result'].get('remote_batch') else ''
        return f'{prefix}{label}-{timestamp}.xlsx'

    def register_objects(self, obj):
        self.objects[obj.id] = obj
        if len(self.objects) > 24:
            self.objects.pop(next(iter(self.objects))).close()

    def current_object(self, q, profile, p):
        key = q.get('object_ref')
        obj = self.objects.get(key) if isinstance(key, str) else None
        if obj is None or (obj.profile, obj.parameter) != (profile, p):
            raise ValueError('请先生成或导入数据。')
        return obj

    def clear_modified_secret(self):
        self.modified_secret_ref = None
        C.memset(self.modified_secret, 0, len(self.modified_secret))

    def material(self, action, q):
        family,p,t,profile = self.validate(q)
        if t != self.local_platform:
            raise ValueError('请切换到 Windows 本机。')
        with self.lock:
            if q.get('field') == 'modified_shared_secret':
                matches = (q.get('request_id'), profile, p) == self.modified_secret_ref
                if action == 'clear-materials':
                    if matches:
                        self.clear_modified_secret()
                    return {}
                if action == 'show-material' and matches:
                    return {'hex': self.modified_secret.raw.hex()}
                raise ValueError('没有可用的数据。')
            if action == 'import-material':
                lib = self.current.libs[profile]
                cap = self.current.descriptors[profile]['workspace_bytes']
                obj = self.current_object(q,profile,p) if q.get('object_ref') else crypto.Objects(lib,profile,p)
                crypto.import_material(lib,cap,obj,q.get('field'),q.get('hex'))
                self.register_objects(obj)
                return obj.state()
            obj = self.current_object(q,profile,p)
            if action == 'clear-materials':
                del self.objects[obj.id]
                obj.close()
                return {}
            field = q.get('field')
            slots = obj.view_slots() if action == 'show-material' else obj.slots()
            buf, loaded = slots.get(field, (None, False))
            if not loaded:
                raise ValueError('没有可用的数据。')
            if action == 'show-material':
                return {'hex': buf.raw.hex()}
            now = monotonic()
            self.downloads = {key: item for key,item in self.downloads.items() if item[0] > now}
            if len(self.downloads) >= 24:
                self.downloads.pop(next(iter(self.downloads)))
            ticket = secrets.token_hex(24)
            self.downloads[ticket] = (now + 30, obj.id, obj.revision, field, family)
            return {'url': f'/wb/download/{ticket}.bin'}

    def material_download(self, ticket):
        with self.lock:
            item = self.downloads.pop(ticket, None)
            if item and item[0] > monotonic():
                _, ident, revision, field, family = item
                obj = self.objects.get(ident)
                if obj and obj.revision == revision:
                    buf, loaded = obj.slots()[field]
                    if loaded:
                        return buf.raw, f'{family}-{obj.parameter}-{crypto.MATERIALS[field]}.bin'
        raise ValueError('保存链接已失效，请重新保存。')

    def public_file(self, ident, field):
        if field not in PUBLIC_FILES:
            raise ValueError('没有可保存的文件。')
        record = self.get_record(ident)
        if record.get('kind') != 'crypto' or record.get('platform') != self.local_platform:
            raise ValueError('没有可保存的文件。')
        result = record['result']
        for row in result.get('rows', [result]):
            item = row.get('public_outputs', {}).get(field)
            if row.get('verified') and isinstance(item, dict) and item.get('hex'):
                raw = bytes.fromhex(item['hex'])
                if len(raw) == item['length']:
                    name = f"{record['algorithm']}-{row['parameter']}-{PUBLIC_FILES[field]}.bin"
                    return raw, name
        raise ValueError('没有可保存的文件。')

    def board_file(self, ident):
        record = self.get_record(ident)
        raw = record['result'].get('raw_response') or record['result'].get('raw_responses')
        if record.get('kind') not in ('board-suite', 'security', 'performance') or record.get('source_kind') != 'live_board' or not isinstance(raw, dict):
            raise ValueError('没有设备应答。')
        return raw, f"{NAMES[record['platform']]}-{record['parameter']}-板端应答.json"

    def operation_rows(self, record):
        result = record['result']
        if 'rows' in result:
            return result['rows']
        rows = []
        refs = result.get('inputs', {})
        p = result.get('parameter', record['parameter'])
        normal = crypto.OPERATIONS.get(self.parameters.get(str(p), {}).get('algorithm'), ())
        parents = zip(('key_record', 'payload_record', 'check_record'), normal)
        for key, operation in parents:
            ident = refs.get(key)
            if not ident:
                continue
            try:
                earlier = self.get_record(ident)
            except (ValueError, OSError):
                continue
            if earlier.get('kind') != 'crypto':
                continue
            step = earlier['result']
            rows.extend(r for r in step.get('rows', [step])
                        if r.get('object_ref') == result.get('object_ref') and r.get('operation') == operation)
        return [*rows, result]

    def crypto_export(self, record, info):
        headings = ['参数', '操作', '结果', '耗时（ms）', '公钥（B）', '私钥（B）',
                    '密文（B）', '签名（B）', '共享秘密（B）']
        steps, checks = [headings], [['操作', '检查', '结果']]
        rows = self.operation_rows(record)
        library = next((row['library'] for row in rows if row.get('library')), None)
        if library:
            info.extend([['配置', {'low-memory':'低内存', 'performance':'高性能'}.get(record['profile'], record['profile'])],
                         ['库文件', library]])
        for row in rows:
            op = crypto.NAMES.get(row.get('operation'), row.get('operation', ''))
            pub = row.get('public_outputs', {})
            p = row.get('parameter', record['parameter'])
            parameter = self.parameters.get(str(p), {}).get('algorithm')
            duration = row.get('duration_ms')
            steps.append([f'{parameter}-{p}' if parameter else p, op,
                          row.get('summary') or ('成功' if row.get('verified') else '失败'),
                          round(duration, 6) if duration is not None else None, pub.get('public_key', {}).get('length'),
                          pub.get('secret_key_length'), pub.get('ciphertext', {}).get('length'),
                          pub.get('signature', {}).get('length'), pub.get('shared_secret_length')])
            checks.extend([op, CHECK_NAMES[key], '是' if value else '否']
                          for key,value in row.get('checks', {}).items() if key in CHECK_NAMES)
        tabs = [('运行信息', [['字段','值'], *info]), ('操作结果', steps)]
        if len(checks) > 1:
            tabs.append(('检查结果', checks))
        return workbook(tabs)

    def vector_export(self, record, finished, parameter):
        result = record['result']
        rows = result.get('rows', [])
        outputs = [key for key in VECTOR_FIELDS if any(key in row.get('output_checks', {}) for row in rows)]
        platform_name = NAMES.get(record['platform'],record['platform'])
        if result.get('board_vectors') and record['source_kind']=='live_board':
            platform_name += f" {record['profile']} KiB"
        summary = [
            ['测试时间','平台','算法参数','测试集','计划','已执行','通过','失败','状态'],
            [finished.strftime('%Y-%m-%d %H:%M:%S'), platform_name, parameter,
             {'acvp':'NIST ACVP','wycheproof':'Wycheproof'}.get(result.get('suite')),
             result.get('total'), result.get('executed',len(rows)), sum(bool(row.get('verified')) for row in rows),
             sum(not row.get('verified') for row in rows), record['status']],
        ]
        each = [['用例','操作','预期结果','实际结果',*[VECTOR_FIELDS[key]+'检查' for key in outputs],'状态','返回码']]
        detail = [['用例','输入长度','输出长度','输出检查','缓冲区保护','工作区清理','工作区使用量（B）','原始用例编号']]
        if result.get('board_vectors'):
            each[0].insert(0,'算法参数')
            detail[0].insert(0,'算法参数')
        for row in rows:
            category = row.get('tested_category') or row.get('tested_operation')
            identifier = row.get('case_id') or row.get('operation')
            case = f"tc{row['tc_id']}" if row.get('tc_id') is not None else identifier
            rc = row.get('return_code')
            expected, actual = row.get('expected_accept'), row.get('actual_accept')
            accepted, rejected = ('验签通过','验签失败') if category == 'verify' else ('接受','拒绝')
            expected_label = {True:accepted, False:rejected}.get(expected)
            actual_label = {True:accepted, False:rejected}.get(actual) if rc in (0,-1,-2,-6) else '运行出错'
            checks = row.get('output_checks', {})
            match = {True:'与预期一致', False:'与预期不一致'}
            each.append([case, VECTOR_OPERATIONS.get(category, '未完成'), expected_label, actual_label,
                         *[match.get(checks.get(key)) for key in outputs],
                         '通过' if row.get('verified') else '失败', rc])
            input_lengths = row.get('input_lengths', {})
            output_lengths = row.get('output_lengths') or {key: value['length'] for key,value in row.get('public_outputs', {}).items()}
            guard = {True:'通过',False:'失败'}
            detail.append([case, '\n'.join(f'{VECTOR_FIELDS.get(key,key)} {value} B' for key,value in input_lengths.items()),
                           '\n'.join(f'{VECTOR_FIELDS.get(key,key)} {value} B' for key,value in output_lengths.items()),
                           '\n'.join(f'{VECTOR_FIELDS.get(key,key)}{match.get(value, "")}' for key,value in checks.items()),
                           guard.get(row.get('canaries_ok')), guard.get(row.get('used_workspace_erased')),
                           row.get('workspace_used_bytes'), identifier])
            if result.get('board_vectors'):
                p=row['parameter']
                name=f"{'ML-KEM' if p>100 else 'ML-DSA'}-{p}"
                each[-1].insert(0,name)
                detail[-1].insert(0,name)
        parameter_width = [18] if result.get('board_vectors') else []
        return workbook([('测试汇总',summary),('逐项结果',each),('用例详情',detail)],
                        widths={'测试汇总':[24,19,20,17,10,12,10,10,15],
                                '逐项结果':[*parameter_width,14,22,15,15,*([16]*len(outputs)),11,10],
                                '用例详情':[*parameter_width,14,27,28,26,15,15,22,57]},
                        filters=('逐项结果','用例详情'))

    @staticmethod
    def security_export(result, info):
        evidence = result['security_input']
        field, before, after = (evidence[key] for key in ('field', 'before', 'after'))
        labels = {'ciphertext': '密文', 'signature': '签名', 'message': '消息', 'public_key': '公钥',
                  'workspace_bytes': '工作区容量', 'entropy_bytes': '测试随机源'}
        sources = {'current': '当前密码流程', 'fresh': '本次生成', 'fixture': '公开测试向量', 'firmware': '当前板上固件'}
        info = [*info, ['检查对象', labels[field]], ['输入来源', sources[evidence['source']]]]
        if evidence.get('reference'):
            info.append(['输入来源标识', evidence['reference']])
        checks = [['项目', '结果']]
        for key, label in (('function','调用 API'), ('original_return_code','原始返回码'),
                           ('return_code','本次返回码'), ('expected_return_code','预期返回码'),
                           ('recovery_return_code','恢复后返回码')):
            if result.get(key) is not None:
                checks.append([label, result[key]])
        checks.extend([row['label'], row['value']] for row in result.get('findings', ()))
        if not result.get('findings'):
            labels = {'failure_output_zero': '失败输出清零', 'original_shared_secret_equal': '原始共享秘密一致',
                      'differs_from_original': '替代共享秘密与原值不同', 'replacement_matches_fips203': '替代共享秘密独立核验',
                      'original_signature_verified': '原始验签通过', 'modified_signature_rejected': '修改签名后拒绝验签',
                      'modified_message_rejected': '修改消息后拒绝验签'}
            checks.extend([labels[key], '通过' if passed else '失败']
                          for key, passed in result.get('checks', {}).items() if key in labels)
        if isinstance(before, int):
            data = [['项目', '正常条件（B）', '本次条件（B）'], [evidence['field']=='workspace_bytes'
                    and '工作区容量' or '随机源字节数', before, after]]
        else:
            info.extend([['原始长度（B）', len(before)//2], ['本次传入长度（B）', len(after)//2]])
            data = [['字节偏移（从 0 开始）', '原始输入（HEX）', '本次传入（HEX）']]
            data.extend([offset//2, before[offset:offset+2048], after[offset:offset+2048]]
                        for offset in range(0, max(len(before), len(after)), 2048))
        return workbook([('运行信息', [['字段','值'], *info]), ('输入与变更', data), ('测试结果', checks)])

    def export(self,ident):
        record=self.get_record(ident)
        result=record['result']
        finished=datetime.fromisoformat(record['finished_at']).astimezone()
        operation=record['operation']
        parameter=record['parameter']
        if isinstance(parameter,int):
            parameter=f"{record['algorithm']}-{parameter}"
        if record.get('kind') == 'vectors':
            return self.vector_export(record,finished,parameter)
        if record.get('kind') == 'performance':
            rows = result.get('steps') or []
            header = ['参数','操作','返回码','周期','耗时（ms）','结果','临时缓冲区容量（工作区，B）','临时缓冲区实测峰值（工作区，B）']
            data = [[parameter_name(row['parameter']),crypto.NAMES[row['operation']],row['return_code'],
                     row.get('cycles'),row.get('duration_ms',result.get('duration_ms')),row['summary'],
                     row.get('workspace_bytes'),row.get('workspace_used_bytes')] for row in rows]
            board=record['source_kind']=='live_board'
            profile=record['profile']+' KiB' if board else {'low-memory':'低内存','performance':'高性能'}[record['profile']]
            info=[['项目','记录'],['类型','当前设备'],['时间',finished.strftime('%Y-%m-%d %H:%M:%S')],
                  ['计时范围','本次运行中的所选操作']]
            if result.get('timing_method'):
                info.append(['计时方式',result['timing_method']])
            if result.get('clock_hz'):
                info.append(['处理器频率（Hz）',result['clock_hz']])
            if record.get('build_id'):
                info.append(['构建标识',record['build_id']])
            if result.get('total'):
                info.extend([['实际执行项数',result['executed']],['通过项数',result['passed']],
                             ['本次批量实际总耗时（ms）',result['elapsed_ms']]])
            if result.get('log'):
                info.extend(['运行日志',entry] for entry in result['log'])
            if record.get('traffic'):
                info.append(['通信记录编号',record['request_id']])
            sheets=[('测试汇总',[['设备','配置','操作','结果'],
                      [NAMES[record['platform']],profile,crypto.NAMES.get(operation,operation),record['status']]]),
                    ('逐项数据',[header,*data]),('测试信息',info)]
            usage=result.get('resource_usage',{}) | self.performance_resources(record,result)
            resource_labels={
                'workspace_bytes': ('临时缓冲区容量最大值（工作区）','本次运行'),
                'workspace_used_bytes': ('临时缓冲区实测峰值（工作区）','本次运行'),
                'ram_budget_bytes': ('RAM 预算','当前固件'),
                'static_ram_bytes': ('完整 RAM','当前固件'),
                'firmware_workspace_bytes': ('临时缓冲区预留（固件工作区）','当前固件'),
                'flash_bytes': ('Flash 占用','当前固件'),
                'code_bytes': ('代码段（.text）','当前构建'),
                'library_bytes': ('算法库文件大小','当前构建'),
            }
            if usage:
                sheets.append(('资源占用',[['项目','字节数','来源'],
                               *[[label,usage[key],source] for key,(label,source) in resource_labels.items() if key in usage]]))
            return workbook(sheets)
        if record.get('kind')=='arithmetic' and (record['source_kind']=='live_board' or record['platform']=='arm') and 'output' in result:
            op = next(title for key,title,*_ in arithmetic.OPERATIONS if key == operation)
            inputs = result['inputs']
            keys = [key for key in ('a','b') if key in inputs]
            columns = [('计算结果',result['output'])]
            for key,label in (('expected_output','独立预期值'),('native_output','板端原始代表元')):
                if key in result:
                    columns.append((label,result[key]))
            board = record['source_kind'] == 'live_board'
            profile = record['profile']+' KiB' if board else record['profile']
            timing = result['cycles'] if board else result['duration_ns']
            return workbook([('测试汇总',[
                ['平台','算法参数','配置','操作','周期' if board else '耗时（ns）','检查结果'],
                [NAMES[record['platform']],parameter,profile,op,timing,result['summary']],
            ]),('逐项数据',[
                ['次数',*[f'多项式 {key.upper()}' for key in keys],*[label for label,_ in columns]],
                *[[i,*values] for i,values in enumerate(zip(*(inputs[key] for key in keys),*(values for _,values in columns)))],
            ]),('测试信息',[['项目','记录'],['类型','当前设备'],['独立校验',result.get('check')],
                         ['时间',finished.strftime('%Y-%m-%d %H:%M:%S')]])])
        info=[
            ['时间',finished.strftime('%Y-%m-%d %H:%M:%S')],
            ['平台',NAMES.get(record['platform'],record['platform'])],
            ['参数',parameter],
            ['操作',crypto.NAMES.get(operation,operation)],
            ['结果',result.get('summary') or record['status']],
        ]
        if record.get('kind') == 'security':
            info.extend(['运行日志', line] for line in result.get('log', ()))
        if result.get('remote_batch'):
            rows = result['rows']
            return workbook([('运行信息', [['字段', '值'], *info]), ('逐项结果', [
                ['参数', '操作', '结果', '返回码', '周期'],
                *[[f"{'ML-KEM' if row['parameter'] > 100 else 'ML-DSA'}-{row['parameter']}",
                   crypto.NAMES[row['operation']], row['summary'], row['return_code'], row['cycles']] for row in rows],
            ])])
        if record.get('kind') == 'crypto':
            return self.crypto_export(record,info)
        if record.get('kind') == 'security' and result.get('security_input'):
            return self.security_export(result, info)
        if record.get('kind') == 'board-suite' or 'remote_test' in result:
            if record['platform'] in PROVIDER:
                profile = {'low-memory': '低内存', 'performance': '高性能'}.get(record['profile'], record['profile'])
                info.append(['配置', profile if record['platform'] == 'arm' else f'{profile} KiB'])
            raw = result.get('raw_response', {})
            if record['algorithm'] == 'ML-DSA' and raw:
                info.extend([['消息（B）', raw['message_bytes']], ['上下文（B）', raw['context_bytes']]])
            if 'expected_return_code' in result:
                info.append(['预期返回码', result['expected_return_code']])
            rows = result.get('steps') or []
            sheets = [('运行信息', [['字段', '值'], *info])]
            if rows:
                sheets.append(('逐项结果', [
                    ['操作', '结果', '返回码', '周期'],
                    *[[crypto.NAMES[row['operation']], row['summary'], row['return_code'], row['cycles']] for row in rows],
                ]))
            if result.get('findings'):
                sheets.append(('测试结果', [
                    ['项目', '结果'], *[[row['label'], row['value']] for row in result['findings']],
                ]))
            return workbook(sheets)
        test = result.get('ciphertext_test')
        if record.get('kind') == 'security' and test:
            checks = result['checks']
            # 旧版记录会在原始共享秘密一致后运行密文篡改测试。
            original = '解封装出错' if test.get('original_return_code', 0) else (
                'K = K′' if checks.get('original_shared_secret_equal', True) else 'K ≠ K′')
            modified = '解封装出错' if result['return_code'] else (
                'K ≠ K″' if checks['differs_from_original'] else 'K = K″')
            rows = [
                ['原始解封装', original],
                ['修改字节数', test['changed_bytes']],
                ['修改后解封装', modified],
            ]
            return workbook([('运行信息',[['字段','值'],*info]), ('测试结果',[['项目','结果'],*rows])])
        test = result.get('signature_test') or result.get('message_test')
        if record.get('kind') == 'security' and test:
            labels = {0: '验签通过', -6: '验签失败'}
            # 旧版记录只有在原始验签通过后才会保存篡改结果。
            rows = [
                ['原始验签', labels.get(test.get('original_return_code', 0), '验签出错')],
                ['修改字节数', test.get('changed_bytes', 1)],
                ['修改后验签', labels.get(result['return_code'], '验签出错')],
            ]
            return workbook([('运行信息',[['字段','值'],*info]), ('测试结果',[['项目','结果'],*rows])])
        return workbook([('运行信息',[['字段','值'],*info]),
                         ('结果',[['字段','值'],*flat(result)])])

    def connect(self,q):
        _,_,target,profile=self.validate(q,live=False)
        if target not in PROVIDER or PROVIDER[target] not in self.live.providers:
            raise ValueError('请先配置设备连接。')
        try:
            with self.lock:
                if target=='ch32v307':
                    self.connect_ch32(profile)
                else:
                    self.live.connect(PROVIDER[target])
        except ProviderError as error:
            if error.code in ('IDENTITY_MISMATCH','NOT_CONFIGURED') and target=='ch32v307':
                raise ValueError('请连接已部署 28 KiB 或 80 KiB 正式固件的 CH32V307。') from None
            if error.code=='IDENTITY_MISMATCH':
                raise ValueError('未识别板上固件。') from None
            message = self.remote_error(error)
            raise ValueError(message if message != '未收到设备结果。' else '连接失败，请检查设备。') from None
        return self.catalog()

    def connect_ch32(self, profile):
        directory=self.root/'03_复现环境与运行程序/firmware/CH32V307/双策略'
        profiles={'28':directory/'low/连接.xml','80':directory/'high/连接.xml'}
        choices=(profile, *(p for p in PROFILES['ch32v307'] if p!=profile))
        if getattr(self.live,'ch32_external_config',False):
            self.live.connect('ch32')
            return
        for choice in choices:
            provider=platform_config.board_provider(profiles[choice],records_directory=self.output/'ch32')
            self.live.providers['ch32']=provider
            self.live.remote_rows.pop('ch32',None)
            try:
                self.live.connect('ch32')
                return
            except ProviderError as error:
                if error.code!='IDENTITY_MISMATCH':
                    raise
        raise ProviderError('IDENTITY_MISMATCH')

    def ensure_stm32_ready(self,profile):
        target='stm32f407'
        provider=self.live.providers.get(target)
        if not provider:
            raise ValueError('当前配置无法运行。')
        if provider.observed_mode()=='cdc' and self.available(target,profile):
            return
        expected_rom=provider.engine.rom_serial
        if not expected_rom:
            raise ValueError('请先连接已登记正式固件的 STM32F407。')
        try:
            self.live.connect(target)
            if not self.available(target,profile) or provider.engine.rom_serial!=expected_rom:
                raise ValueError('STM32 设备或固件档位已变更，请重新连接。')
            if provider.mode=='dfu':
                provider.boot_resident()
        except ProviderError as error:
            raise ValueError(self.remote_error(error)) from None

    def deploy_stm32(self,q):
        profile = q.get('profile')
        if q.get('platform') != 'stm32f407' or profile not in PROFILES['stm32f407']:
            raise ValueError('请选择 STM32 的正式部署配置。')
        from targets.stm32f407.maintenance import DeploymentError

        with self.lock:
            provider = self.live.providers.get('stm32f407')
            if not provider or not provider.can_run_kat():
                raise ValueError('请先连接已登记正式固件的 STM32F407。')
            self.live.remote_rows.pop('stm32f407', None)
            try:
                provider.deploy(profile)
                self.live.connect('stm32f407')
                if not self.available('stm32f407',profile) or provider.mode != 'cdc':
                    raise ValueError('板上固件身份未通过核验，请重新连接 STM32。')
            except DeploymentError as error:
                if error.can_reconnect:
                    try:
                        self.live.connect('stm32f407')
                    except (ProviderError, ValueError):
                        pass
                raise ValueError(str(error)) from None
            except (ProviderError, ValueError) as error:
                self.live.remote_rows.pop('stm32f407', None)
                if isinstance(error, ValueError):
                    raise
                raise ValueError(self.remote_error(error)) from None
        return self.catalog()

    def deploy_ch32(self,q):
        profile=q.get('profile')
        if q.get('platform')!='ch32v307' or profile not in PROFILES['ch32v307']:
            raise ValueError('请选择 CH32 的正式部署配置。')
        controller=getattr(self.live,'ch32_strategy',None)
        if controller is None:
            raise ValueError('已登记设备的部署功能不可用。')
        from demo.ch32_strategy import Ch32UpdateError
        with self.lock:
            try:
                controller.select(self.live,'low' if profile=='28' else 'high')
            except (Ch32UpdateError,ProviderError) as error:
                raise ValueError(self.remote_error(error)) from None
            if not self.available('ch32v307',profile):
                raise ValueError('板上固件身份未通过核验。')
        return self.catalog()

    def remote_run(self, target, profile, parameter, q, mode='normal'):
        if target=='stm32f407':
            self.ensure_stm32_ready(profile)
        row = self.remote_row(target, profile)
        if not self.available(target, profile) or not row:
            raise ValueError('设备未连接。')
        if parameter not in row.get('parameters', ()):
            raise ValueError('当前设备不支持此参数。')
        presets = row['run_presets']
        if mode not in presets['modes']:
            raise ValueError('当前设备不支持这项测试。')
        message = context = 0
        if parameter < 100:
            choices = presets['message_lengths']
            message = q.get('message_bytes', 32 if 32 in choices else choices[0])
            context = q.get('context_bytes', 0)
        if (type(message) is not int or message not in presets['message_lengths']
                or type(context) is not int or context not in presets['context_lengths']):
            raise ValueError('请选择设备支持的消息和上下文大小。')
        raw = self.live.run(dict(library=row['id'],parameter=parameter,mode=mode,
                                 message_bytes=message,context_bytes=context))
        for step in self.remote_steps(raw,parameter):
            if step['return_code'] is not None:
                label = operation_progress(parameter,step['operation'])
                wire.observe_frame(NAMES[target],'RX',b'',
                    f"{label} · 返回码 {step['return_code']}" +
                    (f"，{step['cycles']} 周期" if step['cycles'] is not None else ''))
        return raw

    @staticmethod
    def remote_steps(raw, parameter):
        ops = {row['operation']: row for row in raw['operations']}
        ticks = {row['operation']: row['ticks'] for row in raw.get('device_metrics', {}).get('operations', ())
                 if row['return_code'] != -127}
        family = 'ML-KEM' if parameter > 100 else 'ML-DSA'
        steps = []
        for operation in crypto.OPERATIONS[family]:
            row = ops.get(operation, {})
            code = row.get('return_code')
            if code == -127:
                code = None
            summary = '未执行' if code is None else '成功' if code == 0 else '失败'
            passed = code == 0
            if operation == 'verify' and code is not None:
                summary = '验签通过' if passed else '验签失败' if code == -6 else '验签出错'
            if operation == 'decaps' and passed:
                checks = raw['checks']
                equal = checks.get('shared_secret_equal', checks.get('解封装'))
                passed = equal is True
                summary = 'K = K′' if passed else 'K ≠ K′' if equal is False else '未返回比较结果'
            steps.append(dict(operation=operation, parameter=parameter, return_code=code,
                              summary=summary, verified=passed, cycles=row.get('cycles', ticks.get(operation))))
        return steps

    @staticmethod
    def remote_findings(raw, steps, case):
        def finding(label, value, valid):
            return dict(label=label, value=value, verified=valid)

        if case == 'capacity':
            rejected = raw.get('insufficient_code', (raw['operations'] or [{}])[0].get('return_code')) == -5
            recovered = (raw.get('recovery_code') == 0 and raw['functional_checks_passed']
                         or raw.get('recovery', {}).get('functional_checks_passed') is True)
            return [finding('工作区不足', '已拒绝' if rejected else '检查失败', rejected),
                    finding('恢复后重试', '通过' if recovered else '失败', recovered)]

        ciphertext = case == 'ciphertext'
        op = 'decaps_modified_ciphertext' if ciphertext else 'verify_modified_signature'
        changed = next((row['return_code'] for row in raw['operations'] if row['operation'] == op), None)
        original = steps[-1]
        checks = raw['checks']
        if ciphertext:
            differs = checks.get('implicit_rejection', checks.get('篡改密文隐式拒绝'))
            passed = changed == 0 and differs is True
            value = ('K ≠ K″' if passed else 'K = K″' if differs is False else '未返回比较结果'
                     ) if changed == 0 else '未执行' if changed in (None, -127) else '解封装出错'
        else:
            passed = changed == -6
            value = '验签失败' if passed else '验签通过' if changed == 0 else '未执行' if changed in (None, -127) else '验签出错'
        findings = [finding('原始解封装' if ciphertext else '原始验签',
                            original['summary'], original['verified'])]
        if changed not in (None, -127):
            # The bundled runners flip the first byte before the fourth operation.
            findings.append(finding('修改字节数', '1 字节', None))
        findings.append(finding('修改后解封装' if ciphertext else '修改后验签', value, passed))
        return findings

    @staticmethod
    def remote_error(error):
        from demo.platform_server import ERROR_MESSAGES
        from demo.ch32_strategy import Ch32UpdateError
        if isinstance(error,Ch32UpdateError):
            return str(error)
        messages = {'PORT_BUSY': '端口被占用。', 'busy': '端口被占用。',
                    'MULTIPLE_DEVICES': '检测到多个设备，请只连接一块板。',
                    'IDENTITY_MISMATCH': '请检查设备连接和固件。', 'FIRMWARE_MISSING': '请检查设备连接和固件。',
                    'DEVICE_UNAVAILABLE': '请检查设备连接和固件。', 'TRANSPORT_FAILED': '远端连接失败。',
                    'NOT_CONNECTED': '设备未连接。', 'STM32_USB_MISSING': 'STM32 的 USB 接口未重新出现。请复位开发板后重新连接。'}
        code = getattr(error, 'code', '')
        if isinstance(error, ValueError) and str(error) in (
                '设备未连接。', '当前设备不支持此参数。', '当前设备不支持这项测试。',
                '请选择设备支持的消息和上下文大小。'):
            return str(error)
        message = messages.get(code, ERROR_MESSAGES.get(code, '未收到设备结果。'))
        return '设备响应超时。' if '超时' in message else message

    @staticmethod
    def start_security_log(record, report):
        entries = []
        def update(message):
            entries.append(message)
            report(message)
        platform, profile = record['platform'], record['profile']
        configuration = {'low-memory': '低内存', 'performance': '高性能'}.get(profile, f'{profile} KiB')
        update(f"{NAMES[platform]} · {configuration} · {parameter_name(record['parameter'])} · {record['operation']}")
        return update, entries

    def finish_security(self, record, result, report, entries):
        for message in security_checks.result_log(result):
            report(message)
        status = '检查通过' if result['verified'] else '检查失败'
        summary = result.get('summary')
        report(f"结论 · {status}" + (f' · {summary}' if summary and summary != status else ''))
        return self.finish(record, result | {'log': entries})

    def run_remote_test(self, q, target, profile, parameter, report):
        case = q.get('test')
        if case is not None and case not in ('capacity', 'ciphertext' if parameter > 100 else 'signature'):
            raise ValueError('当前参数不支持这项测试。')
        if target == self.local_platform or target not in PROVIDER:
            raise ValueError('请选择远端平台。')
        title = REMOTE_TESTS[case] if case else '完整流程'
        record = self.prepare_record(q, title, kind='security' if case else 'board-suite')
        if case:
            report, entries = self.start_security_log(record, report)
        with self.lock:
            try:
                report(f'正在请求 {NAMES[target]} 运行')
                raw = self.remote_run(target, profile, parameter, q, 'insufficient' if case == 'capacity' else 'normal')
                steps = self.remote_steps(raw, parameter)
                if not case:
                    report_remote_steps(steps,report)
                findings = self.remote_findings(raw, steps, case) if case else []
                verified = all(row['verified'] is not False for row in findings) if case else all(row['verified'] for row in steps)
                result = dict(verified=verified, raw_response=raw, steps=steps if not case else [], findings=findings,
                              summary='检查通过' if verified else '检查失败',
                              build_id=raw.get('binary_sha256') or raw.get('build_tag'))
            except (ValueError, OSError, KeyError, RuntimeError) as error:
                result = dict(verified=False, status='未完成', summary=self.remote_error(error))
            if case:
                result['remote_test'] = case
                if case == 'capacity' and 'raw_response' in result:
                    normal = raw['workspace_bytes']
                    limited = raw.get('test_workspace_bytes')
                    if limited is None and raw.get('recovery'):
                        limited, normal = normal, raw['recovery']['workspace_bytes']
                    if limited is not None:
                        result['security_input'] = crypto.security_input('workspace_bytes', normal, limited, source='firmware')
                    result.update(return_code=raw.get('insufficient_code', raw['operations'][0]['return_code']),
                                  expected_return_code=-5, function='lc_keypair',
                                  recovery_return_code=raw.get('recovery_code'),
                                  checks={'failure_output_zero': raw.get('failure_output_zero')},
                                  canaries_ok=raw.get('canaries_ok'),
                                  workspace_used_bytes=raw.get('observed_arena_high_water_bytes'))
                elif 'raw_response' in result:
                    modified = 'decaps_modified_ciphertext' if case == 'ciphertext' else 'verify_modified_signature'
                    operation = next((step for step in raw['operations'] if step['operation'] == modified), {})
                    result.update(original_return_code=steps[-1]['return_code'],
                                  return_code=operation.get('return_code'), expected_return_code=wire.SECURITY_CODES[case],
                                  function='lc_decaps' if case == 'ciphertext' else 'lc_verify')
                return self.finish_security(record, result, report, entries)
            return self.finish(record, result)

    def run_remote_security(self, q, target, profile, parameter, report):
        case = q.get('case')
        if case not in wire.security_cases(parameter):
            raise ValueError('当前参数不支持这项测试。')
        row = self.remote_row(target, profile)
        provider = self.live.providers[PROVIDER[target]]
        remote_runner = target == 'arm' and provider.capabilities.get(row['id'], {}).get('security_checks') is True
        legacy = case in ('ciphertext', 'signature') or case == 'capacity' and 'insufficient' in row['run_presets']['modes']
        board_inputs = target in ('stm32f407', 'ch32v307') and case in security_checks.BOARD_CASES
        if not remote_runner and legacy and (not board_inputs or target == 'stm32f407' and case == 'capacity'):
            return self.run_remote_test(q | {'test': case}, target, profile, parameter, report)

        expected = wire.SECURITY_CODES[case]
        record = self.prepare_record(q, REMOTE_TESTS[case], kind='security')
        report, entries = self.start_security_log(record, report)
        with self.lock:
            try:
                self.validate(q)
                report(f'正在请求 {NAMES[target]} 执行{REMOTE_TESTS[case]}')
                if remote_runner:
                    reply = provider.run_security(row['id'], parameter, case)
                    code = reply['return_code']
                    findings = [security_checks.finding('实际返回码', '未执行' if code is None else code, code == expected)]
                    for key, label in (('failure_output_zero', '失败输出清零'), ('recovered', '恢复后重试')):
                        if reply[key] is not None:
                            findings.append(security_checks.finding(label, '通过' if reply[key] else '失败', reply[key]))
                    result = dict(verified=reply['verified'], findings=findings, return_code=code,
                                  expected_return_code=expected, build_id=reply['binary_sha256'],
                                  **{key: reply[key] for key in ('security_input', 'original_return_code',
                                      'recovery_return_code', 'function') if key in reply})
                elif board_inputs:
                    if target == 'stm32f407' and case == 'capacity':
                        raise ValueError('当前固件未提供工作区不足测试。')
                    result = security_checks.board_check(self, target, profile, parameter, case, expected, report)
                    result['build_id'] = row.get('binary_sha256')
                else:
                    raise ValueError('请更新 Linux 端运行程序后重试。')
                result['summary'] = '检查通过' if result['verified'] else '检查失败'
            except (ValueError, OSError, KeyError, RuntimeError, StopIteration) as error:
                result = dict(verified=False, status='未完成',
                              summary=str(error) if isinstance(error, ValueError) else self.remote_error(error))
            return self.finish_security(record, result | dict(remote_test=case), report, entries)

    def act(self,action,q,*,report=ignore_progress):
        family,p,t,profile=self.validate(q,allow_stm32_dfu=action=='arithmetic')
        if action == 'board-suite':
            return self.run_remote_test(q, t, profile, p, report)
        if action == 'security' and t != self.local_platform:
            return self.run_remote_security(q, t, profile, p, report)
        if action == 'arithmetic' and t == 'arm':
            record = self.prepare_record(q,q.get('operation'),kind='arithmetic')
            try:
                exchange = None
                with self.lock:
                    if self.local_platform != 'arm':
                        provider = self.live.providers['arm']
                        row = self.remote_row('arm',profile)
                        if provider.capabilities[row['id']].get('arithmetic_sha256') != arithmetic.arm_build_hash():
                            raise ValueError('当前 Linux 软件未启用此算术模块。')
                        if q['operation'] in arithmetic.POLYNOMIAL:
                            exchange = provider.run_arithmetic
                        elif provider.capabilities[row['id']].get('primitive_sha256') == arithmetic.primitive_digest():
                            exchange = provider.run_primitive
                        else:
                            raise ValueError('当前 Linux 端运行程序未启用采样与编解码。')
                    run = arithmetic.execute_linux if q['operation'] in arithmetic.POLYNOMIAL else arithmetic.execute_primitive
                    result = run(q,exchange,report=report)
            except (ValueError,OSError,KeyError,RuntimeError) as error:
                result = dict(verified=False,status='未完成',summary=self.remote_error(error))
            return self.finish(record,result)
        if action == 'arithmetic' and t in ('stm32f407','ch32v307'):
            record=self.prepare_record(q,q.get('operation'),kind='arithmetic')
            try:
                with self.lock:
                    self.validate(q,allow_stm32_dfu=True)
                    report(f'已连接 {NAMES[t]}（{profile} KiB）')
                    if t=='stm32f407':
                        driver = self.live.providers[t].run_ring
                    else:
                        def driver(a,b,modulus,*,report,operation):
                            return self.live.ch32_strategy.run_ring(profile,a,b,modulus,report=report,operation=operation)
                    if q['operation'] in (*arithmetic.POLYNOMIAL,'reduce'):
                        result=arithmetic.execute_board(q,driver,report=report)
                    else:
                        if t=='stm32f407':
                            binding=self.live.providers[t].run_primitive
                        else:
                            def binding(packet,**kwargs):
                                return self.live.ch32_strategy.run_primitive(profile,packet,**kwargs)
                        result=arithmetic.execute_primitive(q,binding,report=report)
                    size = (f"{len(result['output'])} 个系数" if 'output' in result
                            else f"{len(result['output_hex'])//2} 字节")
                    wire.observe_frame(NAMES[t],'RX',b'',f"{result['cycles']} 周期 · {size}")
                    wire.observe_frame('本机','HOST',b'',result['summary'])
                    if t=='ch32v307':
                        self.connect_ch32(profile)
            except (ValueError,OSError,KeyError,RuntimeError) as error:
                result=dict(verified=False,status='未完成',
                            summary=str(error) if isinstance(error,ValueError) else self.remote_error(error))
            return self.finish(record,result)
        rec=self.prepare_record(q,q.get('operation',action),kind=action)
        if action == 'security':
            rec['operation'] = REMOTE_TESTS.get(q.get('case'), '安全检查')
            report, entries = self.start_security_log(rec, report)
        with self.lock:
            if action == 'security':
                self.clear_modified_secret()
            try:
                if t!=self.local_platform: raise ValueError('当前设备不支持这项操作。')
                desc=self.current.descriptors[profile]
                lib,cap=self.current.libs[profile],desc['workspace_bytes']
                if action=='crypto':
                    op=q.get('operation')
                    if op=='keygen':
                        obj=crypto.Objects(lib,profile,p)
                        self.register_objects(obj)
                    else:
                        obj=self.current_object(q,profile,p)
                    report(f'{operation_progress(p,op)} · 正在执行')
                    result=crypto.operation(lib,cap,obj,op,*crypto.message_bytes(q))
                    result['library'] = Path(lib._name).name
                    if result['verified']:
                        if op=='keygen': obj.key_record=rec['request_id']
                        if op in ('sign','encaps'): obj.payload_record=rec['request_id']
                        if op in ('verify','decaps'): obj.check_record=rec['request_id']
                    result['materials'] = obj.state()
                elif action=='security':
                    case=q.get('case')
                    ref=q.get('object_ref')
                    current=self.objects.get(ref) if case in ('ciphertext','message','signature') and isinstance(ref,str) else None
                    if current is not None and (current.profile,current.parameter)!=(profile,p):
                        current=None
                    output = self.modified_secret if case == 'ciphertext' else None
                    result=crypto.security(lib,cap,profile,p,case,current,modified_secret=output,report=report)
                elif action=='onboarding':
                    if self.sessions is None: raise ValueError('当前平台只有接入记录。')
                    result=onboarding.run(self.sessions,q,report=report)
                    rec.update(algorithm='ML-KEM / ML-DSA',parameter=f"{q['kem']} / {q['dsa']}",profile='设备接入')
                elif action=='arithmetic':
                    result=arithmetic.execute(self.root,q,report=report)
                    rec['profile']='算术测试'
                else:
                    raise ValueError('操作无效')
            except (ValueError, OSError, KeyError, RuntimeError) as error:
                result=dict(verified=False,status='未完成',summary=str(error))
            if action != 'security':
                return self.finish(rec,result)
            test = result.get('ciphertext_test')
            can_show = test and result['return_code'] == 0 and result['canaries_ok'] and result['used_workspace_erased']
            try:
                if can_show:
                    test['modified_secret_available'] = True
                completed = self.finish_security(rec,result,report,entries)
                if can_show:
                    self.modified_secret_ref = (rec['request_id'], profile, p)
                return completed
            finally:
                if self.modified_secret_ref is None:
                    self.clear_modified_secret()

    def case_list(self,q):
        _,p,t,_=self.validate(q,live=False)
        if t!=self.local_platform: raise ValueError('当前设备不支持这项测试。')
        return list(vectors.corpus(self.source,q.get('suite'),p))

    def run_board_vectors(self, q, *, report=ignore_progress):
        _, parameter, target, profile = self.validate(q)
        if target not in ('stm32f407','ch32v307','arm','windows'):
            raise ValueError('当前固件无法运行标准测试向量。')
        all_cases=q.get('all_cases') is True
        case_id=q.get('case_id')
        parameters=[512,768,1024,44,65,87] if all_cases else [parameter]
        cases=[case for p in parameters for case in vectors.board_cases(self.root,p)]
        if len(cases)!=(21 if all_cases else 3 if parameter>100 else 4):
            raise ValueError('板上用例清单不完整。')
        if case_id is not None:
            if all_cases:
                raise ValueError('请选择支持的测试范围。')
            cases=[case for case in cases if vectors.board_case_id(case)==case_id]
            if not cases:
                raise ValueError('用例不存在。')
        record = self.prepare_record(q, ACVP_TEST, kind='vectors')
        if all_cases:
            record.update(algorithm='ML-KEM / ML-DSA',parameter='6 组')
        total = len(cases)
        done = 0

        def on_start(index,parameter,operation,tc):
            report(vector_log_line(index,total,parameter,operation,tc,'正在执行'))

        def on_result(row):
            nonlocal done
            done += 1
            report(vector_result_log(done,total,row))
        try:
            with self.lock:
                self.validate(q)
                if target=='stm32f407':
                    rows,details=self.stm32_vectors(cases,report,on_start,on_result)
                elif target=='ch32v307':
                    rows,details=self.ch32_vectors(profile,cases,report,on_start,on_result)
                else:
                    ids=[[case['parameter'],vectors.board_case_id(case)] for case in cases]
                    if target==self.local_platform:
                        image=self.current.descriptors[profile]
                        result=vectors.execute_acvp(self.current.libs[profile],image['workspace_bytes'],
                                                    self.source,self.root,ids,image['binary_sha256'],
                                                    on_start=on_start,on_result=on_result)
                    else:
                        row=self.remote_row(target,profile)
                        report(f"正在请求 Linux 主机执行 {total} 条 ACVP 用例 · {'、'.join(map(parameter_name,parameters))}")
                        result=self.live.providers['arm'].run_acvp(row['id'],ids)
                    rows,details=result['rows'],result['details']
                    if target!=self.local_platform:
                        for row in rows:
                            on_result(row)
            passed = sum(row['verified'] for row in rows)
            report(f'已执行 {len(rows)}/{total} · 通过 {passed} · 失败 {len(rows)-passed}')
            result = dict(rows=rows,vector_details=details,total=total,executed=len(rows),passed=passed,
                          failed=len(rows)-passed,verified=passed==len(cases))
        except (ValueError,OSError,KeyError,RuntimeError) as error:
            result = dict(verified=False,status='未完成',summary=self.remote_error(error))
        return self.finish(record, result|dict(suite='acvp',board_vectors=True))

    def ch32_vectors(self,profile,cases,report,on_start,on_result):
        controller = self.live.ch32_strategy
        ids = [(case['parameter'],case['operation'],case['tcId']) for case in cases]
        rows, details = [], {}

        def start(index):
            parameter,operation,tc = ids[index]
            family = 'ML-KEM' if parameter > 100 else 'ML-DSA'
            on_start(index+1,parameter,crypto.OPERATIONS[family][operation],tc)

        def receive(index,reply,actual):
            row,detail = vectors.ch32_live_case(self.source,cases[index],reply,actual,profile)
            rows.append(row)
            details[row['case_id']] = detail
            on_result(row)
            if len(rows) == len(cases):
                report('用例已跑完，正在恢复板端连接')

        report('正在准备 CH32V307 板上测试')
        controller.run_acvp(profile,ids,on_start=start,on_reply=receive)
        self.connect_ch32(profile)
        return rows,details

    def stm32_vectors(self,cases,report,on_start,on_result):
        provider = self.live.providers['stm32f407']
        values = [vectors.board_case_data(self.source,case) for case in cases]
        items = []
        for case,(inputs,_) in zip(cases,values):
            fields = {field: bytes.fromhex(value) for field,value in inputs.items()}
            fields['coins'] = fields.pop('seed', fields.pop('randomness', b''))
            items.append((case['parameter'],case['operation'],case['tcId'],fields))
        rows, details = [], {}

        def start(index, parameter, operation, tc):
            family = 'ML-KEM' if parameter > 100 else 'ML-DSA'
            on_start(index+1,parameter,crypto.OPERATIONS[family][operation],tc)

        def receive(index, reply, output):
            case = cases[index]
            inputs, expected = values[index]
            code = struct.unpack('<i',struct.pack('<I',reply[24]))[0]
            comparisons = [dict(field=field,expected=value,actual=data.hex())
                           for (field,value),data in zip(expected.items(),output)]
            checks = {item['field']: item['actual'] == item['expected'].lower() for item in comparisons}
            lengths_ok = tuple(map(len,output)) == tuple(
                ([len(value)//2 for value in expected.values()]+[0,0])[:2])
            passed = (lengths_ok and all(checks.values()) and code == (0 if case['accepted'] else -6)
                      and reply[28] == 1 and reply[30] == 0 and reply[31] == 1)
            row = vectors.board_result_row(case,inputs,expected,code,passed,checks,
                        canaries_ok=bool(reply[28]),workspace_used_bytes=reply[29],
                        cycles=reply[32],used_workspace_erased=bool(reply[33]))
            rows.append(row)
            details[row['case_id']] = dict(inputs=inputs,outputs=comparisons)
            on_result(row)

        provider.run_acvp_bytes(items,report=report,on_start=start,on_reply=receive)
        return rows,details

    def board_archive(self, q):
        _, parameter, target, _ = self.validate(q,live=False)
        profile = q.get('archive')
        if target == 'stm32f407':
            rows = vectors.stm32_archive(self.root, parameter, profile)
            return dict(rows=rows,passed=sum(all(row['checks']) for row in rows))
        if target != 'ch32v307' or profile not in ('低内存','高性能'):
            raise ValueError('请选择开发板的历史记录。')
        cases = vectors.board_cases(self.root, parameter, role=profile)
        rows = [vectors.ch32_case(self.root,self.source,profile,case)[0] for case in cases]
        return dict(rows=rows,passed=sum(row['verified'] for row in rows))

    def board_case_detail(self, q):
        case_id = q.get('case_id')
        if q.get('request_id'):
            rec = self.get_record(q['request_id'])
            if not rec['result'].get('board_vectors') or not any(
                    row['case_id'] == case_id for row in rec['result'].get('rows', [])):
                raise ValueError('用例不存在。')
            saved=rec['result'].get('vector_details',{})
            if case_id in saved:
                return saved[case_id]
            case = next((info for info in vectors.board_cases(self.root,rec['parameter'])
                         if vectors.board_case_id(info)==case_id),None)
            if case is not None:
                inputs, outputs = vectors.board_case_data(self.source,case)
                return {'inputs':inputs,'outputs':[dict(field=field,expected=value) for field,value in outputs.items()]}
        else:
            _, parameter, target, _ = self.validate(q,live=False)
            role = q.get('archive')
            if target == 'ch32v307' and role in ('低内存','高性能'):
                case = next((info for info in vectors.board_cases(self.root,parameter,role)
                             if vectors.board_case_id(info)==case_id),None)
                if case is not None:
                    return vectors.ch32_case(self.root,self.source,role,case)[1]
        raise ValueError('用例不存在。')

    def vector_inputs(self, q):
        ident, case = q.get('request_id'), q.get('case_id')
        if not isinstance(ident, str) or not isinstance(case, str):
            raise ValueError('用例不存在。')
        with self.jobs_lock:
            job = self.jobs.get(ident)
            captured = job.get('vector_inputs', {}).get(case) if job and job['result'] is not None else None
        if captured is None:
            raise ValueError('该用例的输入已不可用。')
        inputs = {field: value.hex() for field,value in captured['inputs'].items()}
        if not q.get('include_outputs'):
            return inputs
        return {'inputs': inputs, 'outputs': [{'field':field,'actual':actual.hex(),'expected':expected.hex()}
                                              for field,actual,expected in captured['outputs']]}

    def start_job(self,q):
        family,p,t,profile=self.validate(q)
        remote = t != self.local_platform
        mode=q.get('mode')
        if mode not in ('all','parameter','vectors','performance'): raise ValueError('批量操作无效')
        if remote and mode not in ('all','performance'):
            raise ValueError('当前设备不支持这项测试。')
        if mode=='vectors':
            cases=vectors.corpus(self.source,q.get('suite'),p)
            keys=list(cases) if q.get('case_id')=='all' else [q.get('case_id')]
            if not keys or any(k not in cases for k in keys): raise ValueError('测试用例不存在')
            plan=[(p,k) for k in keys]
        else:
            cases={}
            params=[n for ns in crypto.PARAMETERS.values() for n in ns] if mode in ('all','performance') else [p]
            plan=[(n,op) for n in params for op in crypto.OPERATIONS['ML-KEM' if n>100 else 'ML-DSA']]
        record=self.prepare_record(q,'标准测试向量' if mode=='vectors' else '全部 18 项' if mode=='all' else '完整流程',kind='vectors' if mode=='vectors' else 'crypto')
        if mode=='performance':
            record=self.prepare_record(q,PERFORMANCE_BATCH,kind='performance')
        if mode in ('all','performance'):
            record.update(algorithm='ML-KEM / ML-DSA',parameter='6 组')
        ident=record['request_id']
        with self.jobs_lock:
            if any(x['state']=='运行中' for x in self.jobs.values()): raise ValueError('已有批量任务正在运行')
            job=dict(state='运行中',cancel=threading.Event(),rows=[],plan=plan,current=None,result=None,log=deque(maxlen=64))
            if mode=='vectors': job['vector_inputs']={}
            if remote: job['traffic']=wire.Traffic()
            self.jobs[ident]=job
            if len(self.jobs)>8: self.jobs.pop(next(iter(self.jobs)))
        def worker():
            if mode=='performance':
                self.run_performance_job(job,record,q,t,profile)
                return
            if remote:
                wire.RUN_TRAFFIC.set(job['traffic'])
            objects={}
            retained = None
            try:
                if not remote:
                    lib,cap=self.current.libs[profile],self.current.descriptors[profile]['workspace_bytes']
                    message,context=crypto.message_bytes(q)
                for param,label in plan:
                    if job['cancel'].is_set(): break
                    if remote:
                        if label != 'keygen':
                            continue
                        job['current']=[param,'完整流程']
                        family = 'ML-KEM' if param > 100 else 'ML-DSA'
                        job['log'].append(f'{family}-{param} 完整流程 · 等待设备应答')
                        try:
                            with self.lock:
                                raw = self.remote_run(t, profile, param, q)
                        except (ValueError, OSError, KeyError, RuntimeError) as error:
                            job['summary'] = self.remote_error(error)
                            break
                        steps = self.remote_steps(raw,param)
                        report_remote_steps(steps,job['log'].append,len(job['rows']))
                        job['rows'].extend(steps)
                        continue
                    job['current']=[param,label]
                    if mode!='vectors':
                        index = len(job['rows']) + 1
                        label_text = operation_progress(param,label)
                        step_text = f'{index}/{len(plan)} {label_text}' if mode=='all' else label_text
                        job['log'].append(f'{step_text} · 正在执行')
                    begin=crypto.now()
                    try:
                        if mode=='vectors':
                            captured={'inputs':{},'outputs':[]}
                            def start(operation,tc):
                                job['log'].append(vector_log_line(len(job['rows'])+1,len(plan),param,operation,tc,'正在执行'))
                            row=vectors.run_case(lib,cap,param,q['suite'],cases[label],self.root,captured=captured,on_start=start)
                            job['vector_inputs'][label]=captured
                            row.update(started_at=begin,finished_at=crypto.now())
                        else:
                            if label=='keygen': objects[param]=crypto.Objects(lib,profile,param)
                            obj = objects[param]
                            row=crypto.operation(lib,cap,obj,label,message,context,detail=mode=='parameter')
                            row['library'] = Path(lib._name).name
                    except (ValueError,OSError,KeyError) as error:
                        row=dict(verified=False,summary=str(error),started_at=begin,finished_at=crypto.now())
                    if mode=='vectors':
                        row['case_id'] = label
                        row.setdefault('tc_id',cases[label][2]['tcId'])
                    job['rows'].append(row|{'parameter':param,'operation':label})
                    if mode=='vectors':
                        job['log'].append(vector_result_log(len(job['rows']),len(plan),job['rows'][-1]))
                    else:
                        if not row['verified']:
                            outcome = '失败'
                        elif label=='decaps':
                            outcome = 'K = K′'
                        elif label=='verify':
                            outcome = '验签通过'
                        else:
                            outcome = '通过'
                        job['log'].append(f'{step_text} · {outcome}')
                rows=job['rows']; done=len(rows); passed=sum(r['verified'] for r in rows)
                executed=sum(row['return_code'] is not None for row in rows) if remote else done
                cancelled=done<len(plan) and job['cancel'].is_set()
                result=dict(verified=not cancelled and passed==len(plan),rows=rows,
                            status='已取消' if cancelled else '检查通过' if passed==len(plan) else '检查失败',
                            total=len(plan),executed=executed,passed=passed,failed=executed-passed,
                            not_executed=[list(item) for item in plan[done:]],suite=q.get('suite'))
                if remote:
                    result.update(remote_batch=True, summary=job.get('summary'))
                if mode == 'parameter' and result['verified']:
                    retained = objects[p]
                    retained.key_record = retained.payload_record = retained.check_record = ident
                    result['materials'] = retained.state()
            except Exception as error:
                result=dict(verified=False,status='未完成',summary=str(error),rows=job['rows'],
                            not_executed=[list(item) for item in plan[len(job['rows']):]])
            finally:
                for obj in objects.values():
                    if obj is not retained:
                        obj.close()
            try:
                completed = self.finish(record,result)
            except (OSError, ValueError):
                if retained:
                    retained.close()
                completed = record | {'verification': False, 'status': '检查失败',
                                      'result': {'verified': False, 'summary': '未能保存运行记录。'}}
                retained = None
                result = completed['result'] | {'status': completed['status']}
            if retained:
                with self.lock:
                    self.register_objects(retained)
            job['result']=completed
            job['state']=result['status']
            job['current']=None
        threading.Thread(target=worker,name='workbench-case-runner',daemon=True).start()
        return {'request_id':ident}

    def job(self,ident,stop=False):
        job=self.jobs.get(ident)
        if job is None: raise ValueError('批量任务不存在')
        if stop: job['cancel'].set()
        rows = job['rows'][:]
        return dict(state=job['state'],done=len(rows),total=len(job['plan']),current=job['current'],
                    passed=sum(r['verified'] for r in rows),log=list(job['log'].copy()),
                    rows=[(r['parameter'],r['operation'],r['verified']) for r in rows[-18:]],result=job['result'])
