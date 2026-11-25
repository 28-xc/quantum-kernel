"""A single UI over the existing local application and explicit live providers."""
from pathlib import Path
import copy
import hashlib
import secrets
from urllib.parse import urlsplit

from demo import platform_protocol as wire
from demo.f407_provider import F407Provider, HISTORY, _history_identity, MEMORY_FIELDS, read_history, read_memory
from demo.platform_providers import LocalProvider, ProviderError

LABELS = {'windows': 'Windows', 'arm': 'Linux AArch64', 'ch32': 'CH32V307', 'stm32f407': 'STM32F407'}
ERROR_MESSAGES = {
    'NOT_CONFIGURED': '未配置设备连接。',
    'FIRMWARE_MISSING': '固件或运行依赖缺失。',
    'IDENTITY_MISMATCH': '固件身份或请求编号不匹配。',
    'INVALID_REQUEST': '参数或输入长度超出设备支持范围。',
    'BAD_RESPONSE': '设备返回格式无效。',
    'PORT_BUSY': 'USB 接口被占用。请断开 CubeProgrammer 的连接。',
    'MULTIPLE_DEVICES': '检测到多块开发板，请只连接一块。',
    'TIMEOUT': '设备响应超时。',
    'DISCONNECTED': '开发板已断开。',
    'DEVICE_NOT_FOUND': '未检测到开发板。',
    'no_device': '未检测到 STM32F407。',
    'ambiguous': '检测到多块开发板，请只连接一块。',
    'busy': 'USB 接口被占用。请断开 CubeProgrammer 的连接。',
    'transport': 'USB 通信中断。',
    'image_missing': '所选固件缺失。',
    'image_invalid': '固件未通过校验。',
    'identity': '设备身份或请求编号不匹配。',
    'protocol': '设备回复格式不符。',
    'timeout': '开发板响应超时。',
    'invalid_request': '测试输入超出设备支持范围。',
    'NOT_CONNECTED': '设备尚未连接，请先连接所选平台。',
    'BUSY': '设备正在执行，请等待当前操作结束。',
    'DEVICE_UNAVAILABLE': '开发板暂不可用。请检查连接或接口占用。',
    'CH32_HANDSHAKE': 'CH32V307 未完成串口握手。请检查 WCH-Link 数据线、板卡供电和串口占用，再点击连接。本次密码操作尚未发送。',
    'CH32_RESPONSE': 'CH32V307 的串口应答未通过校验，本次结果未确认。请检查连接后重新连接板卡。软件不会自动重发密码操作。',
    'TRANSPORT_TIMEOUT': '设备响应超时，本次未完成，未自动重发。',
    'TRANSPORT_FAILED': 'ARM 连接未完成，请检查网络、主机指纹和外部连接配置。',
}


def row_platform(row):
    p = row.get('platform', '')
    return 'arm' if 'aarch64' in p else 'ch32' if 'ch32' in p else 'windows'


class UnifiedApplication:
    def __init__(self, base, providers=None, *, f407=None):
        self.base = base
        self.providers = dict(providers or {})
        if f407 is not None:
            self.providers['stm32f407'] = f407
        wire.require(set(self.providers) <= {'arm', 'ch32', 'stm32f407'}, 'Unknown injected platform')
        self.local = LocalProvider(base)
        self.remote_rows = {}
        self.runs = base.runs

    def __getattr__(self, name):
        return getattr(self.base, name)

    def representative_history(self,board=None):
        from demo.board_representatives import snapshot
        return snapshot(self.providers['stm32f407'].package,board)

    def f407_history(self):
        provider = self.providers.get('stm32f407')
        folder = provider.package / HISTORY.parent if provider else None
        result = {'source': '历史实板测量', 'rows': [], 'memory': {}, 'errors': {},
                  'raw_available': bool(folder and (folder / 'transactions.tsv').is_file())}
        for key, reader in (('rows', read_history), ('memory', read_memory)):
            try:
                result[key] = reader(provider.package) if provider else []
            except (ValueError, OSError, TypeError, KeyError):
                result[key] = []
                result['errors'][key] = '历史数据读取失败'
        return result

    def f407_packet(self, ident):
        if not wire.REQUEST_ID.fullmatch(ident):
            return None
        observation = self.runs.get(ident, {})
        provider = self.providers.get('stm32f407')
        if (not provider or not provider.records_directory or
                observation.get('kind') != 'stm32f407_live_observation'):
            return None
        name = observation.get('response_file')
        if not name or name != observation['request_id'] + '.bin' or not wire.REQUEST_ID.fullmatch(observation['request_id']):
            return None
        path = provider.records_directory / name
        if not path.is_file():
            return None
        data = path.read_bytes()
        if len(data) != 256 or hashlib.sha256(data).hexdigest() != observation['response_sha256']:
            raise ValueError('Original board reply has changed')
        return data

    def platform_catalog(self):
        return {'schema': 'lattice.platform_catalog.v1', 'platforms': [
            {'id': name, 'title': title, 'configured': name == 'windows' or name in self.providers,
             'mode': self.providers[name].observed_mode() if name == 'stm32f407' and name in self.providers else None,
             'state': 'connected' if name == 'windows' else self.providers[name].state if name in self.providers else 'disconnected'}
            for name, title in LABELS.items() if name != 'stm32f407' or name in self.providers]}

    def connect(self, platform_id, *, restored_original_elf=None):
        wire.require(platform_id in LABELS, 'Unknown platform')
        if platform_id == 'windows':
            return self.platform_catalog()
        if platform_id not in self.providers:
            raise ProviderError('NOT_CONFIGURED')
        provider = self.providers[platform_id]
        try:
            catalog = provider.catalog()
        except Exception:
            if provider.state == 'disconnected':
                self.remote_rows.pop(platform_id, None)
            raise
        from demo.board_representatives import catalog_rows
        choices=self.representative_history('ch32')['deployments'] if 'stm32f407' in self.providers else []
        original={r['id']:r for r in catalog_rows([dict(r,platform_id=row_platform(r)) for r in self.base.catalog()['libraries']],choices)}
        eligible={('ch32-finals-'+v['role'],v['elf_sha256']) for v in choices}
        if restored_original_elf is not None:
            owner=getattr(self,'ch32_strategy',None)
            wire.require(platform_id=='ch32' and owner is not None and restored_original_elf==owner.index['original_elf_sha256'], 'Unknown original device image')
            eligible={('ch32-partial64',restored_original_elf)}
        if platform_id=='ch32' and (not catalog['libraries'] or any((r.get('id'),r.get('binary_sha256')) not in eligible for r in catalog['libraries'])):
            self.remote_rows.pop('ch32',None)
            provider.state='disconnected'
            provider.capabilities={}
            raise ProviderError('NOT_CONFIGURED')
        try:
            for row in catalog['libraries']:
                if row['id'] in original:
                    wire.require(row_platform(original[row['id']]) == platform_id, 'Library ID collides with another platform')
                    # Archive-to-live association is explicit; do not silently replace an image.
                    known = original[row['id']]
                    wire.require(row['binary_sha256'] in (known['binary_sha256'], known.get('measured_binary_sha256')),
                                 'Live image has no identity correspondence to this archived library')
                for other, rows in self.remote_rows.items():
                    wire.require(other == platform_id or all(x['id'] != row['id'] for x in rows), 'Duplicate live library ID')
        except (ValueError, KeyError, TypeError):
            provider.state = 'disconnected'
            provider.capabilities = {}
            self.remote_rows.pop(platform_id, None)
            raise
        self.remote_rows[platform_id] = copy.deepcopy(catalog['libraries'])
        return self.platform_catalog()

    def catalog(self):
        catalog = copy.deepcopy(self.base.catalog())
        original = {row['id']: row for row in catalog['libraries']}
        for row in original.values():
            name = row_platform(row)
            row['platform_id'] = name
            row['run_presets'] = dict(message_lengths=[0,32,1024,16384], context_lengths=[0,1,255], modes=['normal','insufficient'])
            if name != 'windows':
                row.update(execution_available=False, execution_reason='未连接')
        for name, rows in self.remote_rows.items():
            provider = self.providers[name]
            for entry in rows:
                row = copy.deepcopy(original.get(entry['id'], {}))
                row.update(entry)
                row.update(platform_id=name, execution_available=provider.state == 'connected' and entry['execution_available'],
                           execution_reason='' if provider.state == 'connected' else '未连接')
                row.setdefault('title', LABELS[name])
                row.setdefault('configuration', entry['id'])
                row.setdefault('platform', 'ch32v307' if name == 'ch32' else 'linux_aarch64')
                original[entry['id']] = row
        from demo.board_representatives import catalog_rows
        registered=self.representative_history('ch32')['deployments'] if 'stm32f407' in self.providers else []
        catalog['libraries'] = catalog_rows(list(original.values()),registered)
        # This current original can run a recovery check. Performance and resource history still have two registered deployments.
        owner=getattr(self,'ch32_strategy',None)
        if owner and any(row.get('id')=='ch32-partial64' and row.get('binary_sha256')==owner.index['original_elf_sha256'] for row in self.remote_rows.get('ch32',())):
            catalog['libraries'].append(original['ch32-partial64'])
        return catalog

    def run(self, value):
        is_f407 = isinstance(value, dict) and isinstance(value.get('library'), str) and value['library'].startswith(F407Provider.prefix)
        if is_f407 and 'stm32f407' not in self.providers:
            raise ProviderError('NOT_CONFIGURED')
        if not is_f407:
            wire.run_request(value)
        for platform_id, rows in tuple(self.remote_rows.items()):
            if any(row['id'] == value['library'] for row in rows):
                if platform_id=='ch32' and getattr(self,'ch32_strategy',None):
                    with self.ch32_strategy.transaction():
                        result=self.providers[platform_id].run(value)
                        self.ch32_strategy.annotate(value,result)
                else:
                    result = self.providers[platform_id].run(value)
                # Retain the original device run ID; the local export key must be unique.
                result['run_id'] = secrets.token_hex(16)
                self.runs[result['run_id']] = result
                if len(self.runs) > 100:
                    self.runs.pop(next(iter(self.runs)))
                return result
        if is_f407:
            raise ProviderError('NOT_CONNECTED')
        if value['library'] in self.base.descriptors and row_platform(self.base.descriptors[value['library']]) == 'windows':
            result = self.local.run(value)
            self.runs[result['run_id']] = result
            return result
        raise ProviderError('NOT_CONNECTED')

    def public_results(self, library=None):
        if library is not None and library not in self.base.descriptors:
            wire.require(any(any(x['id'] == library for x in rows) for rows in self.remote_rows.values()), 'Unknown live library')
            return {'schema': 'lattice.technical_result_catalog.v1', 'views': []}
        return self.base.public_results(library)


def handler(base_module, app, address):
    class Handler(base_module.handler(app, address)):
        def do_GET(self):
            if not self.valid_host():
                return self.send(403, {'error': '仅接受本地访问'})
            url = urlsplit(self.path)
            if url.path == '/' and not url.query:
                page = (Path(__file__).parent/'index.html').read_text(encoding='utf8')
                bar = '<div class="platform-controls"><label>执行平台<select id="live-platform"><option value="windows">Windows 本机</option><option value="arm">Linux AArch64 设备</option><option value="ch32">CH32V307 开发板</option><option value="stm32f407">STM32F407 开发板</option></select></label><span id="live-state" aria-live="polite">未连接</span><button id="live-connect" class="secondary">连接</button></div><p id="live-help" class="platform-help"></p>'
                if 'stm32f407' not in app.providers:
                    bar = bar.replace('<option value="stm32f407">STM32F407 开发板</option>', '')
                page = page.replace('</header>', bar + '</header>', 1)
                page = page.replace('</head>', '<link rel="stylesheet" href="/platform.css"></head>')
                page = page.replace('</body>', '<script src="/platform.js"></script></body>')
                return self.send(200, page.replace('__CSRF__', app.token), 'text/html')
            if url.path in ('/platform.js', '/platform.css') and not url.query:
                return self.send(200, (Path(__file__).parent/url.path[1:]).read_bytes(),
                                 'text/javascript' if url.path.endswith('.js') else 'text/css')
            if url.path.startswith('/export/stm32f407/response/') and url.path.endswith('.bin') and not url.query:
                try:
                    ident = url.path.removeprefix('/export/stm32f407/response/').removesuffix('.bin')
                    packet = app.f407_packet(ident)
                    if packet is not None:
                        return self.send(200, packet, 'application/octet-stream')
                except (OSError, ValueError):
                    return self.send(409, {'error': '板端原始应答校验失败'})
                return self.send(404, {'error': '无此板端应答'})

            if url.path == '/export/stm32f407/previous-28.tsv' and not url.query:
                provider=app.providers.get('stm32f407')
                if not provider:return self.send(404, {'error':'缺少开发板记录'})
                from xml.etree import ElementTree as ET
                folder=provider.package/'02_测试代码与数据/performance/完整密码操作/STM32F407/28KiB双策略'
                try:
                    raw=(folder/'transactions.tsv').read_bytes()
                    m=ET.parse(folder/'evidence.xml').getroot()
                    target=next((v for v in m if v.get('path')=='transactions.tsv'),None)
                    if m.get('firmware_sha256')!='059fb457ed7bf6c3016eaffa49b58621784690f0292606b174e003d3f90e2aa8' or target is None or hashlib.sha256(raw).hexdigest()!=target.get('sha256'):
                        raise ValueError('previous history identity mismatch')
                    return self.send(200,raw,'text/tab-separated-values')
                except (OSError,ValueError,ET.ParseError):
                    return self.send(409,{'error':'既有实板样本校验失败'})
            if url.path == '/export/stm32f407/transactions.tsv' and not url.query:
                provider = app.providers.get('stm32f407')
                source = provider.package / HISTORY.parent / 'transactions.tsv' if provider else None
                if not source or not source.is_file():
                    return self.send(404, {'error': '未收录历史实板样本'})
                try:
                    _history_identity(provider.package,'transactions.tsv')
                    return self.send(200, source.read_bytes(), 'text/tab-separated-values')
                except (OSError,ValueError):
                    return self.send(409, {'error': '历史样本读取失败'})
            if url.path == '/export/stm32f407/history.xlsx' and not url.query:
                try:
                    snapshot = app.f407_history()
                    history = snapshot['rows']
                    if snapshot['errors']:
                        return self.send(409, {'error': '历史测量表读取失败'})
                    if not history and not snapshot['memory']:
                        return self.send(404, {'error': '暂无历史实板测量'})
                    from demo.f407_provider import HISTORY_FIELDS, NAMES, STRATEGY_NAMES
                    from demo.spreadsheet_export import workbook
                    rows = [['参数', '操作', '实现', '样本数', '周期中位数', '时钟（Hz）',
                             '耗时中位数（μs）', '工作区峰值（B）', '观测栈峰值（B）']]
                    for item in history:
                        row = []
                        for key in HISTORY_FIELDS:
                            value = item[key]
                            if key == 'operation':
                                value = NAMES[value]
                            elif key == 'implementation':
                                value=STRATEGY_NAMES.get(value,value)
                            elif value is not None:
                                value = float(value) if '.' in value or 'e' in value.lower() else int(value)
                            row.append(value)
                        rows.append(row)
                    tables = [('STM32F407历史实板测量', rows)] if history else []
                    if snapshot['memory']:
                        flash=all(x.get('image_storage')=='flash' for x in snapshot['memory'])
                        memory = [['参数', '实现', '主 SRAM（B）', 'CCM（B）', '栈预算（B）', '工作区（B）', 'Flash 程序（B）' if flash else 'SRAM 镜像（B）', 'RAM 合计（B）']]
                        memory.extend([STRATEGY_NAMES.get(x[key],x[key]) if key=='implementation' else x[key] for key in MEMORY_FIELDS] for x in snapshot['memory'])
                        tables.append(('资源占用', memory))
                    return self.send(200, workbook(tables),
                                     'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                except (ValueError, TypeError, KeyError, OSError):
                    return self.send(409, {'error': '历史测量表读取失败'})
            if url.path in ('/export/representatives/ch32.tsv','/export/representatives/stm32f407.tsv') and not url.query:
                from demo.board_representatives import export_timings
                try:return self.send(200,export_timings(app.representative_history(url.path.rsplit('/',1)[-1][:-4])),'text/tab-separated-values')
                except (OSError,ValueError,KeyError):return self.send(409,{'error':'代表配置记录校验失败'})
            if url.path in ('/api/representatives', '/api/representatives/ch32','/api/representatives/stm32f407') and not url.query:
                try:
                    board=None if url.path=='/api/representatives' else url.path.rsplit('/',1)[-1]
                    return self.send(200,app.representative_history(board))
                except (OSError,ValueError,KeyError):
                    return self.send(409,{'error':'代表档固件或历史记录验证失败'})
            if url.path == '/api/platforms/stm32f407/history' and not url.query:
                try:
                    return self.send(200, app.f407_history())
                except (ValueError, OSError, TypeError, KeyError):
                    return self.send(409, {'error': '实板历史测量表读取失败'})
            if url.path == '/api/platforms' and not url.query:
                return self.send(200, app.platform_catalog())
            return super().do_GET()

        def do_POST(self):
            if self.path not in ('/api/platforms/connect', '/api/run'):
                return super().do_POST()
            if not self.valid_host() or self.headers.get('X-Demo-Token') != app.token or self.headers.get('Origin') not in (None, 'http://' + address):
                timeout = self.connection.gettimeout()
                try:
                    n = int(self.headers.get('Content-Length', '0'))
                    if 0 < n <= 256:
                        self.connection.settimeout(.25)
                        self.rfile.read(n)
                except (ValueError, OSError):
                    pass
                finally:
                    self.connection.settimeout(timeout)
                return self.send(403, {'error': '请求来源不匹配'})
            try:
                wire.require(self.headers.get('Content-Type', '').split(';')[0] == 'application/json', 'JSON required')
                n = int(self.headers.get('Content-Length', '0'))
                wire.require(0 < n <= 2048, 'Invalid live request size')
                request = wire.decode(self.rfile.read(n), 2048)
                if self.path == '/api/run':
                    return self.send(200, app.run(request))
                if type(request) is dict and set(request)=={'platform_id','strategy'} and request['platform_id']=='ch32':
                    from demo.ch32_strategy import Ch32UpdateError
                    try:return self.send(200,app.ch32_strategy.select(app,request['strategy']))
                    except Ch32UpdateError as error:return self.send(409,{'error':str(error)})
                wire.require(type(request) is dict and set(request) == {'platform_id'}, 'Unknown connection fields')
                return self.send(200, app.connect(request['platform_id']))
            except (ValueError, TypeError, KeyError):
                return self.send(400, {'error': '连接配置或程序身份不匹配'})
            except ProviderError as e:
                return self.send(409, {'error': ERROR_MESSAGES.get(e.code, '设备响应未通过检查，本次未完成，未自动重发。')})
            except (OSError, ImportError):
                return self.send(409, {'error': '设备暂不可用，请检查连接与驱动；未自动重发。'})
            except Exception:
                return self.send(409, {'error': '实际执行未完成，请检查设备状态；未自动重发。'})
    return Handler
