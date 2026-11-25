"""Bounded transport envelope around the existing five-field functional API."""
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from contextvars import ContextVar
import struct
import json
from threading import Lock
import re

SCHEMA = 'lattice.live_platform.v1'
MAX_REQUEST = 4096
MAX_RESPONSE = 1048576
PARAMETERS = (512, 768, 1024, 44, 65, 87)
ARITHMETIC = ('add', 'sub', 'mul', 'ntt', 'intt')
UNARY = ('ntt', 'intt')
PRIMITIVE_INPUT = struct.Struct('<7I256i384s64s')
PRIMITIVE_OUTPUT = struct.Struct('<256i384s')


def binary_field(value, size):
    require(type(value) is str and len(value)==((size+2)//3)*4, 'Unexpected binary field length')
    try:
        data=b64decode(value,validate=True)
    except Base64Error:
        raise ValueError('Invalid binary field') from None
    require(len(data)==size, 'Unexpected binary length')
    return data
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
REQUEST_ID = re.compile(r'[0-9a-f]{32}\Z')


RUN_TRAFFIC = ContextVar('run_traffic', default=None)


class Traffic:
    def __init__(self, *, public=False):
        self.public = public
        self._lock = Lock()
        self._frames = []
        self._size = 0
        self._omitted = 0

    def observe(self, link, direction, payload, description):
        with self._lock:
            size = len(payload) if self.public else 0
            if len(self._frames) >= 1024 or self._size + size > 1024 * 1024:
                self._omitted += 1
                return
            self._frames.append(dict(link=link,direction=direction,bytes=len(payload),
                                     description=description,hex=payload.hex() if self.public and size else None))
            self._size += size

    def snapshot(self, start=0):
        with self._lock:
            return dict(frames=self._frames[start:], omitted=self._omitted)


def observe_frame(link, direction, payload, description):
    recorder = RUN_TRAFFIC.get()
    if recorder is not None:
        recorder.observe(link,direction,payload,description)


def require(value, message):
    if not value:
        raise ValueError(message)


def decode(blob, limit):
    require(isinstance(blob, bytes) and 0 < len(blob) <= limit, 'Invalid transport size')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON field')
            result[key] = value
        return result
    return json.loads(blob.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, 'Nonfinite JSON number'))


def encode(value, limit):
    data = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode() + b'\n'
    require(len(data) <= limit, 'Transport response is too large')
    return data


def run_request(value):
    fields={'library', 'parameter', 'message_bytes', 'context_bytes', 'mode'}
    require(type(value) is dict and fields <= set(value) <= fields|{'workspace_bytes'},
            'Unknown run fields')
    if 'workspace_bytes' in value:require(type(value['workspace_bytes']) is int and 32<=value['workspace_bytes']<=1048576 and value['workspace_bytes']%32==0,'Invalid workspace choice')
    require(type(value['library']) is str and TOKEN.fullmatch(value['library']), 'Invalid library ID')
    require(type(value['parameter']) is int and value['parameter'] in PARAMETERS, 'Invalid parameter')
    require(type(value['message_bytes']) is int and value['message_bytes'] in (0, 32, 1024, 16384), 'Invalid message preset')
    require(type(value['context_bytes']) is int and value['context_bytes'] in (0, 1, 255), 'Invalid context preset')
    require(value['mode'] in ('normal', 'insufficient'), 'Invalid run mode')
    require(value['parameter'] < 100 or (value['message_bytes'] == 0 and value['context_bytes'] == 0),
            'KEM has no message/context preset')
    return value


def encode_polynomials(values):
    return b64encode(struct.pack('<'+'I'*len(values),*values)).decode('ascii')


def decode_polynomials(value, count, modulus):
    require(type(value) is str and len(value) == ((count*4 + 2)//3)*4, 'Wrong polynomial length')
    try:
        raw = b64decode(value, validate=True)
    except Base64Error:
        raise ValueError('Invalid polynomial encoding') from None
    require(len(raw) == count*4, 'Wrong polynomial byte length')
    values = list(struct.unpack('<'+'I'*count, raw))
    require(all(x < modulus for x in values), 'Polynomial coefficient outside the modulus')
    return values


def request(value):
    require(type(value) is dict and set(value) == {'schema', 'request_id', 'action', 'payload'}, 'Invalid request fields')
    require(value['schema'] == SCHEMA and type(value['request_id']) is str and REQUEST_ID.fullmatch(value['request_id']),
            'Invalid request identity')
    require(value['action'] in ('catalog', 'run', 'acvp', 'arithmetic', 'performance', 'security'), 'Unsupported action')
    if value['action'] == 'catalog':
        require(value['payload'] == {} and type(value['payload']) is dict, 'Catalog has no arguments')
    elif value['action'] == 'acvp':
        payload=value['payload']
        require(type(payload) is dict and set(payload)=={'library','cases'} and type(payload['library']) is str
                and TOKEN.fullmatch(payload['library'])
                and type(payload['cases']) is list and 1<=len(payload['cases'])<=21,'Invalid ACVP request')
        for case in payload['cases']:
            require(type(case) is list and len(case)==2 and type(case[0]) is int and case[0] in PARAMETERS
                    and type(case[1]) is str and re.fullmatch(r'ML-(?:KEM|DSA)-[A-Za-z0-9-]+/g[0-9]+/tc[0-9]+',case[1])
                    and len(case[1])<=96,'Invalid ACVP case')
        require(len({tuple(case) for case in payload['cases']})==len(payload['cases']),'Duplicate ACVP case')
    elif value['action'] == 'performance':
        performance_request(value['payload'])
    elif value['action'] == 'security':
        security_request(value['payload'])
    elif value['action'] == 'arithmetic':
        data = value['payload']
        require(type(data) is dict, 'Invalid arithmetic request')
        if set(data)=={'binding'}:
            packed = binary_field(data['binding'],PRIMITIVE_INPUT.size)
            _,parameter,operation,*_ = PRIMITIVE_INPUT.unpack(packed)
            require(parameter in PARAMETERS and operation<=8,'Unsupported native arithmetic binding')
        else:
            require(set(data) == {'operation','modulus','coefficients'}, 'Invalid arithmetic request')
            require(data['operation'] in ARITHMETIC and type(data['modulus']) is int and
                    data['modulus'] in (3329,8380417), 'Unsupported polynomial operation')
            decode_polynomials(data['coefficients'], 256 if data['operation'] in UNARY else 512, data['modulus'])
    else:
        run_request(value['payload'])
    return value


def response(value, sent, platform):
    fields = {'schema', 'request_id', 'action', 'platform_id', 'session_id', 'sequence', 'ok'}
    require(type(value) is dict and fields <= set(value) <= fields | {'body', 'error'}, 'Invalid response fields')
    require(value['schema'] == SCHEMA and value['request_id'] == sent['request_id'] and
            value['action'] == sent['action'] and value['platform_id'] == platform, 'Response identity mismatch')
    require(type(value['session_id']) is str and TOKEN.fullmatch(value['session_id']), 'Missing process/device session identity')
    require(type(value['sequence']) is int and value['sequence'] >= 1, 'Invalid response sequence')
    require(type(value['ok']) is bool, 'Invalid response status')
    if value['ok']:
        require(set(value) == fields | {'body'} and type(value['body']) is dict, 'Missing complete response body')
    else:
        require(set(value) == fields | {'error'} and type(value['error']) is str and TOKEN.fullmatch(value['error']),
                'Invalid bounded error')
    return value


SECURITY_CODES = {'length': -2, 'encoding': -6, 'random': -4, 'capacity': -5,
                  'ciphertext': 0, 'signature': -6, 'message': -6}


def security_cases(parameter):
    common = ('length', 'encoding', 'capacity', 'random')
    return (('ciphertext',) if parameter > 100 else ('message', 'signature')) + common


def security_request(value):
    require(type(value) is dict and set(value) == {'library', 'parameter', 'case'},
            'Invalid security request fields')
    require(type(value['library']) is str and TOKEN.fullmatch(value['library']), 'Invalid library ID')
    parameter = value['parameter']
    require(type(parameter) is int and parameter in PARAMETERS and value['case'] in security_cases(parameter),
            'Invalid security check')
    return value


def security_input(value, case, parameter):
    fields = {'field', 'before', 'after', 'source'}
    require(type(value) is dict and set(value) == fields and value['source'] == 'fresh',
            'Invalid remote security input record')
    expected = {'length': 'ciphertext' if parameter > 100 else 'signature',
                'encoding': 'public_key' if parameter > 100 else 'signature',
                'capacity': 'workspace_bytes', 'random': 'entropy_bytes'}.get(case, case)
    require(value['field'] == expected, 'Unexpected remote security input field')
    before, after = value['before'], value['after']
    if expected in ('workspace_bytes', 'entropy_bytes'):
        require(all(type(count) is int and 0 <= count <= 1048576 for count in (before, after)),
                'Invalid remote security input size')
    else:
        require(all(type(blob) is str and len(blob) <= 131072 and len(blob)%2 == 0 and
                    re.fullmatch('[0-9a-f]*',blob) for blob in (before, after)), 'Invalid public input bytes')


def security_result(value, sent):
    fields = {'binary_sha256', 'return_code', 'verified', 'failure_output_zero', 'recovered'}
    extra = {'security_input', 'original_return_code', 'recovery_return_code', 'function'}
    required = set(sent) | fields
    require(type(value) is dict and required <= set(value) <= required | extra, 'Invalid security result fields')
    if value.get('security_input') is not None:
        security_input(value['security_input'], sent['case'], sent['parameter'])
    for key in ('original_return_code', 'recovery_return_code'):
        code = value.get(key)
        require(code is None or type(code) is int and -16 <= code <= 0, 'Invalid security control outcome')
    require(value.get('function') in (None, 'lc_keypair', 'lc_encaps', 'lc_decaps', 'lc_verify'),
            'Invalid security API')
    require(all(type(value[key]) is type(expected) and value[key] == expected
                for key, expected in sent.items()), 'Remote security request mismatch')
    require(type(value['binary_sha256']) is str and SHA256.fullmatch(value['binary_sha256']),
            'Invalid security library identity')
    code, zero, recovered = (value[key] for key in ('return_code', 'failure_output_zero', 'recovered'))
    require((code is None or type(code) is int and -16 <= code <= 0) and type(value['verified']) is bool
            and all(flag is None or type(flag) is bool for flag in (zero, recovered)), 'Invalid security outcome')
    recovery = sent['case'] in ('random', 'capacity')
    require(not value['verified'] or (code == SECURITY_CODES[sent['case']]
            and (not recovery or zero is True and recovered is True)), 'Inconsistent security outcome')
    return value


def performance_request(value):
    require(type(value) is dict and set(value) == {'library', 'parameter', 'operation'},
            'Invalid performance request fields')
    require(type(value['library']) is str and TOKEN.fullmatch(value['library']), 'Invalid library ID')
    parameter = value['parameter']
    require(type(parameter) is int and parameter in PARAMETERS, 'Invalid parameter')
    operations = ('keygen', 'encaps', 'decaps') if parameter > 100 else ('keygen', 'sign', 'verify')
    require(value['operation'] in operations, 'Invalid timed operation')
    return value


def performance_result(value, sent):
    required = set(sent) | {'binary_sha256', 'duration_ns', 'return_code', 'verified'}
    resources = {'workspace_bytes', 'workspace_used_bytes'}
    materials = {'inputs', 'public_outputs'}
    require(type(value) is dict and required <= set(value) <= required | resources | materials and
            all(group <= set(value) or not group & set(value) for group in (resources, materials)),
            'Invalid timing result fields')
    if materials <= set(value):
        for key in materials:
            payload = value[key]
            require(type(payload) is dict and set(payload) <= {'public_key', 'ciphertext', 'signature',
                    'message', 'context', 'shared_secret_length', 'secret_key_length'}, 'Invalid public timing materials')
            for name, blob in payload.items():
                if name.endswith('_length'):
                    require(type(blob) is int and 0 <= blob <= 8192, 'Invalid output length')
                else:
                    require(type(blob) is dict and set(blob) == {'length','hex','sha256'}
                            and type(blob['length']) is int and 0 <= blob['length'] <= 8192
                            and type(blob['hex']) is str and len(blob['hex'])==2*blob['length']
                            and re.fullmatch('[0-9a-f]*',blob['hex']) and type(blob['sha256']) is str
                            and SHA256.fullmatch(blob['sha256']), 'Invalid timed operation bytes')
    if resources <= set(value):
        capacity, peak = value['workspace_bytes'], value['workspace_used_bytes']
        require(type(capacity) is int and type(peak) is int and 0 <= peak <= capacity <= 1048576,
                'Invalid timed workspace observation')
    require(all(type(value[key]) is type(expected) and value[key] == expected
                for key, expected in sent.items()), 'Remote timing request mismatch')
    require(type(value['binary_sha256']) is str and SHA256.fullmatch(value['binary_sha256']),
            'Invalid timing library identity')
    require(type(value['duration_ns']) is int and 0 <= value['duration_ns'] <= 120_000_000_000,
            'Invalid native operation duration')
    require(type(value['return_code']) is int and -16 <= value['return_code'] <= 0
            and type(value['verified']) is bool and (not value['verified'] or value['return_code'] == 0),
            'Invalid timed operation outcome')
    return value


def functional_result(value, sent, recovery=False):
    """Public-only closed result shape; never forward arbitrary firmware fields."""
    base = {'operations', 'checks', 'functional_checks_passed', 'workspace_bytes',
            'observed_arena_high_water_bytes', 'canaries_ok', 'failure_output_zero'}
    identity = {'schema', 'kind', 'run_id', 'library', 'parameter', 'algorithm', 'message_bytes',
                'context_bytes', 'mode', 'binary_sha256', 'performance_measurement'}
    optional = {'measured_binary_sha256', 'deployment_derivation_sha256', 'recovery', 'device_metrics','requested_workspace_bytes'}
    require(type(value) is dict and (set(value) == base if recovery else base | identity <= set(value) <= base | identity | optional),
            'Unknown functional result fields')
    if not recovery:
        for name in ('library', 'parameter', 'message_bytes', 'context_bytes', 'mode'):
            require(type(value[name]) is type(sent[name]) and value[name] == sent[name], 'Remote input mismatch')
        require(value['schema'] == 1 and value['kind'] == 'local_functional_observation', 'Unknown functional result version')
        require(value['algorithm'] == ('ML-KEM' if sent['parameter'] > 100 else 'ML-DSA'), 'Wrong algorithm')
        require(type(value['run_id']) is str and TOKEN.fullmatch(value['run_id']), 'Invalid run identity')
        require(type(value['performance_measurement']) is bool and
                (not value['performance_measurement'] or 'device_metrics' in value), 'Performance requires explicit device metrics')
        for name in ('binary_sha256', 'measured_binary_sha256', 'deployment_derivation_sha256'):
            if name in value:
                require(type(value[name]) is str and SHA256.fullmatch(value[name]), 'Invalid result image identity')
        if 'recovery' in value:
            functional_result(value['recovery'], sent, recovery=True)
        if 'workspace_bytes' in sent:
            require(value.get('requested_workspace_bytes')==sent['workspace_bytes'],'Remote requested workspace mismatch')
            require(value['workspace_bytes']==(32 if sent['mode']=='insufficient' else sent['workspace_bytes']),'Remote workspace mismatch')
            if 'recovery' in value:require(value['recovery']['workspace_bytes']==sent['workspace_bytes'],'Remote recovery workspace mismatch')
    require(type(value['functional_checks_passed']) is bool and type(value['canaries_ok']) is bool and
            (value['failure_output_zero'] is None or type(value['failure_output_zero']) is bool), 'Invalid functional flags')
    for name in ('workspace_bytes', 'observed_arena_high_water_bytes'):
        require(type(value[name]) is int and 0 <= value[name] <= 1048576, 'Invalid workspace observation')
    require(value['observed_arena_high_water_bytes'] <= value['workspace_bytes'], 'Invalid workspace high water')
    expected_checks = {'shared_secret_equal', 'implicit_rejection'} if sent['parameter'] > 100 else {
        'signature_verified', 'modified_signature_rejected'}
    require(type(value['checks']) is dict and set(value['checks']) <= expected_checks and
            all(type(v) is bool for v in value['checks'].values()), 'Unknown functional checks')
    operations = ['keygen', 'encaps', 'decaps', 'decaps_modified_ciphertext'] if sent['parameter'] > 100 else [
        'keygen', 'sign', 'verify', 'verify_modified_signature']
    rows = value['operations']
    require(type(rows) is list and 1 <= len(rows) <= 4, 'Incomplete operation list')
    for position, row in enumerate(rows):
        fields = {'operation', 'return_code', 'outcome', 'arena_high_water_bytes'}
        require(type(row) is dict and fields <= set(row) <= fields | {'operation_title', 'result_description'}, 'Unknown operation fields')
        require(row['operation'] == operations[position] and type(row['return_code']) is int and
                -16 <= row['return_code'] <= 0, 'Invalid operation/order')
        require(row['outcome'] in ('SUCCESS', 'CAPACITY_INSUFFICIENT', 'REJECTED', 'UNSUPPORTED', 'ERROR'), 'Invalid operation status')
        require(type(row['arena_high_water_bytes']) is int and 0 <= row['arena_high_water_bytes'] <= value['workspace_bytes'],
                'Invalid per-operation workspace')
        for name in ('operation_title', 'result_description'):
            if name in row:
                require(type(row[name]) is str and len(row[name]) <= 256 and not any(ord(c) < 32 for c in row[name]),
                        'Invalid operation description')
    if value['functional_checks_passed']:
        require(value['canaries_ok'] and set(value['checks']) == expected_checks and all(value['checks'].values()) and
                len(rows) == 4 and [r['return_code'] for r in rows] == ([0, 0, 0, 0] if sent['parameter'] > 100 else [0, 0, 0, -6]),
                'Inconsistent successful functional result')
    if not recovery and 'device_metrics' in value:
        device_metrics(value['device_metrics'], value, operations)
    return value


def device_metrics(value, functional, operations):
    """Independent, explicitly scoped device observations, never host latency."""
    require(type(value) is dict and set(value) == {'schema', 'timer', 'operations', 'resources', 'scope'}, 'Unknown device metric fields')
    require(value['schema'] == 'lattice.device_metrics.v1' and value['scope'] ==
            'public-api-including-internal-cleanup;excluding-outer-cleanup-hash-uart', 'Unsupported device timing scope')
    timer = value['timer']
    require(type(timer) is dict and set(timer) == {'source', 'frequency_hz', 'counter_bits', 'validated'} and
            timer['source'] == 'systick-hclk' and timer['counter_bits'] == 64 and timer['validated'] is True and
            type(timer['frequency_hz']) is int and 1 <= timer['frequency_hz'] <= 1000000000, 'Unvalidated device timer')
    resources = value['resources']
    resource_names = {'flash_bytes', 'static_ram_bytes', 'workspace_bytes', 'test_stack_reserved_bytes',
                      'control_stack_reserved_bytes', 'caller_io_bytes'}
    require(type(resources) is dict and set(resources) == resource_names and all(
        type(n) is int and 0 < n <= 16777216 for n in resources.values()), 'Invalid device linked resource fields')
    require(resources['workspace_bytes'] == functional['workspace_bytes'], 'Device workspace identity mismatch')
    rows = value['operations']
    require(type(rows) is list and len(rows) == 4, 'Four device operation records required')
    executed = functional['operations']
    for i, row in enumerate(rows):
        require(type(row) is dict and set(row) == {'operation', 'return_code', 'ticks', 'observed_stack_bytes',
                                                  'observed_arena_high_water_bytes'}, 'Unknown device operation metrics')
        require(row['operation'] == operations[i] and type(row['return_code']) is int, 'Device operation identity mismatch')
        # Duration ticks must survive JSON -> browser without integer rounding.
        # The hardware counter is still 64-bit; reject an impractically long sample.
        require(type(row['ticks']) is int and 0 <= row['ticks'] < 2**53, 'Invalid or non-exact JSON duration ticks')
        for key, bound in (('observed_stack_bytes', resources['test_stack_reserved_bytes']),
                           ('observed_arena_high_water_bytes', resources['workspace_bytes'])):
            require(type(row[key]) is int and 0 <= row[key] <= bound, 'Device observation exceeds reservation')
        if i < len(executed):
            require(row['return_code'] == executed[i]['return_code'] and row['ticks'] > 0 and
                    row['observed_arena_high_water_bytes'] == executed[i]['arena_high_water_bytes'], 'Device/function record mismatch')
        else:
            require(row['return_code'] == -127 and row['ticks'] == row['observed_stack_bytes'] ==
                    row['observed_arena_high_water_bytes'] == 0, 'Unexecuted operation cannot contain measurements')
    return value


def run_presets(value):
    require(type(value) is dict and set(value) == {'message_lengths', 'context_lengths', 'modes'}, 'Explicit supported presets required')
    for key, allowed in (('message_lengths', (0, 32, 1024, 16384)), ('context_lengths', (0, 1, 255)), ('modes', ('normal', 'insufficient'))):
        rows = value[key]
        require(type(rows) is list and rows and len(rows) == len(set(rows)) and all(
            type(x) is (str if key == 'modes' else int) and x in allowed for x in rows), 'Unsupported capability value')
    return value


class FunctionalRunner:
    """No crypto implementation: delegates to an existing validated Application."""
    def __init__(self, application, platform_id, session_id, acvp=None, arithmetic=None, performance=None, security=None):
        require(TOKEN.fullmatch(platform_id) and TOKEN.fullmatch(session_id), 'Invalid runner identity')
        self.application = application
        self.platform_id = platform_id
        self.session_id = session_id
        self.sequence = 0
        self.acvp = acvp
        self.arithmetic = arithmetic
        self.performance = performance
        self.security = security

    def dispatch(self, value):
        value = request(value)
        self.sequence += 1
        reply = dict(schema=SCHEMA, request_id=value['request_id'], action=value['action'],
                     platform_id=self.platform_id, session_id=self.session_id,
                     sequence=self.sequence, ok=True)
        try:
            if value['action'] == 'catalog':
                reply['body'] = self.application.catalog()
                for row in reply['body']['libraries']:
                    row['run_presets'] = {'message_lengths': [0, 32, 1024, 16384],
                                          'context_lengths': [0, 1, 255], 'modes': ['normal', 'insufficient']}
                    if self.performance:
                        row['operation_timing'] = True
                    if self.security:
                        row['security_checks'] = True
                    if self.acvp:
                        row['acvp'] = True
                    if self.arithmetic:
                        row['arithmetic_sha256'] = self.arithmetic[0]
                        if len(self.arithmetic)>2:
                            row['primitive_sha256'] = self.arithmetic[2]
            elif value['action'] == 'performance':
                require(self.performance is not None, 'Performance runner is unavailable')
                reply['body'] = performance_result(self.performance(value['payload']), value['payload'])
            elif value['action'] == 'security':
                require(self.security is not None, 'Security runner is unavailable')
                reply['body'] = security_result(self.security(value['payload']), value['payload'])
            elif value['action'] == 'arithmetic':
                require(self.arithmetic is not None, 'Arithmetic runner is unavailable')
                reply['body'] = self.arithmetic[1](value['payload'])
            elif value['action'] == 'acvp':
                require(self.acvp is not None,'ACVP runner is unavailable')
                reply['body'] = self.acvp(value['payload'])
            else:
                reply['body'] = self.application.run(value['payload'])
        except (ValueError, KeyError, TypeError):
            reply.pop('body',None)
            reply.update(ok=False, error='INVALID_REQUEST_OR_CONFIGURATION')
        return response(reply, value, self.platform_id)
