"""Versioned technical data model. No project workspace or remote dependency."""
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
import math
import re

class DataError(ValueError):
    pass

def require(value, message):
    if not value:
        raise DataError(message)

COMMON = {'kind', 'algorithm', 'parameter', 'operation', 'configuration', 'platform',
          'execution', 'historical', 'binary_sha256'}
REQUIRED = COMMON - {'binary_sha256'}
FIELDS = {
    'timing_series': (REQUIRED | {'round_id', 'samples_ns', 'sample_semantics', 'samples_per_batch'},
                      COMMON | {'round_id', 'samples_ns', 'sample_semantics', 'samples_per_batch',
                                'message_bytes', 'context_bytes', 'thread_count', 'timer', 'outcomes', 'return_codes'}),
    'test_result': (REQUIRED | {'test_suite', 'case_id', 'outcome'},
                    COMMON | {'test_suite', 'case_id', 'outcome', 'return_code', 'expected_return_code',
                              'cases_run', 'cases_failed', 'diagnostic', 'message_bytes', 'context_bytes'}),
    'resource': (REQUIRED | {'boundary', 'full_ram_bytes', 'program_bytes'},
                 COMMON | {'boundary', 'full_ram_bytes', 'program_bytes', 'workspace_bytes', 'stack_bytes',
                           'context_bytes', 'globals_bytes', 'extra_heap_bytes', 'input_output_bytes',
                           'stack_margin_bytes', 'alignment_bytes', 'outcome'}),
}
OUTCOMES = {'PASS', 'FAIL', 'SUCCESS', 'REJECTED', 'CAPACITY_INSUFFICIENT',
            'ERROR', 'UNSUPPORTED', 'NOT_APPLICABLE', 'NOT_TESTED', 'INTERRUPTED'}
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')

def integer(value, name, nonnegative=True):
    require(type(value) is int and (not nonnegative or value >= 0), name + ': integer required')

def validate_record(row):
    require(type(row) is dict and row.get('kind') in FIELDS, 'Unknown technical record kind')
    needed, allowed = FIELDS[row['kind']]
    require(needed <= row.keys() and row.keys() <= allowed, 'Missing or undeclared technical fields')
    require(row['algorithm'] in ('ML-KEM', 'ML-DSA'), 'Unknown algorithm')
    parameters, operations = (({512, 768, 1024}, {'keygen', 'encaps', 'decaps'}) if row['algorithm'] == 'ML-KEM'
                              else ({44, 65, 87}, {'keygen', 'sign', 'verify'}))
    require(type(row['parameter']) is int and row['parameter'] in parameters and row['operation'] in operations,
            'Parameter/operation does not belong to algorithm')
    require(row['execution'] in ('native', 'instruction_emulation'), 'Execution classification missing')
    require(type(row['historical']) is bool, 'History classification missing')
    for key in ('configuration', 'platform'):
        require(type(row[key]) is str and TOKEN.fullmatch(row[key]), 'Invalid technical identity')
    if 'binary_sha256' in row:
        require(type(row['binary_sha256']) is str and SHA.fullmatch(row['binary_sha256']), 'Invalid binary digest')
    for key, value in row.items():
        if key.endswith('_bytes') or key in ('thread_count', 'samples_per_batch', 'cases_run', 'cases_failed'):
            integer(value, key)
        if key in ('return_code', 'expected_return_code'):
            integer(value, key, False)
        if key in ('test_suite', 'case_id', 'round_id'):
            require(type(value) is str and TOKEN.fullmatch(value), 'Invalid record identity')
        if key in ('timer', 'diagnostic'):
            require(type(value) is str and len(value) <= 2048 and '\x00' not in value, 'Invalid technical text')
        if key == 'outcome':
            require(value in OUTCOMES, 'Unknown observed outcome')
    if row['kind'] == 'timing_series':
        require(row['execution'] == 'native', 'Emulated host timing cannot be a native algorithm timing series')
        require(row['sample_semantics'] in ('individual_call', 'batch_mean'), 'Unknown sample unit')
        require(row['samples_per_batch'] > 0 and (row['sample_semantics'] != 'individual_call' or row['samples_per_batch'] == 1), 'Invalid batch unit')
        samples = row['samples_ns']
        require(type(samples) is list and samples, 'Empty sample series')
        require(all(type(v) in (int, float) and math.isfinite(v) and v >= 0 for v in samples), 'Invalid observed nanoseconds')
        if 'outcomes' in row:
            require(type(row['outcomes']) is list and len(row['outcomes']) == len(samples) and all(v in OUTCOMES for v in row['outcomes']), 'Sample/outcome correspondence lost')
        if 'return_codes' in row:
            require(type(row['return_codes']) is list and len(row['return_codes']) == len(samples) and all(type(v) is int for v in row['return_codes']), 'Sample/return-code correspondence lost')
    if row['kind'] == 'resource':
        require(row['boundary'] in ('core_reserved', 'target_program', 'process_observed'), 'Resource boundary required')
        components = ('workspace_bytes', 'stack_bytes', 'context_bytes', 'globals_bytes', 'extra_heap_bytes')
        if row['boundary'] == 'core_reserved' and all(v in row for v in components):
            require(sum(row[v] for v in components) == row['full_ram_bytes'], 'Core resource sum is inconsistent')
    return row

def validate(data):
    require(type(data) is dict and set(data) == {'schema', 'kind', 'dataset_id', 'records'}, 'Undeclared dataset fields')
    require(data['schema'] == 1 and data['kind'] == 'lattice_technical_observations', 'Unsupported technical schema')
    require(type(data['dataset_id']) is str and TOKEN.fullmatch(data['dataset_id']), 'Invalid dataset identity')
    require(type(data['records']) is list, 'Observation array required')
    for row in data['records']:
        validate_record(row)
    return data

def load(path):
    def pairs(items):
        row={}
        for key,value in items:
            require(key not in row,'Duplicate technical JSON field')
            row[key]=value
        return row
    with open(path, encoding='utf-8-sig') as stream:
        return validate(json.load(stream,object_pairs_hook=pairs,
            parse_constant=lambda v: (_ for _ in ()).throw(DataError('Non-finite JSON number'))))
