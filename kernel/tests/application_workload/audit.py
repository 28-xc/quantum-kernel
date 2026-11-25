"""Project and independently audit the complete fixed-pool application study.

Projection selects scientific fields from the original collector output. Every
trial is retained through an ordered public record and its source digest.
The validate and negative-tests commands operate entirely on public data.
"""
from pathlib import Path
import argparse
import copy
import hashlib
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
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from publicschemas import application_v1 as schema


def save(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def project(source, output, platform, resource_root=None):
    source = Path(source).resolve(); output = Path(output).resolve()
    schema.need(not output.exists(), 'Use a fresh public output directory')
    protocol = schema.read(source/'protocol.xml'); result = schema.read(source/'result.xml')
    schema.keys(protocol, ('schema','libraries','budgets_bytes','seeds','seed','parameters',
        'application_stack_extra_bytes','compiler','host','machine','source_sha256',
        'executable_sha256','scope','budget_equation','infrastructure','entropy','timing_collected'))
    schema.need(protocol['schema'] == 'lattice.application_resources.v1' and
        protocol['parameters'] == [list(p) for p in schema.PAIRS] and
        protocol['budgets_bytes'] == list(schema.BUDGETS) and protocol['seeds'] == 24 and
        protocol['seed'] == schema.SEED and protocol['application_stack_extra_bytes'] == 768 and
        protocol['timing_collected'] is False, 'Changed source protocol')
    schema.need((platform == 'windows_x86_64' and protocol['machine'] in ('amd64','x86_64') and protocol['host'].startswith('Windows')) or
        (platform == 'linux_aarch64' and protocol['machine'] in ('aarch64','arm64') and protocol['host'].startswith('Linux')),
        'Platform does not match collector environment')
    schema.keys(result, ('status','trials','protocol_sha256','raw_sha256','all_rows_retained'))
    schema.need(result == dict(status='PASS', trials=2336,
        protocol_sha256=schema.sha(source/'protocol.xml'), raw_sha256=schema.sha(source/'trials.records.xml'),
        all_rows_retained=True), 'Source completion or byte identities differ')
    configurations = []
    resource_index = {}
    if resource_root is not None:
        for path in Path(resource_root).rglob('resource_evidence.xml'):
            resource_index[schema.sha(path)] = path
    for lib in protocol['libraries']:
        schema.keys(lib, ('id','path','sha256','resource','core_stack','application_stack','globals','resource_sha256'))
        resource_path = Path(lib['resource'])
        if not resource_path.is_file():
            resource_path = resource_index.get(lib['resource_sha256'])
        schema.need(resource_path is not None and resource_path.is_file() and
            schema.sha(resource_path) == lib['resource_sha256'],
            'Supply the SHA-bound algorithm evidence via --resource-root')
        resource = schema.read(resource_path)
        schema.need(resource['status'] == 'PASS' and resource['dll_sha256'] == lib['sha256'] and
            [p['parameter'] for p in resource['parameters']] == [512,768,1024,44,65,87] and
            max(p['stack_reserved_bytes'] for p in resource['parameters']) == lib['core_stack'],
            'Algorithm resource evidence differs from the application protocol')
        algorithm_workspace = [dict(parameter=p['parameter'], workspace_bytes=p['workspace_bytes'])
                               for p in resource['parameters']]
        configurations.append(dict(id=lib['id'], binary_sha256=lib['sha256'],
            core_stack_bytes=lib['core_stack'], application_stack_bytes=lib['application_stack'],
            globals_and_tls_bytes=lib['globals'], resource_evidence_sha256=lib['resource_sha256'],
            algorithm_workspace_by_parameter=algorithm_workspace,
            algorithm_common_workspace_bytes=max(p['workspace_bytes'] for p in resource['parameters'])))
    data = dict(schema=schema.OBSERVATIONS_SCHEMA,
        dataset_id=platform+'_fixed_pool_application', platform=platform, scope=copy.deepcopy(schema.SCOPE),
        method=dict(parameters=[list(p) for p in schema.PAIRS], budgets_bytes=list(schema.BUDGETS),
            seeds_per_cell=24, base_seed=schema.SEED,
            seed_formula='base_seed + kem * 65537 + repeat * 131071',
            operation_order=list(schema.OPERATIONS), domain_utf8='A1-27 device enrollment v1',
            application_stack_extra_bytes=768, pool_alignment_bytes=32, controls_per_configuration=4),
        configurations=configurations,
        collector=dict(binary_sha256=protocol['executable_sha256'],
            compiler=protocol['compiler'].splitlines()[0], source_sha256=protocol['source_sha256']),
        provenance=dict(protocol_sha256=result['protocol_sha256'], trials_sha256=result['raw_sha256'],
            result_sha256=schema.sha(source/'result.xml'), original_trial_count=2336,
            all_original_records_retained=True,
            original_record_digest_rule=schema.XML_DIGEST_RULE,
            projection='scientific fields selected; command paths excluded; numerical events unchanged'),
        raw=dict(path='trials.records.xml', sha256='0'*64, bytes=1, rows=2336))
    originals = schema.read(source/'trials.records.xml')
    schema.need(isinstance(originals, list) and len(originals) == 2336, 'Incomplete XML trial collection')
    libraries = {c['id']: c for c in protocol['libraries']}
    rows = []
    for i, original in enumerate(originals):
        schema.keys(original, ('id','library','kem','dsa','budget','stack','seed','control',
            'purpose','command','exit_code','stdout','stderr','classification','result'))
        schema.need(original['id'] == i and original['library'] in libraries,
            'Original record identity differs')
        lib = libraries[original['library']]
        command = original['command']
        schema.need(type(command) is list and len(command) == 9 and command[1] == lib['path'] and
            command[2:] == list(map(str, [original['kem'],original['dsa'],original['budget'],
                original['stack'],lib['globals'],original['seed'],original['control']])),
            'Original command differs from declared library or condition')
        schema.need(Path(command[0].replace('\\','/')).name in ('application_resource.exe','application_resource'),
            'Unexpected measurement driver')
        stdout = schema.restore_stdout(original['stdout'])
        schema.need(type(original['stderr']) is str, 'Invalid collector diagnostic')
        events = [schema.loads(line) for line in stdout.splitlines()]
        schema.need(all(isinstance(event, dict) for event in events), 'Invalid collector event')
        row = dict(ordinal=i, configuration=lib['id'], binary_sha256=lib['sha256'],
            kem=original['kem'], dsa=original['dsa'], budget_bytes=original['budget'],
            stack_bytes=original['stack'], seed=original['seed'], control=original['control'],
            purpose=original['purpose'], exit_code=original['exit_code'],
            classification=original['classification'], events=events, result=original['result'],
            stderr=original['stderr'], source_record_sha256=sha_bytes((json.dumps(original)+'\n').encode('utf-8')),
            source_stdout_sha256=sha_bytes(stdout.encode('utf-8')),
            source_stderr_sha256=sha_bytes(original['stderr'].encode()))
        rows.append(row)
    schema.validate_rows(data, rows)
    output.mkdir(parents=True)
    raw = output/'trials.records.xml'
    json.write_records(raw, rows)
    data['raw'].update(sha256=schema.sha(raw), bytes=raw.stat().st_size)
    save(output/'observations.xml', data)
    summary, checked = schema.recompute(output/'observations.xml')
    schema.need(checked == rows, 'Public projection changed the scientific records')
    save(output/'summary.xml', summary)
    return summary


def negative_tests(observations, output):
    """Check data mutation, incomplete cells, changed identity and strict JSON."""
    path = Path(observations).resolve(); output = Path(output).resolve()
    schema.need(not output.exists(), 'Use a fresh test directory')
    original = schema.read(path); original_raw = (path.parent/original['raw']['path']).read_bytes()
    schema.recompute(path)
    output.mkdir(parents=True)
    outcomes = []
    for name in ('changed_byte', 'missing_row', 'changed_library'):
        directory = output/name; directory.mkdir()
        data = copy.deepcopy(original); raw = original_raw
        if name == 'changed_byte':
            raw = raw.replace(b'<name>completed_operations</name>', b'<name>completed_operationx</name>', 1)
            schema.need(raw != original_raw, 'Mutation anchor absent')
        else:
            rows = schema.loads(raw)
            if name == 'missing_row':
                del rows[4]
            else:
                schema.need(rows[4]['binary_sha256'] != original['configurations'][1]['binary_sha256'],
                            'Library mutation has no effect')
                rows[4]['binary_sha256'] = original['configurations'][1]['binary_sha256']
            raw = (json.dumps(rows)+'\n').encode('utf-8')
        (directory/'trials.records.xml').write_bytes(raw)
        if name != 'changed_byte':
            data['raw'].update(sha256=sha_bytes(raw), bytes=len(raw))
        save(directory/'observations.xml', data)
        try:
            schema.recompute(directory/'observations.xml')
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            outcomes.append(dict(case=name, detected=True, reason=str(error)))
        else:
            raise ValueError('Tampered data accepted: '+name)
    field = '<field><name>ordinal</name><integer>0</integer></field>'
    for name, wire, body in (
        ('duplicate_field', '{"ordinal":0,"ordinal":0}', '<object>'+field+field+'</object>'),
        ('nan', '{"value":NaN}', '<number>NaN</number>'),
        ('positive_infinity', '{"value":Infinity}', '<number>Infinity</number>'),
        ('negative_infinity', '{"value":-Infinity}', '<number>-Infinity</number>'),
        ('overflow_number', '{"value":1e9999}', '<number>1e9999</number>'),
    ):
        try:
            schema.loads(wire)
        except ValueError:
            pass
        else:
            raise ValueError('Invalid wire input accepted: '+name)
        fixture = output/(name+'.xml')
        fixture.write_text('<record format="typed-xml-v1">'+body+'</record>\n', encoding='utf-8')
        try:
            schema.read(fixture)
        except ValueError as error:
            outcomes.append(dict(case=name, detected=True, reason=str(error)))
        else:
            raise ValueError('Invalid typed XML accepted: '+name)
    report = dict(status='PASS', observations_sha256=schema.sha(path), cases=outcomes)
    save(output/'result.xml', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    projection = sub.add_parser('project', help='Select scientific fields from a completed collector directory')
    projection.add_argument('--input', type=Path, required=True)
    projection.add_argument('--output', type=Path, required=True)
    projection.add_argument('--platform', choices=('windows_x86_64','linux_aarch64'), required=True)
    projection.add_argument('--resource-root', type=Path,
        help='Directory holding returned resource_evidence.xml files with the recorded hashes')
    validation = sub.add_parser('validate', help='Recompute public budgets and every retained outcome')
    validation.add_argument('observations', type=Path)
    validation.add_argument('--summary', type=Path)
    mutation = sub.add_parser('negative-tests', help='Exercise three data-integrity failures on copies')
    mutation.add_argument('observations', type=Path)
    mutation.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'project':
        result = project(args.input, args.output, args.platform, args.resource_root)
        print(json.dumps(result['counts']))
    elif args.action == 'negative-tests':
        print(json.dumps(negative_tests(args.observations, args.output)))
    else:
        result, _ = schema.recompute(args.observations)
        if args.summary:
            schema.validate_summary(schema.read(args.summary), args.observations)
        print(json.dumps(result['counts']))


if __name__ == '__main__':
    main()
