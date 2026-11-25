"""Synthetic-only conservation, provenance and negative tests for public PMU."""
from pathlib import Path
import copy
import csv
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
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from publicschemas.pmu_v1 import SCHEMA, CELLS, COLUMNS, validate_manifest, validate_summary
from tools.recompute_pmu import recompute

SHA = 'a'*64


def digest(data): return hashlib.sha256(data).hexdigest()


def fixture(root):
    method = dict(event='cycles:u', sampling_mode='frequency', frequency_hz=199, cpu_index=2,
        attribution='leaf_self_no_children', percent_limit=0, recorded_call_graph='dwarf_4096_private_not_published',
        perf_version='synthetic fixture', count_meaning='retained_samples_and_sampled_event_periods',
        population='recorded_process_including_setup_and_external_code', elapsed_time_measurement=False)
    config = dict(id='synthetic-config', target_dso='libtest.so', library_sha256=SHA, crypto_sha256=SHA,
        driver_sha256=SHA, source_profile_result_sha256=SHA,
        source_hashes={name:SHA for name in ('profile_driver.c', 'driver.c', 'profile_linux.py', 'latticecore.h')})
    data = dict(schema=SCHEMA, dataset_id='synthetic-pmu', platform='synthetic', method=method,
        configuration_order=[config['id']], configurations=[config], cells=[], limitations=['Synthetic only.'],
        source_export_sha256=SHA, exporter_sha256=SHA)
    for p, o in CELLS:
        path = root/f'raw/{config["id"]}/{p}_{o}.csv'; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f, lineterminator='\n'); w.writerow(COLUMNS)
            w.writerow([0,'libtest.so','function_a','user',1,1,1,1])
            w.writerow([1,'libtest.so','function_b','user',1,2,100,1])
            w.writerow([2,'[unknown]','unresolved-leaf-2','kernel',0,1,9,0])
        blob = path.read_bytes()
        data['cells'].append(dict(configuration=config['id'], parameter=p, operation=o, iterations=10, seed=7,
            workload='fixed_serialized_input_key_and_message_fresh_operation_entropy', source_perf_data_sha256=SHA,
            source_report_sha256=SHA, source_stderr_sha256=SHA, total_samples=4, total_period=110,
            lost_samples=1, exact_header_samples=4, report_event_period=110,
            leaf_csv=dict(file=path.relative_to(root).as_posix(), sha256=digest(blob), bytes=len(blob), rows=3, columns=COLUMNS)))
    manifest = root/'observations.xml'; manifest.write_text(json.dumps(data), encoding='utf-8')
    return manifest, data


class PublicPMU(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.path, self.data = fixture(self.root)

    def test_integer_period_not_sample_count(self):
        summary = recompute(self.path); cell = summary['cells'][0]
        self.assertEqual((summary['leaf_rows'], summary['total_samples'], summary['total_period'], summary['lost_samples']), (54,72,1980,18))
        self.assertEqual(cell['leaves'][1]['sample_fraction_all'], 0.5)
        self.assertEqual(cell['leaves'][1]['period_fraction_all'], 100/110)
        self.assertEqual(cell['leaves'][1]['period_fraction_target'], 100/101)
        self.assertIsNone(cell['leaves'][2]['period_fraction_target'])
        self.assertEqual(cell['leaves'][2]['symbol_context'], 'kernel')
        self.assertEqual(summary['rows_removed'], 0)

    def test_pure_validation_has_no_io(self):
        summary = recompute(self.path)
        with patch.object(Path, 'open', side_effect=AssertionError('Unexpected IO')):
            validate_manifest(self.data); validate_summary(summary, self.data)

    def test_closed_manifest_negative_cases(self):
        changes = [lambda d:d['cells'].pop(), lambda d:d['cells'].append(d['cells'][0]),
            lambda d:d['cells'][0]['leaf_csv'].update(file='../private.csv'),
            lambda d:d.update(private_host='secret'), lambda d:d['method'].update(elapsed_time_measurement=True),
            lambda d:d['cells'][0].update(report_event_period=109),
            lambda d:d['cells'][0].update(exact_header_samples=3),
            lambda d:d['cells'][0].update(operation=False),
            lambda d:d['configurations'][0].update(target_dso='/home/private/lib.so')]
        for mutate in changes:
            with self.subTest(mutate=mutate):
                data = copy.deepcopy(self.data); mutate(data)
                with self.assertRaises(ValueError): validate_manifest(data)

    def test_raw_identity_and_count_tamper(self):
        raw = self.data['cells'][0]['leaf_csv']; path = self.root/raw['file']
        path.write_text(path.read_text().replace(',2,100,1', ',2,99,1'))
        with self.assertRaises(ValueError): recompute(self.path)
        blob = path.read_bytes(); raw.update(sha256=digest(blob), bytes=len(blob))
        self.path.write_text(json.dumps(self.data))
        with self.assertRaises(ValueError): recompute(self.path)

    def test_no_outside_deletion_or_relabel(self):
        summary = recompute(self.path)
        for mutate in (lambda s:s['cells'][0]['leaves'].pop(),
                       lambda s:s['cells'][0]['leaves'][2].update(target_module=True),
                       lambda s:s['cells'][0]['leaves'][2].update(symbol='0xffff12345678'),
                       lambda s:s['cells'][0]['leaves'][2].update(symbol_context='discarded')):
            s = copy.deepcopy(summary); mutate(s)
            with self.assertRaises(ValueError): validate_summary(s, self.data)

    def test_summary_binding_fractions_and_nonfinite(self):
        original = recompute(self.path)
        for mutate in (lambda s:s['cells'][0].update(leaf_csv_sha256='b'*64),
                       lambda s:s['cells'][0]['leaves'][0].update(period_fraction_all=float('nan')),
                       lambda s:s['cells'][0]['leaves'][0].update(period_fraction_all=0.5),
                       lambda s:s.update(total_period=2000), lambda s:s.update(rows_removed=1)):
            value=copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError): validate_summary(value,self.data)


if __name__ == '__main__': unittest.main()
