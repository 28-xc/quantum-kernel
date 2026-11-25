"""Synthetic public-data tests; these are not cryptographic timing measurements."""
from pathlib import Path
import copy
import hashlib
import importlib.util
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
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from publicschemas import timing_v1 as model
spec = importlib.util.spec_from_file_location('public_recompute_timing', ROOT / 'tools/recompute_timing.py')
tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)


def fixture(root):
    rng = np.random.default_rng(12345)
    conditions = dict(timer='synthetic', unit='synthetic_units', cpu_logical=0,
        samples_per_record=100, warmup_before_record=0, class_batch_size=10,
        class_assignment='balanced_fisher_yates_xorshift64_per_block', checkpoints=[20, 50, 100],
        threshold_abs_t=4.5, statistics=model.STATISTICS, slow_observation_policy='retain_all',
        checkpoint_policy='all_registered_checkpoints_no_significance_early_stop',
        difference_direction='class1_minus_class0', welch_numerator='class0_minus_class1',
        second_moment_center='pooled_mean_at_each_checkpoint', familywise_error_probability_claimed=False,
        positive_control_definition='Synthetic fixture with additive class difference; no detector was executed.')
    jobs = []; records = []
    for rid, positive in [('000', False), ('001', True)]:
        classes = np.concatenate([rng.permutation([0]*5 + [1]*5) for _ in range(10)])
        a = np.column_stack((classes, rng.integers(80, 130, 100) + classes*(200 if positive else 0), np.zeros(100)))
        rel = f'raw/synthetic/{rid}.csv'; path = root / rel; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('class,tsc_ticks,norm_result\n' + ''.join(','.join(str(int(v)) for v in row)+'\n' for row in a), encoding='ascii')
        history = tool.compute_history(a, conditions)
        jobs.append(dict(record_id=rid, mode='keccak1', parameter=44, seed=12345, positive_control=positive))
        records.append(dict(record_id=rid, raw=dict(file=rel, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            bytes=path.stat().st_size, rows=100, columns=['class', 'tsc_ticks', 'norm_result']),
            reported_history=history, reported_detected=any(abs(h['welch_t']) >= 4.5 for h in history),
            norm_one_counts_by_class=[0, 0], input_fnv64='0'*16, actual_input_fnv64=None,
            public_segment_fnv64=None, key_pool_size=1, actual_module_checked=True, original_record=None,
            input_identity_sha256=dict.fromkeys(['public_pool', 'ciphertext', 'key_indices', 'public_rhos', 'polynomials']),
            log_sha256='0'*64))
    study = dict(study_id='synthetic', platform='synthetic', configuration='synthetic', phase='registered_screen',
        repeat_of=None, artifact_sha256='0'*64, core_source_sha256='0'*64,
        source_identity={k:'0'*64 for k in ['protocol_sha256', 'results_sha256', 'driver_sha256', 'runner_sha256',
            'executable_sha256', 'bindings_sha256', 'validation_sha256', 'base_driver_sha256', 'public_header_sha256']}, conditions=conditions,
        families=[dict(mode='keccak1', class_definition='Synthetic fixture only.', timed_region='No code was timed.',
            input_validity='Synthetic integers.', limits='Not a measured cryptographic experiment.')],
        jobs=jobs, records=records, environment_events=[], scope='Synthetic regression fixture only.')
    return dict(schema=model.SCHEMA, dataset_id='synthetic', study_order=['synthetic'], studies=[study],
                limitations=['Synthetic fixture; no cryptographic security claim.'])


class TimingTests(unittest.TestCase):
    def setUp(self):
        base = ROOT.parent / 'tmp'; base.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=base, prefix='public-timing-synthetic-')
        self.root = Path(self.tmp.name); self.data = fixture(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def manifest(self, data=None):
        p = self.root / 'observations.xml'
        p.write_text(json.dumps(self.data if data is None else data), encoding='utf-8')
        return p

    def test_complete_recompute_and_identity(self):
        result = tool.recompute(self.manifest()); model.validate_summary(result, self.data)
        self.assertEqual(result['raw_rows_checked'], 200)
        self.assertEqual(result['studies'][0]['positive_controls_detected'], 1)
        self.assertEqual(result['deleted_rows'], 0)

    def test_missing_positive_is_rejected(self):
        self.data['studies'][0]['records'].pop()
        with self.assertRaises(ValueError): model.validate(self.data)

    def test_structural_tampering(self):
        changes = [
            lambda d: d.update(secret_path='D:/private/key'),
            lambda d: d['studies'].clear(),
            lambda d: d['studies'][0]['jobs'].append(copy.deepcopy(d['studies'][0]['jobs'][0])),
            lambda d: d['studies'][0]['records'][0]['raw'].update(file='../secret.csv'),
            lambda d: d['studies'][0]['records'][0]['raw'].update(file='raw/synthetic/../000.csv'),
            lambda d: d['studies'][0]['records'][1]['raw'].update(file='raw/synthetic/000.csv'),
            lambda d: d['studies'][0]['records'][0].update(actual_module_checked=False),
            lambda d: d['studies'][0]['records'][0]['reported_history'].pop(),
            lambda d: d['studies'][0]['records'][0]['reported_history'][0].update(welch_t=float('nan')),
            lambda d: d['studies'][0]['conditions'].update(slow_observation_policy='trim'),
            lambda d: d['studies'][0]['conditions'].update(unit='ns'),
            lambda d: d['studies'][0]['conditions'].update(familywise_error_probability_claimed=True),
            lambda d: d['studies'][0].update(scope='Read /home/ubuntu/private/results.'),
            lambda d: d['studies'][0].update(phase='repeat_screen', repeat_of='omitted'),
            lambda d: d['studies'][0]['records'][0].update(original_record=dict(study_id='absent',record_id='000')),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                data = copy.deepcopy(self.data); change(data)
                with self.assertRaises(ValueError): model.validate(data)

    def test_raw_hash_and_reported_number_tampering(self):
        path = self.root / self.data['studies'][0]['records'][0]['raw']['file']
        path.write_text(path.read_text() + '\n')
        with self.assertRaises(ValueError): tool.recompute(self.manifest())
        self.data = fixture(self.root)
        self.data['studies'][0]['records'][0]['reported_history'][0]['mean0'] += 1
        with self.assertRaises(ValueError): tool.recompute(self.manifest())

    def test_summary_not_a_security_gate(self):
        summary = tool.recompute(self.manifest())
        summary['security_pass'] = True
        with self.assertRaises(ValueError): model.validate_summary(summary, self.data)

    def test_summary_wrong_effect_direction(self):
        summary = tool.recompute(self.manifest())
        summary['studies'][0]['records'][1]['final_class1_minus_class0'] *= -1
        with self.assertRaises(ValueError): model.validate_summary(summary, self.data)

    def test_pure_validators_do_not_open_files(self):
        summary = tool.recompute(self.manifest())
        with patch('builtins.open', side_effect=AssertionError('unexpected I/O')):
            model.validate_manifest(self.data)
            model.validate_summary(summary, self.data)

    def test_preserved_complete_repeat_and_changed_input(self):
        repeat = copy.deepcopy(self.data['studies'][0])
        repeat.update(study_id='repeat', phase='repeat_screen', repeat_of='synthetic')
        for record in repeat['records']:
            record['raw']['file'] = record['raw']['file'].replace('/synthetic/', '/repeat/')
        self.data['study_order'].append('repeat'); self.data['studies'].append(repeat)
        model.validate(self.data)
        repeat['records'][0]['input_fnv64'] = '1'*16
        with self.assertRaises(ValueError): model.validate(self.data)

    def test_complete_diagnostic_link_and_missing_origin_cell(self):
        original = self.data['studies'][0]
        original['families'][0]['mode'] = 'decaps_key'
        for job in original['jobs']: job.update(mode='decaps_key', parameter=512)
        extra_job = copy.deepcopy(original['jobs'][0]); extra_job.update(record_id='002', parameter=768)
        extra_record = copy.deepcopy(original['records'][0]); extra_record['record_id'] = '002'
        extra_record['raw']['file'] = 'raw/synthetic/002.csv'
        original['jobs'].append(extra_job); original['records'].append(extra_record)
        diagnostic = copy.deepcopy(original)
        diagnostic.update(study_id='diagnostic', phase='public_matrix_diagnostic')
        diagnostic['families'][0]['mode'] = 'public_matrix_diagnostic'
        diagnostic['jobs'] = [copy.deepcopy(j) for j in original['jobs'] if not j['positive_control']]
        wanted = {j['record_id'] for j in diagnostic['jobs']}
        diagnostic['records'] = [copy.deepcopy(r) for r in original['records'] if r['record_id'] in wanted]
        for j, r in zip(diagnostic['jobs'], diagnostic['records']):
            j['mode'] = 'public_matrix_diagnostic'
            r['original_record'] = dict(study_id='synthetic', record_id=r['record_id'])
            r['raw']['file'] = r['raw']['file'].replace('/synthetic/', '/diagnostic/')
        self.data['study_order'].append('diagnostic'); self.data['studies'].append(diagnostic)
        model.validate(self.data)
        diagnostic['jobs'].pop(); diagnostic['records'].pop()
        with self.assertRaises(ValueError): model.validate(self.data)

    def test_nonfinite_raw_rejected_even_with_updated_file_hash(self):
        record = self.data['studies'][0]['records'][0]
        path = self.root / record['raw']['file']
        rows = path.read_text().splitlines(); fields = rows[1].split(','); fields[1] = 'nan'
        rows[1] = ','.join(fields); path.write_text('\n'.join(rows)+'\n')
        record['raw'].update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)
        with self.assertRaises(ValueError): tool.recompute(self.manifest())


if __name__ == '__main__':
    unittest.main()
