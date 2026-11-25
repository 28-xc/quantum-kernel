"""Read-only integrity regressions using the supplied public trial observations.

All negative cases modify in-memory copies. No crypto invocation, compilation,
timing acquisition, original-data rewrite or fuzzing is performed.
"""
from pathlib import Path
import argparse
import copy
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from publicschemas.common_context_v1 import derive_artifact, read, shard, strict_line, validate_manifest


class CommonContext(unittest.TestCase):
    def reject(self, change):
        rows = copy.deepcopy(self.rows); change(rows)
        with self.assertRaises(ValueError): derive_artifact(self.artifact, self.point, rows)

    def reject_manifest(self, change):
        data = copy.deepcopy(self.data); change(data)
        with self.assertRaises(ValueError): validate_manifest(data, self.resources)

    def test_actual_complete_artifact(self):
        d = derive_artifact(self.artifact, self.point, self.rows)
        self.assertEqual(d['trials'], 68)
        self.assertEqual(d['fixed_reservation_sequences'], 48)
        self.assertEqual(d['fixed_reservation_operation_observations'], 864)
        self.assertEqual(len(d['fixed_reservation_cells']), 18)
        self.assertIsNone(d['simultaneous_observed_peak_bytes'])

    def test_other_platform_actual_artifact(self):
        d = derive_artifact(self.other_artifact, self.other_point, self.other_rows)
        self.assertEqual(d['stack_positive_controls'], 1)
        self.assertEqual(d['heap_positive_controls'], 1)

    def test_missing_trial(self): self.reject(lambda x: x.pop(8))
    def test_reordered_trials(self): self.reject(lambda x: x.reverse())
    def test_unknown_private_field(self): self.reject(lambda x: x[8]['result'].update(host_path='private'))
    def test_false_exit_success(self): self.reject(lambda x: x[8].update(exit_code=1))
    def test_false_classification(self): self.reject(lambda x: x[56].update(classification='SUCCESS'))
    def test_duplicate_confirmation_seed(self):
        def change(x):
            x[10]['arguments']['seed'] = x[8]['arguments']['seed']
            x[10]['result']['seed'] = x[8]['result']['seed']
        self.reject(change)

    def test_context_reset_inside_sequence(self): self.reject(lambda x: x[8]['result'].update(context_init_calls=2))
    def test_context_identity_change(self): self.reject(lambda x: x[8]['result'].update(context_and_arena_identity_stable=False))
    def test_omitted_operation(self): self.reject(lambda x: x[8]['result']['rows'].pop())
    def test_wrong_interleaving(self): self.reject(lambda x: x[8]['result']['rows'].reverse())
    def test_oom_recovery_missing(self): self.reject(lambda x: x[56]['result'].update(recovery_executed=False))
    def test_oom_output_not_cleared(self): self.reject(lambda x: x[56]['result']['rows'][-1].update(failure_outputs_cleared=False))
    def test_changed_secret_bytes_retained(self): self.reject(lambda x: x[8]['result']['rows'][0].update(changed_nonzero_released_bytes=1))
    def test_watermark_outside_bound(self):
        self.reject(lambda x: x[8]['result']['rows'][0].update(stack_watermark_bytes=x[8]['arguments']['stack_bytes'] + 1))

    def test_unaccounted_heap(self): self.reject(lambda x: x[8]['result'].update(outside_heap_calls=1))
    def test_heap_positive_absent(self): self.reject(lambda x: x[3]['result'].update(outside_heap_peak_requested_bytes=0))
    def test_unknown_fault(self): self.reject(lambda x: x[1].update(exit_code=17))
    def test_raw_fault_address_forbidden(self):
        def change(x):
            if x[1]['fault'] is None: x[1]['fault'] = {'event': 'stack_fault', 'protected_region_hit': True}
            x[1]['fault']['address_hex'] = 'ffffffff'
        self.reject(change)

    def test_budget_result_not_same_capacity(self):
        a = copy.deepcopy(self.artifact); a['reported_budget_trials'][0]['charged_core_bytes'] += 32
        with self.assertRaises(ValueError): derive_artifact(a, self.point, self.rows)

    def test_wrong_image_binding(self):
        a = copy.deepcopy(self.artifact); a['binary_sha256'] = '0' * 64
        with self.assertRaises(ValueError): derive_artifact(a, self.point, self.rows)

    def test_wrong_common_result_source(self):
        a = copy.deepcopy(self.artifact); a['source_sha256']['result'] = '0' * 64
        with self.assertRaises(ValueError): derive_artifact(a, self.point, self.rows)

    def test_bad_raw_sha(self):
        d = dict(self.artifact['raw']); d['sha256'] = '0' * 64
        with self.assertRaises(ValueError): shard(self.root, d)

    def test_path_escape(self):
        d = dict(self.artifact['raw']); d['path'] = '../internal/trials.records.xml'
        with self.assertRaises(ValueError): shard(self.root, d)

    def test_missing_method_version(self): self.reject_manifest(lambda x: x['method_sources'].pop())
    def test_method_private_path(self): self.reject_manifest(lambda x: x['method_sources'][0].update(path='D:/private/source.c'))
    def test_alias_shared_raw_path(self): self.reject_manifest(lambda x: x['artifacts'][1].update(raw=x['artifacts'][0]['raw']))
    def test_missing_library(self): self.reject_manifest(lambda x: x['artifacts'].pop())
    def test_bool_capacity(self): self.reject(lambda x: x[8]['arguments'].update(stack_bytes=True))
    def test_duplicate_json_key(self):
        with self.assertRaises(ValueError): strict_line('{"id":1,"id":2}')

    def test_nonfinite_json(self):
        with self.assertRaises(ValueError): strict_line('{"watermark":NaN}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--observations', type=Path, required=True)
    p.add_argument('--resources', type=Path, required=True)
    a = p.parse_args(); data = read(a.observations); resources = read(a.resources)
    validate_manifest(data, resources)
    CommonContext.data = data; CommonContext.resources = resources
    CommonContext.root = a.observations.resolve().parent
    pointmap = {x['id']: x for x in resources['points']}
    first = data['artifacts'][0]
    other = next(x for x in data['artifacts'] if x['platform'] != first['platform'])
    for prefix, artifact in (('', first), ('other_', other)):
        setattr(CommonContext, prefix + 'artifact', artifact)
        setattr(CommonContext, prefix + 'point', pointmap[artifact['resource_id']])
        setattr(CommonContext, prefix + 'rows', shard(CommonContext.root, artifact['raw']))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CommonContext))
    sys.exit(not result.wasSuccessful())


if __name__ == '__main__':
    main()
