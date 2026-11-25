"""Finite boundary checks for registered fixed-owner observations; no target calls."""
import argparse
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas import application_owner_v1 as model, science
from publicschemas.application_v1 import read, loads
from demo.presentation import configuration_title, primitive_title, result_export

DATA=None


class OwnerViews(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.obs=read(DATA);cls.summary=model.recompute(DATA)

    def changed(self, change):
        d=copy.deepcopy(self.obs);change(d)
        with self.assertRaises(ValueError):model.validate_observations(d)

    def test_complete_recompute(self):
        n=len(self.obs['configurations'])
        self.assertEqual(self.summary['counts']['processes'],216*n)
        self.assertEqual((len(self.summary['cells']),len(self.summary['comparisons'])),(24*n,12*(2*n)*(2*n-1)//2))
        self.assertEqual(self.summary['counts']['trimmed_processes'],0)

    def test_unknown_top_field(self):self.changed(lambda d:d.update(private_goal=True))
    def test_missing_field(self):self.changed(lambda d:d.pop('provenance'))
    def test_unknown_method(self):self.changed(lambda d:d['method'].update(p95='individual'))
    def test_changed_scope(self):self.changed(lambda d:d['method'].update(timed_scope='flows only'))
    def test_changed_replicates(self):self.changed(lambda d:d['method']['statistics'].update(replicates=10000))
    def test_changed_units(self):self.changed(lambda d:d['method'].update(unit='individual flow'))
    def test_missing_run(self):self.changed(lambda d:d['jobs'].pop())
    def test_reordered_run(self):self.changed(lambda d:d['jobs'].reverse())
    def test_duplicate_block(self):self.changed(lambda d:d['jobs'][24*len(d['configurations'])].update(block=0))
    def test_failed_process(self):self.changed(lambda d:d['jobs'][0].update(exit_code=1))
    def test_boolean_exit(self):self.changed(lambda d:d['jobs'][0].update(exit_code=False))
    def test_unknown_job(self):self.changed(lambda d:d['jobs'][0].update(command='hidden'))
    def test_absolute_path(self):self.changed(lambda d:d['jobs'][0]['raw'].update(path='D:/data/x'))
    def test_traversal(self):self.changed(lambda d:d['jobs'][0]['raw'].update(path='../x'))
    def test_duplicate_config(self):self.changed(lambda d:d['configurations'][1].update(id=d['configurations'][0]['id']))
    def test_wrong_application(self):self.changed(lambda d:d['configurations'][1].update(application_sha256='0'*64))
    def test_unaligned_workspace(self):self.changed(lambda d:d['configurations'][0].update(workspace_bytes=33))
    def test_incomplete_resource_rows(self):self.changed(lambda d:d['resources'][0]['records'].pop())
    def test_unknown_resource_cell(self):self.changed(lambda d:d['resources'][0]['cells'][0].update(goal_pass=True))
    def test_recovery_conditions_cannot_be_replaced_by_duplicates(self):
        data=copy.deepcopy(self.obs)
        resource=next((r for r in data['resources'] if len(r['records'])==62),None)
        if resource is None:self.skipTest('This observation set has no capacity-recovery records')
        replacements={}
        base=DATA.parent
        for label in ('insufficient','restored'):
            rows=[r for r in resource['records'] if r['label']==label]
            template=model.raw_rows(base,rows[0]['raw'])
            for row in rows[1:]:replacements[row['raw']['path']]=template
        original=model.raw_rows
        def synthetic_recovery(base,spec):
            return copy.deepcopy(replacements[spec['path']]) if spec['path'] in replacements else original(base,spec)
        with patch.object(model,'raw_rows',side_effect=synthetic_recovery),self.assertRaises(ValueError):
            model._resource_replay(data,base)
    def test_nonfinite(self):
        for value in ('NaN','Infinity','1e999'):
            with self.assertRaises(ValueError):loads('{"x":'+value+'}')
    def test_duplicate_json(self):
        with self.assertRaises(ValueError):loads('{"a":1,"a":2}')
    def test_raw_hash_and_length(self):
        with tempfile.TemporaryDirectory() as t:
            import record_io
            p=Path(t)
            raw=p/'a.records.xml'
            record_io.write(raw,[{'n':1}])
            blob=raw.read_bytes()
            d=dict(path=raw.name,sha256=hashlib.sha256(blob).hexdigest(),bytes=len(blob))
            self.assertEqual(model.raw_rows(p,d),[{'n':1}])
            for change in ({'sha256':'0'*64},{'bytes':len(blob)+1}):
                with self.assertRaises(ValueError):model.raw_rows(p,d|change)
    def library(self):
        c=self.summary['configurations'][0]
        return dict(platform=self.summary['platform'],configuration=c['id'],binary_sha256=c['binary_sha256'],workspace_bytes=c['workspace_bytes'])
    def test_current_identity(self):
        s=science.summary(self.summary,self.library())
        self.assertEqual(len(s['resources']),6);self.assertEqual(len(s['cells']),24)
    def test_wrong_binary(self):self.assertIsNone(science.summary(self.summary,self.library()|{'binary_sha256':'0'*64}))
    def test_wrong_workspace(self):self.assertIsNone(science.summary(self.summary,self.library()|{'workspace_bytes':32}))
    def test_wrong_platform(self):self.assertIsNone(science.summary(self.summary,self.library()|{'platform':'other'}))
    def test_wrong_id(self):self.assertIsNone(science.summary(self.summary,self.library()|{'configuration':'history'}))
    def test_archive_kept(self):
        s=science.summary(self.summary);n=len(self.obs['configurations'])
        self.assertEqual(len(s['resources']),6*n);self.assertEqual(len(s['cells']),24*n)
    def test_csv_keeps_all(self):
        import csv,io
        rows=list(csv.DictReader(io.StringIO(model.samples_csv(self.summary))))
        n=len(self.obs['configurations']);comparisons=12*(2*n)*(2*n-1)//2
        self.assertEqual(len(rows),30*n+comparisons)
        self.assertEqual(sum(r['record_type']=='paired_ratio' for r in rows),comparisons)
        self.assertNotIn('p95',model.samples_csv(self.summary))
    def test_throughput_interval_direction(self):
        for c in self.summary['cells']:
            self.assertLessEqual(c['ci95_flows_per_second'][0],c['ci95_flows_per_second'][1])
            self.assertEqual(c['complete_flows_per_second'],c['flows']*1e9/c['mean_batch_ns'])
    def test_primitive_labels_are_contextual(self):
        self.assertEqual(primitive_title('native-balanced'),'原生算术后端')
        self.assertEqual(primitive_title('portable-compact'),'可移植算术后端')
        self.assertEqual(configuration_title('native-balanced'),'小缓存实现')
        d=dict(schema='lattice.primitive_samples_statistics.v1',dataset_id='test',cells=[dict(configuration='native-balanced')])
        self.assertEqual(result_export(d)['configuration_titles']['native-balanced'],'原生算术后端')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--observations',type=Path,required=True);a,rest=p.parse_known_args();DATA=a.observations.resolve()
    unittest.main(argv=[sys.argv[0],*rest])
