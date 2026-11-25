"""Behavioral checks for explicit service-mix selection and resource identity."""
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from publicschemas.workload_selection import rank, normalize
from publicschemas.resources import CELLS


class WorkloadSelection(unittest.TestCase):
    def setUp(self):
        self.statistics=dict(schema='lattice.mean_tail_statistics.v1',dataset_id='paired',platform='windows_x86_64',
            configurations=[dict(id='a',library_sha256='a'*64),dict(id='b',library_sha256='b'*64)],cells=[])
        for name in ('a','b'):
            for p,o in sorted(CELLS):
                ns=100 if name=='a' else 200
                if (p,o)==(87,1):ns=1000 if name=='a' else 300
                self.statistics['cells'].append(dict(configuration=name,parameter=p,operation=o,statistics={'mean':{'ns':ns}}))
        self.budget=dict(schema='lattice.budget_query.v1',request=dict(timing_dataset='paired',platform='windows_x86_64'),
            selected=None,candidates=[dict(configuration=n,binary_sha256=n*64,core_reserved_bytes=10000,program_bytes=100000,equal_weight_18_operation_mean_ns=0) for n in ('a','b')],
            excluded=[dict(resource_id='too-large',reasons=['RAM_BUDGET_EXCEEDED'])])

    def test_service_mix_changes_choice(self):
        equal=rank(self.budget,self.statistics,[dict(parameter=p,operation=o,calls=1) for p,o in CELLS])
        signing=rank(self.budget,self.statistics,[dict(parameter=87,operation=1,calls=100)])
        self.assertEqual(equal['selected']['configuration'],'a')
        self.assertEqual(signing['selected']['configuration'],'b')
        self.assertEqual(signing['selected']['workload_total_service_ns'],30000)
        self.assertEqual(signing['excluded'],self.budget['excluded'])
        self.assertIsNone(self.budget['selected'])

    def test_scaling_does_not_change_average_or_choice(self):
        rows=[dict(parameter=87,operation=0,calls=1),dict(parameter=87,operation=1,calls=100)]
        first=rank(self.budget,self.statistics,rows)
        scaled=rank(self.budget,self.statistics,[dict(x,calls=7*x['calls']) for x in rows])
        self.assertEqual(first['selected']['configuration'],scaled['selected']['configuration'])
        self.assertAlmostEqual(first['selected']['workload_mean_ns'],scaled['selected']['workload_mean_ns'])
        self.assertAlmostEqual(first['selected']['workload_total_service_ns']*7,scaled['selected']['workload_total_service_ns'])

    def test_rejects_missing_or_mismatched_measurements(self):
        count=[dict(parameter=87,operation=1,calls=1)]
        for field,value in [('platform','linux_aarch64'),('dataset_id','different')]:
            data=copy.deepcopy(self.statistics);data[field]=value
            with self.assertRaises(ValueError):rank(self.budget,data,count)
        data=copy.deepcopy(self.statistics);data['configurations'][0]['library_sha256']='c'*64
        with self.assertRaises(ValueError):rank(self.budget,data,count)
        data=copy.deepcopy(self.statistics);data['cells'].pop()
        with self.assertRaises(ValueError):rank(self.budget,data,count)

    def test_rejects_ambiguous_counts(self):
        valid=dict(parameter=87,operation=1,calls=1)
        invalid=[[],[valid,valid],[dict(valid,calls=0)],[dict(valid,calls=-1)],
                 [dict(valid,calls=True)],[dict(valid,calls=1.5)],[dict(valid,calls=1000001)],
                 [dict(valid,parameter=66)],[dict(valid,operation=3)],[dict(valid,unknown=1)]]
        for rows in invalid:
            with self.subTest(rows=rows),self.assertRaises(ValueError):normalize(rows)

if __name__=='__main__':unittest.main()
