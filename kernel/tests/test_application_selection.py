"""Application choice uses complete memory and measured batch identities."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas.application_selection import select
from publicschemas.application_owner_v1 import SUMMARY


class ApplicationSelection(unittest.TestCase):
    def setUp(self):
        self.profiles=dict(profiles=[])
        self.data=dict(schema=SUMMARY,dataset_id='measured',platform='windows_x86_64',
                       observations_sha256='e'*64,configurations=[],cells=[],resources=[])
        for name,digest,ram,time in [('compact','a',30000,500),('speed','b',99000,100)]:
            self.data['configurations'].append(dict(id=name,binary_sha256=digest*64,application_sha256='c'*64,workspace_bytes=ram-20000))
            self.profiles['profiles'].append(dict(platform='windows_x86_64',configuration=name,binary_sha256=digest*64,workspace_bytes=ram-20000))
            self.data['cells'].append(dict(configuration=name,kem=1024,dsa=87,flows=200,fresh_identity=0,layout=1,mean_batch_ns=time,ci95_batch_ns=[time-10,time+10]))
            self.data['resources'].append(dict(configuration=name,kem=1024,dsa=87,layout=1,charged_bytes=ram,program_bytes=200000))
        self.request=dict(platform='windows_x86_64',kem=1024,dsa=87,flows=200,fresh_identity=0,ram_bytes=65536,program_bytes=262144)

    def test_complete_application_budget_changes_choice(self):
        r=select([self.data],self.profiles,self.request)
        self.assertEqual(r['selected']['configuration'],'compact')
        self.assertEqual(r['excluded'][0]['reasons'],['APPLICATION_RAM_BUDGET_EXCEEDED'])
        r=select([self.data],self.profiles,dict(self.request,ram_bytes=131072))
        self.assertEqual(r['selected']['configuration'],'speed')
        self.assertEqual(r['selected']['ci95_batch_ns'],[90,110])

    def test_no_match_and_old_image_cannot_be_selected(self):
        self.assertIsNone(select([self.data],self.profiles,dict(self.request,program_bytes=1000))['selected'])
        altered=copy.deepcopy(self.profiles);altered['profiles'][0]['binary_sha256']='f'*64
        self.assertIsNone(select([self.data],altered,self.request)['selected'])

    def test_refuses_unmeasured_workload_or_ambiguous_repeat(self):
        for k,v in [('flows',201),('dsa',65),('fresh_identity',2),('ram_bytes',True)]:
            with self.assertRaises(ValueError):select([self.data],self.profiles,dict(self.request,**{k:v}))
        with self.assertRaises(ValueError):select([self.data,self.data],self.profiles,self.request)

if __name__=='__main__':unittest.main()
