"""Check the fixed dataset-to-protocol boundary without executing collectors."""
import argparse,copy,unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import replay
BUNDLE=None
class Contract(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.tasks=replay.construct(BUNDLE.resolve(),{})
 def test_counts_and_controller_versions(self):
  self.assertEqual([b['jobs'] for b in self.tasks['batches']],[144,864,864,216,72,40,90])
  self.assertEqual(self.tasks['tasks'][0]['controller'],'constraints/run.py')
  self.assertEqual(self.tasks['tasks'][144]['controller'],'constraints/run_v2.py')
  self.assertTrue(replay.validate_tasks(self.tasks,BUNDLE))
 def test_changed_seed(self):
  d=copy.deepcopy(self.tasks);d['tasks'][-1]['seed']+=1
  with self.assertRaises(ValueError):replay.validate_tasks(d,BUNDLE)
 def test_changed_limit(self):
  d=copy.deepcopy(self.tasks);d['tasks'][150]['memory_max_bytes']*=2
  with self.assertRaises(ValueError):replay.validate_tasks(d,BUNDLE)
 def test_dropped_failure_condition(self):
  d=copy.deepcopy(self.tasks);d['tasks'].pop(1872)
  with self.assertRaises(ValueError):replay.validate_tasks(d,BUNDLE)
 def test_changed_controller(self):
  d=copy.deepcopy(self.tasks);d['tasks'][144]['controller']='constraints/run.py'
  with self.assertRaises(ValueError):replay.validate_tasks(d,BUNDLE)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True);a=p.parse_args();BUNDLE=a.bundle;unittest.main(argv=['test_replay'])
