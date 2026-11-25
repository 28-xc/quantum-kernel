from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas.tradeoffs_v1 import frontier,AXES

def point(name,ram,program,time):return dict(id=name,**dict(zip(AXES,(ram,program,time))))

class FrontierCases(unittest.TestCase):
 def test_ram_program_latency_tradeoff(self):
  points=[point('tiny',16,128,8),point('small_code',32,64,7),point('fast',64,256,2),point('worse',64,256,9)]
  self.assertEqual([p['id'] for p in frontier(points)],['tiny','small_code','fast'])
 def test_equal_coordinates_keep_distinct_implementations(self):
  points=[point('a',16,64,2),point('b',16,64,2),point('c',16,65,2)]
  self.assertEqual([p['id'] for p in frontier(points)],['a','b'])
 def test_each_axis_can_independently_dominate(self):
  points=[point('a',1,1,1),point('ram',2,1,1),point('code',1,2,1),point('time',1,1,2)]
  self.assertEqual([p['id'] for p in frontier(points)],['a'])
 def test_invalid_observations(self):
  for value in (float('nan'),float('inf'),0,-1):
   with self.assertRaises(ValueError):frontier([point('invalid',1,1,value)])
if __name__=='__main__':unittest.main(verbosity=2)
