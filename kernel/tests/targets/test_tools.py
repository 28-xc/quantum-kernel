"""Synthetic parser negative controls and deterministic vector extraction."""
from pathlib import Path
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
import copy, importlib.util, record_io as json, tempfile, unittest
ROOT=Path(__file__).resolve().parents[2]
def load(p,n):
    s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
tool=load(ROOT/'tools/build_targets.py','target_tool')
vectors=load(Path(__file__).with_name('generate_vectors.py'),'vector_tool')

def synthetic_records():
    rows=[dict(event='begin',rng='test_callback_only'),dict(event='layout',pointer_bits=32,test_stack_reservation_bytes=16384),
          dict(event='watermark_positive_control',ok=True)]
    index=0
    for p in (44,65,87,512,768,1024):
        for op in range(3):
            kinds=['acvp_positive','short_length','alias','workspace_exhaustion','recovery_after_errors']
            if op<2:kinds+=['rng_failure','missing_rng']
            for kind in kinds:rows.append(dict(event='case',index=index,kind=kind,parameter=p,operation=op,ok=True,stack_watermark_bytes=1024))
            index+=1
            if p<100 and op==2:
                rows.append(dict(event='case',index=index,kind='acvp_negative',parameter=p,operation=op,ok=True,stack_watermark_bytes=1024));index+=1
    rows.append(dict(event='summary',cases=117,failures=0));return rows
def encode(rows):return '\n'.join(json.dumps(r) for r in rows)
class Tools(unittest.TestCase):
    def test_synthetic_complete(self):self.assertEqual(tool.parse_run(encode(synthetic_records()),{})['status'],'SUBSET_AND_BOUNDARY_CHECKS_PASSED')
    def test_missing(self):
        rows=synthetic_records();del rows[8]
        with self.assertRaises(ValueError):tool.parse_run(encode(rows),{})
    def test_duplicate(self):
        rows=synthetic_records();rows[5]=copy.deepcopy(rows[4])
        with self.assertRaises(ValueError):tool.parse_run(encode(rows),{})
    def test_failure(self):
        rows=synthetic_records();rows[4]['ok']=False
        with self.assertRaises(ValueError):tool.parse_run(encode(rows),{})
    def test_guard(self):
        rows=synthetic_records();rows[4]['stack_watermark_bytes']=16370
        with self.assertRaises(ValueError):tool.parse_run(encode(rows),{})
    def test_positive_control(self):
        rows=synthetic_records();rows[2]['ok']=False
        with self.assertRaises(ValueError):tool.parse_run(encode(rows),{})
    def test_wrong_abi(self):
        rows=synthetic_records();rows[1]['pointer_bits']=64
        with self.assertRaises(ValueError):tool.parse_run(encode(rows),{})
    def test_wrong_matrix(self):
        rows=synthetic_records();rows[4]['parameter']=999
        with self.assertRaises(ValueError):tool.parse_run(encode(rows),{})
    def test_vectors(self):
        # All outputs under D: on Windows, not the system temporary directory.
        scratch=ROOT/'test-output/target_tool_tests';scratch.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temp:
            result=vectors.generate(ROOT,Path(temp));self.assertEqual(result['positive_operation_cells'],18)
            self.assertEqual(result['negative_verify_cases'],3);self.assertEqual(len(result['cases']),21)
            again=vectors.generate(ROOT,Path(temp));self.assertEqual(result,again)
if __name__=='__main__':unittest.main()
