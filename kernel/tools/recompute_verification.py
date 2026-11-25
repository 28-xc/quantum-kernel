"""Recompute public verification counts from a closed, ordered dataset."""
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
import argparse, hashlib, record_io as json, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas.verification_v2 import validate,recompute
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('data',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
 raw=a.data.read_bytes();d=json.loads(raw,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite number')));validate(d)
 result={'schema':'lattice.verification_recomputed.v1','input_sha256':hashlib.sha256(raw).hexdigest(),'summary':recompute(d),'records_match_summary':True}
 text=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
 if a.output:
  if a.output.exists():raise ValueError('Fresh output required')
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(text,encoding='utf-8')
 else:print(text,end='')
if __name__=='__main__':main()
