"""Recompute individual memory watermarks and fixed-budget observations."""
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
import argparse, record_io as json, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas.resource_watermarks_v1 import recompute

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--observations',type=Path,required=True)
    p.add_argument('--resources',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():raise ValueError('Fresh output required')
    result=recompute(a.observations,a.resources)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result['summary']))

if __name__=='__main__':main()
