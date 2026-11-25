"""Export the complete measured resource frontier and twenty budget queries."""
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
import argparse, csv, record_io as json, sys
sys.path[:]=[p for p in sys.path if Path(p or '.').resolve()!=Path(__file__).resolve().parent]
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas.profiling_v1 import read,sha,need
from publicschemas.tradeoffs_v1 import derive,AXES

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('observations','statistics','resources','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();need(not a.output.exists(),'Fresh output required')
 observations=read(a.observations);statistics=read(a.statistics);resources=read(a.resources)
 need(statistics['observations_sha256']==sha(a.observations),'Observation identity differs')
 result=derive(observations,statistics,resources)
 result['inputs_sha256']=dict(observations=sha(a.observations),statistics=sha(a.statistics),resources=sha(a.resources))
 a.output.mkdir(parents=True)
 (a.output/'tradeoffs.xml').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 fields=('configuration','binary_sha256','workspace_bytes',*AXES)
 with (a.output/'all_measured_points.csv').open('w',newline='',encoding='utf-8') as fp:
  writer=csv.DictWriter(fp,fieldnames=fields);writer.writeheader()
  writer.writerows({k:v[k] for k in fields} for v in result['points'])
 print(json.dumps(dict(status='FINITE_MEASURED_TRADEOFFS_EXPORTED',points=len(result['points']),frontier=len(result['nondominated_points']),budget_queries=len(result['budget_queries']))))
if __name__=='__main__':main()
