"""Export public median-specific tables without renaming them as mean ratios."""
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
import argparse, csv, record_io as json, platform
import pooled_model as model
import pooled_statistics as stats

def export(observations,summary,output):
    model.validate(summary,observations);out=Path(output).resolve()
    model.need(not out.exists(),'Fresh export directory required')
    model.need(out.drive.upper()=='D:' if platform.system()=='Windows' else True,'Windows output must stay on D')
    out.mkdir(parents=True)
    def table(name,rows):
        with (out/name).open('w',newline='',encoding='utf-8') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    table('pooled_operation_statistics.csv',summary['cells'])
    rows=[];aggregate=[]
    for c in summary['comparisons']:
        for row in c['cells']:
            lo,hi=row['paired_complete_block_ci95']
            rows.append(dict(comparison=c['id'],reference=c['reference'],candidate=c['candidate'],
                parameter=row['parameter'],operation=row['operation'],pooled_median_ratio=row['pooled_median_ratio'],
                paired_block_ci95_low=lo,paired_block_ci95_high=hi))
        lo,hi=c['paired_complete_block_ci95']
        aggregate.append(dict(comparison=c['id'],reference=c['reference'],candidate=c['candidate'],
            equal_weight_18_cell_median_ratio_geomean=c['equal_weight_18_cell_median_ratio_geomean'],
            paired_block_ci95_low=lo,paired_block_ci95_high=hi))
    table('pooled_median_comparisons.csv',rows);table('pooled_median_aggregates.csv',aggregate)
    (out/'method.xml').write_text(json.dumps(summary['method'],indent=2)+'\n',encoding='utf-8')
    return dict(status='PUBLIC_MEDIAN_TABLES_EXPORTED',operation_rows=len(summary['cells']),comparison_rows=len(rows))

def main():
    p=argparse.ArgumentParser();p.add_argument('--observations',type=Path,required=True)
    p.add_argument('--summary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();o=stats.read_observations(a.observations);s=stats.read(a.summary)
    model.need(stats.sha(a.observations)==s['observations_sha256'],'Observation file identity changed')
    print(json.dumps(export(o,s,a.output)))
if __name__=='__main__':main()
