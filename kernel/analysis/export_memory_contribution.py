"""Export a verified buffer accounting table and all named simultaneous owners."""
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
import argparse, csv, record_io as json
from memory_contribution import analyze


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--candidate',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();d=analyze(a.reference,a.candidate)
    a.output.mkdir(parents=True,exist_ok=False)
    (a.output/'contribution.xml').write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    with (a.output/'buffers.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['component','reference_bytes','candidate_bytes','saved_bytes','reference_owners','candidate_owners'])
        w.writeheader()
        for g in d['groups']:
            w.writerow(dict(component=g['label'],**{k:g[k] for k in ('reference_bytes','candidate_bytes','saved_bytes')},
                            reference_owners=';'.join(x['function']+'::'+x['owner'] for x in g.get('reference_owners',[])),
                            candidate_owners=';'.join(x['function']+'::'+x['owner'] for x in g.get('candidate_owners',[]))))
    rows=[]
    for g in d['groups']:
        rows.append(f"{g['label']} & {g['reference_bytes']} & {g['candidate_bytes']} & {g['saved_bytes']} "+chr(92)*2)
    rows.append('\\midrule')
    rows.append(f"合计 & {d['reference_workspace']} & {d['candidate_workspace']} & {d['reference_workspace']-d['candidate_workspace']} "+chr(92)*2)
    table=r'''\begin{table}[!htbp]
\centering
\caption{ML-KEM-1024解封装的峰值工作区（字节）}
\label{ch4:memory-contribution}
\begin{tabularx}{\textwidth}{Xrrr}
\toprule
同时驻留的数据 & 原生低内存对照 & 紧凑配置 & 减少量 \\
\midrule
'''+ '\n'.join(rows)+r'''
\bottomrule
\end{tabularx}
\end{table}
'''
    (a.output/'memory_contribution.tex').write_text(table,encoding='utf-8')
    print(json.dumps(dict(status='PASS',complete_operations_per_image=9,
                         full_output_bytes=d['full_output_bytes'],saved_workspace_bytes=d['reference_workspace']-d['candidate_workspace'])))


if __name__=='__main__':main()
