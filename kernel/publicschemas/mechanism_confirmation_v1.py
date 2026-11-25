"""Recompute complete-operation mechanism comparisons from every retained CSV row."""
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
import argparse, csv, hashlib, io, record_io as json, math, statistics, sys, importlib.util
import numpy as np
sys.dont_write_bytecode=True

def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def require(ok,message):
    if not ok:raise ValueError(message)
def recompute(root):
    root=Path(root);p=read(root/'protocol.xml');require(p['schema']=='lattice.mechanism_confirmation.v1','Protocol schema')
    require(p['blocks']==20 and p['samples']==500 and p['warmups']==20,'Experiment dimensions')
    require(len(p['arms'])==7 and len(p['batches'])==2520,'Complete seven-arm schedule')
    model_path=root/'deployment_image.py';require(sha(model_path.read_bytes())==p['deployment_model_sha256'],'Deployment model identity')
    spec=importlib.util.spec_from_file_location('confirmation_deployment_image',model_path);model=importlib.util.module_from_spec(spec);spec.loader.exec_module(model)
    for arm,record in p['arms'].items():
        model.load_deployment_image(root/record['image_path'],root/record['derivation_path'],record['derivation_sha256'],measured_sha256=record['measured_image_sha256'],binary_sha256=record['deployment_image_sha256'])
    cells=[(q,o)for q in (512,768,1024,44,65,87)for o in range(3)];lookup={};paired={};rawrows=0
    columns=['case_id','iteration','warmup','elapsed_ticks','tick_frequency','elapsed_ns','status','entropy_sha256','message_sha256','context_sha256']
    for ordinal,batch in enumerate(p['batches']):
        require(batch['ordinal']==ordinal,'Schedule ordering')
        path=(root/batch['raw_path']).resolve();require(path.is_relative_to(root.resolve()),'CSV path')
        raw=path.read_bytes();require(sha(raw)==batch['raw_sha256'],'CSV identity: '+batch['raw_path'])
        reader=csv.DictReader(io.StringIO(raw.decode('utf-8')));require(reader.fieldnames==columns,'CSV columns');rows=list(reader)
        require(len(rows)==520,'Warmup and measured row count');rawrows+=len(rows);times=[];fingerprints=[]
        for n,row in enumerate(rows):
            require(int(row['iteration'])==n-20 and int(row['warmup'])==int(n<20),'Iteration sequence')
            require(int(row['status'])==0 and int(row['tick_frequency'])==batch['tick_frequency'],'Call result or timer identity')
            elapsed=float(row['elapsed_ns']);ticks=int(row['elapsed_ticks']);require(math.isfinite(elapsed)and elapsed>=0 and ticks>=0,'Finite duration')
            require(abs(elapsed-ticks*1e9/batch['tick_frequency'])<=0.00051,'Timer conversion')
            fingerprints.append(tuple(row[k]for k in ('case_id','iteration','warmup','entropy_sha256','message_sha256','context_sha256')))
            if n>=20:times.append(elapsed)
        key=(batch['arm'],batch['block'],batch['parameter'],batch['operation']);require(key not in lookup,'Duplicate operation batch')
        lookup[key]=statistics.mean(times)
        pairkey=key[1:];identity=(fingerprints,batch['input_sequence_sha256'],batch['output_sequence_sha256'])
        if pairkey in paired:require(paired[pairkey]==identity,'Paired inputs or outputs differ')
        else:paired[pairkey]=identity
    require(rawrows==1310400 and len(paired)==360,'Complete observation count')
    B=p['blocks'];arrays={arm:np.array([[lookup[(arm,b,q,o)]for q,o in cells]for b in range(B)])for arm in p['arms']}
    draw=np.random.default_rng(p['statistics']['seed']).integers(0,B,size=(p['statistics']['resamples'],B));results=[];aggregates=[]
    for comp in p['comparisons']:
        a,b=comp['candidate'],comp['reference'];ratios=arrays[a].mean(0)/arrays[b].mean(0)
        boot=arrays[a][draw].mean(1)/arrays[b][draw].mean(1)
        for j,(q,o)in enumerate(cells):
            results.append(dict(comparison=comp['id'],candidate=a,reference=b,parameter=q,operation=o,mean_ns=float(arrays[a][:,j].mean()),reference_mean_ns=float(arrays[b][:,j].mean()),time_ratio=float(ratios[j]),ci95=np.quantile(boot[:,j],[.025,.975]).tolist(),paired_block_ratios=(arrays[a][:,j]/arrays[b][:,j]).tolist()))
        for group,ids in [('all18',list(range(18))),('three_signatures',[10,13,16])]:
            total=float(arrays[a].mean(0)[ids].sum()/arrays[b].mean(0)[ids].sum())
            totalboot=arrays[a][draw].mean(1)[:,ids].sum(1)/arrays[b][draw].mean(1)[:,ids].sum(1)
            aggregates.append(dict(comparison=comp['id'],candidate=a,reference=b,operations=group,equal_frequency_time_ratio=total,equal_frequency_ci95=np.quantile(totalboot,[.025,.975]).tolist(),geometric_time_ratio=float(np.exp(np.log(ratios[ids]).mean())),geometric_ci95=np.quantile(np.exp(np.log(boot[:,ids]).mean(1)),[.025,.975]).tolist()))
    means=[dict(arm=arm,parameter=q,operation=o,mean_ns=float(arrays[arm][:,j].mean()),block_means_ns=arrays[arm][:,j].tolist())for arm in p['arms']for j,(q,o)in enumerate(cells)]
    return dict(schema='lattice.mechanism_confirmation_summary.v1',protocol_sha256=sha((root/'protocol.xml').read_bytes()),status='RECOMPUTED',blocks=B,raw_rows=rawrows,measured_rows=1260000,warmup_rows=50400,batches=len(lookup),resamples=p['statistics']['resamples'],bootstrap_seed=p['statistics']['seed'],resample_unit='complete matched block',all_raw_rows_retained=True,arms=p['arms'],cells=results,aggregate=aggregates,complete_operation_means=means)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--data',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    require(not a.output.exists(),'Output must be a new file');v=recompute(a.data);a.output.write_text(json.dumps(v,indent=2,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf-8')
    print(json.dumps(dict(status=v['status'],batches=v['batches'],raw_rows=v['raw_rows'],comparisons=len(v['aggregate'])//2)))
if __name__=='__main__':main()
