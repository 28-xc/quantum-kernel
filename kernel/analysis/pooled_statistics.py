"""Public-only pooled medians and a single paired-block PCG64 bootstrap.

Separate schema and fields from block_statistics.py's mean-ratio method.
All requested comparisons reuse the same configuration/cell median replicates.
"""
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
import json as _canonical_json
import argparse, hashlib, record_io as json, math, platform
import numpy as np
import pooled_model as model

SEED=202609230127
RESAMPLES=10000

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def canonical(value):return _canonical_json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def digest_value(value):return hashlib.sha256(canonical(value)).hexdigest()

def read(path):
    def pairs(items):
        out={}
        for k,v in items:
            model.need(k not in out,'Duplicate JSON key');out[k]=v
        return out
    def reject(value):raise ValueError('Nonfinite JSON: '+value)
    return json.loads(Path(path).read_text(encoding='utf-8-sig'),object_pairs_hook=pairs,parse_constant=reject)

def read_observations(path):
    model.need(Path(path).stat().st_size<=256*1024*1024,
               'Large inline observation JSON refused; use byte-exact CSV shard manifest')
    return read(path)

def write(path,value):
    path=Path(path).resolve();model.need(not path.exists(),'Fresh output required')
    model.need(path.drive.upper()=='D:' if platform.system()=='Windows' else True,'Windows output must stay on D')
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf-8')

def q7(x,p):return float(np.quantile(x,p,method='linear'))

class WeightedBlockCDF:
    """Exact repeated-whole-block quantile, inherited from the tested engine method."""
    def __init__(self,samples):
        x=np.asarray(samples,dtype=np.float64)
        model.need(x.ndim==2 and x.size and np.all(np.isfinite(x)) and np.all(x>0),'Positive rectangular samples required')
        self.blocks,self.n=x.shape;self.values=np.unique(x)
        self.cdf=np.column_stack([np.searchsorted(np.sort(b),self.values,side='right') for b in x]).astype(np.int32)
    def ranks(self,counts,rank):
        lo=np.zeros(len(counts),dtype=np.int64);hi=np.full(len(counts),len(self.values)-1,dtype=np.int64)
        while np.any(lo<hi):
            mid=(lo+hi)//2;below=np.einsum('ij,ij->i',self.cdf[mid],counts,dtype=np.int64)<=rank
            lo=np.where(below,mid+1,lo);hi=np.where(below,hi,mid)
        return self.values[lo]
    def quantiles(self,counts,p):
        counts=np.asarray(counts)
        model.need(counts.ndim==2 and counts.shape[1]==self.blocks and counts.dtype.kind in 'iu','Wrong block counts')
        model.need(np.all(counts>=0) and np.all(counts.sum(axis=1)==self.blocks) and 0<=p<=1,'Invalid whole-block draw')
        h=(self.blocks*self.n-1)*p;lo=self.ranks(counts,math.floor(h))
        return lo if h==math.floor(h) else lo+(h-math.floor(h))*(self.ranks(counts,math.ceil(h))-lo)

def draws(blocks,resamples,seed):
    model.integer(blocks,2);model.integer(resamples,1);model.integer(seed)
    rng=np.random.Generator(np.random.PCG64(seed))
    indices=rng.integers(0,blocks,size=(resamples,blocks),dtype=np.int64)
    counts=np.zeros((resamples,blocks),dtype=np.int32)
    np.add.at(counts,(np.arange(resamples)[:,None],indices),1)
    return counts,hashlib.sha256(indices.astype('<i8',copy=False).tobytes()).hexdigest()

def observations_arrays(data,base_dir=None):
    model.public_observations(data);e=data['experiment'];labels=[c['id'] for c in data['configurations']]
    arrays={(label,p,o):np.full((e['blocks'],e['samples_per_run']),np.nan) for label in labels for p,o in model.CELLS}
    paired={};timers=set();frequencies=set()
    if data['schema']=='lattice.block_observation_shards.v2':
        from pooled_shards import iter_runs
        model.need(base_dir is not None,'Public CSV shard directory required')
        sequence=iter_runs(data,base_dir)
    else:sequence=((s,r,r['samples']) for s,r in zip(data['schedule'],data['runs'],strict=True))
    for schedule,run,samples in sequence:
        key=(schedule['configuration'],schedule['parameter'],schedule['operation']);b=schedule['block']
        values=[x['elapsed_ns'] for x in samples if not x['warmup']]
        model.need(len(values)==e['samples_per_run'],'Missing samples')
        model.need(np.all(np.isfinite(values)) and np.all(np.asarray(values)>0),'Nonpositive timing; retained, not dropped')
        arrays[key][b]=values
        transcript=digest_value([[x[k] for k in ('case_id','entropy_sha256','message_sha256','context_sha256')] for x in samples])
        identity=(run['input_sequence_sha256'],run['output_sequence_sha256'],transcript)
        pair=(b,schedule['parameter'],schedule['operation'])
        model.need(pair not in paired or paired[pair]==identity,'Unpaired sample input/output identity')
        paired[pair]=identity;timers.add(run['timer']);frequencies.add(run['frequency'])
        del values,samples
    model.need(len(timers)==len(frequencies)==1 and None not in timers and None not in frequencies,'Inconsistent measurement clock')
    model.need(all(np.all(np.isfinite(x)) for x in arrays.values()),'Missing block/cell')
    return labels,arrays

def analyze(data,pairs,observations_sha256,resamples=RESAMPLES,seed=SEED,base_dir=None):
    labels,arrays=observations_arrays(data,base_dir);model.comparisons(pairs,labels);model.digest(observations_sha256)
    e=data['experiment'];counts,draw_hash=draws(e['blocks'],resamples,seed)
    replicates=np.empty((len(labels),18,resamples),dtype=np.float64);rows=[];medians={};means={}
    for li,label in enumerate(labels):
        for ci,(p,o) in enumerate(model.CELLS):
            x=arrays[label,p,o];flat=x.ravel();medians[label,p,o]=q7(flat,.5);means[label,p,o]=float(np.mean(flat))
            replicates[li,ci]=WeightedBlockCDF(x).quantiles(counts,.5)
            rows.append(dict(configuration=label,parameter=p,operation=o,pooled_samples=x.size,
                pooled_mean_ns=means[label,p,o],pooled_median_ns=medians[label,p,o],pooled_p95_ns=q7(flat,.95),
                pooled_p99_ns=q7(flat,.99),minimum_ns=float(np.min(flat)),maximum_ns=float(np.max(flat))))
    results=[]
    for pair in pairs:
        ref,cand=pair['reference'],pair['candidate'];ri,ci=labels.index(ref),labels.index(cand)
        ratios=replicates[ri]/replicates[ci]
        overall=np.exp(np.mean(np.log(ratios),axis=0));cellrows=[]
        for i,(p,o) in enumerate(model.CELLS):
            cellrows.append(dict(parameter=p,operation=o,pooled_median_ratio=medians[ref,p,o]/medians[cand,p,o],
                                 paired_complete_block_ci95=[q7(ratios[i],.025),q7(ratios[i],.975)]))
        families={}
        for name,ix in [('ML-KEM',list(range(9))),('ML-DSA',list(range(9,18)))]:
            boot=np.exp(np.mean(np.log(ratios[ix]),axis=0))
            families[name]=dict(median_ratio_geomean=math.exp(sum(math.log(cellrows[i]['pooled_median_ratio']) for i in ix)/9),
                                paired_complete_block_ci95=[q7(boot,.025),q7(boot,.975)])
        results.append(dict(**pair,cells=cellrows,
            equal_weight_18_cell_median_ratio_geomean=math.exp(sum(math.log(r['pooled_median_ratio']) for r in cellrows)/18),
            paired_complete_block_ci95=[q7(overall,.025),q7(overall,.975)],families=families,
            reference_equal_weight_mean_ns=sum(means[ref,p,o] for p,o in model.CELLS)/18,
            candidate_equal_weight_mean_ns=sum(means[cand,p,o] for p,o in model.CELLS)/18))
    summary=dict(schema=model.SCHEMA,**{k:data[k] for k in ('dataset_id','platform','execution','target_machine')},
        observations_sha256=observations_sha256,
        ordered_observations_digest=digest_value({'schedule':data['schedule'],'runs':data['runs']}),
        source_code_sha256=sha(__file__),configuration_order=labels,configurations=data['configurations'],
        cell_order=[list(c) for c in model.CELLS],
        method=dict(estimator='ratio_of_pooled_individual_medians',ratio_direction='reference_over_candidate',quantile='linear_type7',
            bootstrap_unit=model.BOOTSTRAP_UNIT,bootstrap_rng='PCG64',bootstrap_seed=seed,resamples=resamples,
            interval='percentile_0.025_0.975',block_draws_sha256=draw_hash,
            replicate_values_sha256=hashlib.sha256(replicates.astype('<f8',copy=False).tobytes()).hexdigest(),
            weighting='equal_18_operation_cells',slow_observation_policy='retain_all',
            warmup_policy='retain_in_observations_exclude_only_from_statistics',
            mixture_estimator='arithmetic_mean_of_component_pooled_means',interval_scope='pointwise_no_simultaneous_coverage_claim'),
        counts=dict(blocks=e['blocks'],samples_per_run=e['samples_per_run'],raw_rows=data['completeness']['sample_rows'],
            measured_rows=e['blocks']*e['samples_per_run']*len(labels)*18,
            warmup_rows=e['blocks']*e['warmups_per_run']*len(labels)*18,deleted_rows=0),
        cells=rows,comparisons=results,runtime=dict(python=platform.python_version(),numpy=np.__version__))
    model.validate(summary,data)
    return summary,dict(complete_block_counts=counts,pooled_median_replicates_ns=replicates)

def recompute(data,summary,observations_sha256,base_dir=None):
    model.validate(summary,data)
    model.need(summary['observations_sha256']==observations_sha256,'Observation artifact changed')
    model.need(summary['source_code_sha256']==sha(__file__),'Statistics source changed')
    pairs=[{k:p[k] for k in ('id','reference','candidate')} for p in summary['comparisons']]
    actual,_=analyze(data,pairs,observations_sha256,summary['method']['resamples'],summary['method']['bootstrap_seed'],base_dir=base_dir)
    for key in summary:
        if key!='runtime':model.need(actual[key]==summary[key],'Exact public statistics differ: '+key)
    return dict(status='EXACT_PUBLIC_POOLED_MEDIANS_RECOMPUTED',dataset_id=summary['dataset_id'],
                statistical_cells=len(summary['cells']),comparisons=len(pairs),bootstrap_rng='PCG64',
                block_draws_sha256=summary['method']['block_draws_sha256'],sample_rows=summary['counts']['raw_rows'])

def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    for action in ('derive','recompute'):
        s=sub.add_parser(action);s.add_argument('--observations',type=Path,required=True)
        if action=='derive':
            s.add_argument('--comparisons',type=Path,required=True);s.add_argument('--output',type=Path,required=True)
            s.add_argument('--replicates',type=Path);s.add_argument('--resamples',type=int,default=RESAMPLES);s.add_argument('--seed',type=int,default=SEED)
        else:s.add_argument('--summary',type=Path,required=True)
    a=parser.parse_args();data=read_observations(a.observations);identity=sha(a.observations)
    if a.action=='recompute':result=recompute(data,read(a.summary),identity,base_dir=a.observations.resolve().parent)
    else:
        summary,reps=analyze(data,read(a.comparisons),identity,a.resamples,a.seed,base_dir=a.observations.resolve().parent)
        if a.replicates:
            model.need(a.replicates.suffix=='.npz','Replicate artifact must have .npz suffix')
            model.need(not a.replicates.exists(),'Fresh replicate artifact required')
            model.need(a.replicates.resolve().drive.upper()=='D:' if platform.system()=='Windows' else True,'Windows output must stay on D')
            a.replicates.parent.mkdir(parents=True,exist_ok=True);np.savez_compressed(a.replicates,**reps)
        write(a.output,summary);result=dict(status='PUBLIC_POOLED_MEDIANS_DERIVED',dataset_id=data['dataset_id'],
                                           comparisons=len(summary['comparisons']),summary_sha256=sha(a.output))
    print(json.dumps(result))

if __name__=='__main__':main()
