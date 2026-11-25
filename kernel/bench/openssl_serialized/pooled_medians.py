"""Pooled individual medians with whole, paired block bootstrap.

Companion to summarize_blocks.py: its mean estimator and all raw data remain
unchanged. The exact weighted-block CDF method is inherited from the project's
v1 tools/statistics.py; no individual calls or slow tails are resampled/dropped.
"""
from pathlib import Path, PureWindowsPath, PurePosixPath
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
import argparse, csv, hashlib, record_io as json, math, os, platform, re
import numpy as np
from run import validate_csv

CELLS=tuple((p,o) for p in (512,768,1024,44,65,87) for o in range(3))
SEED=202609230127
RESAMPLES=10000

def require(ok,message):
    if not ok: raise ValueError(message)
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def digest(s): return isinstance(s,str) and re.fullmatch('[0-9a-f]{64}',s) is not None
def read(p):
    def pairs(items):
        obj={}
        for k,v in items:
            require(k not in obj,'Duplicate JSON key: '+k);obj[k]=v
        return obj
    def nonfinite(value): raise ValueError('Nonfinite JSON: '+value)
    return json.loads(Path(p).read_text(encoding='utf-8'),object_pairs_hook=pairs,parse_constant=nonfinite)
def path_key(value):
    value=str(value)
    return str(PureWindowsPath(value)).casefold() if re.match(r'^[a-zA-Z]:[\\/]',value) else str(PurePosixPath(value))
def file_at(root,relative):
    result=(root/relative).resolve();require(result.is_relative_to(root),'Evidence path escapes study');return result
def q7(x,p): return float(np.quantile(x,p,method='linear'))

class WeightedBlockCDF:
    """Exactly select order statistics of repeated complete blocks, including ties."""
    def __init__(self,samples):
        x=np.asarray(samples,dtype=np.float64)
        require(x.ndim==2 and x.size and np.all(np.isfinite(x)) and np.all(x>0),'Positive finite rectangular samples required')
        self.blocks,self.n=x.shape;self.values=np.unique(x)
        self.cdf=np.column_stack([np.searchsorted(np.sort(batch),self.values,side='right') for batch in x]).astype(np.int32)
    def ranks(self,counts,ranks):
        lo=np.zeros(len(counts),dtype=np.int64);hi=np.full(len(counts),len(self.values)-1,dtype=np.int64)
        while np.any(lo<hi):
            mid=(lo+hi)//2;below=np.einsum('ij,ij->i',self.cdf[mid],counts,dtype=np.int64)<=ranks
            lo=np.where(below,mid+1,lo);hi=np.where(below,hi,mid)
        return self.values[lo]
    def quantiles(self,counts,p):
        counts=np.asarray(counts)
        require(counts.ndim==2 and counts.shape[1]==self.blocks and counts.dtype.kind in 'iu','Wrong block-count shape/type')
        require(np.all(counts>=0) and np.all(counts.sum(axis=1)==self.blocks) and 0<=p<=1,'Invalid block draw/probability')
        h=(self.blocks*self.n-1)*p;low=self.ranks(counts,math.floor(h))
        return low if h==math.floor(h) else low+(h-math.floor(h))*(self.ranks(counts,math.ceil(h))-low)

def block_draws(blocks,resamples=RESAMPLES,seed=SEED):
    require(type(blocks) is int and blocks>=2 and type(resamples) is int and resamples>0,'Invalid bootstrap size')
    rng=np.random.Generator(np.random.PCG64(seed));draws=rng.integers(0,blocks,size=(resamples,blocks),dtype=np.int64)
    counts=np.zeros((resamples,blocks),dtype=np.int32);np.add.at(counts,(np.arange(resamples)[:,None],draws),1)
    return counts,hashlib.sha256(draws.astype('<i8',copy=False).tobytes()).hexdigest()

def load_dataset(root):
    root=Path(root).resolve();result=read(root/'result.xml');manifest=read(root/'manifest.xml');records=read(root/'commands.xml')
    require(manifest.get('schema')=='latticecore.blocked.v1','Unknown acquisition schema')
    require(manifest.get('replication_unit')=='randomized complete block','Wrong experimental unit')
    require(result['status']=='PASS' and result.get('trimmed_rows')==0,'Failed/trimmed experiment')
    require(sha(root/'manifest.xml')==result['manifest_sha256'] and sha(root/'commands.xml')==result['commands_sha256'],'Changed experiment identity')
    cfg=manifest['configuration'];variants=cfg['configurations'];labels=[v['label'] for v in variants];n=cfg['blocks'];samples=cfg['samples'];warmups=cfg['warmups']
    require(type(n) is int and n>=2 and type(samples) is int and samples>0 and type(warmups) is int and warmups>=0,'Invalid matrix shape')
    require(len(labels)==len(set(labels)) and len(labels)>=2,'Repeated/missing configurations')
    schedule=manifest['schedule'];require(len(records)==len(schedule)==len(labels)*18*n,'Incomplete schedule')
    require(result.get('completed')==len(schedule) and result.get('blocks')==n and result.get('operation_cells')==18 and result.get('configurations')==labels,'Completion metadata differs from matrix')
    binary_map={path_key(p):h for p,h in manifest['binary_sha256'].items()}
    require(len(binary_map)==len(manifest['binary_sha256']) and all(digest(x) for x in binary_map.values()),'Ambiguous binary identities')
    require(path_key(cfg['driver']) in binary_map and path_key(cfg['crypto_library']) in binary_map,'Missing driver/provider identity')
    descriptors={}
    for v in variants:
        path=v['library'] if v['provider']=='lattice' else cfg['crypto_library']
        require(v['provider'] in ('lattice','openssl') and path_key(path) in binary_map,'Unknown implementation')
        descriptors[v['label']]={**v,'binary_sha256':binary_map[path_key(path)],'measured_library':path,
          'oracle_library_sha256':binary_map.get(path_key(v['library'])),'machine':manifest['machine'],'host':manifest['host'],
          'driver_sha256':binary_map[path_key(cfg['driver'])],'openssl_library_sha256':binary_map[path_key(cfg['crypto_library'])]}
    arrays={(label,p,o):np.full((n,samples),np.nan) for label in labels for p,o in CELLS}
    seen=set();paths=set();pairs={};raw_count=0;raw_index=[];frequencies=set();timers=set()
    for rec,planned in zip(records,schedule,strict=True):
        require(all(rec[k]==planned[k] for k in planned),'Schedule changed/reordered')
        b,p,o,vi=rec['block'],rec['parameter'],rec['operation'],rec['variant']
        require(type(b) is int and 0<=b<n and (p,o) in CELLS and type(vi) is int and 0<=vi<len(variants),'Unexpected matrix index')
        v=variants[vi];label=v['label'];require(rec['label']==label and rec['exit_code']==0,'Wrong label or failed run')
        key=(label,p,o,b);require(key not in seen,'Duplicate block/cell/configuration');seen.add(key)
        raw_path=file_at(root,rec['raw_csv']);require(raw_path not in paths,'Reused raw file across calls');paths.add(raw_path)
        for name,field in [('raw_csv','raw_sha256'),('log','log_sha256'),('stderr','stderr_sha256')]:
            require(sha(file_at(root,rec[name]))==rec[field],'Changed raw/log evidence')
        summary=read(file_at(root,rec['log']))
        expected={'status':'PASS','mode':'measure','parameter':p,'operation':o,'seed':rec['seed'],'samples':samples,'warmups':warmups,'cpu':cfg['cpu'],'backend':v['provider'],'import_pct':v['pct'],'message_bytes':cfg['message_bytes'],'context_bytes':cfg['context_bytes'],'workspace_reserved':v['workspace']}
        require(all(summary.get(k)==value for k,value in expected.items()),'Driver identity differs from scheduled call')
        require(path_key(summary['openssl_library'])==path_key(cfg['crypto_library']),'Wrong loaded OpenSSL')
        require(summary.get('fresh_serialized_key_every_call') is True and summary.get('entropy_mode')=='supplied_test_entropy','Wrong measurement boundary/entropy')
        require(summary.get('provider')=='default' and summary.get('message_encoding')==1 and summary.get('mu')==0,'Wrong cryptographic service semantics')
        require(digest(summary['input_sequence_sha256']) and digest(summary['output_sequence_sha256']),'Invalid transcript identity')
        rows=validate_csv(file_at(root,rec['raw_csv']),summary);raw_count+=len(rows)
        transcript=hashlib.sha256()
        for row in rows:
            transcript.update(('\t'.join(row[k] for k in ('case_id','entropy_sha256','message_sha256','context_sha256'))+'\n').encode())
        identity=(summary['input_sequence_sha256'],summary['output_sequence_sha256'],transcript.hexdigest())
        pair=(p,o,b);require(pair not in pairs or pairs[pair]==identity,'Unpaired input/output transcript');pairs[pair]=identity
        obs=np.asarray([float(r['elapsed_ns']) for r in rows if r['warmup']=='0'])
        require(len(obs)==samples and np.all(np.isfinite(obs)) and np.all(obs>0),'Nonpositive/nonfinite timing; retained, not replaced')
        arrays[label,p,o][b]=obs
        require(abs(float(np.mean(obs))-rec['mean_ns'])<=1e-8*max(float(np.mean(obs)),1),'Recorded mean differs from raw')
        require(abs(q7(obs,.5)-rec['median_ns'])<=1e-8*max(q7(obs,.5),1),'Recorded median differs from raw')
        frequencies.add(summary['frequency']);timers.add(summary['timer'])
        raw_index.append({'raw_csv':rec['raw_csv'],'sha256':rec['raw_sha256'],'block':b,'label':label,'parameter':p,'operation':o})
    require(raw_count==result['raw_rows'] and all(np.all(np.isfinite(x)) for x in arrays.values()),'Missing samples/blocks')
    require(len(seen)==len(labels)*18*n and len(frequencies)==1 and len(timers)==1,'Incomplete or inconsistent timer matrix')
    return {'root':root,'manifest':manifest,'configuration':cfg,'arrays':arrays,'labels':labels,'descriptors':descriptors,'raw_count':raw_count,'raw_index':raw_index,'timer':next(iter(timers)),'frequency':next(iter(frequencies))}

def analyze(data,reference,resamples=RESAMPLES,seed=SEED):
    labels=data['labels'];require(reference in labels,'Reference is not in this study')
    arrays=data['arrays'];cfg=data['configuration'];counts,draw_hash=block_draws(cfg['blocks'],resamples,seed)
    replicates=np.empty((len(labels),18,resamples));medians={};rows=[]
    for li,label in enumerate(labels):
        for ci,(p,o) in enumerate(CELLS):
            x=arrays[label,p,o];flat=x.ravel();medians[label,p,o]=q7(flat,.5)
            replicates[li,ci]=WeightedBlockCDF(x).quantiles(counts,.5)
            rows.append({'configuration':label,'parameter':p,'operation':o,'blocks':cfg['blocks'],'samples_per_block':cfg['samples'],'pooled_samples':x.size,'pooled_mean_ns':float(np.mean(flat)),'pooled_median_ns':medians[label,p,o],'pooled_p95_ns':q7(flat,.95),'pooled_p99_ns':q7(flat,.99),'minimum_ns':float(np.min(flat)),'maximum_ns':float(np.max(flat))})
    bi=labels.index(reference);ratios=replicates[bi][None,:,:]/replicates;overall=np.exp(np.mean(np.log(ratios),axis=1));configs=[]
    for li,label in enumerate(labels):
        selected=[r for r in rows if r['configuration']==label]
        for ci,row in enumerate(selected):
            p,o=CELLS[ci];row.update(reference=reference,pooled_median_ratio=medians[reference,p,o]/medians[label,p,o],ratio_ci95=[q7(ratios[li,ci],.025),q7(ratios[li,ci],.975)])
        point=math.exp(sum(math.log(r['pooled_median_ratio']) for r in selected)/18)
        families={}
        for name,indices in [('ML-KEM',list(range(9))),('ML-DSA',list(range(9,18)))]:
            boot=np.exp(np.mean(np.log(ratios[li,indices,:]),axis=0));families[name]={'median_ratio_geomean':math.exp(sum(math.log(selected[j]['pooled_median_ratio']) for j in indices)/9),'ci95':[q7(boot,.025),q7(boot,.975)]}
        configs.append({'identity':data['descriptors'][label],'cells':selected,'equal_weight_18_cell_median_ratio_geomean':point,'paired_complete_block_ci95':[q7(overall[li],.025),q7(overall[li],.975)],'families':families,'equal_weight_mean_of_component_medians_ns':sum(r['pooled_median_ns'] for r in selected)/18,'equal_weight_mean_of_component_means_ns':sum(r['pooled_mean_ns'] for r in selected)/18})
    result={'schema':'latticecore.pooled_medians.r2.v1','status':'ANALYZED',
      'study_role':cfg['study_role'],'reference':reference,'estimator':'ratio of pooled individual medians; equal-weight 18-cell geometric mean','quantile':'linear_type7',
      'bootstrap_unit':'one complete paired block, all configurations/cells/within-block samples together','resamples':resamples,'bootstrap_rng':'PCG64','bootstrap_seed':seed,'block_draws_sha256':draw_hash,
      'block_count':cfg['blocks'],'samples_per_cell_block':cfg['samples'],'raw_rows_checked':data['raw_count'],'warmups_retained_but_excluded':len(labels)*18*cfg['blocks']*cfg['warmups'],'deleted_samples':0,
      'uncertainty_scope':'Intervals resample the observed complete blocks; small block counts give limited information about between-block variation. Sample counts and study_role are retained for downstream interpretation.',
      'mixture_scope':'Arithmetic averages of component medians are descriptive proxies for the specified equal-operation mixture, not measured workload latency.',
      'configuration_order':labels,'cell_order':[list(x) for x in CELLS],'timer':data['timer'],'frequency':data['frequency'],'configurations':configs,'runtime':{'python':platform.python_version(),'numpy':np.__version__}}
    return result,{'complete_block_counts':counts,'pooled_median_replicates_ns':replicates,'cell_median_ratio_replicates':ratios,'overall_median_ratio_geomeans':overall}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--reference',required=True);p.add_argument('--seed',type=int,default=SEED);a=p.parse_args()
    out=a.output.resolve();require(not out.exists(),'Fresh output required');require(0<a.seed<2**63,'Invalid bootstrap seed')
    require(os.name!='nt' or out.drive.upper()=='D:','Windows output must stay on D:')
    data=load_dataset(a.input);report,reps=analyze(data,a.reference,seed=a.seed);root=data['root'];out.mkdir(parents=True)
    archive=out/'paired_bootstrap.npz';np.savez_compressed(archive,**reps)
    table=[]
    for c in report['configurations']:
        for row in c['cells']:
            r=dict(row);r['binary_sha256']=c['identity']['binary_sha256'];r['ratio_ci95_low'],r['ratio_ci95_high']=r.pop('ratio_ci95');table.append(r)
    with (out/'operation_medians.csv').open('w',newline='',encoding='utf-8') as f:
        writer=csv.DictWriter(f,fieldnames=list(table[0]));writer.writeheader();writer.writerows(table)
    report.update(source_root=str(root),source_result_sha256=sha(root/'result.xml'),source_manifest_sha256=sha(root/'manifest.xml'),source_commands_sha256=sha(root/'commands.xml'),analysis_code_sha256=sha(Path(__file__)),raw_validator_sha256=sha(Path(__file__).with_name('run.py')),replicates_sha256=sha(archive),table_sha256=sha(out/'operation_medians.csv'))
    (out/'summary.xml').write_bytes((json.dumps(report,indent=2,allow_nan=False)+'\n').encode())
    print(json.dumps({'status':'ANALYZED','study_role':report['study_role'],'blocks':report['block_count'],'configurations':len(report['configurations']),'estimator':report['estimator'],'summary_sha256':sha(out/'summary.xml')}))

if __name__=='__main__':main()
