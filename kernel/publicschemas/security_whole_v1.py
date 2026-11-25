"""Independently recompute frozen-image timing observations; never run crypto."""
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
import argparse, hashlib, record_io as json, math, os
os.environ.setdefault('OPENBLAS_NUM_THREADS','1')
os.environ.setdefault('OMP_NUM_THREADS','1')
import numpy as np
from scipy.stats import t as student_t

DT=np.dtype([(n,'<u8') for n in ('start_tsc','elapsed_tsc','thread_cycles','output_fnv')]+[(n,'<u4') for n in ('pair_id','source_index','key','condition','cpu_before','cpu_after','rc','slot')]+[('out','u1',(32,))])
assert DT.itemsize==96
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def write(p,v):Path(p).write_text(json.dumps(v,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
def require(value,message):
    if not value:raise ValueError(message)
MASK=(1<<64)-1
def step(s):
    s^=(s<<13)&MASK;s^=s>>7;s^=(s<<17)&MASK;return s&MASK
def orders(seed,n):
    out=np.empty((50000,n),dtype=np.int16)
    for i in range(-128,50000):
        v=list(range(n))
        for q in range(n-1,0,-1):seed=step(seed);z=seed%(q+1);v[q],v[z]=v[z],v[q]
        if i>=0:out[i]=v
    return out
def fnv(a):
    r=np.full(len(a),1469598103934665603,dtype=np.uint64)
    with np.errstate(over='ignore'):
        for col in a.T:r=(r^col)*np.uint64(1099511628211)
    return r
def stat(a,boot):
    n=len(a);mean=float(np.mean(a));se=float(np.std(a,ddof=1)/math.sqrt(n))
    require(se>0,'Degenerate phase variance')
    t=mean/se;q=float(student_t.ppf(.975,n-1))
    return dict(blocks=n,mean=mean,se=se,t=t,p=float(2*student_t.sf(abs(t),n-1)),block_t_ci95=[mean-q*se,mean+q*se],bootstrap_ci95=np.quantile(boot,[.025,.975],method='linear').tolist())
def holm(values):
    v=np.asarray(values);order=np.argsort(v);res=np.empty(len(v));res[order]=np.minimum(1,np.maximum.accumulate(v[order]*(len(v)-np.arange(len(v)))))
    return res.tolist()

def whole(path,j,p):
    a=np.loadtxt(path,delimiter=',',skiprows=1,dtype=np.float64)
    require(a.shape==(j['formal_calls'],3) and np.isfinite(a).all(),'Whole raw dimensions/nonfinite')
    require(np.isin(a[:,0],[0,1]).all() and (a[:,1]>=0).all() and np.equal(a[:,1],np.floor(a[:,1])).all() and not a[:,2].any(),'Whole class/ticks/return')
    require(np.all(a[:,0].reshape(-1,1000).sum(axis=1)==500),'Whole balanced blocks')
    history=[]
    for n in p['whole_analysis']['checkpoints']:
        x=a[:n];center=x[:,1].mean()
        for name,z in [('raw_mean',x[:,1]),('centered_second_moment',(x[:,1]-center)**2)]:
            u=z[x[:,0]==0];v=z[x[:,0]==1];v0=float(u.var(ddof=1));v1=float(v.var(ddof=1));d=float(u.mean()-v.mean());se=math.sqrt(v0/len(u)+v1/len(v))
            require(se>0,'Degenerate whole variance')
            t=d/se;df=(v0/len(u)+v1/len(v))**2/((v0/len(u))**2/(len(u)-1)+(v1/len(v))**2/(len(v)-1))
            history.append(dict(samples=n,statistic=name,n0=len(u),n1=len(v),mean0=float(u.mean()),mean1=float(v.mean()),variance0=v0,variance1=v1,mean_difference_fixed_minus_variable=d,welch_t=t,welch_df=df,pointwise_normal_ci95=[d-1.959963984540054*se,d+1.959963984540054*se]))
    return dict(job=j,raw_sha256=sha(path),retained_samples=len(a),history=history,detected=any(abs(r['welch_t'])>=p['whole_analysis']['threshold_abs_t'] for r in history))


def verify_dependency(root,path,record):
    receipt=path.with_name(path.name+'.derivation.xml')
    if record['path']=='images/representative.dll' and receipt.exists():
        import importlib.util
        spec=importlib.util.spec_from_file_location('measured_image_contract',root/'deployment_image.py')
        model=importlib.util.module_from_spec(spec);spec.loader.exec_module(model)
        derivation=read(receipt)
        result=model.verify_deployment_image(path.read_bytes(),derivation,measured_sha256=record['sha256'])
        require(derivation['original_bytes']==record['bytes'],'Original image length differs')
    else:
        require(path.stat().st_size==record['bytes'] and sha(path)==record['sha256'],'Dependency identity: '+record['path'])

def recompute(data):
    p=read(data/'protocol.xml');m=read(data/'measurement.xml')
    require(p['schema']=='lattice.security_protocol.v1','Protocol schema')
    require(m['status']=='COMPLETED' and m['protocol_sha256']==sha(data/'protocol.xml'),'Unfinished/mismatched measurement')
    phase_enabled=p['phase_enabled']
    expected_jobs=33 if phase_enabled else 21
    expected_calls=8700000 if phase_enabled else 2100000
    require(len(m['records'])==len(p['jobs'])==expected_jobs,'Expected all predeclared phase and whole jobs')
    require([r['job'] for r in m['records']]==p['jobs'],'Job order/identity')
    require(sum(j['formal_calls'] for j in p['jobs'])==expected_calls==m['formal_calls'],'Expected complete registered formal call count')
    for r in p['dependencies']:
        f=data/r['path'];verify_dependency(data,f,r)
    rng=np.random.Generator(np.random.PCG64(p['phase_analysis']['pcg64_seed']))
    draws=rng.integers(0,100,size=(3,10000,100))
    counts=np.array([[(row[:,None]==np.arange(100)).sum(0) for row in dd] for dd in draws])
    phase=[];full=[];pool={}
    for rec in m['records']:
        j=rec['job'];r=rec['raw'];path=data/r['path']
        require(sha(path)==r['sha256'] and path.stat().st_size==r['bytes'],'Raw identity')
        if j['family']=='whole':full.append(whole(path,j,p));continue
        nc=6 if j['kind']=='original' else 8;slots=1 if nc==6 else 2;calls=nc*slots
        d=np.fromfile(path,dtype=DT);require(len(d)==50000*calls==j['formal_calls'],'Phase count')
        pairs=np.fromfile(data/j['inputs']/'pairs.bin',dtype='<u4').reshape(50000,2)
        expected=np.fromfile(data/j['inputs']/'expected_phase.bin',dtype='u1').reshape(257*nc,1600)
        require(np.all((pairs[:,0]>=1)&(pairs[:,0]<=256)),'Key index range')
        oo=orders(j['seed'],calls)
        require(np.array_equal(d['pair_id'],np.repeat(np.arange(50000),calls)) and np.array_equal(d['key'],np.repeat(pairs[:,0],calls)) and np.array_equal(d['source_index'],np.repeat(pairs[:,1],calls)),'Phase pair/key sequence')
        require(np.array_equal(d['condition'],oo.ravel()%nc) and np.array_equal(d['slot'],oo.ravel()//nc),'Phase shuffled conditions/addresses')
        require(all(not np.any(d[n]) for n in ('cpu_before','cpu_after','rc')) and np.all(d['start_tsc'][1:]>d['start_tsc'][:-1]),'Phase CPU/return/monotonic order')
        ids=d['key']*nc+d['condition']
        require(np.array_equal(d['out'],expected[ids,32:64]) and np.array_equal(d['output_fnv'],fnv(expected)[ids]),'Phase independent expected output')
        mapping=p['phase_analysis']['original_contrasts' if nc==6 else 'field_contrasts'];names=list(mapping);weights=np.asarray(list(mapping.values())).T
        result=dict(job=j,raw_sha256=r['sha256'],validated_samples=len(d),clocks={})
        for clock in ('elapsed_tsc','thread_cycles'):
            x=np.empty((50000,slots,nc),dtype=np.float64);x[d['pair_id'],d['slot'],d['condition']]=d[clock]
            blocks=(x@weights).reshape(100,500,slots,-1).mean(axis=1);avg=blocks.mean(axis=1)
            pool.setdefault((j['parameter'],j['kind'],clock),{})[j['repeat']]=avg
            results={}
            for k,name in enumerate(names):
                values=avg[:,k];s=stat(values,counts[j['repeat']]@values/100)
                s['first_half_mean']=float(values[:50].mean());s['last_half_mean']=float(values[50:].mean())
                s['by_slot']=[stat(blocks[:,z,k],counts[j['repeat']]@blocks[:,z,k]/100) for z in range(slots)]
                if slots==2:s['address_interaction']=stat(blocks[:,1,k]-blocks[:,0,k],counts[j['repeat']]@(blocks[:,1,k]-blocks[:,0,k])/100)
                results[name]=s
            result['clocks'][clock]=dict(conditions_mean=x.mean(axis=0).tolist(),conditions_median=np.median(x,axis=0).tolist(),maximum=int(x.max()),contrasts=results)
        phase.append(result)
    pooled=[];primary=[]
    targets={(r['parameter'],r['kind'],r['contrast']) for r in p['phase_analysis']['primary']}
    for (parameter,kind,clock),repeats in sorted(pool.items()):
        require(set(repeats)=={0,1,2},'Missing phase repeat')
        names=list(p['phase_analysis']['original_contrasts' if kind=='original' else 'field_contrasts'])
        values=np.concatenate([repeats[r] for r in range(3)],axis=0)
        boot=sum(counts[r]@repeats[r]/100 for r in range(3))/3
        for k,name in enumerate(names):
            s=stat(values[:,k],boot[:,k]);s.update(parameter=parameter,kind=kind,clock=clock,contrast=name,repeat_means=[float(repeats[r][:,k].mean()) for r in range(3)])
            pooled.append(s)
            if clock=='elapsed_tsc' and (parameter,kind,name) in targets:primary.append(s)
    require(len(primary)==(4 if phase_enabled else 0),'Registered number of primary phase effects')
    for r,h in zip(primary,holm([r['p'] for r in primary])):r['holm_p_four_primary']=h
    target=[r for r in full if not r['job']['positive']];controls=[r for r in full if r['job']['positive']]
    control_valid=all(r['detected'] for r in controls)
    return dict(schema='lattice.security_summary.v1',image=p['representative'],source_manifest_sha256=p['source_manifest_sha256'],
        protocol_sha256=sha(data/'protocol.xml'),measurement_sha256=sha(data/'measurement.xml'),analysis_source_sha256=sha(__file__),
        formal_calls=expected_calls,deleted_samples=0,phase_calls=6600000 if phase_enabled else 0,whole_target_calls=1800000,known_difference_calls=300000,
        phase_primary=primary,phase_pooled_all=pooled,phase_records=phase,whole_records=full,
        whole_target_signal_count=sum(r['detected'] for r in target),positive_detected_count=sum(r['detected'] for r in controls),positive_total=len(controls),
        detector_status='VALID' if control_valid else 'INVALID_POSITIVE_CONTROL',
        interpretation='Image-specific finite software observation; report all phase effects and whole checkpoints separately. Each measured configuration retains its recorded image identity. No automatic constant-time or security PASS.')

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--data',type=Path,required=True);ap.add_argument('--output',type=Path);a=ap.parse_args()
    output=a.output or a.data/'summary.xml'
    if output.exists():raise FileExistsError(output)
    value=recompute(a.data);write(output,value);print(output)
if __name__=='__main__':main()
