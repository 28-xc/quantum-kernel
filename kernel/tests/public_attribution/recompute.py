"""Replay every shared-provider timing observation and paired block estimate."""
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
import argparse, record_io as json, math, sys
import numpy as np
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from publicschemas.timing_attribution_v1 import check_files
from publicschemas.shared_keccak_v1 import need,sha
import _four as four
import _six as six

def equal(a,b,where='$'):
 if type(a)is dict:
  need(set(a)==set(b),where+': result fields differ')
  for k in a:equal(a[k],b[k],where+'.'+k)
 elif type(a)is list:
  need(len(a)==len(b),where+': list length differs')
  for i,(x,y) in enumerate(zip(a,b)):equal(x,y,where+f'[{i}]')
 elif type(a)is float:need(math.isclose(a,b,rel_tol=1e-10,abs_tol=1e-9),where+': numerical replay differs')
 else:need(a==b,where+': value differs')

def load(root,job,cells):
 n=job['condition']['groups'];frame=np.loadtxt(root/job['files']['.csv']['path'],delimiter=',',skiprows=1,dtype=np.int64)
 need(frame.shape==(n*2*cells,7),'Raw dimensions differ');block,group,key,lib,combo,pos,ticks=frame.T
 width=2*cells
 need(np.array_equal(group,np.repeat(np.arange(n),width)) and np.array_equal(block,group//1000),'Group/block identity differs')
 need(np.all(np.sort((lib*cells+combo).reshape(n,width),axis=1)==np.arange(width)),'Cells are unbalanced')
 need(np.array_equal(pos,np.tile(np.arange(width),n)),'Position identity differs')
 need(np.all(key.reshape(n,width)==key.reshape(n,width)[:,0,None]) and np.all(ticks>0),'Paired input/timer differs')
 values=np.empty((n,2,cells));values[group,lib,combo]=ticks
 return values,key.reshape(n,width)[:,0],lib,combo,pos

def four_cells(root,study):
 rng=np.random.default_rng(study['bootstrap_seed']);records=[];hyp=[]
 for job in study['jobs']:
  values,keyidx,library,comb,position=load(root,job,4);n=job['condition']['groups']
  keys=four.workload((root/job['files']['.public.bin']['path']).read_bytes());mask=np.array([keys[k]['any_tail'] for k in keyidx]).reshape(-1,1000)
  indices=rng.integers(0,n//1000,(20000,n//1000));libs=[]
  for lib in range(2):
   contrasts={};strata={}
   for name,co in four.COEFFICIENTS.items():
    difference=(values[:,lib,:]@np.array(co)).reshape(-1,1000)
    summary=four.paired_summary(difference,indices);contrasts[name]=summary
    strata[name]={label:four.stratum_summary(difference,m,indices) for label,m in [('zero_extra_rounds',~mask),('extra_rounds',mask)]}
    if not job['condition']['positive'] and name in ['related','public_main','secret_main','interaction']:hyp.append(summary)
   libs.append(dict(library=lib,cell_mean_ticks=values[:,lib,:].mean(axis=0).tolist(),cell_std_ticks=values[:,lib,:].std(axis=0,ddof=1).tolist(),
    contrasts=contrasts,public_strata=strata,position_counts=np.bincount(comb[library==lib]*8+position[library==lib],minlength=32).reshape(4,8).tolist()))
  result=dict(job=job['condition'],raw_sha256=job['files']['.csv']['sha256'],libraries=libs,public_workload=keys,fixed_workload=keys[0],
   random_extra_x1=float(np.mean([keys[k]['extra_x1'] for k in keyidx])),random_extra_x4=float(np.mean([keys[k]['extra_x4'] for k in keyidx])),
   random_tail_groups=int(mask.sum()),total_groups=n)
  if job['condition']['positive']:
   bits=np.frombuffer((root/job['files']['.positive_bits.bin']['path']).read_bytes(),dtype=np.uint8)
   result['positive_control']=dict(fixed_bit=int(bits[0]),random_one_fraction=float(bits[keyidx].mean()),expected_secret_main_direction=int(np.sign(bits[keyidx].mean()-bits[0])))
  records.append(result)
 last=0
 for rank,r in enumerate(sorted(hyp,key=lambda r:r['p_unadjusted'])):
  last=max(last,min(1,r['p_unadjusted']*(len(hyp)-rank)));r['p_holm_24']=last
 equal(records,study['results'])

def six_cells(root,study):
 rng=np.random.default_rng(study['bootstrap_seed']);records=[];hyp=[]
 for job in study['jobs']:
  values,keyidx,_,_,_=load(root,job,6);n=job['condition']['groups'];indices=rng.integers(0,n//1000,(20000,n//1000));contrasts={};difference={}
  for name,coefficients in six.CO.items():
   d=values@np.array(coefficients);contrasts[name]=[six.summary(d[:,i],indices) for i in range(2)]
   difference[name]=six.summary(d[:,1]-d[:,0],indices)
   if not job['condition']['positive']:hyp.append(difference[name])
  profiles=six.workload((root/job['files']['.public.bin']['path']).read_bytes(),job['condition']['parameter'])
  mask=np.array([profiles[k]['extra_x1']>0 for k in keyidx]).reshape(-1,1000);strata={}
  for name in ['related','public_main','rho_main','secret_rho']:
   d=values@np.array(six.CO[name]);arms=[]
   for i in range(2):
    sums=[];diff=d[:,i].reshape(-1,1000)
    for label,select in [('random_no_extra_x1',~mask),('random_extra_x1',mask)]:
     totals=(diff*select).sum(axis=1);counts=select.sum(axis=1);need(counts.sum()>0,'Empty public stratum')
     boot=totals[indices].sum(axis=1)/counts[indices].sum(axis=1)
     sums.append(dict(stratum=label,groups=int(counts.sum()),mean_ticks=float(totals.sum()/counts.sum()),ci95=np.quantile(boot,[.025,.975]).tolist()))
    arms.append(sums)
   strata[name]=arms
  result=dict(job=job['condition'],raw_sha256=job['files']['.csv']['sha256'],cell_means=values.mean(axis=0).tolist(),within_library=contrasts,
   candidate_minus_control=difference,public_workload=profiles,fixed_public_work=profiles[0],
   random_extra_x1_mean=float(np.mean([profiles[k]['extra_x1'] for k in keyidx])),strata=strata,all_observations_retained=True)
  if job['condition']['positive']:
   bits=np.frombuffer((root/job['files']['.positive_bits.bin']['path']).read_bytes(),dtype=np.uint8)
   result['positive_fixed_bit']=int(bits[0]);result['positive_random_one_fraction']=float(bits[keyidx].mean())
  records.append(result)
 last=0
 for rank,r in enumerate(sorted(hyp,key=lambda r:r['p'])):
  last=max(last,min(1,r['p']*(len(hyp)-rank)));r['p_holm36']=last
 equal(records,study['results'])

def screen(root,study):
 for job in study['jobs']:
  a=np.loadtxt(root/job['raw']['path'],delimiter=',',skiprows=1,dtype=np.float64)
  need(a.shape==(100000,3) and np.isfinite(a).all(),'Raw screen shape/value differs');history=[]
  for n in study['checkpoints']:
   x=a[:n];center=x[:,1].mean()
   for name,z in [('raw_mean',x[:,1]),('centered_second_moment',(x[:,1]-center)**2)]:
    u=z[x[:,0]==0];v=z[x[:,0]==1];den=np.sqrt(u.var(ddof=1)/len(u)+v.var(ddof=1)/len(v))
    need(len(u)==n//2 and len(v)==n//2 and den>0,'Unbalanced screen classes')
    history.append(dict(samples=n,statistic=name,welch_t=float((u.mean()-v.mean())/den),n0=len(u),n1=len(v),mean0=float(u.mean()),mean1=float(v.mean())))
  equal(history,job['history']);equal(any(abs(x['welch_t'])>=study['threshold_abs_t'] for x in history),job['detected'])
  equal([int(a[a[:,0]==c,2].sum()) for c in [0,1]],job['norm_one_counts_by_class'])

def main():
 p=argparse.ArgumentParser();p.add_argument('observations',type=Path);p.add_argument('--output',type=Path);a=p.parse_args();path=a.observations.resolve()
 checked=check_files(path);data=json.loads(path.read_text());root=path.parent
 for study in data['studies']:
  {'complete-key-factorial':four_cells,'portable-rho-factorial':six_cells,'shared-screen':screen}[study['id']](root,study)
  print(json.dumps(dict(study=study['id'],status='PASS',retained_samples=study['retained_samples'])),flush=True)
 result=dict(**checked,recomputed_studies=3,bootstrap_resamples=20000,replay_source_sha256=sha(Path(__file__)))
 if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
