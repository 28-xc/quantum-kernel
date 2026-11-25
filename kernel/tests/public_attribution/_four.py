"""Frozen estimators and public-input work model for independent data replay."""
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
import argparse, hashlib, record_io as json

import numpy as np


import _stats as stats

COEFFICIENTS={
 'related':[-1,0,0,1], 'public_fixed_secret':[-1,0,1,0],
 'public_random_secret':[0,-1,0,1], 'secret_fixed_public':[-1,1,0,0],
 'secret_random_public':[0,0,-1,1], 'public_main':[-.5,-.5,.5,.5],
 'secret_main':[-.5,.5,-.5,.5], 'interaction':[1,-1,-1,1]}

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def need(c,m):
 if not c:raise ValueError(m)

def workload(public):
 """Exact public-rho block requirement under the reviewed production schedule."""
 need(len(public)==257*1600,'Pool dimensions')
 keys=[]
 for key in range(257):
  data=public[key*1600:(key+1)*1600]
  need(hashlib.sha3_256(data[:1568]).digest()==data[1568:],'Embedded public hash')
  rho=data[1536:1568];extras=[];proposals=[]
  for row in range(4):
   for col in range(4):
    stream=hashlib.shake_128(rho+bytes((row,col)));blocks=3;accepted=0;processed=0;tested=0
    while accepted<256:
     buf=stream.digest(blocks*168)
     for offset in range(processed,len(buf),3):
      for value in ((buf[offset]|buf[offset+1]<<8)&4095,(buf[offset+1]>>4)|(buf[offset+2]<<4)):
       tested+=1;accepted+=value<3329
       if accepted==256:break
      if accepted==256:break
     if accepted<256:processed=len(buf);blocks+=1
    extras.append(blocks-3);proposals.append(tested)
  x1=sum(extras[:8]);x4=max(extras[8:12])+max(extras[12:16])
  keys.append(dict(index=key,extra_x1=x1,extra_x4=x4,extra_rej=x1+4*x4,
                   any_tail=bool(x1+x4),polynomial_extra_blocks=extras,
                   semantic_candidates=proposals))
 return keys

def paired_summary(values,indices):
 means=values.mean(axis=1);estimate=float(means.mean());se=float(means.std(ddof=1)/np.sqrt(len(means)))
 samples=means[indices].mean(axis=1);ci=np.quantile(samples,[.025,.975])
 t,p=stats.ttest_1samp(means,0)
 return dict(mean_ticks=estimate,block_standard_error=se,ci95_ticks=ci.tolist(),
             block_t=float(t),p_unadjusted=float(p),blocks=len(means),groups=int(values.size))

def stratum_summary(values,mask,indices):
 sums=(values*mask).sum(axis=1);counts=mask.sum(axis=1)
 need(counts.sum()>0,'Empty predefined public stratum')
 boot=sums[indices].sum(axis=1)/counts[indices].sum(axis=1)
 return dict(mean_ticks=float(sums.sum()/counts.sum()),groups=int(counts.sum()),
             ci95_ticks=np.quantile(boot,[.025,.975]).tolist(),blocks_with_samples=int((counts>0).sum()))
