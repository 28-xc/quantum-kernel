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

CO={'related':[-1,0,0,1,0,0], 'public_main':[-.5,-.5,.5,.5,0,0],
 'secret_main':[-.5,.5,-.5,.5,0,0], 'rho_main':[-.5,-.5,0,0,.5,.5],
 'secret_rho':[-.5,.5,0,0,-.5,.5], 'public_body':[0,0,.5,.5,-.5,-.5]}

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def summary(diff,indices):
 blocks=diff.reshape(-1,1000).mean(axis=1);t,p=stats.ttest_1samp(blocks,0)
 return dict(mean_ticks=float(blocks.mean()),block_se=float(blocks.std(ddof=1)/np.sqrt(len(blocks))),
  ci95=np.quantile(blocks[indices].mean(axis=1),[.025,.975]).tolist(),t=float(t),p=float(p),blocks=len(blocks),groups=len(diff))

def workload(data,parameter):
 k=parameter//256;pk=384*k+32;stride=pk+32;assert len(data)==257*stride;rows=[]
 for index in range(257):
  item=data[index*stride:(index+1)*stride];assert hashlib.sha3_256(item[:pk]).digest()==item[pk:]
  rho=item[pk-32:pk];extra=[];proposals=[]
  for i in range(k):
   for j in range(k):
    sponge=hashlib.shake_128(rho+bytes((i,j)));blocks=3;accepted=0;offset=0;trials=0
    while accepted<256:
     stream=sponge.digest(168*blocks)
     for at in range(offset,len(stream),3):
      for value in ((stream[at]|stream[at+1]<<8)&4095,(stream[at+1]>>4)|(stream[at+2]<<4)):
       trials+=1;accepted+=value<3329
       if accepted==256:break
      if accepted==256:break
     if accepted<256:offset=len(stream);blocks+=1
    extra.append(blocks-3);proposals.append(trials)
  rows.append(dict(key=index,extra_x1=sum(extra),semantic_candidates=sum(proposals),polynomial_extra_blocks=extra))
 return rows
