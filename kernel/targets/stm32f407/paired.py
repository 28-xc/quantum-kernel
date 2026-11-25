"""Paired confidence intervals from verified raw board replies."""
import csv
import hashlib
import math
import random
import statistics
import sys
from pathlib import Path
from collect import load_rows,write_table
def interval(values,label,repetitions=3000):
    vals=list(values)
    rng=random.Random(int.from_bytes(hashlib.sha256(label.encode()).digest(),'big'))
    n=len(vals);med=statistics.median(vals)
    if n<2:return med,'',''
    draws=sorted(statistics.median(vals[rng.randrange(n)] for i in range(n)) for j in range(repetitions))
    return med,draws[int(.025*repetitions)],draws[min(repetitions-1,math.ceil(.975*repetitions)-1)]
def compare(folder):
    rows=[r for r in load_rows(folder/'transactions.tsv') if r['kind']=='sample' and r['status']=='PASS']
    cells={};byblock={}
    for r in rows:
        p=int(r['parameter']);s=r['implementation'];i=int(r['block']);cy=[int(x) for x in r['cycles'].split(',')]
        if any(x<=0 for x in cy):raise ValueError('invalid cycle sample')
        o=('keypair','encaps','decaps') if p>100 else ('keypair','sign','verify')
        for op,c in zip(o,cy):
            key=(p,op,s)
            if i in cells.setdefault(key,{}):raise ValueError('duplicate paired sample')
            cells[key][i]=c;byblock.setdefault((s,i),{})[p,op]=c
    pairs=(('cached','compact'),('compact','reference'),('cached','reference'),('compact','m4fstack'),('cached','m4fstack'))
    output=[]
    def add(p,op,target,baseline,a,b):
        shared=sorted(a.keys()&b.keys())
        if len(shared)<2:return
        vals=[(b[i]-a[i])*100/b[i] for i in shared]
        m,lo,hi=interval(vals,f'{p}/{op}/{target}/{baseline}')
        output.append(dict(parameter=p,operation=op,implementation=target,reference=baseline,paired_blocks=len(shared),median_change_pct=round(m,5),ci95_low_pct=round(lo,5),ci95_high_pct=round(hi,5),faster_pairs=sum(v>0 for v in vals),slower_pairs=sum(v<0 for v in vals),equal_pairs=sum(v==0 for v in vals)))
    unique=sorted({(p,o) for p,o,s in cells})
    for p,op in unique:
        for target,baseline in pairs:add(p,op,target,baseline,cells.get((p,op,target),{}),cells.get((p,op,baseline),{}))
    for target,baseline in pairs:
        totals=lambda s:{i:sum(x.values()) for (tag,i),x in byblock.items() if tag==s and len(x)==18}
        add('all','18 equal-weight operations',target,baseline,totals(target),totals(baseline))
    if output:write_table(folder/'paired.tsv',output[0].keys(),output)
    return output
if __name__=='__main__':
    result=compare(Path(sys.argv[1]));print('paired comparisons',len(result))

