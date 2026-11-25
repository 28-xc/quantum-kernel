"""On-board fixed/random input timing check on one device, preserving every raw reply.

Each randomized block contains a fixed and a variable test input. A block contributes
one observation of each class. ML-DSA signing exhibits rejection variability and is
not interpreted as a constant-time certificate.
"""
import argparse,csv,hashlib,math,random,statistics,struct,time
from pathlib import Path
from engine import run,return_dfu
from collect import seed_nonce,load_rows,write_table

def audit(directory):
    rows=load_rows(directory/'timing-raw.tsv')
    groups={}
    for r in rows:
        key=r['param'],r['strategy'],r['operation']
        byclass=groups.setdefault(key,{'fixed':{},'random':{}})
        i=int(r['block'])
        if i in byclass[r['class']]:raise ValueError('duplicate timing block')
        byclass[r['class']][i]=int(r['cycles'])
    summary=[]
    for k,g in groups.items():
        ids=sorted(g['fixed'].keys()&g['random'].keys())
        if len(ids)<2:continue
        a=[g['fixed'][i] for i in ids];b=[g['random'][i] for i in ids]
        den=math.sqrt(statistics.variance(a)/len(a)+statistics.variance(b)/len(b))
        tw=(statistics.mean(a)-statistics.mean(b))/den if den else None
        dif=[x-y for x,y in zip(a,b)]
        sd=statistics.stdev(dif)
        tp=statistics.mean(dif)/(sd/math.sqrt(len(ids))) if sd else None
        summary.append(dict(param=k[0],strategy=k[1],operation=k[2],paired_blocks=len(ids),fixed_mean_cycles=round(statistics.mean(a),3),random_mean_cycles=round(statistics.mean(b),3),welch_t=round(tw,5) if tw is not None else 'undefined',paired_t=round(tp,5) if tp is not None else 'undefined',fixed_median=statistics.median(a),random_median=statistics.median(b),fixed_p90=sorted(a)[math.ceil(.9*len(a))-1],random_p90=sorted(b)[math.ceil(.9*len(b))-1]))
    if summary:write_table(directory/'timing-summary.tsv',summary[0],summary)
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--images',type=Path);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--blocks',type=int,default=128);ap.add_argument('--params',nargs='+',type=int,default=[512,44]);ap.add_argument('--strategies',nargs='+',default=['compact','cached']);ap.add_argument('--seed',default='A127-M4-fixed-random-v1');ap.add_argument('--summarize-only',action='store_true');a=ap.parse_args()
    a.output.mkdir(parents=True,exist_ok=True)
    if a.summarize_only:audit(a.output);return
    f=a.output/'timing-raw.tsv';old=load_rows(f);done={(int(r['param']),r['strategy'],int(r['block']),r['class'],r['operation']) for r in old}
    fields=('param','strategy','block','class','operation','cycles','clock_hz','firmware_sha256','uid','request_id','sequence','raw_reply_le_hex')
    with f.open('a',encoding='utf-8' if old else 'utf-8-sig',newline='') as fp:
        out=csv.DictWriter(fp,fieldnames=fields,delimiter='\t',lineterminator='\n')
        if not old:out.writeheader()
        for p in a.params:
            for s in a.strategies:
                order=random.Random(a.seed+'/'+str(p)+'/'+s)
                for i in range(a.blocks):
                    classes=['fixed','random'];order.shuffle(classes)
                    for c in classes:
                        ops=['keypair','encaps','decaps','decaps_mutated'] if p>100 else ['keypair','sign','verify','verify_mutated']
                        done_ops=[(p,s,i,c,k) in done for k in ops]
                        if all(done_ops):continue
                        if any(done_ops):raise RuntimeError('partial timing record in file')
                        nonce=seed_nonce(a.seed,p,c,0 if c=='fixed' else i)
                        z=run(p,s,nonce=nonce,image_dir=a.images,entropy='deterministic',command='timing')
                        if not z['passed']:raise RuntimeError('board correctness/cleanup failed')
                        raw=z['raw_words']
                        for k,cy in zip(ops,z['cycles']):out.writerow(dict(zip(fields,(p,s,i,c,k,cy,z['clock_hz'],z['firmware_sha256'],z['uid'],nonce,raw[3],struct.pack('<64I',*raw).hex()))))
                        fp.flush()
                    if (i+1)%16==0:print(p,s,i+1,flush=True)
    audit(a.output);return_dfu()
if __name__=='__main__':main()

