"""Collect on-board measurements using public, reproducible paired challenges."""
import argparse
import csv
from datetime import datetime,timezone
import hashlib
import math
from pathlib import Path
import random
import statistics
import sys
import time

from engine import PARAMETERS,capabilities,run,return_dfu

FIELDS=("kind","parameter","implementation","block","request_id","uid","firmware_sha256","build_tag","status","clock_hz","message_len","context_len","entropy","clock_cfgr","clock_pllcfgr","guard_intact","main_sram_bytes","ccm_bytes","stack_capacity","arena_capacity","image_bytes","total_ram_bytes","reference_heap_peak","pk_check32","public_output_check32","return_codes","cycles","arena_peaks","stack_peaks","checks","raw_reply_le_hex","duration_s","time_utc")
def seed_nonce(seed,*parts):
    return hashlib.sha256(('/'.join([seed,*map(str,parts)])).encode('ascii')).hexdigest()[:32]
def make_row(kind,param,strategy,block,z,meta,duration):
    checks=",".join(k+'='+str(int(v)) for k,v in z.get('checks',{}).items())
    def seq(k):return ','.join(str(v) for v in z[k])
    import struct
    return dict(zip(FIELDS,(kind,param,strategy,block,z['request_id'],z['uid'],z['firmware_sha256'],z['build_tag'],"PASS" if z['passed'] else "FAIL",z['clock_hz'],z['message_len'],z['context_len'],z['entropy_source'],z['clock_cfgr'],z['clock_pllcfgr'],z.get('guard_intact',''),meta['main_sram_bytes'],meta['ccm_bytes'],z['stack_capacity'],z['workspace_capacity'],z['image_bytes'],z['static_ram_bytes'],z.get('reference_heap_peak',''),z.get('public_key_checksum',''),z.get('public_output_checksum',''),seq('return_codes'),seq('cycles'),seq('workspace_peaks'),seq('stack_peaks'),checks,struct.pack('<64I',*z['raw_words']).hex(),round(duration,4),datetime.now(timezone.utc).isoformat())))
def load_rows(path):
    if not path.is_file():return []
    with path.open(encoding='utf-8-sig',newline='') as stream:return list(csv.DictReader(stream,delimiter='\t'))
def write_table(path,fields,rows):
    tmp=path.with_suffix(path.suffix+'.new')
    with tmp.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields,delimiter='\t',lineterminator='\n');w.writeheader();w.writerows(rows)
    tmp.replace(path)
def summarize(rows,directory):
    groups={}; paired={}; resource={}
    for row in rows:
        if row['kind']!='sample' or row['status']!='PASS':continue
        p=int(row['parameter']);s=row['implementation'];index=int(row['block'])
        k=(p,index)
        digest=row['pk_check32'],row['public_output_check32']
        if k in paired and paired[k]!=digest:raise ValueError("paired public outputs differ "+str(k))
        paired[k]=digest
        cycles=list(map(int,row['cycles'].split(',')));stacks=list(map(int,row['stack_peaks'].split(',')));peaks=list(map(int,row['arena_peaks'].split(',')))
        for op,c,ar,st in zip(("keypair","encaps","decaps") if p>100 else ("keypair","sign","verify"),cycles,peaks,stacks):
            groups.setdefault((p,op,s),[]).append((index,c,ar,st,int(row['clock_hz'])))
        resource[p,s]={x:row[x] for x in ('main_sram_bytes','ccm_bytes','stack_capacity','arena_capacity','image_bytes','total_ram_bytes','firmware_sha256')}
    results=[]
    for (p,op,s),v in sorted(groups.items()):
        if len(set(i[0] for i in v))!=len(v):raise ValueError('duplicate samples')
        cy=sorted(i[1] for i in v);hz=v[0][4];md=statistics.median(cy)
        results.append(dict(param=p,operation=op,implementation=s,samples=len(v),median_cycles=md,clock_hz=hz,median_us=round(md*1e6/hz,6),arena_bytes=max(i[2] for i in v),stack_bytes=max(i[3] for i in v),p10_cycles=cy[math.floor(.1*(len(cy)-1))],p90_cycles=cy[math.ceil(.9*(len(cy)-1))],min_cycles=cy[0],max_cycles=cy[-1]))
    if results:write_table(directory/'operations.tsv',results[0].keys(),results)
    if resource:
        rr=[dict(param=p,implementation=s,**v) for (p,s),v in sorted(resource.items())]
        write_table(directory/'memory.tsv',rr[0].keys(),rr)
    return results

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--images',type=Path);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--blocks',type=int,default=32);ap.add_argument('--batch-size',type=int,default=8)
    ap.add_argument('--seed',default='A127-F407-paired-20261112-v1')
    ap.add_argument('--params',nargs='+',type=int,default=list(PARAMETERS));ap.add_argument('--strategies',nargs='+',default=['compact','cached','reference'])
    ap.add_argument('--checks-only',action='store_true');ap.add_argument('--summarize-only',action='store_true')
    ap.add_argument('--paired-order',action='store_true',help='keep all strategies for a parameter adjacent and reload each image at the start of each block group')
    a=ap.parse_args()
    if not (1<=a.blocks<=4096 and 1<=a.batch_size<=a.blocks):ap.error("invalid number of blocks or batch size")
    folder=a.output.resolve();folder.mkdir(parents=True,exist_ok=True)
    raw=folder/'transactions.tsv';previous=load_rows(raw)
    if a.summarize_only:summarize(previous,folder);return
    rows=[x for x in capabilities(a.images)['images'] if x['parameter'] in a.params and x['strategy'] in a.strategies]
    by={(x['parameter'],x['strategy']):x for x in rows}
    if not rows:raise SystemExit('No matching images')
    pairs=sorted(by);labels=set()
    config=folder/'conditions.txt'
    conditions=f"seed={a.seed}\nblocks={a.blocks}\nbatch_size={a.batch_size}\nclock=168 MHz HSE PLL; M4_CLOCK checks full-speed USB frame interval\npacket=CDC request v1, 16-byte public nonce; one parameter per SRAM image\nsample=32 B generated message, 8 B context; deterministic public input; paired by parameter and block\nwindow=DWT immediately around one public crypto API call, includes its RNG callback; excludes USB, post-call comparisons, wiping audit and host scheduling\nstack=painted high-water per operation; USB application and launch stack included in reserved image budget\nreference=delivered PQClean portable C through its validated wrapper; bounded SHAKE allocation pool, single-threaded\n"
    if 'm4fstack' in a.strategies:
        conditions=conditions.replace('reference=delivered PQClean portable C through its validated wrapper; bounded SHAKE allocation pool, single-threaded','reference=pqm4 m4fstack for FIPS 203/204; unchanged M4F assembly (GNU as 2.41), same Clang 17 -Os C compilation, USB unit, SRAM execution, public test vectors and ABI guards')
    if a.paired_order:
        conditions+='order=parameter order independently seeded per group; strategies stay adjacent within parameter, rotate starting position each group; every image is reloaded and warmed upon entering a group\n'
    if config.exists() and config.read_text(encoding='utf-8')!=conditions:raise SystemExit('existing collection conditions differ')
    config.write_text(conditions,encoding='utf-8')
    for r in previous:
        p=int(r['parameter']);s=r['implementation']
        if r['status']!='PASS':raise SystemExit("a failed measurement is present; use a new directory after diagnosis")
        if (p,s) in by and r['firmware_sha256']!=by[p,s]['sha256']:raise SystemExit("firmware changed since earlier rows")
        labels.add((r['kind'],p,s,int(r['block'])))
    uids={r['uid'] for r in previous}
    if len(uids)>1:raise SystemExit("mixed devices")
    selectors=dict(image_dir=a.images)
    with raw.open('a',encoding='utf-8' if previous else 'utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=FIELDS,delimiter='\t',lineterminator='\n')
        if not previous:w.writeheader();f.flush()
        def record(kind,p,s,i=-1):
            if (kind,p,s,i) in labels:return
            kwargs={'parameter':p,'strategy':s,'mode':'normal','message_len':32,'context_len':8,'entropy':'deterministic','command':'run',**selectors}
            if kind=='clock':kwargs['command']='clock'
            elif kind=='kat':kwargs['command']='kat'
            elif kind=='hardware_rng':kwargs['entropy']='hardware'
            elif kind=='recovery':kwargs['mode']='insufficient'
            elif kind=='boundary':kwargs.update(command='boundary',message_len=0,context_len=0)
            elif kind=='max_context':kwargs.update(message_len=256,context_len=255)
            elif kind=='warmup':kwargs.update(message_len=32,context_len=8)
            nonce=seed_nonce(a.seed,p,kind,i)
            started=time.monotonic();z=run(**kwargs,nonce=nonce);row=make_row(kind,p,s,i,z,by[p,s],time.monotonic()-started)
            if uids and z['uid'] not in uids:raise RuntimeError("device UID changed during the batch")
            uids.add(z['uid']);w.writerow(row);f.flush()
            if not z['passed']:raise RuntimeError(f"{kind} {p} {s} block {i} failed: {z.get('checks')}, rc={z['return_codes']}, raw evidence retained")
            labels.add((kind,p,s,i))
        for p,s in pairs:
            for kind in ('clock','kat','boundary','hardware_rng','recovery','max_context'):
                if kind=='recovery' and s in ('reference','m4fstack'):continue
                if kind=='max_context' and p>100:continue
                if kind=='kat' and by[p,s].get('kat_supported','yes')=='no':continue
                record(kind,p,s)
            print('checks',p,s,flush=True)
        if not a.checks_only:
            rng=random.Random(a.seed)
            for first in range(0,a.blocks,a.batch_size):
                order=pairs[:];rng.shuffle(order)
                if a.paired_order:
                    params=sorted({p for p,s in pairs});rng.shuffle(params);order=[]
                    for p in params:
                        modes=sorted(s for candidate,s in pairs if candidate==p)
                        random.Random(a.seed+'/strategy/'+str(p)).shuffle(modes)
                        offset=(first//a.batch_size)%len(modes)
                        order.extend((p,s) for s in modes[offset:]+modes[:offset])
                for p,s in order:
                    if a.paired_order and any(('sample',p,s,i) not in labels for i in range(first,min(first+a.batch_size,a.blocks))):
                        return_dfu()
                    record('warmup',p,s,first)
                    for i in range(first,min(first+a.batch_size,a.blocks)):record('sample',p,s,i)
                    print('samples',p,s,first,a.blocks,flush=True)
    result=summarize(load_rows(raw),folder)
    print('operations',len(result),'records',len(load_rows(raw)),flush=True)
    return_dfu()
if __name__=='__main__':main()

