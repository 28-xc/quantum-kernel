"""Compare the M4F SHAKE candidate with the unmodified cached implementation."""
import argparse,csv,hashlib,statistics,struct,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ENGINE=next(p for p in (HERE.parent,HERE.parent/'target') if (p/'engine.py').is_file())
sys.path.insert(0,str(ENGINE))
import engine
from usb_windows import Port
from collect import seed_nonce

def xof_check(p,images,out):
    fields=['parameter','bits','input_bytes','output_bytes','incremental_split','request_nonce','firmware_sha256','uid','expected_sha256','actual_sha256','status','raw_replies_le_hex']
    with engine._device_lock():
        item,meta,identity=engine._ensure(p,'cached-m4f',images,None)
        with out.open('x',encoding='utf-8-sig',newline='') as fp,Port(item) as port:
            write=csv.DictWriter(fp,fieldnames=fields,delimiter='\t',lineterminator='\n');write.writeheader();count=0
            for bits,rate in ((128,168),(256,136)):
                cases=[(0,0),(0,32),(1,1),(rate-1,rate-1),(rate,rate),(rate+1,rate+1),(2*rate+1,2*rate+1),(7,2*rate+1),(2*rate+1,7)]
                for ilen,olen in cases:
                    for split in ([0,1] if p<100 else [0]):
                        n=seed_nonce('F407-XOF-corpus-v1',p,bits,ilen,olen,split)
                        challenge=bytes.fromhex(n);msg=bytes((7+13*i+challenge[i&15])&255 for i in range(ilen))
                        expected=(hashlib.shake_128 if bits==128 else hashlib.shake_256)(msg).digest(olen)
                        computed=bytearray();replies=[]
                        for off in (range(0,olen,48) if olen else [0]):
                            r=port.command(9,n,p,5,bits,ilen,olen,off,split)
                            if r[23]!=1 or (r[41],r[42],r[43])!=(olen,off,min(olen-off,48)) or struct.pack('<4I',*r[8:12]).hex()!=meta['tag']:
                                raise RuntimeError('wrong SHAKE slice metadata')
                            replies.append(struct.pack('<64I',*r).hex());computed.extend(struct.pack('<12I',*r[24:36])[:r[43]])
                        ok=expected==computed;h=lambda x:hashlib.sha256(x).hexdigest()
                        write.writerow(dict(zip(fields,[p,bits,ilen,olen,split,n,meta['sha256'],identity['uid'],h(expected),h(computed),'PASS' if ok else 'FAIL',' '.join(replies)])));fp.flush()
                        if not ok:raise RuntimeError(f"SHAKE{bits} {p} lengths {ilen}/{olen}/{split} failed")
                        count+=1
    print('SHAKE',p,count,flush=True)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--images',type=Path,required=True);ap.add_argument('--baseline-images',type=Path);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--params',nargs='+',type=int,default=[512,87]);ap.add_argument('--samples',type=int,default=3)
    a=ap.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    with (a.output/'pilot.tsv').open('x',encoding='utf-8-sig',newline='') as f:
        fields=('param','implementation','test','block','nonce','fw_sha256','uid','pass','cycles','stack_peaks','workspace_peaks','public_key_check32','public_output_check32','raw_reply_le_hex')
        wr=csv.DictWriter(f,fieldnames=fields,delimiter='\t',lineterminator='\n');wr.writeheader()
        for p in a.params:
            expected={};times={}
            for s in ['cached','cached-m4f']:
                times[s]=[]
                for kind,block in [('kat',-1),('boundary',-1),('sample',-1)]+[('sample',i) for i in range(a.samples)]:
                    n=seed_nonce('M4-Keccak-pilot-v1',p,kind,block)
                    folder=(a.baseline_images or a.images) if s=='cached' else a.images
                    z=engine.run(p,s,nonce=n,image_dir=folder,entropy='deterministic',command='run' if kind=='sample' else kind)
                    ok=z['passed'];summary=(z.get('public_key_checksum'),z.get('public_output_checksum'))
                    if kind=='sample':
                        if block in expected and expected[block]!=summary:ok=False
                        expected[block]=summary
                        if block>=0:times[s].append(sum(z['cycles'][:3]))
                    wr.writerow(dict(zip(fields,(p,s,kind,block,n,z['firmware_sha256'],z['uid'],ok,','.join(map(str,z['cycles'])),','.join(map(str,z['stack_peaks'])),','.join(map(str,z['workspace_peaks'])),*summary,struct.pack('<64I',*z['raw_words']).hex()))));f.flush()
                    if not ok:raise RuntimeError(f'{p} {s} {kind} failed')
                if s=='cached-m4f':xof_check(p,a.images,a.output/(f'p{p}-shake.tsv'))
            old,new=map(statistics.median,(times['cached'],times['cached-m4f']))
            print('pilot total cycles',p,old,new,'old/new',round(old/new,3),flush=True)
    engine.return_dfu()
if __name__=='__main__':main()

