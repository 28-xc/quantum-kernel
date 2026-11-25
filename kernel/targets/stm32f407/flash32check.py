"""Validate a *running* Flash-linked compact image. Does not program or erase it."""
import argparse,csv,hashlib,struct,time,xml.etree.ElementTree as ET
from pathlib import Path
import engine
from usb_windows import Port,hello
from collect import seed_nonce

def validate(manifest,output,dfu_after):
    x=ET.parse(manifest).getroot().attrib
    if x.get("execution")!="flash32":raise ValueError("expected a flash32 manifest")
    p=int(x['parameter']);profile=engine.PROFILES[x['strategy']];cap=int(x['caller_workspace_bytes']);ram=int(x['full_reserved_ram_bytes']);flash=int(x['used_flash_bytes'])
    payload=manifest.with_suffix('.bin').read_bytes()
    if hashlib.sha256(payload).hexdigest()!=x['sha256'] or len(payload)!=flash or not 0<ram<=32768:raise ValueError('local Flash identity or declared SRAM allocation')
    fields=('test','parameter','status','uid','build_tag','local_bin_sha256','declared_flash_bytes','board_image_bytes','declared_total_ram','board_total_ram','arena_bytes','stack_limit','stack_peak','mask','raw_reply_le_hex')
    output.parent.mkdir(parents=True,exist_ok=True)
    with engine._device_lock(),output.open('x',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields,delimiter='\t',lineterminator='\n');writer.writeheader()
        item=engine._select()
        if item['mode']!='cdc':raise ValueError("launch the verified Flash image first")
        identity=hello(item)
        if identity['build_tag']!=x['tag'] or identity['parameter']!=p or identity['profile']!=profile or identity['image_bytes']!=flash or identity['static_ram_bytes']!=ram:raise ValueError("CDC is running a different image")
        with Port(item) as port:
            for kind,cmd,mode,budget,mlen,clen,entropy in [('clock',5,0,cap,0,0,0),('ACVP',3,0,cap,32,8,0),('round_trip',2,0,cap,32,8,0),('recovery',2,1,1,32,8,0),('boundary',4,0,cap,0,0,0),('hardware_rng',2,0,cap,32,8,1)]:
                if kind=='recovery' and profile==4:continue
                n=seed_nonce('flash32-functional-v1',p,kind)
                r=port.command(cmd,n,p,profile,budget,mlen,clen,entropy,mode,timeout=45)
                valid=(struct.pack('<4I',*r[8:12]).hex()==x['tag'] and r[12]==p and r[13]==profile and r[38]==cap and r[39]==flash and r[40]==ram)
                masks={'clock':1,'ACVP':7 if p>100 else 15,'round_trip':639,'hardware_rng':639,'recovery':1023,'boundary':639}
                valid=valid and r[23]==masks[kind] and (cmd==5 or bool(r[52]))
                if kind=='boundary':valid=valid and r[53:55]==(0xfffffffa,0) and r[61]==0xfffffffe
                writer.writerow(dict(zip(fields,(kind,p,'PASS' if valid else 'FAIL',identity['uid'],x['tag'],x['sha256'],flash,r[39],ram,r[40],cap,r[37],r[36],r[23],struct.pack('<64I',*r).hex()))));f.flush()
                if not valid:raise RuntimeError(f"{kind} failed (mask {r[23]})")
            if dfu_after:
                if port.command(6)[23]!=1:raise RuntimeError("DFU return")
        if dfu_after:engine._wait('dfu',engine._rom_serial(identity['uid']))
    print(p,'PASS',flash,ram)
if __name__=='__main__':
    cmd=argparse.ArgumentParser();cmd.add_argument('--manifest',type=Path,required=True);cmd.add_argument('--output',type=Path,required=True);cmd.add_argument('--return-dfu',action='store_true');a=cmd.parse_args()
    validate(a.manifest,a.output,a.return_dfu)

