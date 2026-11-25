"""Read actual linked entities from an explicitly supplied PE/ELF image."""
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
import argparse, record_io as json, re, subprocess, sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from size_variants import sha,write,binary_info,entity_table

def main():
    p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--map',type=Path);p.add_argument('--manifest',type=Path);p.add_argument('--nm',default='nm');p.add_argument('--objdump',default='objdump');a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);lib=a.library.resolve();commands=[]
    def run(argv,name):
        r=subprocess.run(list(map(str,argv)),capture_output=True,text=True,encoding='utf-8',errors='replace');f=out/(name+'.log');f.write_text(json.capture_text(r.stdout+r.stderr),encoding='utf-8')
        commands.append(dict(argv=list(map(str,argv)),exit_code=r.returncode,log=f.name,sha256=sha(f)))
        if r.returncode:raise ValueError(name+' failed')
        return r.stdout
    info=binary_info(lib);entities=entity_table(run([a.nm,'-S','--defined-only',lib],'nm'),info)
    headers=run([a.objdump,'-p',lib],'headers');disasm=run([a.objdump,'-d',lib],'disassembly')
    calls=[];caller=None
    for line in disasm.splitlines():
        match=re.match(r'^([0-9a-fA-F]+) <([^>]+)>:',line)
        if match:caller=match[2]
        branch=re.search(r'\b(?:callq?|bl|b)\s+([0-9a-fA-Fx]+)\s+<([^>]+)>',line)
        if branch and caller:calls.append({'caller':caller,'target':branch[2],'target_address':int(branch[1],16)})
    entities['direct_call_edges']=calls
    symbols=entities['primitive_entities'];groups={}
    for item in symbols:
        # This groups real addresses; aliases at one address count once.
        if re.search(r'keccakf1600(?:x4)?_permute',item['symbol'],re.I):groups.setdefault('keccak_permutation_interfaces',[]).append(item)
        if re.search(r'keccakf1600_permute_c|^lc_shared_keccakf1600(?:\.|$)',item['symbol'],re.I):groups.setdefault('keccak_permutation_core',[]).append(item)
        if re.search(r'round.?constant|zetas|qdata',item['symbol'],re.I):groups.setdefault('named_constants',[]).append(item)
        if re.search(r'ntt|intt|basemul',item['symbol'],re.I):groups.setdefault('transform_or_product',[]).append(item)
    for k,items in list(groups.items()):
        addresses={i['address'] for i in items};groups[k]={'unique_addresses':len(addresses),'entities':items,'observed_direct_callers':{str(addr):sorted({c['caller'] for c in calls if c['target_address']==addr}) for addr in addresses}}
    write(out/'entities.xml',entities)
    write(out/'index.xml',dict(status='READ_ONLY_LINKED_IMAGE_INSPECTED',library={'path':str(lib),'sha256':sha(lib)},image=info,primitive_groups=groups,
        map_file={'path':str(a.map.resolve()),'sha256':sha(a.map)} if a.map else None,
        manifest={'path':str(a.manifest.resolve()),'sha256':sha(a.manifest)} if a.manifest else None,commands=commands,
        scope='Actual retained symbols, aliases and visible direct calls. No assertion about inlined/indirect entities; no equality of source spelling implies code sharing.'))
    print('Actual image inspected:',lib.name)
if __name__=='__main__':main()
