"""Select an explicit, small published ACVP subset for freestanding images.

No output is derived from this implementation. KeyGen/encaps/decaps: lowest
tcId. External pure signature tests: shortest message, then tcId, separately
for accepted and rejected verification. This is a subset, not full ACVP.
"""
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
import hashlib, record_io as json

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def generate(root, output, selected_cells=None):
    folder=root/'tests/vectors/acvp'; rows=[]; files={}
    for name in ('ML-KEM-keyGen-FIPS203','ML-KEM-encapDecap-FIPS203',
                 'ML-DSA-keyGen-FIPS204','ML-DSA-sigGen-FIPS204','ML-DSA-sigVer-FIPS204'):
        pp=folder/name/'prompt.xml'; ep=folder/name/'expectedResults.xml'
        prompt=json.loads(pp.read_text(encoding='utf-8')); expected=json.loads(ep.read_text(encoding='utf-8'))
        files[pp.relative_to(root).as_posix()]=sha(pp); files[ep.relative_to(root).as_posix()]=sha(ep)
        wanted={t['tcId']:t for g in expected['testGroups'] for t in g['tests']}
        for g in prompt['testGroups']:
            if g.get('signatureInterface')=='internal' or g.get('preHash')=='preHash': continue
            if g.get('function','').endswith('KeyCheck'): continue
            # One hedged (explicit rnd) signing test per parameter.
            if prompt['mode']=='sigGen' and g['deterministic']: continue
            p=int(g['parameterSet'].split('-')[-1])
            groups=([True,False] if prompt['mode']=='sigVer' else [True])
            for accepted in groups:
                candidates=[t for t in g['tests'] if prompt['mode']!='sigVer' or wanted[t['tcId']]['testPassed']==accepted]
                if not candidates: raise ValueError('Missing requested acceptance class')
                t=min(candidates,key=lambda t:(len(t.get('message','')),t['tcId']))
                e=wanted[t['tcId']];mode=prompt['mode']
                op=0 if mode=='keyGen' else (1 if (mode=='sigGen' or g.get('function')=='encapsulation') else 2)
                r=dict(parameter=p,operation=op,accepted=accepted,category=name,tgId=g['tgId'],tcId=t['tcId'],
                       coins='',pk='',sk='',ct='',signature='',message=t.get('message',''),domain=t.get('context',''),
                       expected0='',expected1='')
                if mode=='keyGen':
                    r['coins']=t['d']+t['z'] if p>100 else t['seed']
                    r['expected0']=e['ek' if p>100 else 'pk'];r['expected1']=e['dk' if p>100 else 'sk']
                elif g.get('function')=='encapsulation':
                    r['coins']=t['m'];r['pk']=t['ek'];r['expected0']=e['c'];r['expected1']=e['k']
                elif g.get('function')=='decapsulation':
                    r['sk']=t['dk'];r['ct']=t['c'];r['expected0']=e['k']
                elif mode=='sigGen':
                    r['coins']=t['rnd'];r['sk']=t['sk'];r['expected0']=e['signature']
                else:
                    r['pk']=t['pk'];r['signature']=t['signature']
                rows.append(r)
    rows.sort(key=lambda r:(r['parameter'],r['operation'],not r['accepted']))
    positives=[r for r in rows if r['accepted']]
    if len(rows)!=21 or len({(r['parameter'],r['operation']) for r in positives})!=18:
        raise ValueError('Subset coverage changed')
    if selected_cells is not None:
        rows=[row for row in rows if (row['parameter'],row['operation']) in selected_cells]
        if {(row['parameter'],row['operation']) for row in rows if row['accepted']} != set(selected_cells):
            raise ValueError('Missing requested published operation cells')
    fields=['coins','pk','sk','ct','signature','message','domain','expected0','expected1']
    arrays={}; body=['/* Generated only from the locked, published NIST vectors. */',
      '#ifndef LC_TARGET_VECTORS_H','#define LC_TARGET_VECTORS_H','#include <stdint.h>',
      'typedef struct { const uint8_t *p; unsigned n; } lc_vector_bytes;',
      'typedef struct { int parameter,operation,accepted; unsigned tc_id; '+
      ' '.join('lc_vector_bytes '+k+';' for k in fields)+' } lc_target_vector;']
    def emit(data):
        raw=bytes.fromhex(data)
        if not raw:return '{0,0}'
        if data not in arrays:
            name='vector_bytes_'+str(len(arrays));arrays[data]=name
            lines=[','.join('0x'+raw[j:j+1].hex() for j in range(i,min(i+16,len(raw)))) for i in range(0,len(raw),16)]
            body.append('static const uint8_t '+name+'[]={\n'+',\n'.join(lines)+'\n};')
        return '{'+arrays[data]+','+str(len(raw))+'}'
    definitions=[]
    for r in rows:
        definitions.append('{'+','.join([str(r['parameter']),str(r['operation']),str(int(r['accepted'])),str(r['tcId'])]+[emit(r[k]) for k in fields])+'}')
    capacities=dict(PK=1,SK=1,CT=1,SS=1,SIG=1)
    for row in rows:
        if row['operation']==0:
            capacities['PK']=max(capacities['PK'],len(row['expected0'])//2)
            capacities['SK']=max(capacities['SK'],len(row['expected1'])//2)
        elif row['parameter']>100:
            capacities['CT']=max(capacities['CT'],len(row['expected0'] if row['operation']==1 else row['ct'])//2)
            capacities['SS']=32
        elif row['operation']==1:capacities['SIG']=max(capacities['SIG'],len(row['expected0'])//2)
    body += ['#define LC_TARGET_CAP_'+key+' '+str(value) for key,value in capacities.items()]
    body+=['static const lc_target_vector target_vectors[]={\n'+',\n'.join(definitions)+'\n};',
           '#define LC_TARGET_VECTOR_COUNT '+str(len(rows)),'#endif']
    output.mkdir(parents=True,exist_ok=True);header=output/'vectors.h'
    header.write_text('\n'.join(body)+'\n',encoding='ascii')
    manifest={'schema':1,'source_commit':(folder/'commit.txt').read_text().strip(),'source_files':files,
      'selection_rule':__doc__,'positive_operation_cells':sum(row['accepted'] for row in rows),'negative_verify_cases':sum(not row['accepted'] for row in rows),
      'vector_header_sha256':sha(header),'constant_input_and_expected_bytes':sum(len(bytes.fromhex(x)) for x in arrays),
      'output_capacities':capacities,'cases':[{k:r[k] for k in ('parameter','operation','accepted','category','tgId','tcId')} for r in rows],
      'not_covered':'Full ACVP, HashML-DSA and internal-mu interfaces. No standard conformance certification is claimed.'}
    (output/'vectors.xml').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    return manifest
