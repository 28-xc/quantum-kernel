#!/usr/bin/env python3
"""Validate and summarize recorded verification data using Python's standard library.

This entry reads data and code hashes. It does not load a cryptographic library,
compile sources, execute test drivers, download vectors, or measure performance.
"""
from pathlib import Path, PurePosixPath
from collections import Counter
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
import argparse, csv, hashlib, record_io as json, re

SCHEMA = 'latticecore.verification_observations.v1'
KINDS = {'acvp','complete','signatures','capacity','wycheproof','go','liboqs',
         'boringssl','key-encoding','openssl','native-codec','native-bitmap',
         'vector24','cbmc','lifetimes','common-context'}
SHA = re.compile(r'^[0-9a-f]{64}$')

def require(ok,message):
    if not ok: raise ValueError(message)
def keys(x,required,optional=()):
    require(type(x)is dict,'expected object')
    require(set(required)<=set(x)<=set(required)|set(optional),'unexpected or missing object field')
def load(p):
    def unique(pairs):
        d={}
        for k,v in pairs:
            require(k not in d,'duplicate JSON key');d[k]=v
        return d
    return json.loads(Path(p).read_text(encoding='utf-8-sig'),object_pairs_hook=unique,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
def safe(x):
    if isinstance(x,dict):
        for k,v in x.items(): safe(k);safe(v)
    elif isinstance(x,list):
        for v in x:safe(v)
    elif isinstance(x,str):
        require(not re.search(r'(?:^|\s)[A-Za-z]:[\\/]|/home/|/Users/|\\Users\\|a127-r[0-9]|pqc-r[0-9]',x),'absolute/private path')
def checked(root,ref):
    keys(ref,['file','sha256','bytes'],['rows','logical_name','logical_names'])
    require(isinstance(ref['file'],str) and '\\' not in ref['file'],'nonportable path')
    rel=PurePosixPath(ref['file'])
    require(not rel.is_absolute() and '..' not in rel.parts and ':' not in ref['file'],'unsafe relative path')
    p=(root/Path(*rel.parts)).resolve()
    require(p.is_relative_to(root.resolve()),'path escapes dataset')
    require(SHA.fullmatch(ref['sha256']) is not None,'invalid SHA256')
    require(type(ref['bytes'])is int and ref['bytes']>=0,'invalid size')
    require(p.stat().st_size==ref['bytes'],'file size mismatch: '+ref['file'])
    require(hashlib.sha256(p.read_bytes()).hexdigest()==ref['sha256'],'hash mismatch: '+ref['file'])
    return p
def validate(value,spec):
    if 'anyOf' in spec:
        for s in spec['anyOf']:
            try:validate(value,s);return
            except ValueError:pass
        raise ValueError('value matches no declared record shape')
    t=spec['type'];good={'null':value is None,'boolean':type(value)is bool,
       'integer':type(value)is int,'number':type(value)in(int,float),
       'string':type(value)is str,'array':type(value)is list,'object':type(value)is dict}[t]
    require(good,'record type mismatch: '+t)
    if t=='object':
        keys(value,spec['required'],set(spec['properties'])-set(spec['required']))
        for k,v in value.items():validate(v,spec['properties'][k])
    if t=='array':
        for v in value:validate(v,spec['items'])
def boolean_fields(rows):
    totals={}
    def visit(x,p=''):
        if isinstance(x,dict):
            for k,v in x.items():visit(v,p+'/'+k)
        elif isinstance(x,list):
            for v in x:visit(v,p+'/*')
        elif type(x)is bool:
            d=totals.setdefault(p,{'true':0,'false':0});d[str(x).lower()]+=1
    for row in rows:visit(row)
    return dict(sorted(totals.items()))
def derive(run,rows,root):
    kind=run['kind'];out={'records':len(rows),'boolean_observations':boolean_fields(rows)}
    if any('status' in r for r in rows):out['observed_status_counts']=dict(sorted(Counter(str(r.get('status')) for r in rows).items()))
    if kind in {'acvp','wycheproof','key-encoding'}:
        out['by_parameter']=dict(sorted(Counter(str(r['parameter']) for r in rows if 'parameter'in r).items()))
    if kind=='complete':
        for r in rows:require(len(r['arena_observations'])==r['complete_sequences'],'complete sequence inventory mismatch')
        out['complete_sequences']=sum(r['complete_sequences'] for r in rows)
    elif kind=='signatures':
        for r in rows:require(len(r['cases'])==r['count'],'signature case inventory mismatch')
        out['complete_signature_pairs']=sum(len(r['cases']) for r in rows)
    elif kind=='capacity':
        out['by_execution']=dict(Counter(r['execution'] for r in rows))
        out['by_phase']=dict(sorted(Counter(r['phase'] for r in rows).items()))
        left=[{k:v for k,v in r.items() if k!='execution'} for r in rows if r['execution']=='sequential']
        right=[{k:v for k,v in r.items() if k!='execution'} for r in rows if r['execution']=='concurrent']
        require(left==right,'sequential/concurrent record mismatch')
    elif kind=='go':
        out.update(key_derivation_comparisons=len(rows),bidirectional_valid_exchanges=2*len(rows),implicit_rejection_comparisons=len(rows))
    elif kind=='liboqs':
        nk=sum(r['parameter']>100 for r in rows);nd=len(rows)-nk
        out.update(keypairs=len(rows),complete_ciphertexts=nk,complete_signatures=nd,cross_decaps=2*nk,cross_verify=2*nd,implicit_rejection=nk,modified_signature_rejections=2*nd)
    elif kind=='boringssl':
        nk=sum(r['parameter']>100 for r in rows);nd=len(rows)-nk
        out.update(key_derivations=len(rows),bidirectional_kem_exchanges=2*nk,implicit_rejection_comparisons=nk,bidirectional_signature_checks=2*nd,modified_signature_rejections=2*nd)
    elif kind=='openssl':
        total=0;cells=set();modes=Counter()
        expected=['case_id','iteration','warmup','elapsed_ticks','tick_frequency','elapsed_ns','status','entropy_sha256','message_sha256','context_sha256']
        for r in rows:
            p=checked(root,r['csv'])
            with p.open(newline='',encoding='utf-8') as f:
                reader=csv.DictReader(f);require(reader.fieldnames==expected,'CSV schema mismatch');data=list(reader)
            require(len(data)==r['raw_rows']==r['samples'],'CSV count mismatch')
            require(r['warmups']==0 and r['mode']=='verify','unexpected performance collection')
            for i,line in enumerate(data):
                require(int(line['iteration'])==i and line['warmup']=='0' and line['status']=='0','CSV sequence or return mismatch')
                require(all(line[k]=='' for k in ['elapsed_ticks','tick_frequency','elapsed_ns']),'unexpected timed row')
                require(all(SHA.fullmatch(line[k]) for k in ['entropy_sha256','message_sha256','context_sha256']),'invalid digest')
            total+=len(data);cells.add((r['parameter'],r['operation']));modes[r['import_pct']]+=len(data)
        out.update(correctness_rows=total,operation_cells=len(cells),import_settings=dict(modes))
    elif kind=='native-codec':
        out.update(domain_coefficients=sum(r['domain_coefficients'] for r in rows),endpoint_rows=sum(r['endpoint_rows'] for r in rows),alias_rows=sum(r['alias_rows'] for r in rows))
    elif kind=='native-bitmap':
        for name in ['hint_endpoints','fips_accepted_fixed_cases','low_roundtrip_coefficients','full_hash_storage_cases','hint_weight_cases','scope_counterexamples_detected']:
            out[name]=sum(r[name] for r in rows)
    elif kind=='vector24':out.update({k:v for k,v in rows[0].items() if k!='status'})
    elif kind=='cbmc':
        out.update(properties=len(rows),successful_properties=sum(r['status']=='SUCCESS' for r in rows),unwinding_assertions=run['conditions']['unwinding_assertions'])
    elif kind=='lifetimes':
        count=0
        for r in rows:
            require(r['temporary_offset']+r['poly_bytes']<=r['storage_bytes'],'temporary exceeds owner')
            for phase in r['phases']:
                intervals=sorted(phase['live'])
                require(all(0<=a<=b<=phase['owner_bytes'] for a,b in intervals),'live interval exceeds owner')
                require(all(a[1]<=b[0] for a,b in zip(intervals,intervals[1:])),'overlapping simultaneous live intervals')
                count+=1
        out.update(parameters=len(rows),phase_interval_checks=count)
    elif kind=='common-context':
        out.update(sequences=len(rows),completed_operations=sum(r['completed_operations'] for r in rows),
                   maximum_arena_bytes=max(r['arena_high_water_observed_bytes'] for r in rows),
                   maximum_stack_observed_bytes=max(r['stack_watermark_observed_bytes'] for r in rows),
                   return_codes=dict(sorted(Counter(str(r['rc']) for r in rows).items())))
    return out
def recompute(path):
    root=Path(path).resolve().parent;obs=load(path);safe(obs)
    keys(obs,['schema','selected_images','runs','attachments','record_schema'])
    require(obs['schema']==SCHEMA,'unknown observation schema')
    keys(obs['selected_images'],['windows-x86_64','linux-aarch64'])
    require(all(SHA.fullmatch(s) for s in obs['selected_images'].values()),'invalid selected image')
    sp=checked(root,obs['record_schema']);schemas=load(sp)
    keys(schemas,['schema','records','conditions']);require(schemas['schema']=='latticecore.verification_record_schemas.v1','unknown record schema')
    ids=[r['id'] for r in obs['runs']];require(len(ids)==len(set(ids)),'duplicate run');require(set(ids)==set(schemas['records']),'record schema/run mismatch')
    for a in obs['attachments']:checked(root,a)
    result=[]
    for r in obs['runs']:
        keys(r,['id','platform','kind','images','origin_sha256','records','code','conditions','files'])
        require(r['kind']in KINDS and r['platform']in ('windows-x86_64','linux-aarch64','portable-c'),'unknown run kind/platform')
        validate(r['conditions'],schemas['conditions'][r['id']])
        keys(r['conditions'],[],['build','workspace_bytes','vector_repository','vector_revision','vectors',
            'sanitizers','leak_detection','abort_on_error','coverage','repository','revision','peer',
            'peer_version','measurement','scope','compiler','component_image','case','condition',
            'tool','tool_version','tool_sha256','exit_code','unwinding_assertions','build_sha256',
            'archive_sha256','source_order_checks','reserved_stack_bytes','runtime_memory_bytes',
            'normal_control_zero_only'])
        if 'peer' in r['conditions']:keys(r['conditions']['peer'],['sha256'],['version','filename'])
        for f in r['conditions'].get('vectors',[]):checked(root,f)
        require(SHA.fullmatch(r['origin_sha256']) and all(SHA.fullmatch(h) for h in r['images']),'invalid origin/image hash')
        for c in r['code']:
            if 'file'in c:checked(root,c)
            else:
                keys(c,['logical_name','sha256','availability']);require(c['availability']=='digest-only' and SHA.fullmatch(c['sha256']),'invalid code locator')
        for f in r['files']:checked(root,f)
        p=checked(root,r['records']);rows=[]
        for line in p.read_text(encoding='utf-8').splitlines():
            x=json.loads(line);keys(x,['origin_sha256','origin_pointer','record'])
            require(x['origin_sha256']==r['origin_sha256'] and x['origin_pointer'].startswith('/'),'row provenance mismatch')
            validate(x['record'],schemas['records'][r['id']]);safe(x['record']);rows.append(x['record'])
        require(len(rows)==r['records']['rows'] and rows,'missing rows')
        result.append({'id':r['id'],'platform':r['platform'],'kind':r['kind'],'images':r['images'],'conditions':r['conditions'],'statistics':derive(r,rows,root)})
    return {'schema':'latticecore.verification_summary.v1','observations_sha256':hashlib.sha256(Path(path).read_bytes()).hexdigest(),'selected_images':obs['selected_images'],'run_count':len(result),'projected_record_count':sum(x['statistics']['records'] for x in result),'runs':result}
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('observations',type=Path);ap.add_argument('--check',type=Path);ap.add_argument('--output',type=Path);args=ap.parse_args()
    result=recompute(args.observations)
    if args.check:require(result==load(args.check),'summary differs from exact recomputation')
    if args.output:args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    print(json.dumps({'runs':result['run_count'],'projected_records':result['projected_record_count'],'exact_recomputation':args.check is not None}))
if __name__=='__main__':main()
