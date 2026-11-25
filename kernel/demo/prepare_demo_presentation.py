"""Build presentation snapshots with the original scientific readers, once at packaging time."""
from pathlib import Path
from types import SimpleNamespace
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
import copy, gzip, hashlib, record_io as json, sys, time
sys.dont_write_bytecode=True
import argparse
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--package',type=Path,required=True)
p.add_argument('--workspace',type=Path,required=True,help='Verified demo compatibility workspace from prepare_workspace.py')
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();VIEW=a.workspace.resolve(strict=True);R=a.package.resolve(strict=True);OUT=a.output.resolve()
if OUT.exists() or OUT.is_relative_to(R):p.error('Use a fresh output directory outside the package')
OUT.mkdir(parents=True)
receipt=json.loads((VIEW/'workspace.xml').read_text(encoding='utf-8'))
if receipt.get('status')!='VERIFIED':
    # Older compatible receipts state the successful copy explicitly.
    if receipt.get('status') not in ('COPIED_AND_VERIFIED','PASS','VERIFIED_COPY_COMPLETE'):raise ValueError('Unverified workspace receipt: '+str(receipt.get('status')))
mapping=receipt['copied_files']
from concurrent.futures import ThreadPoolExecutor
def verify(row):
    logical,entry=row;file=(VIEW/logical).resolve()
    if not file.is_relative_to(VIEW) or not file.is_file() or file.stat().st_size!=entry['bytes'] or hashlib.sha256(file.read_bytes()).hexdigest()!=entry['sha256']:raise ValueError('Workspace dependency changed: '+logical)
with ThreadPoolExecutor(max_workers=8) as workers:list(workers.map(verify,mapping.items()))
sys.path.insert(0,str(VIEW));sys.path.insert(0,str(VIEW/'source'))
from unified_shell.application import build
start=time.monotonic()
args=SimpleNamespace(source=VIEW/'source',archive_adapter=VIEW/'session-demo',arm_config=None,board_config=None,
    config=VIEW/'live-demo/windows.xml',archive_config=VIEW/'history/frozen-demo.xml',session_config=VIEW/'session-demo/session.xml',output=OUT/'generation')
handler,live,archive,unavailable=build(args,'127.0.0.1:8134')
print('Original validation completed',time.monotonic()-start,flush=True)
def physical(path):
    path=Path(path).resolve()
    if path.is_relative_to(VIEW):
        rel=path.relative_to(VIEW).as_posix()
        if rel in mapping:
            target=(R/mapping[rel]['physical']).resolve()
            if not target.is_relative_to(R) or not target.exists():raise ValueError('Missing package target '+str(target))
            return target
        options=set()
        for logical,row in mapping.items():
            if logical.startswith(rel+'/'):
                tail=Path(logical[len(rel)+1:])
                parent=Path(row['physical'])
                for _ in tail.parts:parent=parent.parent
                options.add(parent.as_posix())
        if len(options)==1:
            target=(R/next(iter(options))).resolve()
            if not target.is_relative_to(R) or not target.exists():raise ValueError('Missing package target '+str(target))
            return target
        raise ValueError('Ambiguous directory mapping '+str(path)+' '+str(options))
    raise ValueError('External path '+str(path))
def encode(value):
    if isinstance(value,Path):return {'__package_path__':physical(value).relative_to(R).as_posix()}
    if isinstance(value,tuple):return {'__tuple__':[encode(v) for v in value]}
    if isinstance(value,dict):
        if any(not isinstance(k,str) for k in value):return {'__mapping__':[[encode(k),encode(v)] for k,v in value.items()]}
        return {k:encode(v) for k,v in value.items()}
    if isinstance(value,list):return [encode(v) for v in value]
    if value is None or type(value) in (str,int,float,bool):return value
    raise TypeError(str(type(value)))
def descriptors(value,base):
    if isinstance(value,dict):
        out={k:descriptors(v,base) for k,v in value.items()}
        if isinstance(value.get('path'),str) and isinstance(value.get('sha256'),str):
            out['path']=physical(base/value['path']).relative_to(R).as_posix()
        return out
    if isinstance(value,list):return [descriptors(v,base) for v in value]
    return value
def config(path):
    value=json.loads(path.read_text(encoding='utf-8'))
    # No science is recomputed during ordinary startup. Existing ABI/CPU/image checks remain.
    keep={'schema','kind','libraries','deployment_profiles','host_probe'}
    result={k:v for k,v in value.items() if k in keep};result.update(datasets=[],scientific_views=[],pooled_views=[])
    for row in result['libraries']:row.pop('measurement_reuse',None)
    return descriptors(result,path.parent)
def state(app):
    names=('datasets','scientific','pooled','equal_frequency','upgrades','measurement_reuse','equivalence_files')
    result={key:copy.deepcopy(getattr(app,key)) for key in names}
    for entry in result['upgrades'].values():
        entry['request']=descriptors(entry['request'],entry['base'])
        entry['base']=None # restored to the package root at runtime
    result['prepared_science_views']={key:app.science_views(key or None) for key in ['',*app.descriptors]}
    encoded=encode(result)
    recovered=json.loads(json.dumps(encoded,ensure_ascii=False))
    if recovered!=encoded:raise ValueError('Presentation roundtrip mismatch')
    for key,value in result['prepared_science_views'].items():
        if encode(value)!=recovered['prepared_science_views'][key]:raise ValueError('Scientific view mismatch')
    return encoded
payload={'schema':'lattice.demo.prepared-presentation.v1','policy':'Prepared using original hash-bound readers; original results unmodified. Ordinary startup displays this verified snapshot; full audits/recomputation remain explicit.',
    'current':state(live.base),'experiments':state(archive)}
blob=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode('utf-8')
(OUT/'presentation.xml.gz').write_bytes(gzip.compress(blob,compresslevel=9,mtime=0))
for name,path in [('current',args.config),('experiments',args.archive_config)]:
    (OUT/(name+'.xml')).write_text(json.dumps(config(path),ensure_ascii=False,indent=2),encoding='utf-8')
session=descriptors(json.loads(args.session_config.read_text(encoding='utf-8')),args.session_config.parent)
(OUT/'session.xml').write_text(json.dumps(session,ensure_ascii=False,indent=2),encoding='utf-8')
types={scope:{k:type(v).__name__ for k,v in app.__dict__.items()} for scope,app in [('current',live.base),('experiments',archive)]}
proof=dict(status='PASS',generation_seconds=time.monotonic()-start,uncompressed_bytes=len(blob),compressed_bytes=(OUT/'presentation.xml.gz').stat().st_size,types=types,
    original_config_sha256={str(p.relative_to(VIEW)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [args.config,args.archive_config,args.session_config]},
    source_workspace_sha256=hashlib.sha256((VIEW/'workspace.xml').read_bytes()).hexdigest(),raw_measurements_modified=False,
    prepared_view_sha256={scope+':'+key:hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest() for scope in ('current','experiments') for key,value in payload[scope]['prepared_science_views'].items()})
(OUT/'generation.xml').write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(proof,ensure_ascii=False),flush=True)
