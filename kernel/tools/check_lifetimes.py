"""Check finite signing owner intervals using actual compiled SCU sizes and flags.

The scope is the compact-row/hash transition. It checks every row and lifetime
phase in these layouts, alongside exact source-order and release anchors. It is
not a proof of arbitrary C control flow or all signing allocation behavior.
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
import argparse, hashlib, record_io as json, os, re, subprocess
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def write(p,v):Path(p).write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
def body(text,name,occurrence=0):
    at=[m.start() for m in re.finditer(re.escape(name)+r'\(',text)][occurrence];a=text.index('{',at);i=a+1;depth=1
    while depth:depth+=(text[i]=='{')-(text[i]=='}');i+=1
    return text[a:i]
def validate(row):
    k=row['k'];poly=row['poly_bytes'];stride=row['stride_bytes'];size=row['storage_bytes'];h=row['hash_offset'];hs=row['hash_bytes'];align=row['hash_alignment']
    if row['recompute']:
        assert size>=poly+256 and hs<=256 and poly%align==0
        return [dict(phase='recomputed_row_and_hash',live=[[0,poly],[poly,poly+hs]],owner_bytes=size)]
    assert h%align==0 and row['storage_alignment']>=align and h+hs<=size
    phases=[]
    source_stride=768 if row['packed_accumulator'] else poly
    assert row['last_row_offset']==(k-1)*source_stride
    # The last original row is saved before initialization of the tail hash.
    # During each iteration the current row is read completely before its
    # compact output is written. Future original rows remain untouched.
    for i in range(k):
        written=(i+1)*stride
        live=[[0,written],[h,h+hs]]
        for j in range(i+1,k-1):live.append([j*source_stride,(j+1)*source_stride])
        if not row['packed_accumulator']:
            live.append([written,written+row['encoded_high_bytes']])
        for start,end in live:assert 0<=start<=end<=size
        for a,(start,end) in enumerate(live):
            for b,(other_start,other_end) in enumerate(live):
                if a<b:assert end<=other_start or other_end<=start,(row['parameter'],i,live)
        if row['packed_accumulator']:assert 768+row['encoded_high_bytes']<=poly
        phases.append(dict(row=i,phase='compact_write_then_hash_absorb',live=live,owner_bytes=size,
                           saved_last_and_high_encoding_owner_bytes=poly))
    assert k*stride<=row['temporary_offset'] and row['temporary_offset']+poly<=size
    phases.append(dict(phase='hash_released_then_temporary_live',live=[[0,k*stride],[row['temporary_offset'],row['temporary_offset']+poly]],owner_bytes=size))
    return phases

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    build=a.build.resolve();out=a.output.resolve()
    if out.exists():raise ValueError('Fresh output required')
    record=read(build/'build.xml');commands=read(build/'commands.xml')
    if sha(build/'commands.xml')!=record['commands_sha256']:raise ValueError('Command identity changed')
    for name,digest in record['source_hashes'].items():
        if sha(ROOT/name)!=digest:raise ValueError('Build consumed different source '+name)
    unit=ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted/mldsa_native.c'
    sign=unit.parent/'src/sign.c';text=sign.read_text(encoding='utf-8');helper=body(text,'lc_sign_decompose_hash_bitmap');dense=body(text,'lc_sign_decompose_hash_bitmap',1)
    checks=dict(packed_save_before_hash_init=helper.index('mld_memcpy(saved,')<helper.index('mld_shake256_init(state)'),
                packed_decode_before_compact_write=helper.index('const uint8_t *src=')<helper.index('lc_pack_w0_row(row,scratch)'),
                packed_hash_release=helper.index('mld_shake256_release(state)')<helper.index('mld_zeroize(state,sizeof(*state))'),
                dense_save_before_hash_init=dense.index('mld_memcpy(saved_last,')<dense.index('mld_shake256_init(state)'),
                dense_read_before_compact_write=dense.index('mld_poly_decompose(high,low)')<dense.index('lc_pack_w0_row(row,low)'),
                dense_hash_release=dense.index('mld_shake256_release(state)')<dense.index('mld_zeroize(state,sizeof(*state))'),
                whole_storage_release='MLD_FREE(w0_storage,lc_sign_w0_storage,1,context);' in text,
                size_based_zeroization='mld_zeroize(v, sizeof(T) * (N));' in (unit.parent/'src/common.h').read_text())
    if not all(checks.values()):raise ValueError('Actual source transition changed')
    out.mkdir(parents=True);(out/'tmp').mkdir();env=dict(os.environ,TMP=str(out/'tmp'),TEMP=str(out/'tmp'),TMPDIR=str(out/'tmp'))
    probe=out/'actual_layout.c';original=unit.read_text(encoding='utf-8');prefix=original[:original.index("/* Macro #undef's")]
    probe.write_text(prefix+'\n#include "layout_probe_impl.h"\n',encoding='utf-8')
    logs=[];rows=[]
    archive=build/'liblatticecore.a'
    if not archive.is_file():raise ValueError('Actual build static archive is required')
    for command in commands:
        argv=command['argv']
        if '-c' not in argv:continue
        unit_suffix='/'+unit.relative_to(ROOT).as_posix()
        recorded_unit=argv[argv.index('-c')+1].replace('\\','/')
        if not recorded_unit.endswith(unit_suffix):continue
        recorded_root=recorded_unit[:-len(unit_suffix)]
        # All project dependency hashes above matched this source tree.
        # Only its root path changes when reproducing an archived build.
        argv=[x.replace('\\','/').replace(recorded_root,ROOT.as_posix()) for x in argv]
        level=next(x.split('=',1)[1] for x in argv if x.startswith('-DMLD_CONFIG_PARAMETER_SET='))
        exe=out/('layout-'+level+('.exe' if os.name=='nt' else ''))
        args=[];skip=False
        for x in argv:
            if skip:skip=False;continue
            if x in ('-o','-MF'):skip=True;continue
            if x in ('-c','-MMD'):continue
            args.append(str(probe) if x==str(unit) or x==str(unit).replace('\\','/') else x)
        # Retained shared release entities can refer to the actual adapter.
        # Resolve those references from the build's archive, never a stub.
        args+=['-I'+str(unit.parent),'-I'+str(ROOT/'tests/pruning'),str(archive),'-Wl,--gc-sections','-o',str(exe)]
        if os.name=='nt':args+=['-lbcrypt']
        run=subprocess.run(args,capture_output=True,text=True,env=env);(out/('compile-'+level+'.log')).write_text(json.capture_text(run.stdout+run.stderr),encoding='utf-8')
        if run.returncode:raise RuntimeError('Actual layout compile failed '+level)
        result=subprocess.run([str(exe)],capture_output=True,text=True);(out/('run-'+level+'.xml')).write_text(json.capture_text(result.stdout),encoding='utf-8')
        if result.returncode:raise RuntimeError('Actual layout probe failed')
        row=json.loads(result.stdout);row['phases']=validate(row);row['executable_sha256']=sha(exe);rows.append(row)
        logs.append(dict(argv=args,feature_definitions_unchanged=True,source_sha256=sha(probe),exit_code=0,
            source_root_mapping=dict(recorded=recorded_root,reproduced=ROOT.as_posix())))
    if {r['parameter'] for r in rows}!={p for p in record['parameters'] if p<100}:raise ValueError('Missing actual DSA translation units')
    # Positive detector control: make a live hash overlap the first row. This
    # is a Python interval, never an out-of-bounds target memory operation.
    controls=[]
    for row in rows:
        invalid=dict(row,hash_offset=0)
        try:validate(invalid)
        except AssertionError:controls.append(dict(parameter=row['parameter'],overlapping_layout_rejected=True))
        else:raise ValueError('Layout detector accepted overlap')
    write(out/'result.xml',dict(schema='lattice.local_lifetime_checks.v1',status='PASS',build_sha256=sha(build/'build.xml'),
        archive_sha256=sha(archive),source_sha256={str(p.relative_to(ROOT)):sha(p) for p in (unit,sign,unit.parent/'src/common.h',ROOT/'tests/pruning/layout_probe_impl.h',Path(__file__))},
        source_order_checks=checks,rows=rows,positive_detector_controls=controls,commands=logs,
        scope='All compact-row/hash intervals from the actual compiled types and selected public feature flags; source-order/release anchors.'))
    print('PASS',len(rows),'actual parameter layouts')
if __name__=='__main__':main()
