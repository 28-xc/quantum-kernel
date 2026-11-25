"""Link-time allocator observer for the unchanged native static archive."""
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
import argparse, hashlib, record_io as json, os, shutil, subprocess
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--package',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    src=a.source_root.resolve();package=a.package.resolve();out=a.output.resolve()
    if out.exists() or out.drive.upper()!='D:':raise ValueError('Fresh D: output required')
    out.mkdir(parents=True);(out/'tmp').mkdir();env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'))
    build=json.loads((package/'build.xml').read_text());lib=package/'liblatticecore.a'
    if sha(lib)!=build['binary']['static_sha256'] or build['schedule'].get('secret_prefix_polys')!=3:raise ValueError('Mismatched native archive or configuration')
    result={'status':'RUNNING','formal_timing':False,'coverage_guided':False,'build_json_sha256':sha(package/'build.xml'),'static_sha256':sha(lib),'test_source_sha256':sha(HERE/'prefix_cleanup.c'),'commands':[]}
    def run(argv,label):
        r=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,text=True);log=out/(label+'.log');log.write_text(json.capture_text(r.stdout+r.stderr))
        result['commands'].append({'argv':list(map(str,argv)),'exit_code':r.returncode,'log_sha256':sha(log)})
        if r.returncode:raise RuntimeError(label+' failed')
        return r.stdout
    try:
        exe=out/'prefix_cleanup.exe';cc=shutil.which('gcc');assert cc
        run([cc,'-O2','-std=c11','-I'+str(src/'include'),'-I'+str(src/'src/dsa_packed'),HERE/'prefix_cleanup.c',lib,'-lbcrypt','-Wl,--wrap=lc_dsa_alloc','-Wl,--wrap=lc_dsa_free','-o',exe],'compile')
        text=run([exe],'probe');rows=[json.loads(x) for x in text.splitlines() if x.startswith('{')]
        assert 'PREFIX_ERASURE_DETECTOR_POSITIVE_CONTROL_PASS' in text
        assert len(rows)==3 and [r['parameter'] for r in rows]==[44,65,87] and all(r['status']=='PASS' for r in rows)
        assert sha(lib)==result['static_sha256']
        result.update(status='PASS',records=rows,positive_control_detected=True,exe_sha256=sha(exe),scope='Native static archive, link-time allocator wrapper observes the first 3072-byte signing allocation (s1_prefix in fixed source order), checks all bytes are zero before free. Same context alternates two serialized keys with fixed entropy. Separate actual DLL capacity/whole-byte checks bind the public path. This is not a proof of all secret destruction or failed pre-initialization paths.')
    except Exception as e:
        result.update(status='FAIL_OR_INCOMPLETE',error=str(e));raise
    finally:(out/'result.xml').write_text(json.dumps(result,indent=2)+'\n')
    print('PASS: 54 fixed native signatures; prefix erased before allocator free; positive control detected')
if __name__=='__main__':main()
