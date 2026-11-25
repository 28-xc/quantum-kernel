"""Build the existing serialized/reused driver and verify all eighteen cells."""
from pathlib import Path
import argparse
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
import record_io as json
import os
import shutil
import subprocess
from common import sha, validate_csv

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--boundary', choices=('serialized','reused'), required=True)
    p.add_argument('--library', type=Path, required=True)
    p.add_argument('--crypto-library', type=Path, required=True)
    p.add_argument('--crypto-prefix', type=Path, required=True)
    p.add_argument('--expected-version', choices=('3.6.0','3.6.4'), required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--cc', default='gcc'); p.add_argument('--cpu', type=int, required=True)
    p.add_argument('--count', type=int, default=20); p.add_argument('--workspace', type=int, default=262144)
    p.add_argument('--message-bytes', type=int, default=1024); p.add_argument('--context-bytes', type=int, default=0)
    a = p.parse_args()
    out, library, crypto, prefix = (x.resolve() for x in (a.output,a.library,a.crypto_library,a.crypto_prefix))
    cc = shutil.which(a.cc)
    if out.exists() or out == ROOT or out in ROOT.parents:
        raise ValueError('Use a fresh output directory outside the source root')
    if not cc or not library.is_file() or not crypto.is_file() or not (prefix/'include/openssl/evp.h').is_file():
        raise ValueError('Explicit compiler, libraries and OpenSSL headers are required')
    if not (1<=a.count<=10000 and 32<=a.workspace<=262144 and 0<=a.message_bytes<=16384 and 0<=a.context_bytes<=255 and a.cpu>=0):
        raise ValueError('Invalid bounded preparation size')
    out.mkdir(parents=True); (out/'tmp').mkdir()
    env = os.environ.copy(); env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    env['PATH' if os.name=='nt' else 'LD_LIBRARY_PATH'] = str(crypto.parent)+os.pathsep+env.get('PATH' if os.name=='nt' else 'LD_LIBRARY_PATH','')
    driver_source = ROOT/'bench'/('openssl_'+a.boundary)/'driver.c'
    sources = []
    for source in (driver_source,ROOT/'include/latticecore.h',Path(__file__),HERE/'common.py',HERE/'collect.py'):
        relative = source.relative_to(ROOT)
        destination = out/'source_snapshot'/relative
        destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source,destination)
        sources.append(dict(path=destination.relative_to(out).as_posix(),sha256=sha(destination)))
    records = []
    def save(name, value):
        (out/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    def run(argv, label):
        result = subprocess.run(list(map(str,argv)),cwd=ROOT,env=env,capture_output=True,text=True,timeout=300)
        log = out/(label+'.log'); log.write_text(json.capture_text(result.stdout+result.stderr),encoding='utf-8')
        records.append(dict(arguments=list(map(str,argv)),exit_code=result.returncode,log=log.name,sha256=sha(log)))
        save('commands.xml',records)
        if result.returncode:
            raise RuntimeError(label+' failed with '+str(result.returncode))
        return result.stdout
    try:
        compiler = run([cc,'--version'],'compiler').splitlines()[0]
        driver = out/('driver.exe' if os.name=='nt' else 'driver')
        link_directory = prefix/'lib' if os.name=='nt' else crypto.parent
        command = [cc,'-O3','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'include'),
                   '-I'+str(prefix/'include'),driver_source,'-L'+str(link_directory),'-lcrypto']
        if os.name!='nt':
            command += ['-ldl','-Wl,-rpath,'+str(crypto.parent)]
        run(command+['-o',driver],'build')
        paired = {}; verification = []
        for parameter in (512,768,1024,44,65,87):
            for operation in range(3):
                for pct in ('none','random'):
                    label = f'{parameter}_{operation}_{pct}'
                    raw = out/(label+'.csv')
                    result = json.loads(run([driver,library,'compare',parameter,operation,a.count,
                        20260924,raw,a.workspace,a.message_bytes,a.context_bytes,pct,a.cpu,'verify',0,a.expected_version],label))
                    loaded = Path(result['openssl_library']).resolve()
                    if not loaded.samefile(crypto) or result['status']!='PASS' or result['cpu']!=a.cpu or result['provider']!='default' or result['import_pct']!=pct:
                        raise ValueError('Verification driver loaded a different provider or condition')
                    if a.boundary=='serialized' and result.get('fresh_serialized_key_every_call') is not True:
                        raise ValueError('Wrong serialized-key boundary')
                    if a.boundary=='reused' and result.get('openssl_key_reused_across_batch') != (operation>0):
                        raise ValueError('Wrong retained-key boundary')
                    rows = validate_csv(raw,result)
                    identity = (result['input_sequence_sha256'],result['output_sequence_sha256'],
                                [tuple(row[k] for k in ('case_id','entropy_sha256','message_sha256','context_sha256')) for row in rows])
                    if (parameter,operation) in paired and paired[parameter,operation] != identity:
                        raise ValueError('Import validation modes received different transcripts')
                    paired[parameter,operation] = identity
                    verification.append(dict(parameter=parameter,operation=operation,pct=pct,raw=raw.name,
                        raw_sha256=sha(raw),summary=result))
        record = dict(schema='lattice.complete_operation_driver.v1',status='PASS',boundary=a.boundary,
            expected_version=a.expected_version,driver=dict(path=str(driver),sha256=sha(driver)),
            crypto_library=dict(path=str(crypto),sha256=sha(crypto)),library=dict(path=str(library),sha256=sha(library)),
            compiler=compiler,sources=sources,verified_operation_cells=len(paired),
            all_input_output_sequences_match=True,verification=verification,
            timing_collected=False,commands_sha256=sha(out/'commands.xml'))
        save('prepared.xml',record)
        print(json.dumps(dict(status='PASS',operation_cells=len(paired),verification_calls=36*a.count)))
    except Exception as error:
        save('failure.xml',dict(status='FAIL',reason=str(error),commands=records))
        raise


if __name__=='__main__':
    main()
