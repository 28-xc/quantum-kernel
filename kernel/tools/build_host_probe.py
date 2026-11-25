"""Build a generic x86-64 CPUID helper and record this compiler's native ISA envelope."""
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
import argparse, ctypes, hashlib, record_io as json, os, re, shutil, subprocess, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'demo'))
from publicschemas.cpu_features import FEATURES
import host_cpu

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default='gcc');a=p.parse_args()
    output=a.output.resolve()
    if output.exists():raise ValueError('Fresh helper directory required')
    output.mkdir(parents=True);(output/'tmp').mkdir()
    env=os.environ|{'TEMP':str(output/'tmp'),'TMP':str(output/'tmp')}
    cc=shutil.which(a.cc)
    if not cc:raise ValueError('Compiler missing')
    version=subprocess.check_output([cc,'--version'],env=env,text=True).splitlines()[0]
    macros=subprocess.check_output([cc,'-march=native','-dM','-E','-'],input='',env=env,text=True)
    (output/'native_macros.txt').write_text(macros,encoding='utf-8')
    required=sorted(f for f in FEATURES if re.search(r'^#define __'+('LAHF_SAHF' if f=='sahf' else f.upper())+r'__\s+1$',macros,re.M))
    source=ROOT/'demo/host_features.c';library=output/'host_features.dll'
    command=[cc,'-O2','-std=c11','-march=x86-64','-mtune=generic','-mno-avx','-mno-avx2','-mno-bmi','-mno-bmi2','-fno-tree-vectorize','-shared',str(source),'-o',str(library)]
    result=subprocess.run(command,env=env,capture_output=True,text=True)
    (output/'build.log').write_text(json.capture_text(result.stdout+result.stderr),encoding='utf-8');result.check_returncode()
    objdump=str(Path(cc).with_name('objdump.exe'))
    disasm=subprocess.check_output([objdump,'-d',str(library)],env=env,text=True)
    (output/'disassembly.txt').write_text(disasm,encoding='utf-8')
    instructions=re.findall(r'^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s*([a-z][a-z0-9]+)',disasm,re.M)
    forbidden=[x for x in instructions if x.startswith('v') or x in {'andn','mulx','tzcnt','lzcnt','pdep','pext','blsi','blsr','blsmsk','bextr','bzhi','rorx','sarx','shlx','shrx'}]
    if forbidden:raise ValueError('Helper uses an advanced ISA before checking: '+repr(forbidden))
    host=host_cpu.query(library);assert host['query_succeeded'] and set(required)<=set(host['features'])
    lib=ctypes.CDLL(str(library));lib.lc_host_query.argtypes=[ctypes.POINTER(ctypes.c_uint32),ctypes.c_size_t]
    sentinel=(ctypes.c_uint32*13)(*([0xabcdef01]*13));assert lib.lc_host_query(sentinel,12)==-1 and list(sentinel)==[0xabcdef01]*13
    record=dict(schema='lattice.host_probe.v1',compiler=version,command=command,source_sha256=sha(source),helper_sha256=sha(library),
                native_macros_sha256=sha(output/'native_macros.txt'),baseline_disassembly_sha256=sha(output/'disassembly.txt'),
                inspected_instruction_count=len(instructions),advanced_vector_or_bmi_instructions=[],host=host,
                native_execution=dict(backend='x86_64',required_features=required,required_xcr0=6),
                requirement_scope='Conservative enabled instruction-set macros from this compiler and build CPU; individual core instruction use may be narrower.')
    (output/'result.xml').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(output/'result.xml')

if __name__=='__main__':main()
