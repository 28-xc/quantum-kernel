"""Check exact scalar C representations and bitmap predicates with CBMC.

Functions are taken verbatim from the selected source, with explicit integer
and loop bounds. Vector intrinsics and assembly have separate differential tests.
"""
from pathlib import Path
from decimal import Decimal
import json as wire_json
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
import argparse, hashlib, record_io as json, os, re, subprocess, time
ROOT=Path(__file__).resolve().parents[2]
SRC=ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted/src'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def write_cbmc_output(path, captured, timed_out):
    """Store the verifier's structured output, including completed messages on a timeout."""
    decoder = wire_json.JSONDecoder(parse_float=Decimal)
    try:
        text = captured.decode('utf-8-sig')
    except UnicodeDecodeError as error:
        json.write(path, dict(status='INVALID_CBMC_ENCODING', timed_out=timed_out,
                              captured_bytes=len(captured), byte_offset=error.start,
                              sha256=hashlib.sha256(captured).hexdigest(), error=error.reason))
        return []
    try:
        document = decoder.decode(text)
    except wire_json.JSONDecodeError as error:
        complete = []
        pos = len(text) - len(text.lstrip())
        if text[pos:pos + 1] == '[':
            pos += 1
            while pos < len(text):
                while pos < len(text) and text[pos].isspace():
                    pos += 1
                try:
                    message, end = decoder.raw_decode(text, pos)
                except wire_json.JSONDecodeError:
                    break
                complete.append(message)
                pos = end
                while pos < len(text) and text[pos].isspace():
                    pos += 1
                if text[pos:pos + 1] != ',':
                    break
                pos += 1
        json.write(path, dict(status='INCOMPLETE_CBMC_OUTPUT', timed_out=timed_out,
                              parsed_messages=complete, captured_bytes=len(captured),
                              captured_sha256=hashlib.sha256(captured).hexdigest(),
                              parse_error=error.msg, line=error.lineno, column=error.colno))
        return []
    json.write(path, document)
    return document

def function(path,name):
    s=Path(path).read_text(encoding='utf-8');m=re.search(r'^static[^\n]*\b'+name+r'\(',s,re.M)
    assert m,name
    begin=m.start();brace=s.index('{',m.end());depth=1;end=brace+1
    while depth:
        if s[end]=='{':depth+=1
        if s[end]=='}':depth-=1
        end+=1
    return s[begin:end]+'\n'
PRE='''/* Exact-width types for this freestanding integer-only proof harness. */
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef int int32_t;
_Static_assert(sizeof(uint8_t)==1 && sizeof(uint32_t)==4 && sizeof(int32_t)==4,"integer widths");
#define assert(x) __CPROVER_assert((x),#x)
#define MLD_INLINE inline
#define __contract__(...)
extern int32_t nondet_i32(void);
extern unsigned nondet_u32(void);
'''
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cbmc',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--cases',default='signed24,hint44,hint65,low18,low19,low20,low18-alias,low19-alias,low20-alias,fips44,fips65,fips87')
    p.add_argument('--timeout',type=int,default=600);a=p.parse_args()
    assert not a.output.exists();a.output.mkdir(parents=True);tmp=a.output/'tmp';tmp.mkdir()
    env=dict(os.environ,TMP=str(tmp.resolve()),TEMP=str(tmp.resolve()),TMPDIR=str(tmp.resolve()))
    version=subprocess.check_output([str(a.cbmc.resolve()),'--version'],text=True).strip()
    result=dict(schema='lattice.local_c_proofs.v1',status='RUNNING',tool_version=version,tool_sha256=sha(a.cbmc),runner_sha256=sha(__file__),source_hashes={n:sha(SRC/n) for n in ['lc_inplace_sampling.h','lc_w0_fixed.h','rounding.h']},records=[])
    def save():(a.output/'result.xml').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    for case in a.cases.split(','):
        if case=='signed24':
            source=PRE+function(SRC/'lc_inplace_sampling.h','lc_load_signed24')+function(SRC/'lc_inplace_sampling.h','lc_store_signed24')+'''
int main(void) {
  int32_t x=nondet_i32();__CPROVER_assume(x>=-8388608 && x<=8388607);
  uint8_t p[3];lc_store_signed24(p,x);int32_t y=lc_load_signed24(p);
  assert(y==x);return 0;
}
'''
            condition='All signed 24-bit integers; exact three-byte storage and restoration.'
        elif case in ('hint44','hint65','fips44','fips65','fips87'):
            g=(8380417-1)//(88 if case.endswith('44') else 32)
            source=PRE+f'#define MLDSA_GAMMA2 {g}\n'+function(SRC/'rounding.h','mld_make_hint')+'''
int main(void) {
  int32_t low=nondet_i32(),high=nondet_i32();
  __CPROVER_assume(low>=-2*MLDSA_GAMMA2 && low<=2*MLDSA_GAMMA2);
  __CPROVER_assume(high>=0 && high<(8380417-1)/(2*MLDSA_GAMMA2));
  unsigned original=mld_make_hint(low,high),bitmap=mld_make_hint(low,high!=0);
  assert(original==bitmap);
  assert(bitmap==(low>MLDSA_GAMMA2 || low< -MLDSA_GAMMA2 || (low==-MLDSA_GAMMA2 && high!=0)));
  return 0;
}
'''
            condition='Valid high-part domain and signed low-part domain, including both +/-gamma2 endpoints; replacement of full high value with nonzero predicate.'
            if case.startswith('fips'):
                beta=78 if case.endswith('44') else 120 if case.endswith('87') else 196
                source=PRE+f'#define MLDSA_GAMMA2 {g}\n#define BETA {beta}\n'+function(SRC/'rounding.h','mld_make_hint')+'''
#define Q 8380417
static int32_t canonical(int32_t x) {int32_t r=x%Q;return r<0?r+Q:r;}
static int32_t high_ref(int32_t x,int32_t *low) {
  int32_t a=canonical(x),v=a%(2*MLDSA_GAMMA2);
  if(v>MLDSA_GAMMA2)v-=2*MLDSA_GAMMA2;
  if(a-v==Q-1){*low=v-1;return 0;}
  *low=v;return (a-v)/(2*MLDSA_GAMMA2);
}
int main(void) {
  int32_t w=nondet_i32(),cs=nondet_i32(),ct=nondet_i32(),w0,ignored;
  __CPROVER_assume(w>=0 && w<Q);
  __CPROVER_assume(cs>=-BETA && cs<=BETA);
  __CPROVER_assume(ct> -MLDSA_GAMMA2 && ct<MLDSA_GAMMA2);
  int32_t w1=high_ref(w,&w0),r0=w0-cs;
  __CPROVER_assume(r0> -MLDSA_GAMMA2+BETA && r0<MLDSA_GAMMA2-BETA);
  unsigned fips=(high_ref(w-cs+ct,&ignored)!=high_ref(w-cs,&ignored));
  assert(mld_make_hint(r0+ct,w1!=0)==fips);
  return 0;
}
'''
                condition='All canonical w, bounded challenge-secret product, both strict signing norm premises; actual bitmap predicate equals division-based FIPS MakeHint(-ct,w-cs+ct).'
        elif case.split('-')[0] in ('low18','low19','low20'):
            bits=int(case[3:5]);source=PRE+f'''#define MLDSA_N 256
#define LC_BUILD_ARM_PROFILE 1
#define LC_W0_BITS {bits}
typedef struct {{int32_t coeffs[256];}} mld_poly;
#include "lc_w0_fixed.h"
int main(void) {{
  mld_poly a,b;uint8_t encoded[256*LC_W0_BITS/8];
  for(unsigned j=0;j<256;j++) {{
    a.coeffs[j]=nondet_i32();
    __CPROVER_assume(a.coeffs[j]>=-(1<<(LC_W0_BITS-1)) && a.coeffs[j]<(1<<(LC_W0_BITS-1)));
  }}
  lc_pack_w0_row(encoded,&a);lc_unpack_w0_row(&b,encoded);
  for(unsigned j=0;j<256;j++) assert(a.coeffs[j]==b.coeffs[j]);
  return 0;
}}
'''
            condition=f'All 256 independent signed {bits}-bit coefficients; entire scalar fixed-group functions, exact-sized buffers; loop bound 257 with unwinding assertions.'
            if case.endswith('-alias'):
                source=source.replace('lc_pack_w0_row(encoded,&a);lc_unpack_w0_row(&b,encoded);','mld_poly original=a;lc_pack_w0_row((uint8_t *)&a,&a);lc_unpack_w0_row(&b,(const uint8_t *)&a);a=original;')
                condition+=' Packing output aliases its full input; comparison retains the original before overwrite.'
        else:raise ValueError(case)
        f=a.output/(case+'.c');f.write_text(source,encoding='utf-8')
        cmd=[str(a.cbmc.resolve()),str(f.resolve()),'--gcc','-I'+str(SRC),'--function','main','--unwind','257','--unwinding-assertions','--bounds-check','--pointer-check','--signed-overflow-check','--undefined-shift-check','--div-by-zero-check','--slice-formula','--json-ui']
        start=time.monotonic()
        try:
            proc=subprocess.run(cmd,env=env,capture_output=True,timeout=a.timeout)
            raw=proc.stdout;stderr=proc.stderr.decode('utf-8', errors='replace');code=proc.returncode
        except subprocess.TimeoutExpired as e:
            raw=e.stdout or b''
            stderr='TIMEOUT';code=None
        log=a.output/(case+'.xml')
        doc=write_cbmc_output(log, raw, code is None)
        (a.output/(case+'.stderr')).write_text(stderr,encoding='utf-8')
        try:
            proof=[x for item in doc for x in item.get('result',[])]
            statuses={x['status'] for x in proof};ok=code==0 and bool(proof) and statuses=={'SUCCESS'} and any(item.get('cProverStatus')=='success' for item in doc)
        except (ValueError,TypeError):proof=[];ok=False
        result['records'].append(dict(case=case,status='PROVED' if ok else 'INCOMPLETE_OR_FAILED',condition=condition,command=cmd,exit_code=code,seconds=time.monotonic()-start,properties=len(proof),unwinding_assertions=True,harness_sha256=sha(f),log_sha256=sha(log)))
        save();print(case,result['records'][-1]['status'],len(proof),flush=True)
        if not ok:raise RuntimeError('Proof did not complete: '+case)
    result['status']='PROVED_SELECTED_C_PROPERTIES';save()
if __name__=='__main__':main()
