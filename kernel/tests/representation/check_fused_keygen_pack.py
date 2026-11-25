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
import record_io as json, hashlib, subprocess, argparse
a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);a.add_argument('--compiler',default='gcc');args=a.parse_args();src=Path(__file__).resolve().parents[2];out=args.output.resolve();assert not out.exists();out.mkdir(parents=True)
s=(src/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted/src/sign.c').read_text()
start=s.index('static void lc_keygen_pack_t(');brace=s.index('{',start);depth=1;end=brace+1
while depth:
 depth+=(s[end]=='{')-(s[end]=='}');end+=1
f=s[start:end]
v=(src/'src/dsa_packed/lc_stream4_vector.h').read_text();red=v[v.index('LC_S4_INLINE __m256i lc_s4_reduce'):v.index('\nLC_S4_INLINE int lc_stream4_y_block')].replace('LC_S4_INLINE','static inline')
code='''#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct { int32_t coeffs[256]; } mld_poly;
#define mld_memcpy memcpy
'''+red+f+'''
static unsigned extract(const uint8_t*p,unsigned index,unsigned width){unsigned v=0;for(unsigned j=0;j<width;j++)v|=((p[(index*width+j)/8]>>((index*width+j)%8))&1u)<<j;return v;}
int main(void){
 __attribute__((aligned(32))) mld_poly a,b;
 uint8_t hp[322],lp[418];uint64_t n=0;
 /* Cover the full INTT-plus-error range, including all canonical residues. */
 for(int base=-8380421;base<8380422;base+=256){
  memset(hp,0xA7,sizeof hp);memset(lp,0xB9,sizeof lp);
  for(int i=0;i<256;i++){int x=base+i;if(x>8380421)x=8380421;int e=(i%9)-4;a.coeffs[i]=x-e;b.coeffs[i]=e;}
  lc_keygen_pack_t(hp+1,lp+1,&a,&b);
  if(hp[0]!=0xA7||hp[321]!=0xA7||lp[0]!=0xB9||lp[417]!=0xB9)return 2;
  for(unsigned i=0;i<256;i++){int x=(a.coeffs[i]+b.coeffs[i])%8380417;if(x<0)x+=8380417;unsigned hi=(x+4095)>>13,lo=4096-(x-(int)(hi<<13));if(extract(hp+1,i,10)!=hi||extract(lp+1,i,13)!=lo){fprintf(stderr,"mismatch %d\\n",x);return 3;}n++;}
 }
 printf("{\\"status\\":\\"PASS\\",\\"coefficients\\":%llu,\\"range_min\\":-8380421,\\"range_max\\":8380421,\\"canaries\\":true}\\n",(unsigned long long)n);return 0;
}
'''
p=out/'test.c';p.write_text(code);exe=out/'test.exe';cmd=[args.compiler,'-O3','-march=native','-std=c11',str(p),'-o',str(exe)];q=subprocess.run(cmd,capture_output=True,text=True);(out/'compile.log').write_text(json.capture_text(q.stdout+q.stderr));assert q.returncode==0,q.stderr
q=subprocess.run([str(exe)],capture_output=True,text=True);(out/'run.log').write_text(json.capture_text(q.stdout+q.stderr));assert q.returncode==0,q.stderr
d=json.loads(q.stdout);d.update(command=cmd,source_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),executable_sha256=hashlib.sha256(exe.read_bytes()).hexdigest());(out/'result.xml').write_text(json.dumps(d,indent=2));print(json.dumps(d))
