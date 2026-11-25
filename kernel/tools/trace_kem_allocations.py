"""Record named arena owners in complete ML-KEM operations.

The trace build replaces one allocation macro header and the KEM translation
unit in an existing static archive. It is used for allocation attribution;
timing and stack reservations come from the uninstrumented build.
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
import argparse, hashlib, record_io as json, os, subprocess

ROOT=Path(__file__).resolve().parents[1]

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

TRACE=r'''
#include <stdio.h>
extern int lc_trace_enabled;
static void *lc_trace_alloc(lc_arena *a,size_t n,const char *fn,const char *owner){
 size_t before=a->used;void *p=lc_arena_alloc(a,n);
 if(lc_trace_enabled)printf("{\"event\":\"alloc\",\"function\":\"%s\",\"owner\":\"%s\",\"bytes\":%llu,\"before\":%llu,\"offset\":%llu,\"after\":%llu,\"ok\":%s}\n",fn,owner,(unsigned long long)n,(unsigned long long)before,(unsigned long long)(p?(unsigned char*)p-a->base:0),(unsigned long long)a->used,p?"true":"false");
 return p;
}
static void lc_trace_free(lc_arena *a,void *p,size_t n,const char *fn,const char *owner){
 size_t before=a->used;lc_arena_free(a,p,n);
 if(lc_trace_enabled)printf("{\"event\":\"free\",\"function\":\"%s\",\"owner\":\"%s\",\"bytes\":%llu,\"before\":%llu,\"after\":%llu}\n",fn,owner,(unsigned long long)n,(unsigned long long)before,(unsigned long long)a->used);
}
'''
PROBE=r'''
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "latticecore.h"
int lc_trace_enabled=0;
static uint64_t state;
static int rng(void *u,uint8_t *p,size_t n){(void)u;while(n--){state^=state<<13;state^=state>>7;state^=state<<17;*p++=(uint8_t)state;}return 0;}
static uint64_t hash_bytes(const uint8_t *p,size_t n){uint64_t h=UINT64_C(14695981039346656037);while(n--){h^=*p++;h*=UINT64_C(1099511628211);}return h;}
int main(int argc,char **argv){
 if(argc!=2)return 1;FILE *transcript=fopen(argv[1],"wb");if(!transcript)return 1;
 _Alignas(32) static unsigned char workspace[262144];
 uint8_t pk[1568],sk[3168],ct[1568],ss[32],ss2[32];
 int levels[]={512,768,1024};lc_context ctx;lc_sizes sz;
 for(int j=0;j<3;j++){
  int p=levels[j];state=UINT64_C(274413579)+p;
  if(lc_get_sizes(p,&sz)||lc_context_init(&ctx,workspace,sizeof workspace,rng,0))return 2;
  for(int op=0;op<3;op++){
   printf("{\"event\":\"begin\",\"parameter\":%d,\"operation\":%d}\n",p,op);lc_trace_enabled=1;
   int rc=op==0?lc_keypair(&ctx,p,pk,sz.public_key,sk,sz.secret_key):op==1?lc_encaps(&ctx,p,ct,sz.ciphertext,ss,32,pk,sz.public_key):lc_decaps(&ctx,p,ss2,32,ct,sz.ciphertext,sk,sz.secret_key);
   lc_trace_enabled=0;if(rc||(op==2&&memcmp(ss,ss2,32)))return 3;
   if(op==0){if(fwrite(pk,1,sz.public_key,transcript)!=sz.public_key||fwrite(sk,1,sz.secret_key,transcript)!=sz.secret_key)return 5;}
   else if(op==1){if(fwrite(ct,1,sz.ciphertext,transcript)!=sz.ciphertext||fwrite(ss,1,32,transcript)!=32)return 5;}
   else if(fwrite(ss2,1,32,transcript)!=32)return 5;
   uint64_t h=op==0?hash_bytes(pk,sz.public_key)^hash_bytes(sk,sz.secret_key):op==1?hash_bytes(ct,sz.ciphertext)^hash_bytes(ss,32):hash_bytes(ss2,32);
   for(size_t i=0;i<ctx.arena_high_water;i++)if(workspace[i])return 4;
   printf("{\"event\":\"end\",\"parameter\":%d,\"operation\":%d,\"peak\":%llu,\"output_checksum\":\"%016llx\",\"cleared\":true,\"rc\":%d}\n",p,op,(unsigned long long)ctx.arena_high_water,(unsigned long long)h,rc);
  }
 }return fclose(transcript)?6:0;
}
'''

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();b=args.build.resolve();out=args.output.resolve()
    assert not out.exists();out.mkdir(parents=True);(out/'tmp').mkdir()
    env=dict(os.environ,TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'))
    commands=json.loads((b/'commands.xml').read_text());record=json.loads((b/'build.xml').read_text())
    assert sha(b/'commands.xml')==record['commands_sha256']
    logs=[]
    def run(name,cmd):
        q=subprocess.run(list(map(str,cmd)),env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
        (out/(name+'.log')).write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8')
        logs.append(dict(name=name,argv=list(map(str,cmd)),exit_code=q.returncode))
        (out/'commands.xml').write_text(json.dumps(logs,indent=2))
        assert q.returncode==0,(name,q.stderr[-1200:]);return q.stdout
    command=next(c['argv'] for c in commands if '-c' in c['argv'] and c['argv'][c['argv'].index('-c')+1].replace('\\','/').endswith('/baselines/mlkem/all.c'))
    oldroot=command[command.index('-c')+1].replace('\\','/').removesuffix('/baselines/mlkem/all.c')
    cc=command[0];oldobj=Path(command[command.index('-o')+1]);obj=out/oldobj.name
    header=(ROOT/'configs/hosted/mlkem_config.h').read_text()
    anchor='#define MLK_CUSTOM_ALLOC(v,T,N,context) T *v = (T *)lc_arena_alloc(context,sizeof(T)*(N))'
    assert anchor in header
    header=header.replace(anchor,TRACE+'\n#define MLK_CUSTOM_ALLOC(v,T,N,context) T *v = (T *)lc_trace_alloc(context,sizeof(T)*(N),__func__,#v)')
    header=header.replace('#define MLK_CUSTOM_FREE(v,T,N,context) lc_arena_free(context,v,sizeof(T)*(N))','#define MLK_CUSTOM_FREE(v,T,N,context) lc_trace_free(context,v,sizeof(T)*(N),__func__,#v)')
    (out/'mlkem_config.h').write_text(header,encoding='utf-8')
    argv=[x.replace('\\','/').replace(oldroot,ROOT.as_posix()) for x in command]
    argv[argv.index('-o')+1]=str(obj)
    if '-MF' in argv:argv[argv.index('-MF')+1]=str(out/'trace.d')
    argv.insert(1,'-I'+str(out));run('trace-compile',argv)
    probe=out/'probe.c';probe.write_text(PROBE,encoding='utf-8')
    # Resolve KEM from the trace object before consulting the archive. Its
    # original KEM object therefore stays unselected by the static linker.
    links=['-Os','-flto'] if record['lto'] else ['-'+record['optimization']]
    for label,extra in [('trace',[obj]),('control',[])]:
        exe=out/(label+('.exe' if os.name=='nt' else ''))
        platform_link=['-lbcrypt'] if os.name=='nt' else []
        run(label+'-link',[cc,*links,'-I'+str(ROOT/'include'),probe,*extra,b/'liblatticecore.a',*platform_link,'-o',exe])
        run(label+'-run',[exe,out/(label+'-outputs.bin')])
    assert (out/'trace-outputs.bin').read_bytes()==(out/'control-outputs.bin').read_bytes()
    events=[json.loads(x) for x in (out/'trace-run.log').read_text().splitlines() if x.startswith('{')]
    control=[json.loads(x) for x in (out/'control-run.log').read_text().splitlines() if x.startswith('{')]
    ends=[x for x in events if x['event']=='end'];assert ends==[x for x in control if x['event']=='end']
    cells=[];live=[];cell=None
    for e in events:
        if e['event']=='begin':
            assert not live;cell=dict(parameter=e['parameter'],operation=e['operation'],peak=0,peak_owners=[])
        elif e['event']=='alloc':
            assert e['ok'];live.append(e)
            if e['after']>cell['peak']:
                cell.update(peak=e['after'],peak_owners=[dict(function=x['function'],owner=x['owner'],bytes=x['bytes'],offset=x['offset'],padding_and_header=x['offset']-x['before']) for x in live])
        elif e['event']=='free':
            last=live.pop();assert last['bytes']==e['bytes'] and last['before']==e['after']
        else:
            assert not live and cell['peak']==e['peak'];cell['output_checksum']=e['output_checksum'];cells.append(cell)
    result=dict(schema='lattice.kem_allocation_trace.v1',status='PASS',configuration=record['configuration'],compiler=record['compiler'],optimization=record['optimization'],lto=record['lto'],source_root_mapped=True,source_build_sha256=sha(b/'build.xml'),source_library_sha256=record['binary']['sha256'],original_archive_sha256=sha(b/'liblatticecore.a'),instrumented_header_sha256=sha(out/'mlkem_config.h'),events_sha256=sha(out/'trace-run.log'),control_sha256=sha(out/'control-run.log'),full_output_bytes=(out/'trace-outputs.bin').stat().st_size,full_output_sha256=sha(out/'trace-outputs.bin'),cells=cells,scope='Named workspace owners; original build supplies timing and stack reservations. Every output byte, cleanup, and exact arena high-water match uninstrumented execution.')
    (out/'result.xml').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(dict(status='PASS',cells=len(cells),peaks=[x['peak'] for x in cells])))

if __name__=='__main__':main()
