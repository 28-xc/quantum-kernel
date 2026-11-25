"""Generate only parameter dispatch and instantiation entrypoints."""
import re

ALL = [512,768,1024,44,65,87]

def public_source(root, levels, operations=None):
    text=(root/'src/common/public_api.c').read_text(encoding='utf-8')
    text='#include "latticecore_pruned.h"\nstatic int lc_standard_parameter(int p){return p==512||p==768||p==1024||p==44||p==65||p==87;}\nstatic int lc_pruned_supports(int p){return '+('||'.join('p=='+str(p) for p in levels))+';}\n'+text
    for family,params in [('kem',[p for p in levels if p>100]),('dsa',[p for p in levels if p<100])]:
        pred='||'.join('p=='+str(p) for p in params) or '0'
        text,n=re.subn(r'static int '+family+r'\(int p\)\{return [^}]+\}',f'static int {family}(int p){{return {pred};}}',text)
        if n!=1:raise ValueError('Public family predicate anchor changed')
    for p in ALL:
        if p not in levels:
            text,n=re.subn(r' case '+str(p)+r':s->public_key=[^\n]+\n','',text)
            if n!=1:raise ValueError('Public size selector anchor changed')
    anchor=' default:return LC_E_ARGUMENT;\n }\n if(kem(p))s->shared_secret=32;'
    if text.count(anchor)!=1:raise ValueError('Size default anchor changed')
    text=text.replace(anchor,anchor.replace('LC_E_ARGUMENT','lc_standard_parameter(p)?LC_E_UNSUPPORTED:LC_E_ARGUMENT'))
    for name in ('keypair','encaps','decaps','sign','verify'):
        text,n=re.subn(r'(int lc_'+name+r'\([^\n]+\)\{\n)',r'\1 if(lc_standard_parameter(p)&&!lc_pruned_supports(p))return LC_E_UNSUPPORTED;\n',text)
        if n!=1:raise ValueError('Public operation anchor changed: '+name)
    anchor='const char*lc_error_string(int e){switch(e){'
    if text.count(anchor)!=1:raise ValueError('Error string anchor changed')
    from operation_selection import restrict_public
    return restrict_public(text.replace(anchor,anchor+'case LC_E_UNSUPPORTED:return "unsupported parameter or operation in this build";'),operations,levels)

def kem_source(root, levels, operations=None):
    levels=[p for p in levels if p>100]
    if not levels:return '#include "lc_arena.h"\nint lc_mlk_call(int p,int o,unsigned char*a,unsigned char*b,const unsigned char*c,const unsigned char*d,lc_arena*x){(void)p;(void)o;(void)a;(void)b;(void)c;(void)d;(void)x;return -8;}\n'
    out=['/* Generated selected-level includes. Upstream arithmetic is unchanged. */']
    for i,p in enumerate(levels):
        if i==0:
            out.append('#define MLK_CONFIG_MULTILEVEL_WITH_SHARED')
            if len(levels)>1:out.append('#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS')
        elif i==1:out.append('#define MLK_CONFIG_MULTILEVEL_NO_SHARED')
        if i and i==len(levels)-1:out.append('#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS')
        out += ['#define MLK_CONFIG_PARAMETER_SET '+str(p),'#include "mlkem_native.c"','#undef MLK_CONFIG_PARAMETER_SET']
        if i==0:out.append('#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED')
    original=(root/'baselines/mlkem/all.c').read_text(encoding='utf-8')
    start=original.index('int lc_mlk_call(');dispatch=original[start:]
    old='switch(level) { LC_CASE(512); LC_CASE(768); LC_CASE(1024); }'
    if dispatch.count(old)!=1:raise ValueError('ML-KEM dispatch anchor changed')
    dispatch=dispatch.replace(old,'switch(level) { '+' '.join(f'LC_CASE({p});' for p in levels)+' }')
    from operation_selection import restrict_kem
    return restrict_kem('\n'.join(out)+'\n'+dispatch,operations,levels)

def adapter_source(source,levels,operations=None):
    levels=[p for p in levels if p<100]
    if not levels:
        return '''#include "lc_dsa_api.h"
int lc_dsa_keypair_seed(int l,uint8_t*p,uint8_t*s,const uint8_t*r,void*w,size_t n,lc_dsa_stats*t){return -8;}
int lc_dsa_sign_seed(int l,uint8_t*s,const uint8_t*m,size_t n,const uint8_t*c,size_t k,const uint8_t*r,const uint8_t*d,void*w,size_t z,lc_dsa_stats*t){return -8;}
int lc_dsa_verify(int l,const uint8_t*s,size_t z,const uint8_t*m,size_t n,const uint8_t*c,size_t k,const uint8_t*p,void*w,size_t b,lc_dsa_stats*t){return -8;}
size_t lc_dsa_workspace_bound(int l,int op){(void)l;(void)op;return 0;}
#if LC_DSA_RUNTIME_CACHE
size_t lc_dsa_runtime_sign_workspace(int l,unsigned rows){(void)l;(void)rows;return 0;}
size_t lc_dsa_runtime_keypair_workspace(int l){(void)l;return 0;}
unsigned lc_dsa_runtime_cache_rows(size_t n){(void)n;return 0;}
#endif
'''
    text=source.read_text(encoding='utf-8');start=text.index('#define DISPATCH(');end=text.index('\n',start)
    dispatch='#define DISPATCH(call, ...) switch(l) { '+' '.join(f'case {p}: ret=lcbase{p}_##call(__VA_ARGS__,&a); break;' for p in levels)+' default: ret=-9; }'
    for p in (44,65,87):
        if p not in levels:
            text=text.replace(f'  case {p}:return lc_runtime_sign{p}_workspace(rows);\n','')
            text=text.replace(f'  case {p}:return lc_runtime_keypair{p}_workspace();\n','')
    if 87 not in levels:
        text=text.replace('  if(available>=lc_runtime_sign87_workspace(8))return 8;\n  if(available>=lc_runtime_sign87_workspace(5))return 5;','  (void)available;')
    start=text.index('#define DISPATCH(');end=text.index('\n',start)
    from operation_selection import restrict_adapter
    return restrict_adapter(text[:start]+dispatch+text[end:],operations,levels)

def selected_parameters(text):
    named = {'all': ALL, 'kem': ALL[:3], 'dsa': ALL[3:]}
    values = named[text] if text in named else [int(x) for x in text.split(',')]
    if not values or len(set(values)) != len(values) or not set(values) <= set(ALL):
        raise ValueError('Select a nonempty set of distinct standard parameters')
    return [p for p in ALL if p in values]

def shared_kem_constants(backend, rejection=False):
    # Only primitive data ownership; no KEM parameter implementation is included.
    if backend == 'aarch64':
        return ('#define MLK_CONFIG_PARAMETER_SET 512\n#define MLK_CONFIG_MULTILEVEL_WITH_SHARED\n'
                '#include "src/fips202/native/aarch64/src/keccakf1600_round_constants.c"\n' +
                ('#include "src/native/aarch64/src/rej_uniform_table.c"\n' if rejection else ''))
    if backend != 'x86_64':raise ValueError('Native shared-owner backend required')
    return ('#define MLK_CONFIG_PARAMETER_SET 512\n'
            '#define MLK_CONFIG_MULTILEVEL_WITH_SHARED\n'
            '#include "src/fips202/native/x86_64/src/keccakf1600_constants.c"\n')
