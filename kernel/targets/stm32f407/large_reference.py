"""Single-threaded storage placement for the unchanged arithmetic of large PQClean C.

The F407 CCM upper bound is 64 KiB. Move the same public matrix and three
distinct local vectors to static banks. No two live vectors alias. The
remaining PQClean row/NTT arithmetic, rejection loop and packing are unchanged.
"""
import hashlib
import re
def source_sign(text):
    point='#include <stdint.h>'
    if text.count(point)!=1:raise ValueError('PQClean includes changed')
    decl="""
static polyvecl f407_matrix[K] __attribute__((section(".ccm_matrix")));
static polyvecl f407_s1 __attribute__((section(".low_poly")));
static polyvecl f407_y __attribute__((section(".low_poly")));
static polyvecl f407_z __attribute__((section(".ccm_matrix")));
#define mat f407_matrix
#define s1 f407_s1
#define s1hat f407_y
#define y f407_y
#define z f407_z
"""
    for a in ('    polyvecl mat[K];','    polyvecl s1, s1hat;','    polyvecl mat[K], s1, y, z;','    polyvecl mat[K], z;'):
        if text.count(a)!=1:raise ValueError('PQClean variable placement changed')
        text=text.replace(a,'')
    tail='\nextern void clear_bytes(void*,size_t);\nvoid reference_clear_polys(void){clear_bytes(&f407_s1,sizeof(f407_s1));clear_bytes(&f407_y,sizeof(f407_y));clear_bytes(&f407_z,sizeof(f407_z));clear_bytes(&f407_matrix,sizeof(f407_matrix));}\n'
    return text.replace(point,point+'\n'+decl)+tail
def shorter_vectors(path):
    text=path.read_text()
    arrays={k:bytes.fromhex(v.replace('0x','').replace(',','').replace('\n','')) for k,v in re.findall(r'static const uint8_t (vector_bytes_\d+)\[\]=\{\n([^\}]+)\n\};',text)}
    new={}
    def row(m):
        parts=list(re.finditer(r'\{(0|vector_bytes_\d+),(\d+)\}',m[0]))
        if len(parts)!=9:raise ValueError('vector row layout changed')
        value=m[0]
        for i in (8,7):
            tok=parts[i];name=tok[1]
            if name=='0':continue
            digest=hashlib.sha3_256(arrays[name]).digest()
            new[name+'_digest']=digest
            value=value[:tok.start()]+'{'+name+'_digest,32}'+value[tok.end():]
        return value
    text,n=re.subn(r'^\{\d+,\d+,[01],\d+,[^\n]+$',row,text,flags=re.M)
    if n!=4:raise ValueError('large ML-DSA KAT count changed')
    for name in arrays:
        if len(re.findall(r'\b'+name+r'\b',text))==1:
            text,n=re.subn(r'static const uint8_t '+name+r'\[\]=\{\n[^\}]+\n\};\s*','',text)
            if n!=1:raise ValueError('unused vector removal failed')
    data='\n'.join('static const uint8_t '+k+'[32]={'+','.join(map(str,v))+'};' for k,v in new.items())
    return text.replace('static const lc_target_vector target_vectors[]',data+'\nstatic const lc_target_vector target_vectors[]')
def experiment_source(text):
    old='static int exact(const uint8_t *p,size_t n,lc_vector_bytes v){return n==v.n&&!memcmp(p,v.p,n);}'
    new='#include "fips202.h"\nstatic int exact(const uint8_t *p,size_t n,lc_vector_bytes v){uint8_t h[32];sha3_256(h,p,n);return v.n==32&&!memcmp(h,v.p,32);}'
    if text.count(old)!=1 or text.count('} io;')!=1:raise ValueError('experiment source changed')
    return ('extern void reference_clear_polys(void);\n'+text.replace(old,new).replace('} io;','} io __attribute__((section(".low_io")));').replace('clear_bytes(arena,sizeof(arena));clear_bytes(&ctx,sizeof(ctx));','clear_bytes(arena,sizeof(arena));clear_bytes(&ctx,sizeof(ctx));reference_clear_polys();'))
def startup_source(text):
    old='4: ldr r1,=__stack_guard_bottom'
    new='4: ldr r1,=__low_begin\n ldr r2,=__low_end\n7: cmp r1,r2\n bhs 8f\n str r0,[r1],#4\n b 7b\n8: ldr r1,=__stack_guard_bottom'
    if text.count(old)!=1:raise ValueError('startup source changed')
    return text.replace(old,new)

