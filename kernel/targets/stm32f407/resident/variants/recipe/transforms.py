import re
from pathlib import Path
HERE=Path(__file__).resolve().parent
CONFIG={"ntt":(62,False,True,False),"combined":(65,True,True,True)}
def definitions(src):
    """Match complete top-level function bodies in already-preprocessed C."""
    names={};level=0;start=0;in_body=None
    token=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]')
    for m in token.finditer(src):
        t=m[0]
        if t=='{':
            if level==0:
                pre=src[start:m.start()].strip()
                clean=re.sub(r'__attribute__\s*\(\([^;{}]{0,400}?\)\)','',pre)
                n=re.search(r'([A-Za-z_]\w*)\s*\((?!.*\)\s*=\s*)[^{};]*\)\s*$',clean,flags=re.S)
                in_body=(n[1],start,m.start()) if n and '=' not in clean.split('(')[0] else None
            level+=1
        elif t=='}':
            level-=1
            if level==0:
                if in_body:
                    n,a,z=in_body;names[n]=(a,z,m.end())
                in_body=None;start=m.end()
        elif t==';' and level==0:start=m.end()
    return names
def native_text(text):
    names=definitions(text)
    repl={'lcbase_poly_ntt':'pqcrystals_dilithium_ntt(a->coeffs);','lcbase_poly_invntt_tomont':'pqcrystals_dilithium_invntt_tomont(a->coeffs);','lcbase_poly_pointwise_montgomery':'pqcrystals_dilithium_asm_pointwise_montgomery(a->coeffs,a->coeffs,b->coeffs);'}
    for name in sorted(repl,key=lambda n:names[n][1],reverse=True):
        a,z,end=names[name]
        text=text[:z]+'{'+repl[name]+'}'+text[end:]
    anchor='typedef '
    return 'extern void pqcrystals_dilithium_ntt(int*);extern void pqcrystals_dilithium_invntt_tomont(int*);extern void pqcrystals_dilithium_asm_pointwise_montgomery(int*,const int*,const int*);\n'+text
def direct(s,old,new):
    if s.count(old)!=1:raise ValueError(('expected one active production site',old,s.count(old)))
    return s.replace(old,new)

def body_edit(s,name,fn):
    a,b,e=definitions(s)[name];return s[:b]+fn(s[b:e])+s[e:]

def change(p,st,text):
    ident,dsp,ntt,stream=CONFIG[st];rank={512:2,768:3,1024:4}[p];prefix=f'lc_base_mlk{p}_'
    if dsp or stream:
        first=definitions(text)[f'lc_kem_tile{p}'][0]
        helper=(HERE/'pair_core.c.in').read_text().replace('_LEVEL',str(p))
        helper=f'\n#define A127_DUAL_MAC {int(dsp)}\n#define A127_K {rank}\n'+helper+'\n'
        text=text[:first]+helper+text[first:]
    if dsp:
        name=prefix+'polyvec_basemul_acc_montgomery_cached'
        text=body_edit(text,name,lambda old:'{arm3329_dot(r,a,0,b,b_cache);}')
    if ntt:
        text='extern void ntt(short*);extern void invntt(short*);\n'+text
        text=body_edit(text,'lc_base_mlk_poly_ntt',lambda _: '{ntt(r->coeffs);}')
        # Native inverse requires centered input. Its output is -R times the
        # existing inverse_tomont, R=2^16: montgomery_reduce(-output) removes -R.
        text=body_edit(text,'lc_base_mlk_poly_invntt_tomont',lambda _:'{for(unsigned i=0;i<256;i++)r->coeffs[i]=mlk_barrett_reduce(r->coeffs[i]);invntt(r->coeffs);for(unsigned i=0;i<256;i++)r->coeffs[i]=mlk_montgomery_reduce(-(int32_t)r->coeffs[i]);}')
    if stream:
        for nm,seed,tr in [('indcpa_keypair_derand','buf',0),('indcpa_enc',f'pk+({rank} * 384)',1)]:
            def rewrite(body):
                alloc=re.search(r'lc_arena_alloc\(context,sizeof\(mlk_poly\)\*(\(\(\(1==4\)\?.+?)\);',body)
                if not alloc:raise ValueError('tile allocation layout changed')
                size=alloc[1]
                # The compiler spells zeroize and free differently; use the
                # tile owner's declaration and its matching LIFO clear/release.
                match=re.search(r'(?m)^    mlk_poly \*tile = [^\n]+\n',body)
                body=body[:match.start()]+'    mlk_poly *tile=(mlk_poly*)lc_arena_alloc(context,1024u);\n'+body[match.end():]
                body,n=re.subn(r'do \{ if \(tile != \(\(void\*\)0\)\) \{ mlk_zeroize\(tile, [^;]+; lc_arena_free\(context,tile,[^;]+; tile = \(\(void\*\)0\); \} \} while \(0\);','do { if(tile){mlk_zeroize(tile,1024u);lc_arena_free(context,tile,1024u);tile=0;} } while(0);',body)
                if n!=1:raise ValueError(('tile wipe',n))
                body,n=re.subn(r'\blc_kem_tile'+str(p)+r'\(tile,[^;]+\);','',body)
                if n!=1:raise ValueError(('tile generator',n))
                call=f'{prefix}polyvec_basemul_acc_montgomery_cached(row,(const mlk_polyvec{p} *)(tile+r*{rank}),s,cache);'
                body=direct(body,call,f'arm3329_matrix_row(row,tile,{seed},first+r,{tr},s,cache);')
                if tr:
                    block=f'{prefix}polyvec_frombytes((mlk_polyvec{p} *)tile,pk);'
                    body=direct(body,block,'')
                    body=direct(body,f'{prefix}polyvec_basemul_acc_montgomery_cached(row,(const mlk_polyvec{p} *)tile,s,cache);','arm3329_dot(row,0,pk,s,cache);')
                return body
            text=body_edit(text,prefix+nm,rewrite)
        def decrypt(body):
            body,n=re.subn(r'(?m)^  mlk_polyvec\d+ \*skpv = .+?;\n','',body);assert n==1
            body=direct(body,' || skpv == ((void*)0)','')
            body=direct(body,f'mlk_unpack_sk{p}(skpv, sk);','')
            body=direct(body,f'{prefix}polyvec_basemul_acc_montgomery_cached(sb, skpv, b, b_cache);','arm3329_dot(sb,0,sk,b,b_cache);')
            body,n=re.subn(r'(?m)^  do \{ if \(skpv [^\n]+?while \(0\);\n','',body);assert n==1
            return body
        text=body_edit(text,prefix+'indcpa_dec',decrypt)
    return text
