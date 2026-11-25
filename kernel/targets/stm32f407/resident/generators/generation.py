from pathlib import Path
import re
from compact_build import definitions,read,later,put
def run(spec,parents,out):
    algorithm=spec.get("algorithm")=="1";full_dsa=spec.get("full_dsa")=="1";twist=spec.get("twist")=="1"
    small=spec.get("small")=="1";own_point=spec.get("own_point")=="1";own_kem=spec.get("own_kem")=="1";own_dsa_ntt=spec.get("own_dsa_ntt")=="1"
    balanced=True;canonical=roots=twists=dsa_ntt=None
    provider_names=[spec.get(k) for k in ("extract","xor","permute")]
    bindings={"ntt":spec.get("ntt"),"invntt":spec.get("invntt")};fast_bindings={"invntt_fast":spec.get("fast_inverse")}
    for item in spec.findall("cell"):
        p=int(item.get("parameter"));k=item.get("backend");src=parents/f"{p}-{k}.c";prefix="mlk" if p>100 else "mld"
        text=read(src);decl=definitions(text);func=prefix+'_keccakf1600_permute_c';a,b,z=decl[func]
        body=text[b:z].replace(prefix+'_KeccakF_RoundConstants','round_constants')
        table=re.search(r'static const uint64_t '+prefix+r'_KeccakF_RoundConstants\[24\]\s*=\s*\{[^}]+\};',text)
        if not table:raise ValueError('missing round constants')
        table=table[0].replace(prefix+'_KeccakF_RoundConstants','round_constants')
        key=re.sub(r'\s+','',table+body)
        if canonical is None:
            canonical=key;common='#include <stdint.h>\n'+table+'\nvoid a127_fips_permute(uint64_t *state)\n'+body+'\n'
        elif canonical!=key:raise ValueError('Keccak core or constants differ across production sources')
        # Every call in the production algorithm now goes through a single external C function.
        # The former public permutation symbol remains compatible for other existing object users.
        if balanced:
            names=provider_names
            ext,xor,perm=names;ns='lc_base_mlk_' if p>100 else 'lcbase_'
            subst={ns+'keccakf1600_extract_bytes':'{'+ext+'(state,data,offset,length);}',ns+'keccakf1600_xor_bytes':'{'+xor+'(state,data,offset,length);}',ns+'keccakf1600_permute':'{'+perm+'(state);}'}
            for n in sorted(subst,key=lambda n:decl[n][1],reverse=True):
                _,start,end=decl[n];text=text[:start]+subst[n]+text[end:]
            text='extern void '+ext+'(const void*,unsigned char*,unsigned,unsigned);\nextern void '+xor+'(void*,const unsigned char*,unsigned,unsigned);\nextern void '+perm+'(void*);\n'+text
        else:
            text=text[:a]+'\nextern void a127_fips_permute(uint64_t *state);\n'+text[a:b]+'{a127_fips_permute(state);}'+text[z:]
        if algorithm:
            import algorithm_share
            if p>100:
                bind=bindings
                if own_kem:
                    from native3329 import apply
                    text=apply(text,p)
                    table=re.search(r'static const int kem_twiddle\[128\]=\{[^}]+\};',text)
                    one=table[0].replace('static const int kem_twiddle','const int a127_native_twiddle')
                    if twists and twists!=one:raise ValueError('rank-specific native root table')
                    twists=one
                    text=(text[:table.start()]+'extern const int a127_native_twiddle[128];'+text[table.end():]).replace('kem_twiddle','a127_native_twiddle')
                elif twist:
                    from plant_inverse import rewrite
                    text=rewrite(text,'twist-joint',p)
                    table=re.search(r'static const int kem_montgomery_twist\[256\]=\{[^}]+\};',text)
                    if not table:raise ValueError('joint inverse twist source missing')
                    one=table[0].replace('static const int kem_montgomery_twist','const int a127_montgomery_twist')
                    if twists and twists!=one:raise ValueError('rank-specific final twist data')
                    twists=one
                    text=(text[:table.start()]+'extern const int a127_montgomery_twist[256];'+text[table.end():]).replace('kem_montgomery_twist','a127_montgomery_twist')
                    fast=fast_bindings
                    text=re.sub(r'\binvntt_fast(?=\s*\()',fast['invntt_fast'],text)
                text,poly_roots=algorithm_share.kem(text,{n:bind[n] for n in ('ntt','invntt')})
                if roots is not None and re.sub(r'\s+','',roots)!=re.sub(r'\s+','',poly_roots):raise ValueError('incompatible polynomial roots')
                roots=poly_roots
            else:
                if own_dsa_ntt:
                    from transform import apply as independent_dsa
                    changed=independent_dsa(text);defs=definitions(changed)
                    prefix=changed[:changed.index('extern void '+provider_names[0])]
                    joint=prefix
                    for old_name,new_name in [('lcbase_poly_ntt','a127_8380417_forward'),('lcbase_poly_invntt_tomont','a127_8380417_inverse')]:
                        _,l,r=defs[old_name];joint+='\nvoid '+new_name+'(int *a)\n'+changed[l:r].replace('a->coeffs','a')+'\n'
                        now=definitions(text);_,l,r=now[old_name];text=text[:l]+'{'+new_name+'(a->coeffs);}'+text[r:]
                    if dsa_ntt is not None and re.sub(r'\s+','',dsa_ntt)!=re.sub(r'\s+','',joint):raise ValueError('DSA NTT roots or butterfly program differ')
                    dsa_ntt=joint
                    text='extern void a127_8380417_forward(int *);extern void a127_8380417_inverse(int *);\n'+text
                text=algorithm_share.dsa(text,p,k,small)
                if full_dsa:
                    import dsa_keyverify
                    text=dsa_keyverify.transform(text,p,k)
                if own_point:
                    text=re.sub(r'\bpqcrystals_dilithium_asm_pointwise_montgomery(?=\s*\()','a127_8380417_pointwise',text)

        put(out/f"kernel-{p}-{k}.c",text)
    if algorithm:put(out/"shared_mlkem_roots.c","#include <stdint.h>\n"+roots+"\n"+(twists or "")+"\n")
    if own_dsa_ntt:put(out/"shared_ntt8380417.c",dsa_ntt)
