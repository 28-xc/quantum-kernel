"""Use the FIPS 203 public-key modulus test and an exact signed halfword reducer."""
from source_view import definitions
def rewrite(text,mode,p):
    assert mode in ('pk-scan','halfword','encode-joint')
    defs=definitions(text);new={}
    if mode!='halfword':
        new[f'lc_base_mlk{p}_check_pk']='''{
            (void)context;
            unsigned invalid=0;
            for(unsigned i=0;i<@N@;i+=3){
                unsigned v=(unsigned)pk[i]|((unsigned)pk[i+1]<<8)|((unsigned)pk[i+2]<<16);
                invalid|=((v&4095u)+767u)|((v>>12)+767u);
            }
            return -(int)((invalid>>12)*4u);
        }'''.replace('@N@',str({512:768,768:1152,1024:1536}[p]))
    if mode!='pk-scan':
        new['lc_base_mlk_poly_reduce']='''{
            for(unsigned i=0;i<256;i+=2){
                unsigned packed;
                __asm__("ldr %0,[%1]":"=r"(packed):"r"(r->coeffs+i):"memory");
                int lo,hi;
                __asm__("smlabb %0,%1,%2,%3":"=r"(lo):"r"(packed),"r"(20159),"r"(8192));
                __asm__("smlatb %0,%1,%2,%3":"=r"(hi):"r"(packed),"r"(20159),"r"(8192));
                unsigned q0=(unsigned)(lo>>26)*3329u,q1=(unsigned)(hi>>26)*3329u;
                unsigned sub=(q0&65535u)|(q1<<16),out;
                __asm__("usub16 %0,%1,%2":"=r"(out):"r"(packed),"r"(sub):"cc");
                __asm__("str %0,[%1]"::"r"(out),"r"(r->coeffs+i):"memory");
            }
        }'''
    for n in sorted(new,key=lambda n:defs[n][1],reverse=True):
        _,a,b=defs[n];text=text[:a]+new[n]+text[b:]
    return text

