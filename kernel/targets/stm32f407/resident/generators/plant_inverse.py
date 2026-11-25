"""Retarget the final 128 Plantard twists to the public API's Montgomery convention."""
from pathlib import Path
import re
from source_view import definitions
from bound_encoding import rewrite as encoding
R=1<<32;Q=3329
def scale_table(src):
    expr=re.search(r'const int32_t zetas_inv_CT_asm\[256\] = \{([^}]+)\};',src)
    assert expr
    # The assembly consumes 15 initial values, six first-group butterflies, then
    # eight twists. The following 15 groups consume seven butterflies and eight
    # twists each. The last source comment spans one entry past the true boundary.
    payload=re.sub(r'//[^\n]*','',expr[1]);old=list(map(int,re.findall(r'\b\d+\b',payload)))
    scales=[False]*15+[False]*6+[True]*8+([False]*7+[True]*8)*15+[False]
    assert len(old)==len(scales)==255 and old[-1]==0 and sum(scales)==128
    out=[]
    for n,scaled in zip(old,scales):
        c=n*Q%R;assert c<Q
        out.append((c*(-pow(65536,-1,Q))%Q)*pow(Q,-1,R)%R if scaled else n)
    return old,out,scales
def rewrite(text,mode,p):
    assert mode in ('twisted','twist-joint')
    if mode=='twist-joint':text=encoding(text,'encode-joint',p)
    path=Path(__file__).resolve().parent/"roots"/f"ntt{p}.c"
    before,after,mask=scale_table(path.read_text())
    defs=definitions(text);_,a,b=defs['lc_base_mlk_poly_invntt_tomont']
    body='''{
       for(unsigned i=0;i<256;i+=2){
          unsigned in,x;int lo,hi;
          __asm__("ldr %0,[%1]":"=r"(in):"r"(r->coeffs+i):"memory");
          __asm__("smlabb %0,%1,%2,%3":"=r"(lo):"r"(in),"r"(20159),"r"(33554432));
          __asm__("smlatb %0,%1,%2,%3":"=r"(hi):"r"(in),"r"(20159),"r"(33554432));
          unsigned n0=(unsigned)(lo>>26)*3329u,n1=(unsigned)(hi>>26)*3329u;
          __asm__("usub16 %0,%1,%2":"=r"(x):"r"(in),"r"((n0&65535u)|(n1<<16)):"cc");
          __asm__("str %0,[%1]"::"r"(x),"r"(r->coeffs+i):"memory");
       }
       invntt_fast(r->coeffs,kem_montgomery_twist);
    }'''
    prefix='extern void invntt_fast(short*,const int*);\nstatic const int kem_montgomery_twist[256]={'+','.join(str(c if c<1<<31 else c-R) for c in after)+'};\n'
    return prefix+text[:a]+body+text[b:]

