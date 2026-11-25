import re
from source_view import definitions
def apply(source):
    match=re.search(r'static const int32_t mld_zetas\[256\]\s*=\s*\{([^}]+)\};',source)
    if not match:raise ValueError('canonical signed twiddle source missing')
    z=list(map(int,re.findall(r'-?\d+',match[1])))
    assert len(z)==256 and all(-(1<<22)<=x<(1<<22) for x in z)
    packed=b''.join((x&0xffffff).to_bytes(3,'little') for x in z)
    prefix="""static const unsigned char f407_twiddle[768]={%s};
static inline int f407_z(unsigned k){
 const unsigned char *v=f407_twiddle+3*k;
 return (int)(signed char)v[2]*65536+((int)v[1]<<8)+v[0];
}
static inline int f407_mont(int x,int b,unsigned bqi){
 int hi,correction;
 unsigned t=(unsigned)x*bqi;
 __asm__("smmul %%0,%%1,%%2":"=r"(hi):"r"(x),"r"(b));
 __asm__("smmul %%0,%%1,%%2":"=r"(correction):"r"(t),"r"(8380417));
 /* Low 32 bits of x*b and t*q agree, hence subtraction has no borrow. */
 return hi-correction;
}
"""%','.join(map(str,packed))
    fwd="""{unsigned idx=1;
 for(unsigned len=128;len;len>>=1){
   for(unsigned start=0;start<256;start+=2*len){
     int z=f407_z(idx++);unsigned zqi=(unsigned)z*58728449u;
     for(unsigned j=start;j<start+len;j++){
       int lo=a->coeffs[j],v=f407_mont(a->coeffs[j+len],z,zqi);
       a->coeffs[j]=lo+v;a->coeffs[j+len]=lo-v;
     }
   }
 }
}"""
    inv="""{unsigned idx=255;
 for(unsigned len=1;len<256;len<<=1){
   for(unsigned start=0;start<256;start+=2*len){
     int z=-f407_z(idx--);unsigned zqi=(unsigned)z*58728449u;
     for(unsigned j=start;j<start+len;j++){
       int lo=a->coeffs[j],hi=a->coeffs[j+len];
       a->coeffs[j]=lo+hi;a->coeffs[j+len]=f407_mont(lo-hi,z,zqi);
     }
   }
 }
 for(unsigned j=0;j<256;j++)a->coeffs[j]=f407_mont(a->coeffs[j],41978,41978u*58728449u);
}"""
    prod="""{for(unsigned j=0;j<256;j++){
 int x=b->coeffs[j];
 a->coeffs[j]=f407_mont(a->coeffs[j],x,(unsigned)x*58728449u);
}}"""
    impl={'lcbase_poly_ntt':fwd,'lcbase_poly_invntt_tomont':inv,'lcbase_poly_pointwise_montgomery':prod}
    defs=definitions(source)
    for name in sorted(impl,key=lambda n:defs[n][1],reverse=True):
        _,start,end=defs[name];source=source[:start]+impl[name]+source[end:]
    return prefix+source

