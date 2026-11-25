"""Generate an incomplete FIPS 203 NTT with two 16-bit coefficient lanes per ARM register."""
from source_view import definitions
from bound_encoding import rewrite as encode
Q=3329;S=1<<32;R16=1<<16
def tw(v):
    unsigned=(-S*v%Q)*pow(Q,-1,S)%S
    return unsigned if unsigned<1<<31 else unsigned-S
def apply(src,p):
    src=encode(src,'encode-joint',p);loc=definitions(src)
    z=[tw(pow(17,int(format(i,'07b')[::-1],2),Q)) for i in range(128)]
    code='''static const int kem_twiddle[128]={@TABLE@};
static inline unsigned read2(const short *a){
    unsigned w;__asm__("ldr %0,[%1]":"=r"(w):"r"(a):"memory");return w;
}
static inline void write2(short *a,unsigned w){
    __asm__("str %0,[%1]"::"r"(w),"r"(a):"memory");
}
static inline unsigned add2(unsigned x,unsigned y){
    unsigned o;__asm__("uadd16 %0,%1,%2":"=r"(o):"r"(x),"r"(y):"cc");return o;
}
static inline unsigned sub2(unsigned x,unsigned y){
    unsigned o;__asm__("usub16 %0,%1,%2":"=r"(o):"r"(x),"r"(y):"cc");return o;
}
static inline unsigned plant2(unsigned x,int encoded){
    int l,h;unsigned o;
    __asm__("smulwb %0,%1,%2":"=r"(l):"r"(encoded),"r"(x));
    __asm__("smulwt %0,%1,%2":"=r"(h):"r"(encoded),"r"(x));
    __asm__("smlabb %0,%1,%2,%3":"=r"(l):"r"(l),"r"(3329),"r"(26632));
    __asm__("smlabb %0,%1,%2,%3":"=r"(h):"r"(h),"r"(3329),"r"(26632));
    __asm__("pkhtb %0,%1,%2,asr #16":"=r"(o):"r"(h),"r"(l));return o;
}
static void forward_pair(short *v){
    for(unsigned h=64;h>=4;h>>=2){
        unsigned k=64/h;
        for(unsigned base=0,g=0;base<256;base+=4*h,g++){
            int a=kem_twiddle[k+g],b=kem_twiddle[2*(k+g)],c=kem_twiddle[2*(k+g)+1];
            for(unsigned j=base;j<base+h;j+=2){
                unsigned x=read2(v+j),y=read2(v+j+h);
                unsigned z=plant2(read2(v+j+2*h),a),t=plant2(read2(v+j+3*h),a);
                unsigned left=add2(x,z),right=sub2(x,z);
                unsigned u=plant2(add2(y,t),b),s=plant2(sub2(y,t),c);
                write2(v+j,add2(left,u));write2(v+j+h,sub2(left,u));
                write2(v+j+2*h,add2(right,s));write2(v+j+3*h,sub2(right,s));
            }
        }
    }
    for(unsigned base=0,g=64;base<256;base+=4,g++){
        unsigned x=read2(v+base),t=plant2(read2(v+base+2),kem_twiddle[g]);
        write2(v+base,add2(x,t));write2(v+base+2,sub2(x,t));
    }
}
static void inverse_pair(short *v){
    for(unsigned base=0,g=127;base<256;base+=4,g--){
        unsigned x=plant2(read2(v+base),@ONE@),y=plant2(read2(v+base+2),@ONE@);
        write2(v+base,add2(x,y));write2(v+base+2,plant2(sub2(y,x),kem_twiddle[g]));
    }
    for(unsigned h=4;h<=64;h*=4){
        unsigned k=128/h;
        for(unsigned base=0,g=0;base<256;base+=4*h,g++){
            int a=kem_twiddle[2*k-1-2*g],b=kem_twiddle[2*k-2-2*g],c=kem_twiddle[k-1-g];
            for(unsigned j=base;j<base+h;j+=2){
                unsigned x=read2(v+j),y=read2(v+j+h),z=read2(v+j+2*h),t=read2(v+j+3*h);
                unsigned u=add2(x,y),s=add2(z,t);
                unsigned m=plant2(sub2(y,x),a),n=plant2(sub2(t,z),b);
                unsigned l=add2(u,s),r=add2(m,n);
                if(h==64){
                    l=plant2(l,@SCALE@);r=plant2(r,@SCALE@);
                    write2(v+j+2*h,plant2(plant2(sub2(s,u),c),@SCALE@));
                    write2(v+j+3*h,plant2(plant2(sub2(n,m),c),@SCALE@));
                }else{
                    l=plant2(l,@ONE@);r=plant2(r,@ONE@);
                    write2(v+j+2*h,plant2(sub2(s,u),c));write2(v+j+3*h,plant2(sub2(n,m),c));
                }
                write2(v+j,l);write2(v+j+h,r);
            }
        }
    }
}
'''.replace('@TABLE@',','.join(map(str,z))).replace('@ONE@',str(tw(1))).replace('@SCALE@',str(tw(R16*pow(128,-1,Q)%Q)))
    changes={'lc_base_mlk_poly_ntt':'{forward_pair(r->coeffs);}','lc_base_mlk_poly_invntt_tomont':'{inverse_pair(r->coeffs);}'}
    for n in sorted(changes,key=lambda n:loc[n][1],reverse=True):
        _,a,b=loc[n];src=src[:a]+changes[n]+src[b:]
    return code+src

