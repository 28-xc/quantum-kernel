"""32-bit architecture-specific exact Montgomery product for ML-DSA.
lo=xy mod 2^32, m=lo*q^-1 mod 2^32. Since lo(m*q)=lo(xy),
high(xy-m*q)=signed_high(xy)-signed_high(m*q) without a low-word borrow."""
import re
def apply(src,p):
    mark='static inline int32_t mld_montgomery_reduce(int64_t a)'
    if src.count(mark)!=1:raise ValueError('Montgomery definition not unique')
    start=src.index(mark);end=src.index('\n}',start)+2
    helper=r'''
static inline int32_t a127_m4_mont_product(int32_t x,int32_t y) {
    uint32_t low; int32_t high,correction;
    __asm__("smull %0,%1,%2,%3" : "=&r"(low),"=&r"(high) : "r"(x),"r"(y));
    uint32_t m=low*UINT32_C(58728449);
    __asm__("smmul %0,%1,%2" : "=r"(correction) : "r"(m),"r"((int32_t)8380417));
    return high-correction;
}
'''.replace('UINT32_C(58728449)','58728449u')
    src=src[:end]+helper+src[end:]
    pattern=r'mld_montgomery_reduce\(\(int64_t\)\s*(\w+)\s*\*\s*((?:lc_load_signed24\([^)\n]+\))|(?:[\w]+->coeffs\[[\w]+\])|(?:\(int64_t\)\s*\w+)|(?:\w+))\)'
    src,n=re.subn(pattern,lambda m:'a127_m4_mont_product('+m[1]+','+m[2].replace('(int64_t)','').strip()+')',src)
    if n<2:raise ValueError(('unexpected number of true multiplications',p,n))
    return src
