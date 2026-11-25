/* An independently written canonical-domain scalar kernel.
 * Q is a compile-time public constant. The compiler's lowering of constant
 * remainder is checked in release disassembly; no universal timing claim.
 */
#define LC_CAT_(a,b) a##b
#define LC_CAT(a,b) LC_CAT_(a,b)
#define F(s) LC_CAT(PREFIX,s)
static uint32_t F(_add)(uint32_t a,uint32_t b) {
    uint32_t t=a+b-Q; return t+(Q & (0u-(t>>31)));
}
static uint32_t F(_sub)(uint32_t a,uint32_t b) {
    uint32_t t=a-b; return t+(Q & (0u-(t>>31)));
}
static uint32_t F(_mul)(uint32_t a,uint32_t b) {
#if (defined(LC_POLY_STM32F407_REDUCE) || defined(LC_POLY_TEST_M4_REDUCE)) && !defined(LC_POLY_PORTABLE_REDUCE)
    /* Public API inputs are canonical. Both transforms keep that invariant. */
#if Q == 3329
    uint32_t x = a * b; /* at most 3328^2 */
    uint32_t k = (uint32_t)(((uint64_t)x * UINT32_C(1290167)) >> 32);
    uint32_t r = x - k * UINT32_C(3329);
#elif Q == 8380417
    /* 2^23 = 8191 (mod q). Three fixed folds give a value below 2q. */
    const uint32_t mask = UINT32_C(8388607);
    uint64_t x = (uint64_t)a * b;
    uint64_t first = (x & mask) + (x >> 23) * UINT64_C(8191);
    uint32_t second = ((uint32_t)first & mask) + (uint32_t)(first >> 23) * UINT32_C(8191);
    uint32_t r = (second & mask) + (second >> 23) * UINT32_C(8191);
#else
#error Unsupported canonical modulus
#endif
    uint32_t t = r - Q;
    return t + (Q & (0u - (t >> 31)));
#else
    return (uint32_t)(((uint64_t)a*b)%Q);
#endif
}
static void F(_ntt)(uint32_t a[256]) {
    unsigned len,start,j,k=1;
    for(len=128;len>=(256u>>LAYERS);len>>=1) {
        for(start=0;start<256;start+=2*len) {
            uint32_t z=F(_z)[k++];
            for(j=start;j<start+len;j++) {
                uint32_t u=a[j],v=F(_mul)(z,a[j+len]);
                a[j]=F(_add)(u,v); a[j+len]=F(_sub)(u,v);
            }
        }
    }
}
static void F(_intt)(uint32_t a[256]) {
    unsigned len,start,j,k=(1u<<LAYERS)-1;
    for(len=(256u>>LAYERS);len<=128;len<<=1) {
        for(start=0;start<256;start+=2*len) {
            uint32_t z=F(_z)[k--];
            for(j=start;j<start+len;j++) {
                uint32_t u=a[j],v=a[j+len];
                a[j]=F(_add)(u,v); a[j+len]=F(_mul)(z,F(_sub)(v,u));
            }
        }
    }
    for(j=0;j<256;j++) a[j]=F(_mul)(a[j],INVERSE_N);
}
static void F(_base)(uint32_t c[256],const uint32_t a[256],const uint32_t b[256]) {
    unsigned i;
#if LAYERS == 8
    for(i=0;i<256;i++) c[i]=F(_mul)(a[i],b[i]);
#else
    for(i=0;i<128;i++) {
        uint32_t z=F(_z)[64+i/2]; if(i&1) z=Q-z;
        c[2*i]=F(_add)(F(_mul)(a[2*i],b[2*i]),F(_mul)(z,F(_mul)(a[2*i+1],b[2*i+1])));
        c[2*i+1]=F(_add)(F(_mul)(a[2*i],b[2*i+1]),F(_mul)(a[2*i+1],b[2*i]));
    }
#endif
}
#undef LC_CAT_
#undef LC_CAT
#undef F
