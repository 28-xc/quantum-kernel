/* Montgomery multiplication in Z_8380417 using R=2^32.
 * low + low(m*q) is zero modulo R, so its carry is one exactly when low != 0.
 * The two signed high products plus this carry form (a*b + m*q)/R. */
#include <stdint.h>
static inline int32_t high_signed(int32_t a,int32_t b) {
    int32_t result;
    __asm__("smmul %0,%1,%2":"=r"(result):"r"(a),"r"(b));
    return result;
}
void a127_8380417_pointwise(int32_t out[256],const int32_t left[256],const int32_t right[256]) {
    const uint32_t q=8380417u;
    const uint32_t neg_inverse=0xfc7fdfffu;
    for(unsigned i=0;i<256;i++) {
        int32_t a=left[i],b=right[i];
        uint32_t low=(uint32_t)a*(uint32_t)b;
        int32_t m=(int32_t)(low*neg_inverse);
        uint32_t carry=(low|(0u-low))>>31;
        out[i]=(int32_t)((uint32_t)high_signed(a,b)+(uint32_t)high_signed(m,(int32_t)q)+carry);
    }
}

