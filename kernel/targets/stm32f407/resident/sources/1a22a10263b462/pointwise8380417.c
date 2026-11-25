typedef long long int int64_t;
typedef long long unsigned int uint64_t;
typedef int64_t int_least64_t;
typedef uint64_t uint_least64_t;
typedef int64_t int_fast64_t;
typedef uint64_t uint_fast64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef int32_t int_least32_t;
typedef uint32_t uint_least32_t;
typedef int32_t int_fast32_t;
typedef uint32_t uint_fast32_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int16_t int_least16_t;
typedef uint16_t uint_least16_t;
typedef int16_t int_fast16_t;
typedef uint16_t uint_fast16_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef int8_t int_least8_t;
typedef uint8_t uint_least8_t;
typedef int8_t int_fast8_t;
typedef uint8_t uint_fast8_t;
typedef int intptr_t;
typedef unsigned int uintptr_t;
typedef long long int intmax_t;
typedef long long unsigned int uintmax_t;
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
