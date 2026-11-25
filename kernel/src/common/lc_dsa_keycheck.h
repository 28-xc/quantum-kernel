#ifndef LC_DSA_KEYCHECK_H
#define LC_DSA_KEYCHECK_H
#include <stdint.h>
/* FIPS 204 skEncode puts rho, K and tr before s1 and s2. Every packed
 * coefficient of s1/s2 is eta-s, hence lies in [0,2*eta]. Scan the whole
 * encoded region before returning the aggregate validity bit. Loop bounds
 * and addresses depend only on the public parameter set. */
static int lc_dsa_secret_encoding_valid(int parameter,const uint8_t *sk)
{
    const uint8_t *v=sk+128;
    uint32_t bad=0;
    if(parameter==65){
        for(unsigned i=0;i<11u*128u;i++){
            uint32_t x=v[i];
#if defined(__aarch64__) && defined(LC_DSA_RUNTIME_CACHE) && LC_DSA_RUNTIME_CACHE
            /* A nibble exceeds 8 exactly when its high bit and at least
             * one of its other three bits are set. Check both nibbles. */
            bad |= x & ((x << 1) | (x << 2) | (x << 3)) & UINT32_C(0x88);
#else
            bad|=(8u-(x&15u))>>31;
            bad|=(8u-(x>>4))>>31;
#endif
        }
    }else{
        const unsigned n=parameter==44?8u*96u:15u*96u;
        for(unsigned i=0;i<n;i+=3){
            uint32_t x=(uint32_t)v[i]|((uint32_t)v[i+1]<<8)|((uint32_t)v[i+2]<<16);
#if defined(__aarch64__) && defined(LC_DSA_RUNTIME_CACHE) && LC_DSA_RUNTIME_CACHE
            /* In each three-bit group, codes 5, 6 and 7 have both the
             * high bit and a lower bit set. The mask keeps only the
             * eight group-high positions, so adjacent groups cannot
             * influence one another. All encoded groups are scanned. */
            bad |= x & ((x << 1) | (x << 2)) & UINT32_C(0x924924);
#else
            for(unsigned j=0;j<8;j++)bad|=(4u-((x>>(3*j))&7u))>>31;
#endif
        }
    }
    return bad==0;
}
#endif
