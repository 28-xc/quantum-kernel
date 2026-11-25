/* Internal signed low-part representation; standard encodings are unchanged.
 * Four pairs occupy 36/38 bits each. The three exact output stores contain
 * 18/19 bytes; packing reads the complete group before writing overlapping
 * output. Dense unpacking uses distinct storage. */
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#if LC_W0_BITS != 18 && LC_W0_BITS != 19
#error "Vector low-part codec supports the initial 18/19-bit representation"
#endif
static void lc_pack_w0_row(uint8_t *out,const mld_poly *poly) {
  const uint64_t mask=(UINT64_C(1)<<LC_W0_BITS)-1;
  for(unsigned i=0;i<256;i+=8,out+=LC_W0_BITS) {
    __m256i a=_mm256_and_si256(_mm256_loadu_si256((const __m256i*)(const void*)(poly->coeffs+i)),_mm256_set1_epi32((int)mask));
    __m256i u=_mm256_or_si256(_mm256_and_si256(a,_mm256_set1_epi64x((int64_t)mask)),_mm256_slli_epi64(_mm256_srli_epi64(a,32),LC_W0_BITS));
    uint64_t a0=(uint64_t)_mm256_extract_epi64(u,0),a1=(uint64_t)_mm256_extract_epi64(u,1);
    uint64_t a2=(uint64_t)_mm256_extract_epi64(u,2),a3=(uint64_t)_mm256_extract_epi64(u,3);
    uint64_t w0=a0|(a1<<(2*LC_W0_BITS));
    uint64_t w1=(a1>>(64-2*LC_W0_BITS))|(a2<<(4*LC_W0_BITS-64))|(a3<<(6*LC_W0_BITS-64));
    uint32_t w2=(uint32_t)(a3>>(128-6*LC_W0_BITS));
    memcpy(out,&w0,8);memcpy(out+8,&w1,8);memcpy(out+16,&w2,LC_W0_BITS-16);
  }
}
static void lc_unpack_w0_row(mld_poly *poly,const uint8_t *in) {
  const uint64_t mask=(UINT64_C(1)<<LC_W0_BITS)-1,pairmask=(UINT64_C(1)<<(2*LC_W0_BITS))-1;
  for(unsigned i=0;i<256;i+=8,in+=LC_W0_BITS) {
    uint64_t w0,w1;uint32_t w2=0;memcpy(&w0,in,8);memcpy(&w1,in+8,8);memcpy(&w2,in+16,LC_W0_BITS-16);
    uint64_t a0=w0&pairmask;
    uint64_t a1=((w0>>(2*LC_W0_BITS))|(w1<<(64-2*LC_W0_BITS)))&pairmask;
    uint64_t a2=(w1>>(4*LC_W0_BITS-64))&pairmask;
    uint64_t a3=((w1>>(6*LC_W0_BITS-64))|((uint64_t)w2<<(128-6*LC_W0_BITS)))&pairmask;
    __m256i u=_mm256_setr_epi64x((int64_t)a0,(int64_t)a1,(int64_t)a2,(int64_t)a3);
    __m256i a=_mm256_or_si256(_mm256_and_si256(u,_mm256_set1_epi64x((int64_t)mask)),_mm256_slli_epi64(_mm256_srli_epi64(u,LC_W0_BITS),32));
    a=_mm256_srai_epi32(_mm256_slli_epi32(a,32-LC_W0_BITS),32-LC_W0_BITS);
    _mm256_storeu_si256((__m256i*)(void*)(poly->coeffs+i),a);
  }
}
