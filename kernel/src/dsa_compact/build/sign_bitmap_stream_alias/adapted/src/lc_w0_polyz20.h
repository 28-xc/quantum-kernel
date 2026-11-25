/* SPDX-License-Identifier: Apache-2.0
 * Internal LowBits uses the existing ML-DSA-65/87 z encoding.
 * Input lies in [-(2^19-1),2^19]. Each pair occupies exactly five bytes.
 * Dense input and packed output are disjoint in the selected packed signing path.
 * The decoder remains the existing mld_polyz_unpack implementation.
 */
#ifndef LC_W0_POLYZ20_V1_H
#define LC_W0_POLYZ20_V1_H
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#if LC_W0_BITS != 20
#error "This internal layout has twenty bits per coefficient"
#endif
static void lc_pack_w0_row(uint8_t *out,const mld_poly *p) {
  const __m256i bias=_mm256_set1_epi32(1<<19);
  const __m256i low=_mm256_set1_epi64x(0xffffffffu);
  const __m256i select=_mm256_setr_epi8(
      0,1,2,3,4,8,9,10,11,12,-1,-1,-1,-1,-1,-1,
      0,1,2,3,4,8,9,10,11,12,-1,-1,-1,-1,-1,-1);
  for(unsigned i=0;i<256;i+=8,out+=20) {
    __m256i v=_mm256_sub_epi32(bias,_mm256_loadu_si256(
        (const __m256i *)(const void *)(p->coeffs+i)));
    __m256i pairs=_mm256_or_si256(_mm256_and_si256(v,low),
        _mm256_slli_epi64(_mm256_srli_epi64(v,32),20));
    __m256i b=_mm256_shuffle_epi8(pairs,select);
    __m128i lo=_mm256_castsi256_si128(b),hi=_mm256_extracti128_si256(b,1);
    _mm_storeu_si128((__m128i *)(void *)out,
                    _mm_or_si128(lo,_mm_slli_si128(hi,10)));
    uint32_t tail=(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(hi,6));
    memcpy(out+16,&tail,4);
  }
}
static void lc_unpack_w0_row(mld_poly *p,const uint8_t *in) {
  mld_polyz_unpack(p,in);
}
#endif
