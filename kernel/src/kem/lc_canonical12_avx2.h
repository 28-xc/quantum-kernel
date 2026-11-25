/* SPDX-License-Identifier: Apache-2.0
 * Equivalent modulus check for a whole number of 24-byte packed groups.
 * Every group encodes sixteen unsigned 12-bit coefficients. */
#ifndef LC_CANONICAL12_AVX2_H
#define LC_CANONICAL12_AVX2_H
#include <stdint.h>
#include <stddef.h>
#include <immintrin.h>
#ifndef LC_PK12_BARRIER
#error "Provide the implementation's constant-time value barrier"
#endif
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3")))
#endif
static unsigned lc_canonical12_invalid(const uint8_t *in,size_t bytes) {
 const __m128i sh=_mm_setr_epi8(0,1,2,-1,3,4,5,-1,6,7,8,-1,9,10,11,-1);
 const __m256i mask=_mm256_set1_epi32(4095),limit=_mm256_set1_epi32(3328);
 __m256i any=_mm256_setzero_si256(),parity=_mm256_setzero_si256();
 for(size_t i=0;i<bytes;i+=24) {
  __m128i lo=_mm_loadu_si128((const __m128i*)(in+i));
  __m128i tail=_mm_loadl_epi64((const __m128i*)(in+i+16));
  __m128i hi=_mm_or_si128(_mm_srli_si128(lo,12),_mm_slli_si128(tail,4));
  __m256i x=_mm256_inserti128_si256(_mm256_castsi128_si256(_mm_shuffle_epi8(lo,sh)),_mm_shuffle_epi8(hi,sh),1);
  __m256i a=_mm256_cmpgt_epi32(_mm256_and_si256(x,mask),limit);
  __m256i b=_mm256_cmpgt_epi32(_mm256_srli_epi32(x,12),limit);
  any=_mm256_or_si256(any,_mm256_or_si256(a,b));
  parity=_mm256_xor_si256(parity,_mm256_xor_si256(a,b));
 }
 uint32_t r=(uint32_t)_mm256_movemask_epi8(any),s=(uint32_t)_mm256_movemask_epi8(parity);
 /* The parity dependency and value barrier retain the full scan when any
  * has already become all ones, matching the upstream comparison safeguard. */
 return (unsigned)((LC_PK12_BARRIER((0u-(uint32_t)(r!=0))^s)^s)&1u);
}
#endif
