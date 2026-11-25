/* SPDX-License-Identifier: Apache-2.0
 * Fixed-schedule CBD expansion. Loads exactly 128/192 input bytes.
 * Reverse groups also permit exact input/output base aliasing. */
#ifndef LC_CBD_AVX2_H
#define LC_CBD_AVX2_H
#include <stdint.h>
#include <immintrin.h>
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3")))
#endif
static void lc_cbd2_avx2(int16_t out[256],const uint8_t in[128]) {
 const __m128i m55=_mm_set1_epi8(0x55),m3=_mm_set1_epi8(3);
 for(unsigned b=8;b-- >0;) {
  __m128i x=_mm_loadu_si128((const __m128i*)(in+16*b));
  __m128i d=_mm_add_epi8(_mm_and_si128(x,m55),_mm_and_si128(_mm_srli_epi16(x,1),m55));
  __m128i lo=_mm_sub_epi8(_mm_and_si128(d,m3),_mm_and_si128(_mm_srli_epi16(d,2),m3));
  __m128i hi=_mm_sub_epi8(_mm_and_si128(_mm_srli_epi16(d,4),m3),_mm_and_si128(_mm_srli_epi16(d,6),m3));
  __m256i a=_mm256_cvtepi8_epi16(_mm_unpacklo_epi8(lo,hi));
  __m256i c=_mm256_cvtepi8_epi16(_mm_unpackhi_epi8(lo,hi));
  _mm256_storeu_si256((__m256i*)(out+32*b),a);
  _mm256_storeu_si256((__m256i*)(out+32*b+16),c);
 }
}
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3")))
#endif
static void lc_cbd3_avx2(int16_t out[256],const uint8_t in[192]) {
 const __m128i sh=_mm_setr_epi8(0,1,2,-1,3,4,5,-1,6,7,8,-1,9,10,11,-1);
 const __m256i mask=_mm256_set1_epi32(0x249249),m7=_mm256_set1_epi32(7);
 for(unsigned b=8;b-- >0;) {
  const uint8_t *p=in+24*b;
  __m128i first=_mm_loadu_si128((const __m128i*)p);
  __m128i tail=_mm_loadl_epi64((const __m128i*)(p+16));
  __m128i second=_mm_or_si128(_mm_srli_si128(first,12),_mm_slli_si128(tail,4));
  __m256i x=_mm256_inserti128_si256(_mm256_castsi128_si256(_mm_shuffle_epi8(first,sh)),_mm_shuffle_epi8(second,sh),1);
  __m256i d=_mm256_add_epi32(_mm256_and_si256(x,mask),_mm256_and_si256(_mm256_srli_epi32(x,1),mask));
  d=_mm256_add_epi32(d,_mm256_and_si256(_mm256_srli_epi32(x,2),mask));
#define LC_CBD3_PAIR(S) _mm256_sub_epi32(_mm256_and_si256(_mm256_srli_epi32(d,S),m7),_mm256_and_si256(_mm256_srli_epi32(d,(S)+3),m7))
  __m256i r0=LC_CBD3_PAIR(0),r1=LC_CBD3_PAIR(6),r2=LC_CBD3_PAIR(12),r3=LC_CBD3_PAIR(18);
#undef LC_CBD3_PAIR
  __m256i a=_mm256_unpacklo_epi32(r0,r1),c=_mm256_unpackhi_epi32(r0,r1);
  __m256i e=_mm256_unpacklo_epi32(r2,r3),f=_mm256_unpackhi_epi32(r2,r3);
  __m256i v0=_mm256_unpacklo_epi64(a,e),v1=_mm256_unpackhi_epi64(a,e);
  __m256i v2=_mm256_unpacklo_epi64(c,f),v3=_mm256_unpackhi_epi64(c,f);
  __m256i p01=_mm256_packs_epi32(v0,v1),p23=_mm256_packs_epi32(v2,v3);
  _mm256_storeu_si256((__m256i*)(out+32*b),_mm256_permute2x128_si256(p01,p23,0x20));
  _mm256_storeu_si256((__m256i*)(out+32*b+16),_mm256_permute2x128_si256(p01,p23,0x31));
 }
}
#endif
