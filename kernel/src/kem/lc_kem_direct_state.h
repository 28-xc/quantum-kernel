/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Four independent public SampleNTT streams, consumed in SHAKE byte order.
 * The existing 4096-byte selector is supplied by LC_KEM_REJECTION_TABLE.
 * Each output is a complete, disjoint 256-coefficient object. Padding stores
 * stay inside that object; only coefficients before its count are live.
 */
#ifndef LC_KEM_DIRECT_STATE_H
#define LC_KEM_DIRECT_STATE_H
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#if defined(__GNUC__) && !defined(__clang__)
#define LC_KDS_ATTR __attribute__((noinline,noclone,optimize("O3"),target("avx2,bmi2,popcnt")))
#else
#define LC_KDS_ATTR __attribute__((noinline,target("avx2,bmi2,popcnt")))
#endif
static __attribute__((always_inline)) inline unsigned lc_kds_append8(
 int16_t out[256],unsigned count,__m128i bytes) {
 if(count==256)return count;
 const __m128i decode=_mm_setr_epi8(0,1,1,2,3,4,4,5,6,7,7,8,9,10,10,11);
 __m128i a=_mm_shuffle_epi8(bytes,decode);
 a=_mm_and_si128(_mm_blend_epi16(a,_mm_srli_epi16(a,4),0xaa),_mm_set1_epi16(4095));
 unsigned m=_pext_u32((unsigned)_mm_movemask_epi8(_mm_cmpgt_epi16(_mm_set1_epi16(3329),a)),0x5555u);
 unsigned n=(unsigned)__builtin_popcount(m);
 a=_mm_shuffle_epi8(a,_mm_loadu_si128((const __m128i *)(LC_KEM_REJECTION_TABLE+16*m)));
 if(count<=248)_mm_storeu_si128((__m128i *)(out+count),a);
 else {
  int16_t tail[8];
  if(n>256-count)n=256-count;
  _mm_storeu_si128((__m128i *)(void*)tail,a);
  memcpy(out+count,tail,2*n);
 }
 return count+n;
}
static LC_KDS_ATTR void lc_kem_direct_state_rate4(int16_t out[4][256],
 unsigned count[4],const uint64_t state[100]) {
 /* Slot permutation is identical to the persistent shared Keccak backend. */
 static const uint8_t slots[21]={0,1,2,3,4,5,6,16,17,7,8,18,19,9,10,20,11,12,21,13,14};
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC unroll 1
#elif defined(__clang__)
#pragma clang loop unroll(disable)
#endif
 for(unsigned word=0;word<21;word+=3) {
  __m256i a=_mm256_loadu_si256((const __m256i *)(const void*)(state+4*slots[word]));
  __m256i b=_mm256_loadu_si256((const __m256i *)(const void*)(state+4*slots[word+1]));
  __m256i c=_mm256_loadu_si256((const __m256i *)(const void*)(state+4*slots[word+2]));
  __m256i lo=_mm256_unpacklo_epi64(a,b),hi=_mm256_unpackhi_epi64(a,b);
  __m128i c01=_mm256_castsi256_si128(c),c23=_mm256_extracti128_si256(c,1);
#define LC_KDS_LANE(lane,prefix,lastword) do { \
   __m128i p=(prefix),second=_mm_alignr_epi8((lastword),p,12); \
   unsigned n=count[lane]; \
   n=lc_kds_append8(out[lane],n,p); \
   count[lane]=lc_kds_append8(out[lane],n,second); \
  } while(0)
  LC_KDS_LANE(0,_mm256_castsi256_si128(lo),c01);
  LC_KDS_LANE(1,_mm256_castsi256_si128(hi),_mm_srli_si128(c01,8));
  LC_KDS_LANE(2,_mm256_extracti128_si256(lo,1),c23);
  LC_KDS_LANE(3,_mm256_extracti128_si256(hi,1),_mm_srli_si128(c23,8));
#undef LC_KDS_LANE
 }
}
#undef LC_KDS_ATTR
#endif
