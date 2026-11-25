/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Stable public 12-bit rejection compaction. The shuffle selector is the
 * attributed mlkem-native table. Inputs are read in exact 12-byte blocks;
 * the destination is a complete 256-coefficient object, disjoint from input.
 * count identifies an already accepted prefix. Only public XOF data controls
 * compaction, lengths, addresses and exits. No modulus or ordering changes.
 */
#ifndef LC_KEM_REJECTION8_H
#define LC_KEM_REJECTION8_H
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
#ifndef LC_KEM_REJECTION_TABLE
#define LC_KEM_REJECTION_TABLE mlk_rej_uniform_table
#endif
#if defined(__GNUC__) && !defined(__clang__)
#define LC_REJ8_ATTR __attribute__((noinline,noclone,optimize("O3"),target("avx2,bmi2,popcnt")))
#else
#define LC_REJ8_ATTR __attribute__((noinline,target("avx2,bmi2,popcnt")))
#endif
static LC_REJ8_ATTR unsigned lc_kem_reject8(int16_t out[256],unsigned count,
 const uint8_t *bytes,unsigned length) {
 const __m128i decode=_mm_setr_epi8(0,1,1,2,3,4,4,5,6,7,7,8,9,10,10,11);
 const __m128i mask12=_mm_set1_epi16(4095),q=_mm_set1_epi16(3329);
 unsigned pos=0;
 for(;count<256 && pos+12<=length;pos+=12) {
  uint32_t hi;memcpy(&hi,bytes+pos+8,4);
  __m128i a=_mm_loadl_epi64((const __m128i*)(bytes+pos));
  a=_mm_insert_epi32(a,(int)hi,2);
  a=_mm_shuffle_epi8(a,decode);
  a=_mm_and_si128(_mm_blend_epi16(a,_mm_srli_epi16(a,4),0xaa),mask12);
  unsigned m=_pext_u32((unsigned)_mm_movemask_epi8(_mm_cmpgt_epi16(q,a)),0x5555u);
  unsigned n=(unsigned)__builtin_popcount(m);
  a=_mm_shuffle_epi8(a,_mm_loadu_si128((const __m128i*)(LC_KEM_REJECTION_TABLE+16*m)));
  if(count<=248) {
   /* Padding writes remain inside the complete output object and are
    * overwritten by subsequent accepted coefficients. */
   _mm_storeu_si128((__m128i*)(out+count),a);
  } else {
   int16_t tail[8];
   if(n>256-count)n=256-count;
   _mm_storeu_si128((__m128i*)tail,a);
   memcpy(out+count,tail,2*n);
  }
  count+=n;
 }
 for(;count<256 && pos+3<=length;pos+=3) {
  unsigned a=((unsigned)bytes[pos]|((unsigned)bytes[pos+1]<<8))&4095u;
  unsigned b=((unsigned)bytes[pos+1]>>4)|((unsigned)bytes[pos+2]<<4);
  if(a<3329)out[count++]=(int16_t)a;
  if(count<256 && b<3329)out[count++]=(int16_t)b;
 }
 return count;
}
#undef LC_REJ8_ATTR
#endif
