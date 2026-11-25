/* SPDX-License-Identifier: Apache-2.0
 * Exact block-bounded sparse product. Eta4 uses <=11 terms of magnitude<=11
 * (partial bound121); eta2 uses <=25 terms of magnitude<=5 (partial bound125).
 * Widened int16 accumulators cover bounds195/539/300 for every eta decode.
 */
#ifndef LC_SPARSE8_BLOCKS_I16_H
#define LC_SPARSE8_BLOCKS_I16_H
#include <stdint.h>
#include <string.h>
#include <immintrin.h>
static void lc_sparse16_challenge(uint8_t index[61],const int32_t c[256],unsigned tau){
 unsigned head=1,tail=tau;
 for(unsigned j=0;j<256;j++){
  if(c[j]==1)index[head++]=(uint8_t)j;
  if(c[j]==-1)index[tail--]=(uint8_t)j;
 }
 index[0]=(uint8_t)(head-1);
}


/* Packed secret input has public length96(eta2) or128(eta4).
 * All encodings retain upstream values: [-5,2] and [-11,4].
 * Construct the same first256 signed bytes inside the original1024B owner;
 * the unchanged extension and chunk sums follow; signed16 output remains in bytes512..1023. */
static inline __attribute__((always_inline)) void
lc_sparse8_decode_packed(uint8_t bytes[256],const uint8_t *packed,unsigned chunk) {
 if(chunk==11) {
  const __m128i mask=_mm_set1_epi8(15),eta=_mm_set1_epi8(4);
  for(unsigned i=0;i<128;i+=16) {
   __m128i x=_mm_loadu_si128((const __m128i*)(const void*)(packed+i));
   __m128i lo=_mm_sub_epi8(eta,_mm_and_si128(x,mask));
   __m128i hi=_mm_sub_epi8(eta,_mm_and_si128(_mm_srli_epi16(x,4),mask));
   _mm_storeu_si128((__m128i*)(void*)(bytes+2*i),_mm_unpacklo_epi8(lo,hi));
   _mm_storeu_si128((__m128i*)(void*)(bytes+2*i+16),_mm_unpackhi_epi8(lo,hi));
  }
 } else {
  const __m256i shifts=_mm256_setr_epi32(0,3,6,9,12,15,18,21);
  const __m256i mask=_mm256_set1_epi32(7),eta=_mm256_set1_epi32(2);
  for(unsigned i=0;i<32;i++) {
   uint32_t x=(uint32_t)packed[3*i]|((uint32_t)packed[3*i+1]<<8)|((uint32_t)packed[3*i+2]<<16);
   __m256i fields=_mm256_and_si256(_mm256_srlv_epi32(_mm256_set1_epi32((int32_t)x),shifts),mask);
   __m256i coeff=_mm256_sub_epi32(eta,fields);
   __m128i shorts=_mm_packs_epi32(_mm256_castsi256_si128(coeff),_mm256_extracti128_si256(coeff,1));
   __m128i small=_mm_packs_epi16(shorts,shorts);
   _mm_storel_epi64((__m128i*)(void*)(bytes+8*i),small);
  }
 }
}

#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3")))
#endif
static void lc_sparse8_product_i16(int32_t out[256],const uint8_t *packed,const uint8_t index[61],unsigned tau,unsigned chunk){
 uint8_t *bytes=(uint8_t*)out;
#if LC_DSA_CHECKED_SPARSE
 lc_sparse8_decode_packed(bytes,packed,(chunk==11 || chunk==31)?11:25);
#else
 lc_sparse8_decode_packed(bytes,packed,chunk);
#endif
 for(unsigned j=0;j<256;j+=32){
  __m256i v=_mm256_load_si256((const __m256i*)(bytes+j));
  _mm256_store_si256((__m256i*)(bytes+256+j),v);
  _mm256_store_si256((__m256i*)(bytes+j),_mm256_sub_epi8(_mm256_setzero_si256(),v));
 }
#if LC_DSA_CHECKED_SPARSE
 /* Canonical eta2: every partial signed sum is bounded by tau*2<=120.
  * Negative challenge terms are subtracted before the sole final widening.
  * The caller selects chunk60 only after the complete encoding check. */
 if(chunk==60) {
  for(unsigned j=0;j<256;j+=64) {
   __m256i s0=_mm256_setzero_si256(),s1=s0;
   for(unsigned k=1;k<=(unsigned)index[0];k++) {
    const uint8_t *v=bytes+256+j-index[k];
    s0=_mm256_add_epi8(s0,_mm256_loadu_si256((const __m256i*)(const void*)v));
    s1=_mm256_add_epi8(s1,_mm256_loadu_si256((const __m256i*)(const void*)(v+32)));
   }
   for(unsigned k=(unsigned)index[0]+1;k<=tau;k++) {
    const uint8_t *v=bytes+256+j-index[k];
    s0=_mm256_sub_epi8(s0,_mm256_loadu_si256((const __m256i*)(const void*)v));
    s1=_mm256_sub_epi8(s1,_mm256_loadu_si256((const __m256i*)(const void*)(v+32)));
   }
   _mm256_store_si256((__m256i*)(void*)(bytes+512+2*j),_mm256_cvtepi8_epi16(_mm256_castsi256_si128(s0)));
   _mm256_store_si256((__m256i*)(void*)(bytes+512+2*j+32),_mm256_cvtepi8_epi16(_mm256_extracti128_si256(s0,1)));
   _mm256_store_si256((__m256i*)(void*)(bytes+512+2*j+64),_mm256_cvtepi8_epi16(_mm256_castsi256_si128(s1)));
   _mm256_store_si256((__m256i*)(void*)(bytes+512+2*j+96),_mm256_cvtepi8_epi16(_mm256_extracti128_si256(s1,1)));
  }
  return;
 }
#endif
 for(unsigned j=0;j<256;j+=64){
  __m256i r0=_mm256_setzero_si256(),r1=r0,r2=r0,r3=r0;
  for(unsigned phase=0;phase<2;phase++){
   unsigned begin=phase?(unsigned)index[0]+1:1,end=phase?tau:(unsigned)index[0];
   for(unsigned first=begin;first<=end;first+=chunk){
    unsigned last=end-first<chunk-1?end:first+chunk-1;
    __m256i s0=_mm256_setzero_si256(),s1=s0;
    for(unsigned k=first;k<=last;k++){
     const uint8_t *p=bytes+256+j-index[k];
     s0=_mm256_add_epi8(s0,_mm256_loadu_si256((const __m256i*)p));
     s1=_mm256_add_epi8(s1,_mm256_loadu_si256((const __m256i*)(p+32)));
    }
    __m256i t0=_mm256_cvtepi8_epi16(_mm256_castsi256_si128(s0));
    __m256i t1=_mm256_cvtepi8_epi16(_mm256_extracti128_si256(s0,1));
    __m256i t2=_mm256_cvtepi8_epi16(_mm256_castsi256_si128(s1));
    __m256i t3=_mm256_cvtepi8_epi16(_mm256_extracti128_si256(s1,1));
    if(phase){r0=_mm256_sub_epi16(r0,t0);r1=_mm256_sub_epi16(r1,t1);r2=_mm256_sub_epi16(r2,t2);r3=_mm256_sub_epi16(r3,t3);}
    else{r0=_mm256_add_epi16(r0,t0);r1=_mm256_add_epi16(r1,t1);r2=_mm256_add_epi16(r2,t2);r3=_mm256_add_epi16(r3,t3);}
   }
  }
  _mm256_store_si256((__m256i*)(bytes+512+2*j),r0);
  _mm256_store_si256((__m256i*)(bytes+512+2*j+32),r1);
  _mm256_store_si256((__m256i*)(bytes+512+2*j+64),r2);
  _mm256_store_si256((__m256i*)(bytes+512+2*j+96),r3);
 }

}

/* Source shorts occupy existing bytes512..1023. For same-base z output,
 * each32-byte source group is fully loaded before either dense32 store;
 * the next unread source starts at544+2*j and writes end at64+4*j.
 * Both are ordered until the final group, where no unread source remains. */
__attribute__((noinline)) static uint32_t
lc_sparse16_consume(int32_t out[256],const int32_t base[256],
                    const uint8_t owner[1024],int32_t bound,unsigned subtract){
 __m256i bad=_mm256_setzero_si256();
 const __m256i limit=_mm256_set1_epi32(bound-1);
 const __m256i sign=_mm256_set1_epi32(subtract?-1:1);
 for(unsigned j=0;j<256;j+=16){
  __m256i s=_mm256_load_si256((const __m256i*)(const void*)(owner+512+2*j));
  __m256i lo=_mm256_cvtepi16_epi32(_mm256_castsi256_si128(s));
  __m256i hi=_mm256_cvtepi16_epi32(_mm256_extracti128_si256(s,1));
  lo=_mm256_add_epi32(_mm256_load_si256((const __m256i*)(const void*)(base+j)),_mm256_sign_epi32(lo,sign));
  hi=_mm256_add_epi32(_mm256_load_si256((const __m256i*)(const void*)(base+j+8)),_mm256_sign_epi32(hi,sign));
  _mm256_store_si256((__m256i*)(void*)(out+j),lo);
  _mm256_store_si256((__m256i*)(void*)(out+j+8),hi);
  bad=_mm256_or_si256(bad,_mm256_cmpgt_epi32(_mm256_abs_epi32(lo),limit));
  bad=_mm256_or_si256(bad,_mm256_cmpgt_epi32(_mm256_abs_epi32(hi),limit));
 }
 /* The only norm observation follows all256 coefficients. */
 return 0u-(uint32_t)(_mm256_movemask_epi8(bad)!=0);
}
#endif
