/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Two public matrix columns share one Montgomery reduction and one packed
 * accumulator update. Public rejection cursors retain their original order.
 */
#ifndef LC_PAIR_COLUMN_H
#define LC_PAIR_COLUMN_H
#if !defined(__AVX2__) || !LC_DSA_MATRIX_INTERLEAVED
#error "Paired columns require the interleaved AVX2 backend"
#endif
#if (LC_DSA_CROSSCOL6 && MLDSA_K == 6) || \
    (LC_DSA_FIRST_GAMMA_CACHE && MLDSA_K >= 6) || LC_DSA_STREAM_RECOMPUTE
#error "Paired columns use the second polynomial instead of competing caches"
#endif

static inline __attribute__((always_inline)) __m256i
lc_pair_product(__m256i a, __m256i b, __m256i c, __m256i d)
{
  const __m256i q = _mm256_set1_epi32(8380417);
  const __m256i qi = _mm256_set1_epi32(58728449);
  __m256i even = _mm256_add_epi64(_mm256_mul_epi32(a,b), _mm256_mul_epi32(c,d));
  __m256i odd = _mm256_add_epi64(
      _mm256_mul_epi32(_mm256_srli_epi64(a,32),_mm256_srli_epi64(b,32)),
      _mm256_mul_epi32(_mm256_srli_epi64(c,32),_mm256_srli_epi64(d,32)));
  __m256i te = _mm256_mul_epi32(even,qi);
  __m256i to = _mm256_mul_epi32(odd,qi);
  even = _mm256_sub_epi64(even,_mm256_mul_epi32(te,q));
  odd = _mm256_sub_epi64(odd,_mm256_mul_epi32(to,q));
  return _mm256_blend_epi32(_mm256_srli_epi64(even,32),odd,0xaa);
}

static inline __attribute__((always_inline)) __m256i
lc_pair_decode(__m128i xy, __m128i yz)
{
  const __m128i s0=_mm_setr_epi8(0,1,2,-1,3,4,5,-1,6,7,8,-1,9,10,11,-1);
  const __m128i s1=_mm_setr_epi8(4,5,6,-1,7,8,9,-1,10,11,12,-1,13,14,15,-1);
  __m256i v=_mm256_inserti128_si256(
      _mm256_castsi128_si256(_mm_shuffle_epi8(xy,s0)),
      _mm_shuffle_epi8(yz,s1),1);
  return _mm256_and_si256(v,_mm256_set1_epi32(0x7fffff));
}

/* |a*b+c*d| < 2^55 for public a,c in [0,q) and signed32 b,d.
 * The signed low-word multiplier times q has magnitude < 2^54.
 * Both 64-bit sums and differences fit. The returned value is congruent
 * to the two separate Montgomery products modulo q. */
static __attribute__((noinline,noclone,optimize("O3"))) unsigned
lc_pair_prefix(uint8_t out[1536], const uint64_t state[100],
               const uint8_t slots[25], const int32_t b[256],
               const int32_t d[256], unsigned count)
{
  unsigned used=0;
  while(used+24<=168 && count+8<=256) {
    unsigned word=used/8;
    __m256i x=_mm256_loadu_si256((const __m256i*)(const void*)(state+4*slots[word]));
    __m256i y=_mm256_loadu_si256((const __m256i*)(const void*)(state+4*slots[word+1]));
    __m256i z=_mm256_loadu_si256((const __m256i*)(const void*)(state+4*slots[word+2]));
    __m128i xl=_mm256_castsi256_si128(x),yl=_mm256_castsi256_si128(y),zl=_mm256_castsi256_si128(z);
    __m128i xh=_mm256_extracti128_si256(x,1),yh=_mm256_extracti128_si256(y,1),zh=_mm256_extracti128_si256(z,1);
    __m256i a0=lc_pair_decode(_mm_unpacklo_epi64(xl,yl),_mm_unpacklo_epi64(yl,zl));
    __m256i a1=lc_pair_decode(_mm_unpackhi_epi64(xl,yl),_mm_unpackhi_epi64(yl,zl));
    __m256i a2=lc_pair_decode(_mm_unpacklo_epi64(xh,yh),_mm_unpacklo_epi64(yh,zh));
    __m256i a3=lc_pair_decode(_mm_unpackhi_epi64(xh,yh),_mm_unpackhi_epi64(yh,zh));
    __m256i limit=_mm256_set1_epi32(8380416);
    __m256i bad=_mm256_or_si256(
        _mm256_or_si256(_mm256_cmpgt_epi32(a0,limit),_mm256_cmpgt_epi32(a1,limit)),
        _mm256_or_si256(_mm256_cmpgt_epi32(a2,limit),_mm256_cmpgt_epi32(a3,limit)));
    if(_mm256_movemask_epi8(bad)) break;
    __m256i vb=_mm256_loadu_si256((const __m256i*)(const void*)(b+count));
    __m256i vd=_mm256_loadu_si256((const __m256i*)(const void*)(d+count));
    __m256i r0=lc_pair_product(a0,vb,a1,vd);
    __m256i r1=lc_pair_product(a2,vb,a3,vd);
    uint8_t *p=out+3*count;
    lc_s4_store24(p,lc_s4_reduce(_mm256_add_epi32(r0,lc_s4_load24(p))));
    lc_s4_store24(p+768,lc_s4_reduce(_mm256_add_epi32(r1,lc_s4_load24(p+768))));
    used+=24;
    count+=8;
  }
  return used;
}

static void lc_pair_start(mld_polymat *mat,unsigned col,unsigned row)
{
  mld_memset(&mat->stream4,0,sizeof(mat->stream4));
  for(unsigned lane=0;lane<4;lane++) {
    for(unsigned word=0;word<4;word++) {
      uint64_t value;
      mld_memcpy(&value,mat->rho+8*word,8);
      mat->stream4.state[4*word+lane]=value;
    }
    mat->stream4.state[16+lane]=(uint64_t)(col+(lane&1u))
       |((uint64_t)(row+(lane>>1))<<8)|((uint64_t)0x1f<<16);
    mat->stream4.state[56+lane]=(uint64_t)0x80<<56;
  }
}

static __attribute__((noinline,noclone,optimize("O3"))) void
lc_pair_matrix(uint8_t out[1536],mld_polymat *mat,const mld_poly *b,
               const mld_poly *d,unsigned col,unsigned row)
{
  unsigned ctr[4]={0,0,0,0},pending;
  lc_pair_start(mat,col,row);
  do {
    unsigned used=0;
    pending=0;
    lc_matrix_x4_permute(mat,4);
    if(ctr[0]==ctr[1] && ctr[0]==ctr[2] && ctr[0]==ctr[3]) {
      used=lc_pair_prefix(out,mat->stream4.state,lc_matrix_word_to_slot,
                          b->coeffs,d->coeffs,ctr[0]);
      for(unsigned lane=0;lane<4;lane++) ctr[lane]+=used/3;
    }
    for(unsigned lane=0;lane<4;lane++) {
      if(ctr[lane]>=256) continue;
      if(used==168) { pending=1; continue; }
      lc_matrix_x4_extract(mat,lane,4);
      const int32_t *rhs=(lane&1u)?d->coeffs:b->coeffs;
      uint8_t *dst=out+768*(lane>>1);
      for(unsigned j=used;ctr[lane]<256 && j+3<=168;) {
        const uint8_t *bytes=mat->stream4.rate+j;
        if(j+24<=168 && ctr[lane]+8<=256 &&
           lc_stream4_y_block(dst+3*ctr[lane],bytes,rhs+ctr[lane],0)) {
          ctr[lane]+=8; j+=24; continue;
        }
        uint32_t a=((uint32_t)bytes[0]|((uint32_t)bytes[1]<<8)|((uint32_t)bytes[2]<<16))&0x7fffffu;
        j+=3;
        if(a<MLDSA_Q) {
          unsigned i=ctr[lane]++;
          int32_t value=mld_montgomery_reduce((int64_t)a*rhs[i]);
          value+=lc_load_signed24(dst+3*i);
          lc_store_signed24(dst+3*i,mld_reduce32(value));
        }
      }
      if(ctr[lane]<256) pending=1;
    }
  } while(pending);
  mld_zeroize(&mat->stream4,sizeof(mat->stream4));
}

static void lc_pair_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,
                      mld_poly *first,mld_poly *second)
{
  unsigned col;
  /* Independent rejection streams may advance by different amounts.
   * Initialize every accumulator before either lane can contribute. */
  mld_memset(w,0,MLDSA_K*LC_PACKED_ROW_BYTES);
  for(col=0;col+1<MLDSA_L;col+=2) {
    mld_yvec_get_poly(first,y,col);
    mld_poly_ntt(first);
    lc_stream_transform_order(first);
    mld_yvec_get_poly(second,y,col+1);
    mld_poly_ntt(second);
    lc_stream_transform_order(second);
    for(unsigned row=0;row<MLDSA_K;row+=2)
      lc_pair_matrix(w+row*LC_PACKED_ROW_BYTES,mat,first,second,col,row);
  }
  if(col<MLDSA_L) {
    mld_yvec_get_poly(first,y,col);
    mld_poly_ntt(first);
    lc_stream_transform_order(first);
    for(unsigned row=0;row<MLDSA_K;row+=4) {
      unsigned lanes=MLDSA_K-row<4?MLDSA_K-row:4;
      lc_matrix_y_x4(w+row*LC_PACKED_ROW_BYTES,mat,first,col,row,lanes,0);
    }
  }
}
#endif
