/* Four-way public matrix expansion in one dead polynomial buffer.
 * Each lane consumes its own rejection stream in FIPS 204 order. */
#ifndef LC_MATRIX_STREAM4_H
#define LC_MATRIX_STREAM4_H
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_MATRIX_FUNCTION_O3 && defined(__GNUC__) && !defined(__clang__)
#define LC_MATRIX_FUNCTION_OPT __attribute__((optimize("O3")))
#else
#define LC_MATRIX_FUNCTION_OPT
#endif
#endif
#include "src/fips202/keccakf1600.h"
#include "lc_stream4_vector.h"
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_STREAM_NEON) && LC_DSA_STREAM_NEON
#if !defined(__aarch64__) || !defined(__ARM_NEON) || defined(MLD_USE_NATIVE_NTT_CUSTOM_ORDER)
#error "The stream NEON consumer requires the standard AArch64 NTT order"
#endif
#include "lc_stream_neon.h"
#if LC_DSA_STREAM_CACHE24
#include "lc_stream_cache24.h"
#endif
#endif
#if defined(LC_DSA_STREAM_DIRECT_STATE) && LC_DSA_STREAM_DIRECT_STATE
#if !defined(MLD_SYS_LITTLE_ENDIAN) || !defined(__aarch64__)
#error "Direct state bytes require canonical little-endian AArch64 Keccak lanes"
#endif
#endif
#else
#if LC_DSA_STREAM_CACHE24
#include "lc_stream_cache24.h"
#endif
#if LC_DSA_MATRIX_INTERLEAVED && defined(__AVX2__)
#include "keccak_x4_interleaved.h"
extern const uint64_t lc_base_mlk_keccakf1600_round_constants[24];
extern const uint64_t lc_base_mlk_keccak_rho8[4];
extern const uint64_t lc_base_mlk_keccak_rho56[4];
static const uint8_t lc_matrix_word_to_slot[25]={0,1,2,3,4,5,6,16,17,7,8,18,19,9,10,20,11,12,21,13,14,22,23,15,24};
static void lc_matrix_interleaved_start(mld_polymat *mat,unsigned col,unsigned row,
                                      unsigned varying_rows,unsigned lanes) {
  for(unsigned lane=0;lane<4;lane++) {
    unsigned active=lane<lanes?lane:0;
    for(unsigned word=0;word<4;word++) {
      uint64_t x;mld_memcpy(&x,mat->rho+8*word,8);
      mat->stream4.state[4*word+lane]=x;
    }
    mat->stream4.state[16+lane]=(uint64_t)(col+(varying_rows?0:active))
       |((uint64_t)(row+(varying_rows?active:0))<<8)|((uint64_t)0x1f<<16);
    mat->stream4.state[56+lane]=(uint64_t)0x80<<56;
  }
}
#endif
static void lc_matrix_x4_permute(mld_polymat *mat,unsigned lanes) {
#if LC_DSA_MATRIX_TAIL_SINGLE || (LC_DSA_MATRIX_INTERLEAVED && defined(__AVX2__))
  if(lanes==1) {mld_keccakf1600_permute(mat->stream4.state);return;}
#endif
#if LC_DSA_MATRIX_INTERLEAVED && defined(__AVX2__)
  lc_keccak_x4_interleaved(mat->stream4.state,lc_base_mlk_keccakf1600_round_constants,
                           lc_base_mlk_keccak_rho8,lc_base_mlk_keccak_rho56);
#else
  mld_keccakf1600x4_permute(mat->stream4.state);
#endif
}
static void lc_matrix_x4_extract(mld_polymat *mat,unsigned lane,unsigned lanes) {
#if LC_DSA_MATRIX_INTERLEAVED && defined(__AVX2__)
  if(lanes>1) {
    for(unsigned word=0;word<21;word++)
      mld_memcpy(mat->stream4.rate+8*word,mat->stream4.state+4*lc_matrix_word_to_slot[word]+lane,8);
    return;
  }
#endif
  mld_keccakf1600_extract_bytes(mat->stream4.state+25*lane,mat->stream4.rate,0,SHAKE128_RATE);
}

#ifndef LC_DSA_LOWMEM_MATRIX_FAST
#define LC_DSA_LOWMEM_MATRIX_FAST 0
#endif
#if LC_DSA_LOWMEM_MATRIX_FAST && LC_DSA_MATRIX_INTERLEAVED && defined(__AVX2__) && !LC_DSA_STREAM_CACHE24
/* Decode exactly three public Keccak words without a rate-block round trip.
 * word is a public multiple of three in [0,18]; each word names the same
 * lane in the existing four-way state. No bytes outside the rate are read. */
static inline __attribute__((always_inline)) __m256i
lc_lowmem_public8(const uint64_t *state,unsigned lane,unsigned word) {
  uint64_t v0=state[4*lc_matrix_word_to_slot[word]+lane];
  uint64_t v1=state[4*lc_matrix_word_to_slot[word+1]+lane];
  uint64_t v2=state[4*lc_matrix_word_to_slot[word+2]+lane];
  const __m128i sh0=_mm_setr_epi8(0,1,2,-1,3,4,5,-1,6,7,8,-1,9,10,11,-1);
  const __m128i sh1=_mm_setr_epi8(4,5,6,-1,7,8,9,-1,10,11,12,-1,13,14,15,-1);
  __m128i lo=_mm_shuffle_epi8(_mm_set_epi64x((long long)v1,(long long)v0),sh0);
  __m128i hi=_mm_shuffle_epi8(_mm_set_epi64x((long long)v2,(long long)v1),sh1);
  return _mm256_and_si256(_mm256_inserti128_si256(_mm256_castsi128_si256(lo),hi,1),_mm256_set1_epi32(0x7fffff));
}
/* low32(a*b*QINV) equals low32(a*low32(b*QINV)). Reuse the rhs-derived
 * word across four independent public matrix streams. Both products and
 * the signed Montgomery representative remain identical to lc_s4_product. */
static inline __attribute__((always_inline)) __m256i
lc_lowmem_product(__m256i a,__m256i b,__m256i bqi) {
  const __m256i q=_mm256_set1_epi32(8380417);
  __m256i pe=_mm256_mul_epi32(a,b);
  __m256i po=_mm256_mul_epi32(_mm256_srli_epi64(a,32),_mm256_srli_epi64(b,32));
  __m256i t=_mm256_mullo_epi32(a,bqi);
  __m256i re=_mm256_sub_epi64(pe,_mm256_mul_epi32(t,q));
  __m256i ro=_mm256_sub_epi64(po,_mm256_mul_epi32(_mm256_srli_epi64(t,32),q));
  return _mm256_blend_epi32(_mm256_srli_epi64(re,32),ro,0xaa);
}
static inline __attribute__((always_inline)) unsigned
lc_lowmem_matrix_prefix(uint8_t *out,mld_polymat *mat,const mld_poly *y,
                        unsigned ctr[4],unsigned lanes,unsigned first) {
  if(lanes!=4 || ctr[0]!=ctr[1] || ctr[0]!=ctr[2] || ctr[0]!=ctr[3])return 0;
  unsigned j=0,c=ctr[0];
  for(;j+24<=SHAKE128_RATE && c+8<=MLDSA_N;j+=24,c+=8) {
    __m256i a[4];unsigned rejected=0;
    for(unsigned lane=0;lane<4;lane++) {
      a[lane]=lc_lowmem_public8(mat->stream4.state,lane,j/8);
      rejected|=(unsigned)_mm256_movemask_epi8(_mm256_cmpgt_epi32(a[lane],_mm256_set1_epi32(8380416)));
    }
    /* A rejection advances no lane in this prefix. The existing per-lane
     * loop resumes at this exact byte position and preserves acceptance order. */
    if(rejected)break;
    __m256i b=_mm256_loadu_si256((const __m256i *)(const void *)(y->coeffs+c));
    __m256i bqi=_mm256_mullo_epi32(b,_mm256_set1_epi32(58728449));
    for(unsigned lane=0;lane<4;lane++) {
      uint8_t *dst=out+lane*LC_PACKED_ROW_BYTES+3*c;
      __m256i x=lc_lowmem_product(a[lane],b,bqi);
      if(!first)x=_mm256_add_epi32(x,lc_s4_load24(dst));
      lc_s4_store24(dst,lc_s4_reduce(x));
    }
  }
  for(unsigned lane=0;lane<4;lane++)ctr[lane]=c;
  return j;
}
#endif

#endif

_Static_assert(sizeof(((mld_polymat *)0)->stream4) <= sizeof(mld_poly),
               "four SHAKE states and one rate block fit the dead matrix row");

static void lc_matrix_x4_start(mld_polymat *mat, unsigned col, unsigned row,
                              unsigned varying_rows, unsigned lanes) {
  uint8_t seed[34];
  const uint8_t suffix=0x1f, final=0x80;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  mld_memcpy(seed,mat->rho,32);
#else
#endif
  mld_memset(&mat->stream4,0,sizeof(mat->stream4));
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_MATRIX_INTERLEAVED && defined(__AVX2__)
  if(lanes>1) {lc_matrix_interleaved_start(mat,col,row,varying_rows,lanes);return;}
#endif
  mld_memcpy(seed,mat->rho,32);
#endif
  for(unsigned lane=0;lane<4;lane++) {
    unsigned active=lane<lanes?lane:0;
    seed[32]=(uint8_t)(col+(varying_rows?0:active));
    seed[33]=(uint8_t)(row+(varying_rows?active:0));
    uint64_t *s=mat->stream4.state+25*lane;
    mld_keccakf1600_xor_bytes(s,seed,0,34);
    mld_keccakf1600_xor_bytes(s,&suffix,34,1);
    mld_keccakf1600_xor_bytes(s,&final,SHAKE128_RATE-1,1);
  }
  mld_zeroize(seed,sizeof(seed));
}

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
static void lc_matrix_y_x4(uint8_t *out, mld_polymat *mat,
#else
static LC_MATRIX_FUNCTION_OPT void lc_matrix_y_x4(uint8_t *out, mld_polymat *mat,
#endif
                           const mld_poly *y, unsigned col, unsigned row,
                           unsigned lanes, unsigned first) {
  unsigned ctr[4]={0,0,0,0},pending;
#if LC_DSA_STREAM_CACHE24
  unsigned cache_pending=0;
  for(unsigned lane=0;lane<lanes;lane++) {
    unsigned index=col*MLDSA_K+row+lane;
    if(lc_stream_cache_hit(mat,index)) {
      lc_stream_cache_product(out+lane*LC_PACKED_ROW_BYTES,mat->cache[index],y->coeffs,first);
      ctr[lane]=MLDSA_N;
    } else cache_pending++;
  }
  if(cache_pending==0)return;
#endif
  lc_matrix_x4_start(mat,col,row,1,lanes);
  do {
    pending=0;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_STREAM_ACTIVE_TAIL) && LC_DSA_STREAM_ACTIVE_TAIL
#if LC_DSA_STREAM_CACHE24
    if(cache_pending<=2) {
      for(unsigned active=0;active<lanes;active++)if(ctr[active]<MLDSA_N)
        mld_keccakf1600_permute(mat->stream4.state+25*active);
    } else
#else
    if(lanes<=2) {
      for(unsigned active=0;active<lanes;active++)
        mld_keccakf1600_permute(mat->stream4.state+25*active);
    } else
#endif
#elif LC_DSA_MATRIX_TAIL_SINGLE
    if(lanes==1)mld_keccakf1600_permute(mat->stream4.state);
    else
#endif
    mld_keccakf1600x4_permute(mat->stream4.state);
#else
    lc_matrix_x4_permute(mat,lanes);
#endif
    unsigned lc_prefix_bytes=0;
#if LC_DSA_LOWMEM_MATRIX_FAST && LC_DSA_MATRIX_INTERLEAVED && defined(__AVX2__) && !LC_DSA_STREAM_CACHE24 && MLDSA_K == 8
    lc_prefix_bytes=lc_lowmem_matrix_prefix(out,mat,y,ctr,lanes,first);
#endif
    for(unsigned lane=0;lane<lanes;lane++) {
      if(lc_prefix_bytes) {
        if(ctr[lane]>=MLDSA_N)continue;
        if(lc_prefix_bytes==SHAKE128_RATE){pending=1;continue;}
      }
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_STREAM_DIRECT_STATE) && LC_DSA_STREAM_DIRECT_STATE
      /* Character access preserves the uint64_t effective type. Each lane
       * has 200 bytes; only its first 168 public output bytes are consumed. */
      const uint8_t *rate=(const uint8_t *)(mat->stream4.state+25*lane);
#else
      mld_keccakf1600_extract_bytes(mat->stream4.state+25*lane,
                                  mat->stream4.rate,0,SHAKE128_RATE);
      const uint8_t *rate=mat->stream4.rate;
#endif
#else
      lc_matrix_x4_extract(mat,lane,lanes);
#endif
      for(unsigned j=lc_prefix_bytes;ctr[lane]<MLDSA_N && j+3<=SHAKE128_RATE;) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
        const uint8_t *b=rate+j;
#if LC_DSA_MATRIX_STREAM_VECTOR && defined(__AVX2__)
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N &&
           lc_stream4_y_block(out+lane*LC_PACKED_ROW_BYTES+3*ctr[lane],
                              b,y->coeffs+ctr[lane],first)) {
#if LC_DSA_STREAM_CACHE24
          lc_stream_cache_store8(mat,col*MLDSA_K+row+lane,ctr[lane],b);
#endif
          ctr[lane]+=8;j+=24;continue;
        }
#endif
#if defined(LC_DSA_STREAM_NEON) && LC_DSA_STREAM_NEON
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N) {
          uint32x4_t a0,a1;
          if(lc_stream_public8(b,&a0,&a1)) {
#if LC_DSA_STREAM_CACHE24
            lc_stream_cache_store8(mat,col*MLDSA_K+row+lane,ctr[lane],a0,a1);
#endif
            lc_stream_y8(out+lane*LC_PACKED_ROW_BYTES+3*ctr[lane],y->coeffs+ctr[lane],a0,a1,first);
            ctr[lane]+=8;j+=24;continue;
          }
        }
#endif
#else
        const uint8_t *b=mat->stream4.rate+j;
#if LC_DSA_MATRIX_STREAM_VECTOR && defined(__AVX2__)
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N &&
           lc_stream4_y_block(out+lane*LC_PACKED_ROW_BYTES+3*ctr[lane],
                              b,y->coeffs+ctr[lane],first)) {
#if LC_DSA_STREAM_CACHE24
          lc_stream_cache_store8(mat,col*MLDSA_K+row+lane,ctr[lane],b);
#endif
          ctr[lane]+=8;j+=24;continue;
        }
#endif
#endif
        j+=3;
        uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
        if(a<MLDSA_Q) {
          unsigned i=lc_matrix_native_index(ctr[lane]++);
#if LC_DSA_STREAM_CACHE24
          lc_stream_cache_store1(mat,col*MLDSA_K+row+lane,i,a);
#endif
          uint8_t *v=out+lane*LC_PACKED_ROW_BYTES+3*i;
          int32_t x=mld_montgomery_reduce((int64_t)a*y->coeffs[i]);
          x+=first?0:lc_load_signed24(v);
          lc_store_signed24(v,mld_reduce32(x));
        }
      }
      pending|=(unsigned)(ctr[lane]<MLDSA_N);
    }
  } while(pending);
  mld_zeroize(&mat->stream4,sizeof(mat->stream4));
}

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
static void lc_matrix_v_x4(mld_poly *out, mld_polymat *mat,
#else
static LC_MATRIX_FUNCTION_OPT void lc_matrix_v_x4(mld_poly *out, mld_polymat *mat,
#endif
                           const lc_packed_vecl *v, unsigned col,
                           unsigned row, unsigned lanes) {
  unsigned ctr[4]={0,0,0,0},pending;
  lc_matrix_x4_start(mat,col,row,0,lanes);
  do {
    pending=0;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_STREAM_ACTIVE_TAIL) && LC_DSA_STREAM_ACTIVE_TAIL
    if(lanes<=2) {
      for(unsigned active=0;active<lanes;active++)
        mld_keccakf1600_permute(mat->stream4.state+25*active);
    } else
#elif LC_DSA_MATRIX_TAIL_SINGLE
    if(lanes==1)mld_keccakf1600_permute(mat->stream4.state);
    else
#endif
    mld_keccakf1600x4_permute(mat->stream4.state);
#else
    lc_matrix_x4_permute(mat,lanes);
#endif
    for(unsigned lane=0;lane<lanes;lane++) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_STREAM_DIRECT_STATE) && LC_DSA_STREAM_DIRECT_STATE
      const uint8_t *rate=(const uint8_t *)(mat->stream4.state+25*lane);
#else
      mld_keccakf1600_extract_bytes(mat->stream4.state+25*lane,
                                  mat->stream4.rate,0,SHAKE128_RATE);
      const uint8_t *rate=mat->stream4.rate;
#endif
#else
      lc_matrix_x4_extract(mat,lane,lanes);
#endif
      for(unsigned j=0;ctr[lane]<MLDSA_N && j+3<=SHAKE128_RATE;) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
        const uint8_t *b=rate+j;
#if LC_DSA_MATRIX_STREAM_VECTOR && defined(__AVX2__)
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N &&
           lc_stream4_v_block(out->coeffs+ctr[lane],b,
                              (*v)[col+lane]+3*ctr[lane])) {
          ctr[lane]+=8;j+=24;continue;
        }
#endif
#if defined(LC_DSA_STREAM_NEON) && LC_DSA_STREAM_NEON
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N) {
          uint32x4_t a0,a1;
          if(lc_stream_public8(b,&a0,&a1)) {
            lc_stream_v8(out->coeffs+ctr[lane],(*v)[col+lane]+3*ctr[lane],a0,a1);
            ctr[lane]+=8;j+=24;continue;
          }
        }
#endif
#else
        const uint8_t *b=mat->stream4.rate+j;
#if LC_DSA_MATRIX_STREAM_VECTOR && defined(__AVX2__)
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N &&
           lc_stream4_v_block(out->coeffs+ctr[lane],b,
                              (*v)[col+lane]+3*ctr[lane])) {
          ctr[lane]+=8;j+=24;continue;
        }
#endif
#endif
        j+=3;
        uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
        if(a<MLDSA_Q) {
          unsigned i=lc_matrix_native_index(ctr[lane]++);
          int32_t x=mld_montgomery_reduce((int64_t)a*lc_load_signed24((*v)[col+lane]+3*i));
          out->coeffs[i]+=x;
        }
      }
      pending|=(unsigned)(ctr[lane]<MLDSA_N);
    }
  } while(pending);
  mld_zeroize(&mat->stream4,sizeof(mat->stream4));
}
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#undef LC_MATRIX_FUNCTION_OPT
#endif
#endif
