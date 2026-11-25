#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
/* SPDX-License-Identifier: Apache-2.0
 * A public-parameter ExpandMask prefix. Cache its standard raw encodings
 * once per attempt, then decode the same values for both A*y and z. */
#else
/* SPDX-License-Identifier: Apache-2.0
 * Standard ExpandMask streams, retained in their original 18-bit encoding. */
#endif
#ifndef LC_RAW_Y4_H
#define LC_RAW_Y4_H
#if LC_DSA_JOINT_A_MASK65 && MLDSA_K == 6
#if !LC_DSA_MASK_PIPELINE
#error "Mixed A/mask lanes require the continuous mask pipeline and direct interleaved fill"
#endif
static void lc_fill_joint_matrix_mask65(mld_yvec *y,mld_polymat *mat,uint8_t *encoded);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if !defined(__aarch64__) || !LC_DSA_MATRIX_STREAM_DIRECT4 || LC_DSA_Y_CACHE_COUNT == 0
#error "Raw gamma cache requires a selected AArch64 direct-stream path"
#endif
_Static_assert(MLDSA_CRHBYTES==64 && SHAKE256_RATE==136,"Standard gamma stream input sizes");
_Static_assert(sizeof(mld_shake256ctx)<=sizeof(mld_poly) && _Alignof(mld_shake256ctx)<=_Alignof(mld_poly),"Gamma state fits the existing matrix union");
static void lc_raw_y4_fill(mld_yvec *y,mld_polymat *mat,uint8_t encoded[LC_DSA_Y_CACHE_BYTES])
#else
#if !LC_DSA_RAW_Y_ALL_CACHE
#if !defined(__AVX2__) || MLDSA_K != 4 || MLDSA_L != 4 || !LC_DSA_MATRIX_INTERLEAVED
#error "Raw gamma4 cache requires the selected AVX2 44 interleaved path"
#endif
_Static_assert(MLDSA_CRHBYTES==64 && SHAKE256_RATE==136 && MLDSA_POLYZ_PACKEDBYTES==576,
               "Standard gamma stream sizes");
_Static_assert(((sizeof(mld_yvec)+31)/32)*32==32,"Seed descriptor keeps its arena slot");
static void lc_raw_y4_fill(mld_yvec *y,mld_polymat *mat,uint8_t encoded[2304])
#else
#if !defined(__AVX2__) || !LC_DSA_MATRIX_INTERLEAVED
#error "Raw gamma cache requires the AVX2 interleaved path"
#endif
_Static_assert(MLDSA_CRHBYTES==64 && SHAKE256_RATE==136 && (MLDSA_POLYZ_PACKEDBYTES==576 || MLDSA_POLYZ_PACKEDBYTES==640),
               "Standard gamma stream sizes");
_Static_assert(((sizeof(mld_yvec)+31)/32)*32==32,"Seed descriptor keeps its arena slot");
static void lc_raw_y4_fill(mld_yvec *y,mld_polymat *mat,uint8_t encoded[MLDSA_L*MLDSA_POLYZ_PACKEDBYTES])
#endif
#endif
{
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_MASK_PIPELINE && MLDSA_K > 4
  unsigned consumed=0;
  if(mat->mask_count && mat->mask_nonce==(unsigned)y->kappa) {
    consumed=mat->mask_count;
    mld_memcpy(encoded,mat->mask_future,consumed*MLDSA_POLYZ_PACKEDBYTES);
  }
  mat->mask_count=0;
  for(unsigned group=consumed;group<MLDSA_L;group+=4) {
    unsigned valid=4;
    if((unsigned)y->kappa+group+valid>65536u)valid=65536u-(unsigned)y->kappa-group;
    mld_memset(&mat->stream4,0,sizeof(mat->stream4));
    for(unsigned lane=0;lane<4;lane++) {
      const unsigned selected=lane<valid?lane:0;
      const uint16_t nonce=(uint16_t)((unsigned)y->kappa+group+selected);
      uint64_t *state=mat->stream4.state+25*lane;
      mld_memcpy(state,y->rhoprime,64);
      state[8]=(uint64_t)nonce|((uint64_t)0x1f<<16);
      state[16]=(uint64_t)0x80<<56;
    }
    for(unsigned pos=0;pos<MLDSA_POLYZ_PACKEDBYTES;pos+=SHAKE256_RATE) {
      unsigned bytes=MLDSA_POLYZ_PACKEDBYTES-pos<SHAKE256_RATE?MLDSA_POLYZ_PACKEDBYTES-pos:SHAKE256_RATE;
      mld_keccakf1600x4_permute(mat->stream4.state);
      for(unsigned lane=0;lane<valid;lane++) {
        unsigned index=group+lane;
        uint8_t *out=index<MLDSA_L?encoded+index*MLDSA_POLYZ_PACKEDBYTES:
                           mat->mask_future+(index-MLDSA_L)*MLDSA_POLYZ_PACKEDBYTES;
        mld_memcpy(out+pos,mat->stream4.state+25*lane,bytes);
      }
    }
    if(group+valid>MLDSA_L) {
      mat->mask_count=group+valid-MLDSA_L;
      mat->mask_nonce=(unsigned)y->kappa+MLDSA_L;
    }
    mld_zeroize(&mat->stream4,sizeof(mat->stream4));
  }
#elif LC_DSA_FULL_Y_BATCH
  /* The fixed public vector is sampled once per candidate. Each lane uses
   * its original ExpandMask nonce. A short group duplicates a valid lane;
   * only the required active streams are copied into their exact owners. */
  for(unsigned first=0;first<LC_DSA_Y_CACHE_COUNT;first+=4) {
    unsigned lanes=LC_DSA_Y_CACHE_COUNT-first;
    if(lanes>4)lanes=4;
    if(lanes<=2) {
      for(unsigned lane=0;lane<lanes;lane++) {
        uint16_t nonce=(uint16_t)(y->kappa+first+lane);
        uint8_t b[2]={(uint8_t)nonce,(uint8_t)(nonce>>8)};
        mld_shake256ctx *state=&mat->gamma_state;
        mld_shake256_init(state);mld_shake256_absorb(state,y->rhoprime,64);
        mld_shake256_absorb(state,b,2);mld_shake256_finalize(state);
        mld_shake256_squeeze(encoded+(first+lane)*MLDSA_POLYZ_PACKEDBYTES,
                             MLDSA_POLYZ_PACKEDBYTES,state);
        mld_shake256_release(state);mld_zeroize(state,sizeof(*state));
      }
    } else {
      const uint8_t suffix=0x1f,final=0x80;
      mld_memset(&mat->stream4,0,sizeof(mat->stream4));
      for(unsigned lane=0;lane<4;lane++) {
        const unsigned active=lane<lanes?lane:0;
        uint16_t nonce=(uint16_t)(y->kappa+first+active);
        uint8_t b[2]={(uint8_t)nonce,(uint8_t)(nonce>>8)};
        uint64_t *state=mat->stream4.state+25*lane;
        mld_keccakf1600_xor_bytes(state,y->rhoprime,0,64);
        mld_keccakf1600_xor_bytes(state,b,64,2);
        mld_keccakf1600_xor_bytes(state,&suffix,66,1);
        mld_keccakf1600_xor_bytes(state,&final,SHAKE256_RATE-1,1);
      }
      for(unsigned pos=0;pos<MLDSA_POLYZ_PACKEDBYTES;pos+=SHAKE256_RATE) {
        unsigned bytes=MLDSA_POLYZ_PACKEDBYTES-pos;
        if(bytes>SHAKE256_RATE)bytes=SHAKE256_RATE;
        mld_keccakf1600x4_permute(mat->stream4.state);
        for(unsigned lane=0;lane<lanes;lane++)
          mld_keccakf1600_extract_bytes(mat->stream4.state+25*lane,
                encoded+(first+lane)*MLDSA_POLYZ_PACKEDBYTES+pos,0,bytes);
      }
      mld_zeroize(&mat->stream4,sizeof(mat->stream4));
    }
  }
#else
#if MLDSA_K == 4
  _Static_assert(MLDSA_L==4 && MLDSA_POLYZ_PACKEDBYTES==576,"Standard44 gamma lengths");
  const uint8_t suffix=0x1f,final=0x80;
  mld_memset(&mat->stream4,0,sizeof(mat->stream4));
  for(unsigned lane=0;lane<4;lane++) {
    uint16_t nonce=(uint16_t)(y->kappa+lane);
    uint8_t b[2]={(uint8_t)nonce,(uint8_t)(nonce>>8)};
    uint64_t *state=mat->stream4.state+25*lane;
    mld_keccakf1600_xor_bytes(state,y->rhoprime,0,64);
    mld_keccakf1600_xor_bytes(state,b,64,2);
    mld_keccakf1600_xor_bytes(state,&suffix,66,1);
    mld_keccakf1600_xor_bytes(state,&final,SHAKE256_RATE-1,1);
  }
  for(unsigned pos=0;pos<576;pos+=SHAKE256_RATE) {
    unsigned bytes=576-pos<SHAKE256_RATE?576-pos:SHAKE256_RATE;
    mld_keccakf1600x4_permute(mat->stream4.state);
    for(unsigned lane=0;lane<4;lane++)
      mld_keccakf1600_extract_bytes(mat->stream4.state+25*lane,
                                  encoded+lane*576+pos,0,bytes);
  }
  mld_zeroize(&mat->stream4,sizeof(mat->stream4));
#else
  for(unsigned lane=0;lane<LC_DSA_Y_CACHE_COUNT;lane++) {
    uint16_t nonce=(uint16_t)(y->kappa+lane);
    uint8_t b[2]={(uint8_t)nonce,(uint8_t)(nonce>>8)};
    mld_shake256ctx *state=&mat->gamma_state;
    mld_shake256_init(state);
    mld_shake256_absorb(state,y->rhoprime,64);
    mld_shake256_absorb(state,b,2);
    mld_shake256_finalize(state);
    mld_shake256_squeeze(encoded+lane*MLDSA_POLYZ_PACKEDBYTES,MLDSA_POLYZ_PACKEDBYTES,state);
    mld_shake256_release(state);
    mld_zeroize(state,sizeof(*state));
  }
#endif
#endif /* LC_DSA_FULL_Y_BATCH */
#else
#if !LC_DSA_RAW_Y_ALL_CACHE
  mld_memset(&mat->stream4,0,sizeof(mat->stream4));
  for(unsigned lane=0;lane<4;lane++) {
    for(unsigned word=0;word<8;word++) {
      uint64_t value;mld_memcpy(&value,y->rhoprime+8*word,8);
      mat->stream4.state[4*lc_matrix_word_to_slot[word]+lane]=value;
    }
    uint16_t nonce=(uint16_t)(y->kappa+lane);
    mat->stream4.state[4*lc_matrix_word_to_slot[8]+lane]=(uint64_t)nonce|((uint64_t)0x1f<<16);
    mat->stream4.state[4*lc_matrix_word_to_slot[16]+lane]=(uint64_t)0x80<<56;
  }
  for(unsigned pos=0;pos<576;pos+=SHAKE256_RATE) {
    unsigned bytes=576-pos<SHAKE256_RATE?576-pos:SHAKE256_RATE;
    lc_keccak_x4_interleaved(mat->stream4.state,lc_base_mlk_keccakf1600_round_constants,
                             lc_base_mlk_keccak_rho8,lc_base_mlk_keccak_rho56);
    for(unsigned lane=0;lane<4;lane++)
      for(unsigned word=0;word<bytes/8;word++)
        mld_memcpy(encoded+576*lane+pos+8*word,
                   mat->stream4.state+4*lc_matrix_word_to_slot[word]+lane,8);
  }
  mld_zeroize(&mat->stream4,sizeof(mat->stream4));
#else
#if LC_DSA_MASK_PIPELINE && MLDSA_K > 4
  unsigned consumed=0;
#if LC_DSA_JOINT_A_MASK65 && MLDSA_K == 6
  if(!mat->cache_ready) {lc_fill_joint_matrix_mask65(y,mat,encoded);consumed=2;}
#endif
  if(!consumed && mat->mask_count && mat->mask_nonce==(unsigned)y->kappa) {
    consumed=mat->mask_count;
    mld_memcpy(encoded,mat->mask_future,consumed*MLDSA_POLYZ_PACKEDBYTES);
  }
  mat->mask_count=0;
  for(unsigned group=consumed;group<MLDSA_L;group+=4) {
    unsigned valid=4;
    if((unsigned)y->kappa+group+valid>65536u)valid=65536u-(unsigned)y->kappa-group;
    mld_memset(&mat->stream4,0,sizeof(mat->stream4));
    for(unsigned lane=0;lane<4;lane++) {
      for(unsigned word=0;word<8;word++) {
        uint64_t value;mld_memcpy(&value,y->rhoprime+8*word,8);
        mat->stream4.state[4*lc_matrix_word_to_slot[word]+lane]=value;
      }
      const unsigned selected=lane<valid?lane:0;
      const uint16_t nonce=(uint16_t)((unsigned)y->kappa+group+selected);
      mat->stream4.state[4*lc_matrix_word_to_slot[8]+lane]=(uint64_t)nonce|((uint64_t)0x1f<<16);
      mat->stream4.state[4*lc_matrix_word_to_slot[16]+lane]=(uint64_t)0x80<<56;
    }
    for(unsigned pos=0;pos<MLDSA_POLYZ_PACKEDBYTES;pos+=SHAKE256_RATE) {
      unsigned bytes=MLDSA_POLYZ_PACKEDBYTES-pos<SHAKE256_RATE?MLDSA_POLYZ_PACKEDBYTES-pos:SHAKE256_RATE;
      lc_keccak_x4_interleaved(mat->stream4.state,lc_base_mlk_keccakf1600_round_constants,
                               lc_base_mlk_keccak_rho8,lc_base_mlk_keccak_rho56);
      for(unsigned lane=0;lane<valid;lane++) {
        unsigned index=group+lane;
        uint8_t *out=index<MLDSA_L?encoded+index*MLDSA_POLYZ_PACKEDBYTES:
                           mat->mask_future+(index-MLDSA_L)*MLDSA_POLYZ_PACKEDBYTES;
        for(unsigned word=0;word<bytes/8;word++)
          mld_memcpy(out+pos+8*word,mat->stream4.state+4*lc_matrix_word_to_slot[word]+lane,8);
      }
    }
    if(group+valid>MLDSA_L) {
      mat->mask_count=group+valid-MLDSA_L;
      mat->mask_nonce=(unsigned)y->kappa+MLDSA_L;
    }
    mld_zeroize(&mat->stream4,sizeof(mat->stream4));
  }
#else
  for(unsigned group=0;group<MLDSA_L;group+=4) {
    unsigned lanes=MLDSA_L-group<4?MLDSA_L-group:4;
#if LC_DSA_RAW_SINGLE_TAIL && LC_DSA_STREAM_CACHE24
    if(lanes==1) {
      const uint16_t nonce=(uint16_t)(y->kappa+group);
      const uint8_t b[2]={(uint8_t)nonce,(uint8_t)(nonce>>8)};
      mld_shake256ctx *state=&mat->stream_cache_gamma;
      mld_shake256_init(state);
      mld_shake256_absorb(state,y->rhoprime,64);
      mld_shake256_absorb(state,b,2);
      mld_shake256_finalize(state);
      mld_shake256_squeeze(encoded+group*MLDSA_POLYZ_PACKEDBYTES,
                           MLDSA_POLYZ_PACKEDBYTES,state);
      mld_shake256_release(state);
      mld_zeroize(state,sizeof(*state));
      continue;
    }
#endif
  mld_memset(&mat->stream4,0,sizeof(mat->stream4));
  for(unsigned lane=0;lane<4;lane++) {
    for(unsigned word=0;word<8;word++) {
      uint64_t value;mld_memcpy(&value,y->rhoprime+8*word,8);
      mat->stream4.state[4*lc_matrix_word_to_slot[word]+lane]=value;
    }
    uint16_t nonce=(uint16_t)(y->kappa+group+(lane<lanes?lane:0));
    mat->stream4.state[4*lc_matrix_word_to_slot[8]+lane]=(uint64_t)nonce|((uint64_t)0x1f<<16);
    mat->stream4.state[4*lc_matrix_word_to_slot[16]+lane]=(uint64_t)0x80<<56;
  }
  for(unsigned pos=0;pos<MLDSA_POLYZ_PACKEDBYTES;pos+=SHAKE256_RATE) {
    unsigned bytes=MLDSA_POLYZ_PACKEDBYTES-pos<SHAKE256_RATE?MLDSA_POLYZ_PACKEDBYTES-pos:SHAKE256_RATE;
    lc_keccak_x4_interleaved(mat->stream4.state,lc_base_mlk_keccakf1600_round_constants,
                             lc_base_mlk_keccak_rho8,lc_base_mlk_keccak_rho56);
    for(unsigned lane=0;lane<lanes;lane++)
      for(unsigned word=0;word<bytes/8;word++)
        mld_memcpy(encoded+MLDSA_POLYZ_PACKEDBYTES*(group+lane)+pos+8*word,
                   mat->stream4.state+4*lc_matrix_word_to_slot[word]+lane,8);
  }
  mld_zeroize(&mat->stream4,sizeof(mat->stream4));
  }
#endif
#endif
#endif /* mask pipeline */
  y->encoded=encoded;
}
#endif
