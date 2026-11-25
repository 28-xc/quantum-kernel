/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS204]
 *   FIPS 204 Module-Lattice-Based Digital Signature Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/204/final
 */

#include "polyvec_lazy.h"

#include "debug.h"
#include "fips202/keccakf1600.h"

/* This namespacing is not done at the top to avoid a naming conflict
 * with native backends, which are currently not yet namespaced. */
#define mld_polymat_expand_entry MLD_ADD_PARAM_SET(mld_polymat_expand_entry)

/**
 * Sample a single matrix entry A[k][l] of ExpandA(rho) by rejection sampling
 * from SHAKE128(rho|l|k), and apply the custom-order permutation when a
 * native NTT backend is in use.
 *
 * The caller is expected to have copied rho into the first MLDSA_SEEDBYTES
 * of seed_ext. This function writes the domain-separation bytes
 * seed_ext[SEEDBYTES..+2] = {l, k} before sampling.
 *
 * @spec{Partially implements @[FIPS204, Algorithm 32, ExpandA] (samples one
 * matrix entry via @[FIPS204, Algorithm 30, RejNTTPoly]).}
 *
 * @param[out]    p        Pointer to output polynomial.
 * @param[in,out] seed_ext Seed buffer pre-filled with rho in the first
 *                         MLDSA_SEEDBYTES; the final two bytes are
 *                         overwritten.
 * @param         l        Column index (inner, aka nonce low byte).
 * @param         k        Row index (outer, aka nonce high byte).
 */
static MLD_INLINE void mld_polymat_expand_entry(
    mld_poly *p, uint8_t seed_ext[MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)], uint8_t l,
    uint8_t k)
__contract__(
  requires(memory_no_alias(p, sizeof(mld_poly)))
  requires(memory_no_alias(seed_ext, MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)))
  assigns(memory_slice(p, sizeof(mld_poly)))
  assigns(memory_slice(seed_ext, MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)))
  ensures(array_bound(p->coeffs, 0, MLDSA_N, 0, MLDSA_Q))
)
{
  seed_ext[MLDSA_SEEDBYTES + 0] = l;
  seed_ext[MLDSA_SEEDBYTES + 1] = k;
  mld_poly_uniform(p, seed_ext);
  mld_poly_permute_bitrev_to_custom_optional(p);
}

#if !defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)

MLD_INTERNAL_API
void mld_polyvec_matrix_expand_eager(mld_polymat_eager *mat,
                                     const uint8_t rho[MLDSA_SEEDBYTES])
{
  unsigned int i, j;
  MLD_ALIGN uint8_t seed_ext[4][MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)];

  for (j = 0; j < 4; j++)
  __loop__(
    assigns(j, object_whole(seed_ext))
    invariant(j <= 4)
    decreases(4 - j)
  )
  {
    mld_memcpy(seed_ext[j], rho, MLDSA_SEEDBYTES);
  }

#if !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  /* Sample 4 matrix entries a time. */
  for (i = 0; i < (MLDSA_K * MLDSA_L / 4) * 4; i += 4)
  __loop__(
    assigns(i, j, object_whole(seed_ext), memory_slice(mat, sizeof(mld_polymat_eager)))
    invariant(i <= (MLDSA_K * MLDSA_L / 4) * 4 && i % 4 == 0)
    /* vectors 0 .. i / MLDSA_L are completely sampled */
    invariant(forall(k1, 0, i / MLDSA_L, forall(l1, 0, MLDSA_L,
      array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
    /* last vector is sampled up to i % MLDSA_L */
    invariant(forall(k2, i / MLDSA_L, i / MLDSA_L + 1, forall(l2, 0, i % MLDSA_L,
      array_bound(mat->vec[k2].vec[l2].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
    decreases((MLDSA_K * MLDSA_L / 4) * 4 - i)
  )
  {
    for (j = 0; j < 4; j++)
    __loop__(
      assigns(j, object_whole(seed_ext))
      invariant(j <= 4)
      decreases(4 - j)
    )
    {
      uint8_t x = (uint8_t)((i + j) / MLDSA_L);
      uint8_t y = (uint8_t)((i + j) % MLDSA_L);

      seed_ext[j][MLDSA_SEEDBYTES + 0] = y;
      seed_ext[j][MLDSA_SEEDBYTES + 1] = x;
    }

    mld_poly_uniform_4x(&mat->vec[i / MLDSA_L].vec[i % MLDSA_L],
                        &mat->vec[(i + 1) / MLDSA_L].vec[(i + 1) % MLDSA_L],
                        &mat->vec[(i + 2) / MLDSA_L].vec[(i + 2) % MLDSA_L],
                        &mat->vec[(i + 3) / MLDSA_L].vec[(i + 3) % MLDSA_L],
                        seed_ext);
    mld_poly_permute_bitrev_to_custom_optional(
        &mat->vec[i / MLDSA_L].vec[i % MLDSA_L]);
    mld_poly_permute_bitrev_to_custom_optional(
        &mat->vec[(i + 1) / MLDSA_L].vec[(i + 1) % MLDSA_L]);
    mld_poly_permute_bitrev_to_custom_optional(
        &mat->vec[(i + 2) / MLDSA_L].vec[(i + 2) % MLDSA_L]);
    mld_poly_permute_bitrev_to_custom_optional(
        &mat->vec[(i + 3) / MLDSA_L].vec[(i + 3) % MLDSA_L]);
  }
#else  /* !MLD_CONFIG_SERIAL_FIPS202_ONLY */
  i = 0;
#endif /* MLD_CONFIG_SERIAL_FIPS202_ONLY */

  /* Entries omitted by the batch-sampling are sampled individually. */
  while (i < MLDSA_K * MLDSA_L)
  __loop__(
    assigns(i, object_whole(seed_ext), memory_slice(mat, sizeof(mld_polymat_eager)))
    invariant(i <= MLDSA_K * MLDSA_L)
    /* vectors 0 .. i / MLDSA_L are completely sampled */
    invariant(forall(k1, 0, i / MLDSA_L, forall(l1, 0, MLDSA_L,
      array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
    /* last vector is sampled up to i % MLDSA_L */
    invariant(forall(k2, i / MLDSA_L, i / MLDSA_L + 1, forall(l2, 0, i % MLDSA_L,
      array_bound(mat->vec[k2].vec[l2].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
    decreases(MLDSA_K * MLDSA_L - i)
  )
  {
    uint8_t x = (uint8_t)(i / MLDSA_L);
    uint8_t y = (uint8_t)(i % MLDSA_L);
    mld_polymat_expand_entry(&mat->vec[x].vec[y], seed_ext[0], y, x);
    i++;
  }

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(seed_ext, sizeof(seed_ext));
}

MLD_INTERNAL_API
void mld_polyvec_matrix_pointwise_montgomery_row_eager(mld_poly *t_row,
                                                       mld_polymat_eager *mat,
                                                       const mld_polyvecl *v,
                                                       unsigned int i)
{
  mld_polyvecl_pointwise_acc_montgomery(t_row, &mat->vec[i], v);
}

#if !defined(MLD_CONFIG_NO_SIGN_API)
MLD_INTERNAL_API
void mld_polyvec_matrix_pointwise_montgomery_yvec_eager(
    mld_polyveck *w, mld_polymat_eager *mat, const mld_yvec_eager *y,
    mld_yvec_scratch_eager *scratch)
{
  unsigned int i;
  *scratch = y->vec;
  mld_polyvecl_ntt(scratch);

  for (i = 0; i < MLDSA_K; i++)
  __loop__(
    assigns(i, memory_slice(w, sizeof(mld_polyveck)))
    invariant(i <= MLDSA_K)
    invariant(forall(k0, 0, i,
                     array_abs_bound(w->vec[k0].coeffs, 0, MLDSA_N, MLDSA_Q)))
    decreases(MLDSA_K - i)
  )
  {
    mld_polyvec_matrix_pointwise_montgomery_row_eager(&w->vec[i], mat, scratch,
                                                      i);
  }

  mld_polyveck_invntt_tomont(w);
}
#endif /* !MLD_CONFIG_NO_SIGN_API */

#endif /* !MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

#if defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)

#ifndef LC_DSA_CACHE_REUSE_INPUT
#define LC_DSA_CACHE_REUSE_INPUT 0
#endif
#if LC_DSA_DIRECT_MATRIX
/* Consume canonical public ExpandA coefficients as soon as they are accepted.
 * The optional cache stores the same sequence; no secret index is selected.
 * Each SHAKE128 rate is divisible by three, so no bytes cross block borders. */
static void lc_matrix_sample_acc(mld_poly *out,const mld_poly *rhs,
    uint8_t seed[MLDSA_SEEDBYTES+2],uint8_t l,uint8_t k,
    uint8_t *cache,int add) {
  unsigned ctr=0;
  seed[MLDSA_SEEDBYTES]=l;seed[MLDSA_SEEDBYTES+1]=k;
#if defined(__riscv) && __riscv_xlen == 32 && defined(MLD_SYS_LITTLE_ENDIAN)
  /* Exact fixed-length SHAKE128(rho || column || row). All34 input bytes
   * fit the first rate. The public rejection consumer reads every rate
   * before the next permutation; cache and Montgomery order are unchanged. */
  uint64_t state[25];
  const uint8_t *buf=(const uint8_t *)(const void *)state;
  mld_memset(state,0,sizeof(state));
  mld_memcpy(state,seed,MLDSA_SEEDBYTES+2);
  ((uint8_t *)(void *)state)[MLDSA_SEEDBYTES+2]=0x1f;
  ((uint8_t *)(void *)state)[SHAKE128_RATE-1]=0x80;
#else
  mld_xof128_ctx state;
  uint8_t buf[SHAKE128_RATE];
  mld_xof128_init(&state);
  mld_xof128_absorb_once(&state,seed,MLDSA_SEEDBYTES+2);
#endif
  while(ctr<MLDSA_N) {
#if defined(__riscv) && __riscv_xlen == 32 && defined(MLD_SYS_LITTLE_ENDIAN)
    mld_keccakf1600_permute(state);
#else
    mld_xof128_squeezeblocks(buf,1,&state);
#endif
    for(unsigned j=0;j<SHAKE128_RATE && ctr<MLDSA_N;j+=3) {
      uint32_t a=((uint32_t)buf[j]|((uint32_t)buf[j+1]<<8)|
                  ((uint32_t)buf[j+2]<<16))&UINT32_C(0x7fffff);
      if(a<MLDSA_Q) {
        if(cache!=NULL) {
          cache[3*ctr]=(uint8_t)a;cache[3*ctr+1]=(uint8_t)(a>>8);
          cache[3*ctr+2]=(uint8_t)(a>>16);
        }
        int32_t product=mld_montgomery_reduce((int64_t)a*rhs->coeffs[ctr]);
        out->coeffs[ctr]=add?out->coeffs[ctr]+product:product;
        ctr++;
      }
    }
  }
#if defined(__riscv) && __riscv_xlen == 32 && defined(MLD_SYS_LITTLE_ENDIAN)
  mld_zeroize(state,sizeof(state));
#else
  mld_xof128_release(&state);
#endif
}
/* This is the existing cache-decode/pointwise fusion adapted to the scalar
 * arithmetic helper. Its separate materialized-polynomial owner is absent. */
#if !LC_DSA_CACHE_REUSE_INPUT || LC_DSA_A_CACHE_COUNT < MLDSA_K*MLDSA_L
static void lc_matrix_cache_acc(mld_poly *out,const mld_poly *rhs,
                                const uint8_t *cache,int add) {
  const uint8_t *p=__builtin_assume_aligned(cache,4);
  for(unsigned j=0;j<MLDSA_N;j+=4,p+=12) {
    uint32_t x,y,z;
    __builtin_memcpy(&x,p,4);__builtin_memcpy(&y,p+4,4);
    __builtin_memcpy(&z,p+8,4);
#define LC_APPLY_WORD(K,A) do { \
    int32_t v=mld_montgomery_reduce((int64_t)(A)*rhs->coeffs[j+(K)]); \
    out->coeffs[j+(K)]=add?out->coeffs[j+(K)]+v:v; \
  } while(0)
    LC_APPLY_WORD(0,x&0xffffffu);
    LC_APPLY_WORD(1,((x>>24)|(y<<8))&0xffffffu);
    LC_APPLY_WORD(2,((y>>16)|(z<<16))&0xffffffu);
    LC_APPLY_WORD(3,z>>8);
#undef LC_APPLY_WORD
  }

}
#endif

#if LC_DSA_CACHE_REUSE_INPUT
static __attribute__((always_inline)) inline int32_t lc_matrix_mont_pre(
    uint32_t a,int32_t b,uint32_t bq) {
  int32_t t=(int32_t)(a*bq);
  return (int32_t)(((int64_t)a*b)>>32)-
         (int32_t)(((int64_t)t*8380417)>>32);
}

__attribute__((noinline,noclone))
static void lc_matrix_cached_column(int32_t *out,const int32_t *rhs,const uint8_t *cache,
                     int add,unsigned rows) {
  for(unsigned j=0;j<256;j+=4) {
    const int32_t b0=rhs[j],b1=rhs[j+1],b2=rhs[j+2],b3=rhs[j+3];
    uint32_t p0=(uint32_t)b0*UINT32_C(58728449);
    uint32_t p1=(uint32_t)b1*UINT32_C(58728449);
    uint32_t p2=(uint32_t)b2*UINT32_C(58728449);
    uint32_t p3=(uint32_t)b3*UINT32_C(58728449);
    /* Keep the already computed factors in registers: without this value
     * barrier GCC reassociates each A*(y*qinv) back into (A*y)*qinv.
     * The empty assembly changes no value and has no memory side effects. */
    __asm__("" : "+r"(p0), "+r"(p1), "+r"(p2), "+r"(p3));
    const uint8_t *p=__builtin_assume_aligned(cache+3*j,4);
    int32_t *o=out+j;
    for(unsigned k=0;k<rows;k++,p+=768,o+=256) {
      uint32_t x,y,z;
      __builtin_memcpy(&x,p,4);__builtin_memcpy(&y,p+4,4);
      __builtin_memcpy(&z,p+8,4);
#define APPLY(K,A,B,P) do {int32_t v=lc_matrix_mont_pre((A),(B),(P)); \
  o[(K)]=add?o[(K)]+v:v;} while(0)
      APPLY(0,x&0xffffffu,b0,p0);
      APPLY(1,((x>>24)|(y<<8))&0xffffffu,b1,p1);
      APPLY(2,((y>>16)|(z<<16))&0xffffffu,b2,p2);
      APPLY(3,z>>8,b3,p3);
#undef APPLY
    }
  }
}

#endif

#endif

MLD_INTERNAL_API
void mld_polyvec_matrix_expand_lazy(mld_polymat_lazy *mat,
                                    const uint8_t rho[MLDSA_SEEDBYTES])
{
  mld_memcpy(mat->rho, rho, MLDSA_SEEDBYTES);
#if LC_DSA_ROW_BATCH4
  mat->row_tile = NULL;
  mat->row_batch_base = MLDSA_K*MLDSA_L;
  mat->row_next_index = MLDSA_K*MLDSA_L;
#endif
#if LC_DSA_A_CACHE_POLYS > 0
  mat->cache_ready = 0;
#if LC_DSA_A_CACHE_SIGN_ONLY
  mat->cache = NULL;
#endif
#endif
}

#if !defined(MLD_CONFIG_NO_KEYPAIR_API) || !defined(MLD_CONFIG_NO_VERIFY_API)
MLD_INTERNAL_API
void mld_polyvec_matrix_pointwise_montgomery_row_lazy(mld_poly *t_row,
                                                      mld_polymat_lazy *mat,
                                                      const mld_polyvecl *v,
                                                      unsigned int i)
{
#if LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  if (mat->row_tile != NULL) {
    MLD_ALIGN uint8_t seeds[4][MLD_ALIGN_UP(MLDSA_SEEDBYTES+2)];
    mld_poly *lanes[4]={&mat->cur,&mat->row_tile[0],&mat->row_tile[1],&mat->row_tile[2]};
    for(unsigned j=0;j<4;j++) mld_memcpy(seeds[j],mat->rho,MLDSA_SEEDBYTES);
    for(unsigned l=0;l<MLDSA_L;l++) {
      const unsigned index=i*MLDSA_L+l, base=index&~3u;
      if(mat->row_batch_base!=base || mat->row_next_index!=index) {
        for(unsigned j=0;j<4;j++) {
          const unsigned selected=base+j<MLDSA_K*MLDSA_L ? base+j : MLDSA_K*MLDSA_L-1;
          seeds[j][MLDSA_SEEDBYTES]=(uint8_t)(selected%MLDSA_L);
          seeds[j][MLDSA_SEEDBYTES+1]=(uint8_t)(selected/MLDSA_L);
        }
        mld_poly_uniform_4x(lanes[0],lanes[1],lanes[2],lanes[3],seeds);
        for(unsigned j=0;j<4;j++) mld_poly_permute_bitrev_to_custom_optional(lanes[j]);
        mat->row_batch_base=base;
      }
      mld_poly *entry=lanes[index&3u];
      mat->row_next_index=index+1;
      mld_poly_pointwise_montgomery(entry,&v->vec[l]);
      if(l==0) mld_memcpy(t_row,entry,sizeof(*t_row));
      else mld_poly_add(t_row,entry);
    }
    /* Lane zero precedes every retained tail. At a row boundary cur is dead;
     * key generation and verification may borrow it before the following row.
     * The unconsumed lanes 1..3 remain in row_tile across that boundary. */
    mld_poly_reduce(t_row);
    mld_zeroize(seeds,sizeof(seeds));
    return;
  }
#endif
  unsigned int l;
  MLD_ALIGN uint8_t seed_ext[MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)];
  mld_memcpy(seed_ext, mat->rho, MLDSA_SEEDBYTES);

#if LC_DSA_DIRECT_MATRIX
  for(l=0;l<MLDSA_L;l++)
    lc_matrix_sample_acc(t_row,&v->vec[l],seed_ext,(uint8_t)l,(uint8_t)i,NULL,l!=0);
#else
  mld_polymat_expand_entry(t_row, seed_ext, 0, (uint8_t)i);
  mld_poly_pointwise_montgomery(t_row, &v->vec[0]);

  for (l = 1; l < MLDSA_L; l++)
  __loop__(
    assigns(l, object_whole(seed_ext),
            memory_slice(t_row, sizeof(mld_poly)),
            memory_slice(mat, sizeof(mld_polymat_lazy)))
    invariant(l >= 1 && l <= MLDSA_L)
    invariant(array_abs_bound(t_row->coeffs, 0, MLDSA_N, l * MLDSA_Q))
    decreases(MLDSA_L - l)
  )
  {
    mld_polymat_expand_entry(&mat->cur, seed_ext, (uint8_t)l, (uint8_t)i);
    mld_poly_pointwise_montgomery(&mat->cur, &v->vec[l]);
    mld_poly_add(t_row, &mat->cur);
  }
#endif
  mld_poly_reduce(t_row);

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(seed_ext, sizeof(seed_ext));
}
#endif /* !MLD_CONFIG_NO_KEYPAIR_API || !MLD_CONFIG_NO_VERIFY_API */

#if !defined(MLD_CONFIG_NO_SIGN_API)
#ifndef LC_DSA_CACHE_FUSED
#define LC_DSA_CACHE_FUSED 0
#endif
#if LC_DSA_CACHE_FUSED && LC_DSA_A_CACHE_BITS == 24
#include "cache24_pointwise.h"
#endif
#if LC_DSA_A_CACHE_POLYS > 0
static MLD_INLINE void lc_polymat_cache_store(mld_polymat_lazy *mat,
                                             unsigned index,const mld_poly *p) {
#if LC_DSA_A_CACHE_BITS == 24
  uint8_t *out=mat->cache[index];
  for(unsigned j=0;j<MLDSA_N;j++) {
    uint32_t u=(uint32_t)p->coeffs[j];
    out[3*j]=(uint8_t)u;out[3*j+1]=(uint8_t)(u>>8);out[3*j+2]=(uint8_t)(u>>16);
  }
#else
  mld_memcpy(mat->cache[index],p,sizeof(*p));
#endif
}
#if LC_DSA_A_CACHE_BATCH4
MLD_INTERNAL_API void mld_polymat_cache_prefill(mld_polymat_lazy *mat,
                                               mld_poly scratch[3]) {
  MLD_ALIGN uint8_t seeds[4][MLD_ALIGN_UP(MLDSA_SEEDBYTES+2)];
  unsigned i=0;
  for(unsigned j=0;j<4;j++)mld_memcpy(seeds[j],mat->rho,MLDSA_SEEDBYTES);
#if !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  for(;i+4<=LC_DSA_A_CACHE_COUNT;i+=4) {
    mld_poly *tile[4]={&scratch[0],&scratch[1],&scratch[2],&mat->cur};
    for(unsigned j=0;j<4;j++) {
      seeds[j][MLDSA_SEEDBYTES]=(uint8_t)((i+j)/MLDSA_K);
      seeds[j][MLDSA_SEEDBYTES+1]=(uint8_t)((i+j)%MLDSA_K);
    }
    mld_poly_uniform_4x(tile[0],tile[1],tile[2],tile[3],seeds);
    for(unsigned j=0;j<4;j++) {
      mld_poly_permute_bitrev_to_custom_optional(tile[j]);
      lc_polymat_cache_store(mat,i+j,tile[j]);
    }
  }
#else
  (void)scratch;
#endif
  for(;i<LC_DSA_A_CACHE_COUNT;i++) {
    mld_polymat_expand_entry(&mat->cur,seeds[0],(uint8_t)(i/MLDSA_K),(uint8_t)(i%MLDSA_K));
    lc_polymat_cache_store(mat,i,&mat->cur);
  }
  mld_zeroize(seeds,sizeof(seeds));
  mat->cache_ready=1;
}
#endif
/* The cache contains public A, with a fixed prefix independent of the secret
 * vectors and all rejection outcomes. Every selected entry is filled on the
 * first complete product, before cache_ready becomes true. No state survives
 * the API call: the owning mat or sign-only cache allocation is zeroized
 * before its corresponding arena release. */
static void lc_polymat_sign_entry(mld_poly *p,mld_polymat_lazy *mat,
    uint8_t *seed_ext,unsigned l,unsigned k) {
  const unsigned index=l*MLDSA_K+k;
#if LC_DSA_A_CACHE_SIGN_ONLY
  if(mat->cache==NULL) {
    mld_polymat_expand_entry(p,seed_ext,(uint8_t)l,(uint8_t)k);
    return;
  }
#endif
  if(index<LC_DSA_A_CACHE_COUNT && mat->cache_ready) {
#if LC_DSA_A_CACHE_BITS == 24
    const uint8_t *in=mat->cache[index];
    for(unsigned j=0;j<MLDSA_N;j++)
      p->coeffs[j]=(int32_t)((uint32_t)in[3*j]|((uint32_t)in[3*j+1]<<8)|((uint32_t)in[3*j+2]<<16));
#else
    mld_memcpy(p,mat->cache[index],sizeof(*p));
#endif
    return;
  }
  mld_polymat_expand_entry(p,seed_ext,(uint8_t)l,(uint8_t)k);
  if(index<LC_DSA_A_CACHE_COUNT) {
    lc_polymat_cache_store(mat,index,p);
  }
}
#define LC_SIGN_MATRIX_ENTRY(p,mat,seed,l,k) lc_polymat_sign_entry(p,mat,seed,l,k)
#else
#define LC_SIGN_MATRIX_ENTRY(p,mat,seed,l,k) mld_polymat_expand_entry(p,seed,(uint8_t)(l),(uint8_t)(k))
#endif
MLD_INTERNAL_API
void mld_polyvec_matrix_pointwise_montgomery_yvec_lazy(
    mld_polyveck *w, mld_polymat_lazy *mat, const mld_yvec_lazy *y,
    mld_yvec_scratch_lazy *scratch)
{
  unsigned int k, l;
  MLD_ALIGN uint8_t seed_ext[MLD_ALIGN_UP(MLDSA_SEEDBYTES + 2)];

  mld_memcpy(seed_ext, mat->rho, MLDSA_SEEDBYTES);

  /* Column-by-column: sample y[l], NTT, accumulate column l of A into w. */
  for (l = 0; l < MLDSA_L; l++)
  __loop__(
    assigns(k, l, object_whole(seed_ext),
            memory_slice(w, sizeof(mld_polyveck)),
            memory_slice(mat, sizeof(mld_polymat_lazy)),
            memory_slice(scratch, sizeof(mld_yvec_scratch_lazy)))
    invariant(l <= MLDSA_L)
    invariant(l == 0 ||
              forall(k0, 0, MLDSA_K,
                     array_abs_bound(w->vec[k0].coeffs, 0, MLDSA_N,
                                     (int)l * MLDSA_Q)))
    decreases(MLDSA_L - l)
  )
  {
    mld_yvec_get_poly_lazy(scratch, y, l);
    mld_poly_ntt(scratch);
#if LC_DSA_DIRECT_MATRIX && LC_DSA_CACHE_REUSE_INPUT
    /* A complete retained column permits reusing four y*qinv values across
     * independent rows. The first ExpandA pass and partial columns retain the
     * previous streaming path. No extra polynomial or cache is allocated. */
    if(mat->cache_ready && mat->cache!=NULL &&
       (l+1)*MLDSA_K<=LC_DSA_A_CACHE_COUNT) {
      lc_matrix_cached_column(w->vec[0].coeffs,scratch->coeffs,
                              mat->cache[l*MLDSA_K],l!=0,MLDSA_K);
      continue;
    }
#endif
    for (k = 0; k < MLDSA_K; k++)
    __loop__(
      assigns(k, object_whole(seed_ext),
              memory_slice(w, sizeof(mld_polyveck)),
              memory_slice(mat, sizeof(mld_polymat_lazy)))
      invariant(k <= MLDSA_K)
      invariant(l != 0 ||
                forall(k1, 0, k,
                       array_abs_bound(w->vec[k1].coeffs, 0, MLDSA_N, MLDSA_Q)))
      invariant(l == 0 ||
                forall(k2, 0, k,
                       array_abs_bound(w->vec[k2].coeffs, 0, MLDSA_N,
                                       ((int)l + 1) * MLDSA_Q)))
      invariant(l == 0 ||
                forall(k3, k, MLDSA_K,
                       array_abs_bound(w->vec[k3].coeffs, 0, MLDSA_N,
                                       (int)l * MLDSA_Q)))
      decreases(MLDSA_K - k)
    )
    {
#if LC_DSA_CACHE_FUSED && LC_DSA_A_CACHE_POLYS > 0 && LC_DSA_A_CACHE_BITS == 24
      if (mat->cache_ready && l*MLDSA_K+k < LC_DSA_A_CACHE_COUNT
#if LC_DSA_A_CACHE_SIGN_ONLY
          && mat->cache != NULL
#endif
          ) {
        int use_avx2 = 0;
#if defined(MLD_ARITH_BACKEND_X86_64_DEFAULT) && defined(__AVX2__)
        use_avx2 = mld_sys_check_capability(MLD_SYS_CAP_X86_64_AVX2);
#endif
        lc_cache24_pointwise_acc(w->vec[k].coeffs,mat->cache[l*MLDSA_K+k],
                                scratch->coeffs,l!=0,use_avx2);
        continue;
      }
#endif
#if LC_DSA_DIRECT_MATRIX
      const unsigned index=l*MLDSA_K+k;
      uint8_t *cache=(mat->cache!=NULL && index<LC_DSA_A_CACHE_COUNT)?mat->cache[index]:NULL;
#if !LC_DSA_CACHE_REUSE_INPUT || LC_DSA_A_CACHE_COUNT < MLDSA_K*MLDSA_L
      if(cache!=NULL && mat->cache_ready)
        lc_matrix_cache_acc(&w->vec[k],scratch,cache,l!=0);
      else
#endif
        lc_matrix_sample_acc(&w->vec[k],scratch,seed_ext,(uint8_t)l,(uint8_t)k,cache,l!=0);
#else
      if (l == 0)
      {
        LC_SIGN_MATRIX_ENTRY(&w->vec[k], mat, seed_ext, 0, k);
        mld_poly_pointwise_montgomery(&w->vec[k], scratch);
      }
      else
      {
        LC_SIGN_MATRIX_ENTRY(&mat->cur, mat, seed_ext, l, k);
        mld_poly_pointwise_montgomery(&mat->cur, scratch);
        mld_poly_add(&w->vec[k], &mat->cur);
      }
#endif
    }
  }

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(seed_ext, sizeof(seed_ext));
#if LC_DSA_A_CACHE_POLYS > 0
  mat->cache_ready=1;
#endif
  mld_polyveck_reduce(w);
  mld_polyveck_invntt_tomont(w);
}
#if LC_DSA_A_STREAM_BATCH4 && LC_DSA_A_CACHE_COUNT < MLDSA_K*MLDSA_L && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
MLD_INTERNAL_API void mld_polyvec_matrix_pointwise_montgomery_yvec_stream4(
    mld_polyveck *w, mld_polymat_lazy *mat, const mld_yvec_lazy *y,
    mld_yvec_scratch_lazy *y_scratch, mld_poly tile[3])
{
  MLD_ALIGN uint8_t seeds[4][MLD_ALIGN_UP(MLDSA_SEEDBYTES+2)];
  for (unsigned j=0;j<4;j++) mld_memcpy(seeds[j],mat->rho,MLDSA_SEEDBYTES);
  for (unsigned l=0;l<MLDSA_L;l++) {
    unsigned k=0;
#if LC_DSA_Y_BATCH4 && LC_DSA_A_CACHE_BATCH4 && LC_DSA_A_CACHE_COUNT >= 3*MLDSA_K
    /* The first three matrix columns are retained. During l=0..2 the three
     * streaming slots are therefore free to hold y[1..3]. At l=3 the final
     * y component is consumed before any uncached matrix group reuses them. */
    if(l==0) {
      mld_poly_uniform_gamma1_4x(y_scratch,&tile[0],&tile[1],&tile[2],
          y->rhoprime,y->kappa,(uint16_t)(y->kappa+1),
          (uint16_t)(y->kappa+2),(uint16_t)(y->kappa+3));
    } else if(l<4) {
      mld_memcpy(y_scratch,&tile[l-1],sizeof(*y_scratch));
    } else {
      mld_yvec_get_poly_lazy(y_scratch,y,l);
    }
#else
    mld_yvec_get_poly_lazy(y_scratch,y,l);
#endif
    mld_poly_ntt(y_scratch);
    for (;k+4<=MLDSA_K;k+=4) {
#if LC_DSA_CACHE_FUSED && LC_DSA_A_CACHE_BITS == 24
      if(mat->cache_ready && l*MLDSA_K+k+4<=LC_DSA_A_CACHE_COUNT) {
        int use_avx2=0;
#if defined(MLD_ARITH_BACKEND_X86_64_DEFAULT) && defined(__AVX2__)
        use_avx2=mld_sys_check_capability(MLD_SYS_CAP_X86_64_AVX2);
#endif
        for(unsigned j=0;j<4;j++)
          lc_cache24_pointwise_acc(w->vec[k+j].coeffs,mat->cache[l*MLDSA_K+k+j],
                                  y_scratch->coeffs,l!=0,use_avx2);
        continue;
      }
#endif
      mld_poly *p[4];
      for (unsigned j=0;j<4;j++)
        p[j]=l==0 ? &w->vec[k+j] : (j<3 ? &tile[j] : &mat->cur);
      const unsigned first=l*MLDSA_K+k;
      /* Group membership and cache readiness depend only on the public
       * prefix and complete products. A boundary group uses the scalar
       * path, preserving the exact retention policy for arbitrary counts. */
      if (first>=LC_DSA_A_CACHE_COUNT ||
          (!mat->cache_ready && first+4<=LC_DSA_A_CACHE_COUNT)) {
        for (unsigned j=0;j<4;j++) {
          seeds[j][MLDSA_SEEDBYTES]=(uint8_t)l;
          seeds[j][MLDSA_SEEDBYTES+1]=(uint8_t)(k+j);
        }
        mld_poly_uniform_4x(p[0],p[1],p[2],p[3],seeds);
        for (unsigned j=0;j<4;j++) {
          mld_poly_permute_bitrev_to_custom_optional(p[j]);
          if (first+j<LC_DSA_A_CACHE_COUNT)
            lc_polymat_cache_store(mat,first+j,p[j]);
        }
      } else {
        for (unsigned j=0;j<4;j++)
          lc_polymat_sign_entry(p[j],mat,seeds[j],l,k+j);
      }
      for (unsigned j=0;j<4;j++) {
        mld_poly_pointwise_montgomery(p[j],y_scratch);
        if (l!=0) mld_poly_add(&w->vec[k+j],p[j]);
      }
    }
    for (;k<MLDSA_K;k++) {
#if LC_DSA_CACHE_FUSED && LC_DSA_A_CACHE_BITS == 24
      if(mat->cache_ready && l*MLDSA_K+k<LC_DSA_A_CACHE_COUNT) {
        int use_avx2=0;
#if defined(MLD_ARITH_BACKEND_X86_64_DEFAULT) && defined(__AVX2__)
        use_avx2=mld_sys_check_capability(MLD_SYS_CAP_X86_64_AVX2);
#endif
        lc_cache24_pointwise_acc(w->vec[k].coeffs,mat->cache[l*MLDSA_K+k],
                                y_scratch->coeffs,l!=0,use_avx2);
        continue;
      }
#endif
      mld_poly *p=l==0 ? &w->vec[k] : &mat->cur;
      lc_polymat_sign_entry(p,mat,seeds[0],l,k);
      mld_poly_pointwise_montgomery(p,y_scratch);
      if (l!=0) mld_poly_add(&w->vec[k],p);
    }
  }
  mld_zeroize(seeds,sizeof(seeds));
  mat->cache_ready=1;
  mld_polyveck_reduce(w);
  mld_polyveck_invntt_tomont(w);
}
#endif
#undef LC_SIGN_MATRIX_ENTRY
#endif /* !MLD_CONFIG_NO_SIGN_API */

#endif /* MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef mld_polymat_expand_entry
