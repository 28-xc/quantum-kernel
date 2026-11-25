/* Explicit public-state API. Original stateless operations remain available.
 * The cache contains only exact public A; all working owners end each call. */
#if LC_DSA_PUBLIC_A_SESSION
MLD_EXTERNAL_API size_t MLD_NAMESPACE_KL(a_cache_size)(void) {
  return LC_DSA_A_CACHE_COUNT*MLDSA_N*(LC_DSA_A_CACHE_BITS/8);
}
/* Versioned column-major, natural-order representation: separate low16/high8
 * planes for 24 bits, contiguous little-endian words for 32 bits. */
MLD_EXTERNAL_API uint32_t MLD_NAMESPACE_KL(a_format_tag)(void) {
  return UINT32_C(0x50410000)|((uint32_t)LC_DSA_A_CACHE_BITS<<8)|LC_DSA_A_CACHE_COUNT;
}
MLD_EXTERNAL_API size_t MLD_NAMESPACE_KL(a_scratch_size)(int op) {
  if(op==0)return MLD_ALIGN_UP(sizeof(mld_polymat))+31;
  if(op==2)return (MLDSA_L+3)*sizeof(mld_poly)+MLD_ALIGN_UP(sizeof(mld_shake256ctx))+MLD_ALIGN_UP(MLDSA_CTILDEBYTES)+31;
  return 0;
}
MLD_EXTERNAL_API int MLD_NAMESPACE_KL(a_prepare)(uint8_t *cache,const uint8_t rho[32],MLD_CONFIG_CONTEXT_PARAMETER_TYPE context) {
  MLD_ALLOC(mat,mld_polymat,1,context);
  if(mat==NULL)return MLD_ERR_OUT_OF_MEMORY;
  mld_polyvec_matrix_expand(mat,rho);
  mat->cache=(uint8_t (*)[MLDSA_N*(LC_DSA_A_CACHE_BITS/8)])cache;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  lc_arm_speed32_fill(mat);
#else
  lc_fill_full_cache(mat);
#endif
  MLD_FREE(mat,mld_polymat,1,context);
  return 0;
}
/* Matrix storage uses natural order. Convert once per loaded polynomial to
 * native NTT order; the x86 8x8 transpose is its own inverse. */
static void MLD_ADD_PARAM_SET(lc_session_load_a)(mld_poly *out,const uint8_t *cache,unsigned k,unsigned l) {
  const uint8_t *a=cache+(l*MLDSA_K+k)*MLDSA_N*(LC_DSA_A_CACHE_BITS/8);
#if LC_DSA_A_CACHE_BITS == 32
  mld_memcpy(out->coeffs,a,sizeof(out->coeffs));
#elif LC_DSA_A_PLANES24
#if defined(__AVX2__)
  for(unsigned i=0;i<256;i+=8)_mm256_storeu_si256((__m256i *)(void *)(out->coeffs+i),lc_a_planes_load(a,i));
#elif defined(__aarch64__)
  for(unsigned i=0;i<256;i+=8) {
    uint32x4_t x,y;lc_a_planes_load_neon(a,i,&x,&y);
    vst1q_u32((uint32_t *)(void *)(out->coeffs+i),x);
    vst1q_u32((uint32_t *)(void *)(out->coeffs+i+4),y);
  }
#else
#error "No public-A split-plane decoder for this platform"
#endif
#else
#error "Unsupported prepared public-A representation"
#endif
  lc_stream_transform_order(out);
}
/* Complete ordinary verification, with mu supplied by the segmented public
 * wrapper. All norm, hint encoding and challenge checks remain mandatory. */
MLD_EXTERNAL_API int MLD_NAMESPACE_KL(a_verify)(const uint8_t *cache,const uint8_t *sig,
 const uint8_t mu[64],const uint8_t *pk,MLD_CONFIG_CONTEXT_PARAMETER_TYPE context) {
  int ret=MLD_ERR_OUT_OF_MEMORY,live=0,cmp;
  MLD_ALLOC(z,mld_polyvecl,1,context);
  MLD_ALLOC(cp,mld_poly,1,context);
  MLD_ALLOC(w,mld_poly,1,context);
  MLD_ALLOC(tmp,mld_poly,1,context);
  MLD_ALLOC(hash,mld_shake256ctx,1,context);
  MLD_ALLOC(c2,uint8_t,MLDSA_CTILDEBYTES,context);
  if(!z||!cp||!w||!tmp||!hash||!c2)goto cleanup;
  for(unsigned l=0;l<MLDSA_L;l++) {
    mld_polyz_unpack(&z->vec[l],sig+MLDSA_SIG_Z_OFFSET+l*MLDSA_POLYZ_PACKEDBYTES);
    if(mld_poly_chknorm(&z->vec[l],MLDSA_GAMMA1-MLDSA_BETA)) {ret=MLD_ERR_INVALID_SIGNATURE;goto cleanup;}
    mld_poly_ntt(&z->vec[l]);
  }
  mld_poly_challenge(cp,sig);mld_poly_ntt(cp);
  mld_shake256_init(hash);live=1;mld_shake256_absorb(hash,mu,64);
  for(unsigned k=0;k<MLDSA_K;k++) {
    for(unsigned l=0;l<MLDSA_L;l++) {
      MLD_ADD_PARAM_SET(lc_session_load_a)(tmp,cache,k,l);
      mld_poly_pointwise_montgomery(tmp,&z->vec[l]);
      if(l==0)mld_memcpy(w,tmp,sizeof(*w));else mld_poly_add(w,tmp);
    }
    mld_poly_reduce(w);
    mld_unpack_pk_t1(tmp,pk,k);mld_poly_shiftl(tmp);mld_poly_ntt(tmp);
    mld_poly_pointwise_montgomery(tmp,cp);mld_poly_sub(w,tmp);mld_poly_reduce(w);
    mld_poly_invntt_tomont(w);mld_poly_caddq(w);
    if(mld_sig_unpack_hints(tmp,sig,k)) {ret=MLD_ERR_INVALID_SIGNATURE;goto cleanup;}
    mld_poly_use_hint(w,tmp);mld_polyw1_pack((uint8_t *)tmp,w);
    mld_shake256_absorb(hash,(const uint8_t *)tmp,MLDSA_POLYW1_PACKEDBYTES);
  }
  mld_shake256_finalize(hash);mld_shake256_squeeze(c2,MLDSA_CTILDEBYTES,hash);
  cmp=mld_ct_memcmp(sig,c2,MLDSA_CTILDEBYTES);MLD_CT_TESTING_DECLASSIFY(&cmp,sizeof(cmp));
  ret=cmp==0?0:MLD_ERR_INVALID_SIGNATURE;
cleanup:
  if(live)mld_shake256_release(hash);
  MLD_FREE(c2,uint8_t,MLDSA_CTILDEBYTES,context);
  MLD_FREE(hash,mld_shake256ctx,1,context);
  MLD_FREE(tmp,mld_poly,1,context);MLD_FREE(w,mld_poly,1,context);
  MLD_FREE(cp,mld_poly,1,context);MLD_FREE(z,mld_polyvecl,1,context);
  return ret;
}
#endif
