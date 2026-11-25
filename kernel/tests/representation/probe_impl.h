/* Included after the actual SCU prefix, before upstream macro cleanup.
 * Actual sampler/permutation/cache/codec functions remain unchanged. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <inttypes.h>
/* This executable tests representation helpers only. Any accidental entry
   into allocating/full public APIs fails loudly instead of substituting an
   allocator or random source and pretending that path was checked. */
void *lc_dsa_alloc(struct lc_dsa_arena *a,size_t n){(void)a;(void)n;abort();}
void lc_dsa_free(struct lc_dsa_arena *a,void *p,size_t n){(void)a;(void)p;(void)n;abort();}
int lc_dsa_system_random(uint8_t *p,size_t n){(void)p;(void)n;abort();}
#define RAW_ENTRY MLD_ADD_PARAM_SET(mld_polymat_expand_entry)
#define REQUIRE(x) do {if(!(x)){fprintf(stderr,"check:%u:%s\n",__LINE__,#x);return 1;}}while(0)
static uint32_t repr_state=0x20260924u;
static uint32_t repr_random(void){repr_state^=repr_state<<13;repr_state^=repr_state>>17;repr_state^=repr_state<<5;return repr_state;}
static void reference_pack(uint8_t *b,const mld_poly *p,unsigned bits){
  memset(b,0,256*bits/8);
  for(unsigned j=0;j<256;j++)for(unsigned k=0;k<bits;k++)
    b[(j*bits+k)/8]|=(uint8_t)((((uint32_t)p->coeffs[j]>>k)&1u)<<((j*bits+k)%8));
}
static void put_cache(uint8_t *p,uint32_t x){
  for(unsigned j=0;j<LC_DSA_A_CACHE_BITS/8;j++)p[j]=(uint8_t)(x>>(8*j));
}
int main(void){
  static struct {uint8_t pre[32];mld_polymat_lazy mat;uint8_t post[32];} guarded;
  mld_poly original,got,reference,source;
  uint8_t seed[MLD_ALIGN_UP(MLDSA_SEEDBYTES+2)],reference_seed[MLD_ALIGN_UP(MLDSA_SEEDBYTES+2)],rho[32];
  uint8_t expected[768],packed[800];uint64_t actual_coefficients=0,exhausted=0,codec_values=0;
  memset(&guarded,0xa5,sizeof(guarded));
  REQUIRE(offsetof(mld_polymat_lazy,cache)>=sizeof(mld_poly)+32);
  REQUIRE(sizeof(guarded.mat.cache)==LC_DSA_A_CACHE_COUNT*256*(LC_DSA_A_CACHE_BITS/8));
  for(unsigned trial=0;trial<32;trial++){
    for(unsigned j=0;j<32;j++)rho[j]=(uint8_t)repr_random();
    mld_polyvec_matrix_expand_lazy(&guarded.mat,rho);REQUIRE(guarded.mat.cache_ready==0);
    memcpy(seed,rho,32);memcpy(reference_seed,rho,32);
    /* Real first-product column-major traversal fills every prefix entry. */
    for(unsigned l=0;l<MLDSA_L;l++)for(unsigned k=0;k<MLDSA_K;k++){
      lc_polymat_sign_entry(&got,&guarded.mat,seed,l,k);
      RAW_ENTRY(&reference,reference_seed,(uint8_t)l,(uint8_t)k);
      REQUIRE(!memcmp(&got,&reference,sizeof(got)));
      for(unsigned j=0;j<256;j++)REQUIRE(got.coeffs[j]>=0&&got.coeffs[j]<MLDSA_Q);
      actual_coefficients+=256;
    }
    guarded.mat.cache_ready=1;
    /* A previous rejection may leave a secret challenge in cur, but never
       in the adjacent public cache. Exercise output directly into cur. */
    memset(&guarded.mat.cur,0xcc,sizeof(guarded.mat.cur));
    for(unsigned l=0;l<MLDSA_L;l++)for(unsigned k=0;k<MLDSA_K;k++){
      lc_polymat_sign_entry(&guarded.mat.cur,&guarded.mat,seed,l,k);
      RAW_ENTRY(&reference,reference_seed,(uint8_t)l,(uint8_t)k);
      REQUIRE(!memcmp(&guarded.mat.cur,&reference,sizeof(reference)));actual_coefficients+=256;
    }
    /* A new API seed must invalidate all stale entries before any hit. */
    rho[0]^=1;mld_polyvec_matrix_expand_lazy(&guarded.mat,rho);REQUIRE(!guarded.mat.cache_ready);
    memcpy(seed,rho,32);memcpy(reference_seed,rho,32);
    lc_polymat_sign_entry(&got,&guarded.mat,seed,0,0);RAW_ENTRY(&reference,reference_seed,0,0);
    REQUIRE(!memcmp(&got,&reference,sizeof(got)));
  }
  /* Exhaust every legal q-domain value through the actual cache-hit reader.
     The encoding used to set test inputs is independent byte arithmetic. */
  guarded.mat.cache_ready=1;
  for(uint32_t base=0;base<MLDSA_Q;base+=256){
    for(unsigned j=0;j<256;j++)put_cache(guarded.mat.cache[0]+j*(LC_DSA_A_CACHE_BITS/8),(base+j)%MLDSA_Q);
    lc_polymat_sign_entry(&got,&guarded.mat,seed,0,0);
    for(unsigned j=0;j<256;j++){REQUIRE(got.coeffs[j]==(int32_t)((base+j)%MLDSA_Q));exhausted++;}
  }
  /* Scope positive controls: unsigned24 cannot represent -1 or 2^24. */
  unsigned negative_domain_detected=0;
#if LC_DSA_A_CACHE_BITS == 24
  put_cache(guarded.mat.cache[0],UINT32_MAX);lc_polymat_sign_entry(&got,&guarded.mat,seed,0,0);
  REQUIRE(got.coeffs[0]!=-1);negative_domain_detected++;
  put_cache(guarded.mat.cache[0],1u<<24);lc_polymat_sign_entry(&got,&guarded.mat,seed,0,0);
  REQUIRE(got.coeffs[0]!=(1<<24));negative_domain_detected++;
#endif
  /* Low-part representation uses signed 19/20/24, a different contract from A. */
  for(unsigned trial=0;trial<4096;trial++){
    for(unsigned j=0;j<256;j++){
      uint32_t mask=(1u<<LC_W0_BITS)-1u,u=repr_random()&mask;
      source.coeffs[j]=(int32_t)(u&((1u<<(LC_W0_BITS-1))-1u))-(int32_t)(u&(1u<<(LC_W0_BITS-1)));
    }
    source.coeffs[0]=-(1<<(LC_W0_BITS-1));source.coeffs[1]=(1<<(LC_W0_BITS-1))-1;
    reference_pack(expected,&source,LC_W0_BITS);memset(packed,0xa5,sizeof(packed));
    lc_pack_w0_row(packed,&source);REQUIRE(!memcmp(packed,expected,LC_W0_ROW_BYTES));
    for(unsigned j=LC_W0_ROW_BYTES;j<sizeof(packed);j++)REQUIRE(packed[j]==0xa5);
    lc_unpack_w0_row(&got,packed);REQUIRE(!memcmp(&got,&source,sizeof(got)));
    original=source;lc_pack_w0_row((uint8_t*)&original,&original);
    REQUIRE(!memcmp(&original,expected,LC_W0_ROW_BYTES));codec_values+=256;
  }
  for(unsigned j=0;j<32;j++)REQUIRE(guarded.pre[j]==0xa5&&guarded.post[j]==0xa5);
  REQUIRE(MLDSA_K*LC_W0_FLAG_STRIDE+MLDSA_POLYW1_PACKEDBYTES<=(MLDSA_K-1)*sizeof(mld_poly));
  printf("{\"status\":\"PASS\",\"parameter\":%d,\"cache_bits\":%d,\"cache_count\":%d,\"matrix_actual_coefficients\":%" PRIu64 ",\"q_domain_checks\":%" PRIu64 ",\"lowpart_coefficients\":%" PRIu64 ",\"lowpart_bits\":%d,\"matrix_struct_bytes\":%zu,\"cache_offset\":%zu,\"negative_domain_controls\":%u}\n",
    MLD_CONFIG_PARAMETER_SET,LC_DSA_A_CACHE_BITS,LC_DSA_A_CACHE_COUNT,actual_coefficients,exhausted,codec_values,LC_W0_BITS,sizeof(mld_polymat_lazy),offsetof(mld_polymat_lazy,cache),negative_domain_detected);
  return 0;
}
