/* Included after the exact real SCU prefix, before macro cleanup.
 * Only helper paths are exercised; unused allocating API paths abort. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
void *lc_dsa_alloc(struct lc_dsa_arena*a,size_t n){(void)a;(void)n;abort();}
void lc_dsa_free(struct lc_dsa_arena*a,void*p,size_t n){(void)a;(void)p;(void)n;abort();}
int lc_dsa_system_random(uint8_t*p,size_t n){(void)p;(void)n;abort();}
#define RAW_ENTRY MLD_ADD_PARAM_SET(mld_polymat_expand_entry)
#define CHECK(x) do{if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;}}while(0)
static uint32_t rng=0xa1270924u;
static uint8_t staged_byte(void){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return(uint8_t)rng;}
static int all(const uint8_t*p,size_t n,uint8_t v){while(n--)if(*p++!=v)return 0;return 1;}
int main(void){
 static MLD_ALIGN struct{uint8_t before[32];mld_polymat_lazy mat;uint8_t after[32];} g;
 static MLD_ALIGN struct{uint8_t before[32];mld_poly p[3];uint8_t after[32];} scratch;
 static MLD_ALIGN uint8_t storage[56*256*4+64];
 MLD_ALIGN mld_poly ref,got;MLD_ALIGN uint8_t seed[MLD_ALIGN_UP(34)],refseed[MLD_ALIGN_UP(34)],rho[32];
 const size_t payload=LC_DSA_A_CACHE_COUNT*256*(LC_DSA_A_CACHE_BITS/8);
 uint64_t compared=0,packed=0;memset(&g,0xa5,sizeof g);memset(&scratch,0xa5,sizeof scratch);
 for(unsigned trial=0;trial<32;trial++){
  for(unsigned j=0;j<32;j++)rho[j]=staged_byte();
  memset(storage,0xa5,sizeof storage);memcpy(seed,rho,32);memcpy(refseed,rho,32);
  mld_polyvec_matrix_expand_lazy(&g.mat,rho);
#if LC_DSA_A_CACHE_POLYS > 0
  CHECK(g.mat.cache==NULL&&!g.mat.cache_ready);
  /* Unbound keygen/verify-style lazy object must fall back without access. */
  lc_polymat_sign_entry(&got,&g.mat,seed,0,0);RAW_ENTRY(&ref,refseed,0,0);CHECK(!memcmp(&got,&ref,sizeof ref));compared+=256;
  CHECK(all(storage,sizeof storage,0xa5));
  g.mat.cache=(uint8_t (*)[256*(LC_DSA_A_CACHE_BITS/8)])(storage+32);
  /* Scalar fill and hit path of SIGN_ONLY with no prefill still works. */
  for(unsigned l=0;l<MLDSA_L;l++)for(unsigned k=0;k<MLDSA_K;k++){
   lc_polymat_sign_entry(&got,&g.mat,seed,l,k);RAW_ENTRY(&ref,refseed,(uint8_t)l,(uint8_t)k);
   CHECK(!memcmp(&got,&ref,sizeof ref));compared+=256;
  }
  g.mat.cache_ready=1;
  for(unsigned l=0;l<MLDSA_L;l++)for(unsigned k=0;k<MLDSA_K;k++){
   memset(&g.mat.cur,0xcc,sizeof g.mat.cur);lc_polymat_sign_entry(&g.mat.cur,&g.mat,seed,l,k);
   RAW_ENTRY(&ref,refseed,(uint8_t)l,(uint8_t)k);CHECK(!memcmp(&g.mat.cur,&ref,sizeof ref));compared+=256;
  }
  /* Change rho and reinitialize: old ready and pointer must be discarded. */
  rho[0]^=1;memcpy(seed,rho,32);memcpy(refseed,rho,32);mld_polyvec_matrix_expand_lazy(&g.mat,rho);
  CHECK(g.mat.cache==NULL&&!g.mat.cache_ready);g.mat.cache=(uint8_t (*)[256*(LC_DSA_A_CACHE_BITS/8)])(storage+32);
  memset(storage,0xa5,sizeof storage);
  mld_polymat_cache_prefill(&g.mat,scratch.p);CHECK(g.mat.cache_ready==1);
  for(unsigned index=0;index<LC_DSA_A_CACHE_COUNT;index++){
   RAW_ENTRY(&ref,refseed,(uint8_t)(index/MLDSA_K),(uint8_t)(index%MLDSA_K));
   for(unsigned j=0;j<256;j++){
    CHECK(ref.coeffs[j]>=0&&ref.coeffs[j]<MLDSA_Q);
    for(unsigned b=0;b<LC_DSA_A_CACHE_BITS/8;b++){
     CHECK(g.mat.cache[index][j*(LC_DSA_A_CACHE_BITS/8)+b]==(uint8_t)((uint32_t)ref.coeffs[j]>>(8*b)));packed++;
    }
   }
  }
  for(unsigned l=0;l<MLDSA_L;l++)for(unsigned k=0;k<MLDSA_K;k++){
   memset(&g.mat.cur,0xcc,sizeof g.mat.cur);lc_polymat_sign_entry(&g.mat.cur,&g.mat,seed,l,k);
   RAW_ENTRY(&ref,refseed,(uint8_t)l,(uint8_t)k);CHECK(!memcmp(&g.mat.cur,&ref,sizeof ref));compared+=256;
  }
#else
  for(unsigned l=0;l<MLDSA_L;l++)for(unsigned k=0;k<MLDSA_K;k++){
   RAW_ENTRY(&got,seed,(uint8_t)l,(uint8_t)k);RAW_ENTRY(&ref,refseed,(uint8_t)l,(uint8_t)k);CHECK(!memcmp(&got,&ref,sizeof ref));compared+=256;
  }
#endif
  CHECK(all(g.before,32,0xa5)&&all(g.after,32,0xa5));CHECK(all(scratch.before,32,0xa5)&&all(scratch.after,32,0xa5));
  CHECK(all(storage,32,0xa5)&&all(storage+32+payload,sizeof storage-32-payload,0xa5));
 }
 printf("{\"status\":\"PASS\",\"parameter\":%d,\"requested_count\":%d,\"retained_count\":%d,\"cache_bits\":%d,\"trials\":32,\"compared_coefficients\":%" PRIu64 ",\"compared_packed_bytes\":%" PRIu64 ",\"matrix_struct_bytes\":%zu,\"matrix_alignment\":%zu,\"seed\":\"a1270924\",\"initial_blocks_test_override\":%d,\"forced_tail_is_not_release_binary\":%s}\n",MLD_CONFIG_PARAMETER_SET,LC_DSA_A_CACHE_POLYS,LC_DSA_A_CACHE_COUNT,LC_DSA_A_CACHE_BITS,compared,packed,sizeof(mld_polymat_lazy),(size_t)_Alignof(mld_polymat_lazy),TEST_INITIAL_BLOCKS,TEST_INITIAL_BLOCKS==1?"true":"false");
 return 0;
}
