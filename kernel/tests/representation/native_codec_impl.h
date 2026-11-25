#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
void *lc_dsa_alloc(struct lc_dsa_arena *a,size_t n){(void)a;(void)n;abort();}
void lc_dsa_free(struct lc_dsa_arena *a,void *p,size_t n){(void)a;(void)p;(void)n;abort();}
int lc_dsa_system_random(uint8_t *p,size_t n){(void)p;(void)n;abort();}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"line %u: %s\n",__LINE__,#x);return 1;}}while(0)
static void encode_reference(uint8_t *b,const mld_poly *p){
  memset(b,0,LC_W0_ROW_BYTES);
  for(unsigned i=0;i<256;i++){
#if LC_DSA_W0_POLYZ20 && MLDSA_K>4
    uint32_t u=(uint32_t)((1<<19)-p->coeffs[i]);
#else
    uint32_t u=(uint32_t)p->coeffs[i]&((1u<<LC_W0_BITS)-1u);
#endif
    for(unsigned j=0;j<LC_W0_BITS;j++)b[(i*LC_W0_BITS+j)/8]|=(uint8_t)(((u>>j)&1u)<<((i*LC_W0_BITS+j)%8));
  }
}
int main(void){
  mld_poly p,q,alias;
  struct {uint8_t before[32],bytes[LC_W0_ROW_BYTES],after[32];} encoded;
  uint8_t expected[LC_W0_ROW_BYTES];uint64_t coefficients=0,alias_rows=0;
  for(uint32_t base=0;base<(1u<<LC_W0_BITS);base+=256){
    for(unsigned j=0;j<256;j++){
      uint32_t u=base+j;
#if LC_DSA_W0_POLYZ20 && MLDSA_K>4
      p.coeffs[j]=(1<<19)-(int32_t)u;
#else
      p.coeffs[j]=(int32_t)(u&((1u<<(LC_W0_BITS-1))-1u))-(int32_t)(u&(1u<<(LC_W0_BITS-1)));
#endif
    }
    encode_reference(expected,&p);memset(&encoded,0xa5,sizeof encoded);
    lc_pack_w0_row(encoded.bytes,&p);CHECK(!memcmp(encoded.bytes,expected,sizeof expected));
    lc_unpack_w0_row(&q,encoded.bytes);CHECK(!memcmp(&p,&q,sizeof p));
    for(unsigned j=0;j<32;j++)CHECK(encoded.before[j]==0xa5&&encoded.after[j]==0xa5);
#if !(LC_DSA_W0_POLYZ20 && MLDSA_K>4)
    alias=p;lc_pack_w0_row((uint8_t*)&alias,&alias);CHECK(!memcmp(&alias,expected,sizeof expected));alias_rows++;
#endif
    coefficients+=256;
  }
  /* Every position receives both endpoints, zero and adjacent values. */
  for(unsigned pos=0;pos<256;pos++)for(unsigned end=0;end<6;end++){
    memset(&p,0,sizeof p);
#if LC_DSA_W0_POLYZ20 && MLDSA_K>4
    const int32_t values[6]={-524287,-524286,-1,0,524287,524288};
#else
    const int32_t values[6]={-(1<<(LC_W0_BITS-1)),-(1<<(LC_W0_BITS-1))+1,-1,0,(1<<(LC_W0_BITS-1))-2,(1<<(LC_W0_BITS-1))-1};
#endif
    p.coeffs[pos]=values[end];encode_reference(expected,&p);
    lc_pack_w0_row(encoded.bytes,&p);CHECK(!memcmp(encoded.bytes,expected,sizeof expected));
    lc_unpack_w0_row(&q,encoded.bytes);CHECK(!memcmp(&p,&q,sizeof p));
  }
  printf("{\"status\":\"PASS\",\"parameter\":%d,\"bits\":%d,\"biased_polyz20\":%d,\"domain_coefficients\":%"PRIu64",\"endpoint_rows\":1536,\"alias_rows\":%"PRIu64"}\n",MLD_CONFIG_PARAMETER_SET,LC_W0_BITS,(LC_DSA_W0_POLYZ20&&MLDSA_K>4),coefficients,alias_rows);
  return 0;
}
