#include "lattice_resources.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {uint64_t x;} test_rng;
static int random_bytes(void *u,uint8_t *out,size_t n) {
  test_rng *r=u;while(n--){r->x^=r->x<<13;r->x^=r->x>>7;r->x^=r->x<<17;*out++=(uint8_t)r->x;}return 0;
}
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
static int zeros(const uint8_t *p,size_t n){while(n--)if(*p++)return 0;return 1;}
static int guards(const uint8_t *w,size_t n){for(unsigned j=1;j<=32;j++)if(w[-(int)j]!=0xa5||w[n+j-1]!=0xa5)return 0;return 1;}
int main(void) {
  const int parameters[]={512,768,1024,44,65,87};
  uint8_t *raw=malloc(131072+128),*work;
  uint8_t pk[2592],sk[4896],ct[1568],sig[4627],first[4627],ss[32],ss2[32],msg[1024],domain[255];
  test_rng rng;lc_context ctx;lc_sizes z;lc_resource_requirements r;lc_resource_plan plan;
  size_t common_min=0,common_preferred=0,total;
  CHECK(raw);work=(uint8_t *)(((uintptr_t)(raw+63))&~(uintptr_t)31);
  memset(msg,0x51,sizeof(msg));memset(domain,0xc9,sizeof(domain));
  CHECK(lc_resource_query(42,0,&r)==LC_E_ARGUMENT);
  CHECK(zeros((uint8_t *)&r,sizeof(r)));
  CHECK(lc_resource_query(87,3,&r)==LC_E_ARGUMENT);
  CHECK(zeros((uint8_t *)&r,sizeof(r)));
  CHECK(lc_resource_query(87,-1,&r)==LC_E_ARGUMENT);
  CHECK(lc_resource_query(87,1,NULL)==LC_E_ARGUMENT);
  CHECK(lc_resource_make_plan(87,1,NULL,131072,&plan)==LC_E_ARGUMENT);
  CHECK(lc_resource_make_plan(87,1,work,SIZE_MAX,&plan)==LC_E_ARGUMENT);
  CHECK(lc_resource_make_plan(87,1,work,131072,NULL)==LC_E_ARGUMENT);
  CHECK(lc_resource_algorithm_bytes(SIZE_MAX,1,0,&total)==LC_E_ARGUMENT&&total==0);
  CHECK(lc_resource_algorithm_bytes(0,SIZE_MAX,0,&total)==LC_E_ARGUMENT&&total==0);
  CHECK(lc_resource_algorithm_bytes(0,0,SIZE_MAX,&total)==LC_E_ARGUMENT&&total==0);
  CHECK(lc_resource_algorithm_bytes(0,0,0,NULL)==LC_E_ARGUMENT);
  CHECK(lc_resource_algorithm_bytes(100,200,300,&total)==0&&total==600+sizeof(lc_context));
  for(unsigned i=0;i<6;i++) {
    int p=parameters[i];CHECK(lc_get_sizes(p,&z)==0);
    rng.x=17+p;memset(work,0,131072);
    CHECK(lc_context_init(&ctx,work,131072,random_bytes,&rng)==0);
    CHECK(lc_keypair(&ctx,p,pk,z.public_key,sk,z.secret_key)==0);
    if(p>100)CHECK(lc_encaps(&ctx,p,ct,z.ciphertext,ss,32,pk,z.public_key)==0);
    else CHECK(lc_sign(&ctx,p,sig,z.signature,msg,sizeof(msg),domain,sizeof(domain),sk,z.secret_key)==0);
    for(int op=0;op<3;op++) {
      CHECK(lc_resource_query(p,op,&r)==0);
      CHECK(r.minimum_workspace_bytes>0&&r.preferred_workspace_bytes>=r.minimum_workspace_bytes);
      if(r.minimum_workspace_bytes>common_min)common_min=r.minimum_workspace_bytes;
      if(r.preferred_workspace_bytes>common_preferred)common_preferred=r.preferred_workspace_bytes;
      size_t n=r.minimum_workspace_bytes;
      memset(work-32,0xa5,n+64);memset(work,0,n);
      CHECK(lc_resource_make_plan(p,op,work,n,&plan)==0);
      CHECK(lc_context_init(&ctx,work,n,random_bytes,&rng)==0);
      if(op==0) {
        if(p<100) {
          CHECK(r.exact_workspace_bound&&!r.adaptive);
          CHECK(lc_resource_make_plan(p,op,work,n-1,&plan)==LC_E_WORKSPACE);
          CHECK(lc_context_init(&ctx,work,n-1,random_bytes,&rng)==0);
          memset(pk,0xa5,z.public_key);memset(sk,0xa5,z.secret_key);
          CHECK(lc_keypair(&ctx,p,pk,z.public_key,sk,z.secret_key)==LC_E_WORKSPACE);
          CHECK(zeros(pk,z.public_key)&&zeros(sk,z.secret_key));
          CHECK(lc_context_init(&ctx,work,n,random_bytes,&rng)==0);
        }
        CHECK(lc_keypair(&ctx,p,pk,z.public_key,sk,z.secret_key)==0);
        if(p<100)CHECK(ctx.arena_high_water==n);
      } else if(p>100&&op==1) {
        CHECK(lc_encaps(&ctx,p,ct,z.ciphertext,ss,32,pk,z.public_key)==0);
      } else if(p>100) {
        CHECK(lc_decaps(&ctx,p,ss2,32,ct,z.ciphertext,sk,z.secret_key)==0);
        CHECK(memcmp(ss,ss2,32)==0);
      } else if(op==1) {
        CHECK(lc_sign(&ctx,p,sig,z.signature,msg,sizeof(msg),domain,sizeof(domain),sk,z.secret_key)==0);
      } else CHECK(lc_verify(&ctx,p,sig,z.signature,msg,sizeof(msg),domain,sizeof(domain),pk,z.public_key)==0);
      CHECK(ctx.arena_high_water<=n&&guards(work,n)&&zeros(work,n));
      printf("{\"parameter\":%d,\"operation\":%d,\"supported_bound\":%llu,\"observed_workspace\":%llu,\"exact\":%u,\"mode\":%u}\n",p,op,(unsigned long long)n,(unsigned long long)ctx.arena_high_water,r.exact_workspace_bound,plan.mode);
    }
  }
  CHECK(lc_get_sizes(87,&z)==0);CHECK(lc_resource_query(87,1,&r)==0);
  CHECK(r.adaptive&&r.exact_workspace_bound);
  rng.x=947;CHECK(lc_context_init(&ctx,work,131072,random_bytes,&rng)==0);
  CHECK(lc_keypair(&ctx,87,pk,z.public_key,sk,z.secret_key)==0);
  /* Same key/message/context/random bytes must produce identical signatures
   * through both paths. Repeated seeds exercise candidate rejection/retry. */
  for(unsigned sample=0;sample<24;sample++) {
    for(unsigned mode=0;mode<2;mode++) {
      size_t n=mode?r.minimum_workspace_bytes:r.preferred_workspace_bytes;
      memset(work-32,0xa5,n+64);memset(work,0,n);rng.x=2229+sample;
      CHECK(lc_resource_make_plan(87,1,work,n,&plan)==0);
      CHECK(plan.cached_rows==(mode?5u:8u)&&plan.cached_polynomials==(mode?35u:56u));
      CHECK(plan.matrix_cache_bytes==(mode?26880u:43008u));
      CHECK(lc_context_init(&ctx,work,n,random_bytes,&rng)==0);
      CHECK(lc_sign(&ctx,87,sig,z.signature,msg,sizeof(msg),domain,sizeof(domain),sk,z.secret_key)==0);
      CHECK(ctx.arena_high_water==n&&zeros(work,n)&&guards(work,n));
      if(!mode)memcpy(first,sig,z.signature);else CHECK(memcmp(first,sig,z.signature)==0);
    }
  }
  /* Public address alignment is part of the same admission rule. */
  CHECK(lc_resource_make_plan(87,1,work+1,r.minimum_workspace_bytes+30,&plan)==LC_E_WORKSPACE);
  CHECK(lc_resource_make_plan(87,1,work+1,r.minimum_workspace_bytes+31,&plan)==0);
  CHECK(plan.alignment_padding==31&&plan.cached_rows==5);
  {
    size_t n=r.minimum_workspace_bytes+31;
    memset(work+1-32,0xa5,n+64);memset(work+1,0,n);
    CHECK(lc_context_init(&ctx,work+1,n,random_bytes,&rng)==0);
    CHECK(lc_sign(&ctx,87,sig,z.signature,msg,sizeof(msg),domain,sizeof(domain),sk,z.secret_key)==0);
    CHECK(ctx.arena_high_water==n&&zeros(work+1,n)&&guards(work+1,n));
  }
  CHECK(lc_resource_make_plan(87,1,work,r.preferred_workspace_bytes-1,&plan)==0);
  CHECK(plan.cached_rows==5&&plan.required_workspace_bytes==r.minimum_workspace_bytes);
  CHECK(lc_context_init(&ctx,work,r.preferred_workspace_bytes-1,random_bytes,&rng)==0);
  CHECK(lc_sign(&ctx,87,sig,z.signature,msg,sizeof(msg),domain,sizeof(domain),sk,z.secret_key)==0);
  CHECK(ctx.arena_high_water==r.minimum_workspace_bytes);
  CHECK(lc_resource_make_plan(87,1,work,r.minimum_workspace_bytes-1,&plan)==LC_E_WORKSPACE);
  memset(sig,0xa5,z.signature);rng.x=993;
  CHECK(lc_context_init(&ctx,work,r.minimum_workspace_bytes-1,random_bytes,&rng)==0);
  CHECK(lc_sign(&ctx,87,sig,z.signature,msg,sizeof(msg),domain,sizeof(domain),sk,z.secret_key)==LC_E_WORKSPACE);
  CHECK(zeros(sig,z.signature));
  CHECK(lc_context_init(&ctx,work,r.minimum_workspace_bytes,random_bytes,&rng)==0);
  CHECK(lc_sign(&ctx,87,sig,z.signature,msg,sizeof(msg),domain,sizeof(domain),sk,z.secret_key)==0);
  printf("{\"status\":\"PASS\",\"equal_signature_cases\":24,\"complete_operations\":18,\"common_supported_workspace\":%llu,\"common_preferred_workspace\":%llu,\"scope\":\"workspace_only_stack_globals_and_IO_excluded\"}\n",(unsigned long long)common_min,(unsigned long long)common_preferred);
  free(raw);return 0;
}
