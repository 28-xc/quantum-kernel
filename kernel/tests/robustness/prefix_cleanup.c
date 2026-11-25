/* Ordinary deterministic lifetime probe for a fixed three-poly s1 prefix.
 * Link the real static archive with --wrap=lc_dsa_alloc/lc_dsa_free.
 * No core is modified and no coverage-guided execution is involved. */
#include "latticecore.h"
#include "lc_dsa_arena.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void *__real_lc_dsa_alloc(struct lc_dsa_arena *,size_t);
void __real_lc_dsa_free(struct lc_dsa_arena *,void *,size_t);
static int monitoring,bad;
static void *prefix;
static unsigned prefix_frees,prefix_allocations;
static size_t prefix_offset;
void *__wrap_lc_dsa_alloc(struct lc_dsa_arena *a,size_t n) {
  void *p=__real_lc_dsa_alloc(a,n);
  /* Source order in 8f18d11: first 3072B signing allocation is s1_prefix;
   * the later 3072B allocation is the public matrix prefill tile. */
  if(monitoring&&n==3072&&!prefix&&p) {
    prefix=p;prefix_offset=(size_t)((uint8_t*)p-a->base);prefix_allocations++;
  }
  return p;
}
void __wrap_lc_dsa_free(struct lc_dsa_arena *a,void *p,size_t n) {
  if(monitoring&&p&&p==prefix) {
    size_t i;prefix_frees++;
    if(n!=3072)bad=1;
    /* MLD_FREE must erase before calling the allocator's free hook. */
    for(i=0;i<n;i++)if(((uint8_t*)p)[i])bad=1;
  }
  __real_lc_dsa_free(a,p,n);
}
typedef struct {uint64_t s;int fail;} entropy;
static int rng(void *v,uint8_t*out,size_t n) {
  entropy *e=v;size_t i;if(e->fail)return -1;
  for(i=0;i<n;i++){e->s^=e->s<<13;e->s^=e->s>>7;e->s^=e->s<<17;out[i]=(uint8_t)e->s;}return 0;
}
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL line %u\n",(unsigned)__LINE__);return 1;}} while(0)
int main(void) {
  const int levels[]={44,65,87};unsigned li,i;uint8_t *raw=malloc(131072+64);
  uint8_t *work=(uint8_t*)(((uintptr_t)raw+31)&~(uintptr_t)31);
  CHECK(raw);
  { struct lc_dsa_arena a;memset(&a,0,sizeof a);a.base=work;a.capacity=131072;a.used=3072;
    memset(work,1,3072);prefix=work;monitoring=1;bad=0;prefix_frees=0;
    __wrap_lc_dsa_free(&a,work,3072);monitoring=0;
    CHECK(bad&&prefix_frees==1&&a.used==0);
    puts("PREFIX_ERASURE_DETECTOR_POSITIVE_CONTROL_PASS");
  }
  for(li=0;li<3;li++) {
    lc_context c;lc_sizes z;entropy e;uint8_t pk[2][2592],sk[2][4896],sig[4627],reference[2][4627];
    const uint8_t msg[]={0x52,0x32,0,0xff},domain[]={0,1,2};unsigned checks=0;
    CHECK(lc_get_sizes(levels[li],&z)==0);
    CHECK(lc_context_init(&c,work,131072,rng,&e)==0);
    e.fail=0;
    for(i=0;i<2;i++){e.s=UINT64_C(0xa127202609250001)+100*li+i;CHECK(lc_keypair(&c,levels[li],pk[i],z.public_key,sk[i],z.secret_key)==0);}
    for(i=0;i<18;i++) {
      unsigned key=i%2;int rc;size_t j;
      memset(work,0xcc,131072);e.s=UINT64_C(0xd1b54a32d192ed03)+li;e.fail=0;
      prefix=NULL;prefix_frees=prefix_allocations=0;bad=0;monitoring=1;
      rc=lc_sign(&c,levels[li],sig,z.signature,msg,sizeof msg,domain,sizeof domain,sk[key],z.secret_key);
      monitoring=0;CHECK(rc==0);CHECK(prefix_allocations==1&&prefix_frees==1&&!bad);
      CHECK(prefix_offset+3072<=c.arena_high_water);
      for(j=0;j<3072;j++)CHECK(((uint8_t*)prefix)[j]==0);
      CHECK(lc_verify(&c,levels[li],sig,z.signature,msg,sizeof msg,domain,sizeof domain,pk[key],z.public_key)==0);
      if(i<2)memcpy(reference[key],sig,z.signature);else CHECK(memcmp(reference[key],sig,z.signature)==0);
      checks++;
    }
    printf("{\"parameter\":%d,\"status\":\"PASS\",\"signatures\":%u,\"prefix_bytes\":3072,\"erased_before_free\":true,\"alternating_keys_same_context\":true,\"prefix_offset\":%zu}\n",levels[li],checks,prefix_offset);
  }
  free(raw);return 0;
}
