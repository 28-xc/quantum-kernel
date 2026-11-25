/* SPDX-License-Identifier: Apache-2.0
 * Finite allocator-failure and erasure checks against actual algorithm objects.
 * Validation shims replace allocator entry points, not cryptographic functions.
 * Every observed allocation ordinal is failed once, followed by recovery.
 */
#include "latticecore.h"
#include "lc_arena.h"
#include "lc_dsa_arena.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define MAX_ALLOCS 4096
typedef struct { void *p; size_t n; int family; } allocation;
static allocation live[MAX_ALLOCS];
static size_t sizes[MAX_ALLOCS];
static unsigned monitoring, ordinal, fail_at, failure_reached, depth, bad, cleared, positive_control;
static int parameter, operation;
static uint64_t entropy_state;
static _Alignas(32) uint8_t workspace_region[64+262144+64];
static uint8_t *const workspace=workspace_region+64;
static uint8_t pk[2592],sk[4896],object[4627],secret[32],recovered[32];
static uint8_t initial_pk[2592],initial_sk[4896],initial_object[4627],initial_secret[32];
static uint8_t expected0[4896],expected1[4896];
static lc_context context;
static lc_sizes dimensions;

#ifndef LC_OWNER_PLAIN_CAPTURE
void *__real_lc_arena_alloc(lc_arena *,size_t);
void __real_lc_arena_free(lc_arena *,void *,size_t);
void *__real_lc_dsa_alloc(struct lc_dsa_arena *,size_t);
void __real_lc_dsa_free(struct lc_dsa_arena *,void *,size_t);
#endif

static int all_zero(const void *ptr,size_t n) {
  const uint8_t *p=ptr;for(size_t i=0;i<n;i++)if(p[i])return 0;return 1;
}
static int inject(size_t n) {
  if(!monitoring)return 0;
  ordinal++;
  if(ordinal>=MAX_ALLOCS){bad=1;return 1;}
  sizes[ordinal]=n;
  if(ordinal==fail_at){failure_reached=1;return 1;}
  return 0;
}
static void allocated(void *p,size_t n,int family) {
  if(!monitoring||!p)return;
  if(depth>=MAX_ALLOCS){bad=1;return;}
  live[depth++]=(allocation){p,n,family};
  /* Raw arena allocation has no zero-initialization contract. Poisoning each
   * actual object tests initialization and subsequent erasure of all bytes. */
  memset(p,0x3d,n);
}
static void released(void *p,size_t n,int family) {
  if(!monitoring||!p)return;
  if(!depth||live[depth-1].p!=p||live[depth-1].n!=n||live[depth-1].family!=family) {
    fprintf(stderr,"owner mismatch p=%d op=%d at=%u bytes=%zu\n",parameter,operation,ordinal,n);
    bad=1;return;
  }
  if(!all_zero(p,n)){if(!positive_control)fprintf(stderr,"nonzero object before release p=%d op=%d bytes=%zu\n",parameter,operation,n);bad=1;}
  depth--;cleared++;
}
#ifndef LC_OWNER_PLAIN_CAPTURE
void *__wrap_lc_arena_alloc(lc_arena *a,size_t n) {
  if(inject(n)){if(a)a->failed_size=n;return NULL;}
  void *p=__real_lc_arena_alloc(a,n);allocated(p,n,0);return p;
}
void __wrap_lc_arena_free(lc_arena *a,void *p,size_t n) {
  released(p,n,0);__real_lc_arena_free(a,p,n);
}
void *__wrap_lc_dsa_alloc(struct lc_dsa_arena *a,size_t n) {
  if(inject(n)){if(a){a->allocations++;a->failures++;}return NULL;}
  void *p=__real_lc_dsa_alloc(a,n);allocated(p,n,1);return p;
}
void __wrap_lc_dsa_free(struct lc_dsa_arena *a,void *p,size_t n) {
  released(p,n,1);__real_lc_dsa_free(a,p,n);
}
#endif
static int rng(void *unused,uint8_t *out,size_t n) {
  (void)unused;
  for(size_t i=0;i<n;i++){entropy_state^=entropy_state<<13;entropy_state^=entropy_state>>7;
    entropy_state^=entropy_state<<17;out[i]=(uint8_t)entropy_state;}
  return 0;
}
static int invoke(void) {
  entropy_state=UINT64_C(0x412710082026abcd)+(unsigned)parameter*31+(unsigned)operation;
  if(operation==0)return lc_keypair(&context,parameter,pk,dimensions.public_key,sk,dimensions.secret_key);
  if(dimensions.ciphertext) {
    if(operation==1)return lc_encaps(&context,parameter,object,dimensions.ciphertext,secret,32,pk,dimensions.public_key);
    return lc_decaps(&context,parameter,recovered,32,object,dimensions.ciphertext,sk,dimensions.secret_key);
  }
  static const uint8_t message[]={0,1,0xff,0x27,0x11,0},domain[]={0x52,0x31,0x31};
  if(operation==1)return lc_sign(&context,parameter,object,dimensions.signature,message,sizeof(message),domain,sizeof(domain),sk,dimensions.secret_key);
  return lc_verify(&context,parameter,object,dimensions.signature,message,sizeof(message),domain,sizeof(domain),pk,dimensions.public_key);
}
static void restore(void) {
  memcpy(pk,initial_pk,sizeof(pk));memcpy(sk,initial_sk,sizeof(sk));
  memcpy(object,initial_object,sizeof(object));memcpy(secret,initial_secret,sizeof(secret));
  memset(recovered,0xa5,sizeof(recovered));
  if(operation==0){memset(pk,0xa5,dimensions.public_key);memset(sk,0xa5,dimensions.secret_key);}
  if(operation==1){memset(object,0xa5,dimensions.ciphertext?dimensions.ciphertext:dimensions.signature);
    if(dimensions.ciphertext)memset(secret,0xa5,32);}
  memset(workspace_region,0x69,64);memset(workspace,0,262144);
  memset(workspace+262144,0x96,64);
}
static int guards(void) {
  for(unsigned i=0;i<64;i++)if(workspace_region[i]!=0x69||workspace[262144+i]!=0x96)return 0;
  return context.arena_high_water<=262144;
}
static int check_outputs(int failed,int save) {
  uint8_t *out0=NULL,*out1=NULL;size_t n0=0,n1=0;
  if(operation==0){out0=pk;n0=dimensions.public_key;out1=sk;n1=dimensions.secret_key;}
  else if(operation==1){out0=object;n0=dimensions.ciphertext?dimensions.ciphertext:dimensions.signature;
    if(dimensions.ciphertext){out1=secret;n1=32;}}
  else if(dimensions.ciphertext){out0=recovered;n0=32;}
  if(failed)return (!n0||all_zero(out0,n0))&&(!n1||all_zero(out1,n1));
  if(save){if(n0)memcpy(expected0,out0,n0);if(n1)memcpy(expected1,out1,n1);return 1;}
  return (!n0||memcmp(out0,expected0,n0)==0)&&(!n1||memcmp(out1,expected1,n1)==0);
}
static void print_outputs(void) {
  size_t n0=0,n1=0;
  if(operation==0){n0=dimensions.public_key;n1=dimensions.secret_key;}
  else if(operation==1){n0=dimensions.ciphertext?dimensions.ciphertext:dimensions.signature;if(dimensions.ciphertext)n1=32;}
  else if(dimensions.ciphertext)n0=32;
  printf(",\"output0\":\"");for(size_t i=0;i<n0;i++)printf("%02x",expected0[i]);
  printf("\",\"output1\":\"");for(size_t i=0;i<n1;i++)printf("%02x",expected1[i]);printf("\"");
}
static void start(unsigned fail) {
  restore();ordinal=depth=bad=cleared=failure_reached=0;fail_at=fail;monitoring=1;
}
#define REQUIRE(x) do {if(!(x)){fprintf(stderr,"FAIL parameter=%d operation=%d fail_at=%u ordinal=%u line=%u\n",parameter,operation,fail_at,ordinal,(unsigned)__LINE__);return 1;}} while(0)
int main(void) {
  const int levels[]={512,768,1024,44,65,87};unsigned cases=0,free_checks=0;
  uint8_t marker[8]={1};
  monitoring=positive_control=1;depth=1;live[0]=(allocation){marker,sizeof(marker),0};bad=0;
  released(marker,sizeof(marker),0);REQUIRE(bad==1&&depth==0);
  memset(marker,0,sizeof(marker));depth=1;live[0]=(allocation){marker,sizeof(marker),0};bad=0;
  released(marker,sizeof(marker),0);REQUIRE(bad==0&&depth==0);monitoring=positive_control=0;
  for(unsigned li=0;li<6;li++) {
    parameter=levels[li];monitoring=0;
    REQUIRE(lc_get_sizes(parameter,&dimensions)==0);
    REQUIRE(lc_context_init(&context,workspace,262144,rng,NULL)==0);
    for(operation=0;operation<3;operation++)REQUIRE(invoke()==0);
    if(dimensions.ciphertext)REQUIRE(memcmp(secret,recovered,32)==0);
    memcpy(initial_pk,pk,sizeof(pk));memcpy(initial_sk,sk,sizeof(sk));
    memcpy(initial_object,object,sizeof(object));memcpy(initial_secret,secret,sizeof(secret));
    for(operation=0;operation<3;operation++) {
      start(0);int rc=invoke();monitoring=0;
#ifdef LC_OWNER_PLAIN_CAPTURE
      REQUIRE(rc==0&&guards()&&check_outputs(0,1));
      printf("{\"parameter\":%d,\"operation\":%d,\"status\":\"PASS\"",parameter,operation);
      print_outputs();puts("}");
#else
      REQUIRE(rc==0&&!bad&&depth==0&&ordinal>0&&guards());REQUIRE(check_outputs(0,1));
      unsigned baseline_count=ordinal;size_t baseline_sizes[MAX_ALLOCS];
      memcpy(baseline_sizes,sizes,sizeof(sizes));free_checks+=cleared;
      for(unsigned at=1;at<=baseline_count;at++) {
        start(at);rc=invoke();monitoring=0;
        REQUIRE(failure_reached&&rc==LC_E_WORKSPACE&&context.allocation_failures>0);
        REQUIRE(!bad&&depth==0&&guards()&&check_outputs(1,0));free_checks+=cleared;cases++;
        start(0);rc=invoke();monitoring=0;
        REQUIRE(rc==0&&!bad&&depth==0&&guards()&&check_outputs(0,0));free_checks+=cleared;
      }
      printf("{\"parameter\":%d,\"operation\":%d,\"status\":\"PASS\",\"failed_ordinals\":%u,\"recovery_calls\":%u,\"allocation_sizes\":[",parameter,operation,baseline_count,baseline_count);
      for(unsigned at=1;at<=baseline_count;at++)printf("%s%zu",at>1?",":"",baseline_sizes[at]);
      printf("]");print_outputs();puts("}");
#endif
    }
  }
#ifndef LC_OWNER_PLAIN_CAPTURE
  printf("{\"status\":\"PASS\",\"failed_allocations\":%u,\"erasure_before_free_checks\":%u,\"parameter_operation_cells\":18,\"detector_positive_control\":true}\n",cases,free_checks);
#endif
  return 0;
}
