/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
/* Finite public-API secret-dependence fixture. Its deterministic entropy is
 * marked at the callback boundary: the public adapter calls upstream internal
 * entry points, so their randomized-wrapper annotations are bypassed. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "latticecore.h"
static _Alignas(32) uint8_t workspace[262144];
static uint8_t pk[2592],sk[4896],sig[4627],ct[1568],ss[32],ss2[32];
static uint8_t message[1024],domain[255];
static uint64_t state=UINT64_C(0x142782996871);
static unsigned entropy_requests,secret_bytes;
static int entropy(void *u,uint8_t *out,size_t n) {
  (void)u;
  for(size_t i=0;i<n;i++) {state^=state<<13;state^=state>>7;state^=state<<17;out[i]=(uint8_t)state;}
  entropy_requests++;secret_bytes+=(unsigned)n;
  VALGRIND_MAKE_MEM_UNDEFINED(out,n);
  return 0;
}
#define CHECK(x) do {if(!(x)) {fprintf(stderr,"FAIL line=%d parameter=%d case=%u\n",__LINE__,p,index);return 1;}}while(0)
int main(void) {
  const int parameters[]={512,768,1024,44,65,87};
  unsigned observations=0;
  memset(message,0x47,sizeof(message));memset(domain,0x28,sizeof(domain));
  for(unsigned pi=0;pi<6;pi++)for(unsigned index=0;index<16;index++) {
    int p=parameters[pi];lc_sizes sizes;lc_context context;
    CHECK(lc_get_sizes(p,&sizes)==0);
    CHECK(lc_context_init(&context,workspace,sizeof(workspace),entropy,NULL)==0);
    CHECK(lc_keypair(&context,p,pk,sizes.public_key,sk,sizes.secret_key)==0);
    /* The completed API publishes pk. Keep every secret-key byte tainted;
     * the library itself declassifies its public embedded components. */
    VALGRIND_MAKE_MEM_DEFINED(pk,sizes.public_key);
    VALGRIND_MAKE_MEM_UNDEFINED(sk,sizes.secret_key);
    if(p>100) {
      CHECK(lc_encaps(&context,p,ct,sizes.ciphertext,ss,32,pk,sizes.public_key)==0);
      VALGRIND_MAKE_MEM_DEFINED(ct,sizes.ciphertext);
      CHECK(lc_decaps(&context,p,ss2,32,ct,sizes.ciphertext,sk,sizes.secret_key)==0);
      VALGRIND_MAKE_MEM_DEFINED(ss,32);VALGRIND_MAKE_MEM_DEFINED(ss2,32);
      CHECK(memcmp(ss,ss2,32)==0);
      ct[index%sizes.ciphertext]^=1;
      VALGRIND_MAKE_MEM_UNDEFINED(sk,sizes.secret_key);
      CHECK(lc_decaps(&context,p,ss2,32,ct,sizes.ciphertext,sk,sizes.secret_key)==0);
      VALGRIND_MAKE_MEM_DEFINED(ss2,32);CHECK(memcmp(ss,ss2,32)!=0);
    } else {
      size_t mlen=(index%4==0)?0:(index%4==1)?1:(index%4==2)?32:1024;
      size_t dlen=(index%4==0)?0:(index%4==1)?1:(index%4==2)?32:255;
      CHECK(lc_sign(&context,p,sig,sizes.signature,message,mlen,domain,dlen,sk,sizes.secret_key)==0);
      /* Accepted signatures are public output. Norm/challenge/bitmap
       * declassification during an attempt remains entirely in the library. */
      VALGRIND_MAKE_MEM_DEFINED(sig,sizes.signature);
      CHECK(lc_verify(&context,p,sig,sizes.signature,message,mlen,domain,dlen,pk,sizes.public_key)==0);
      sig[index%sizes.signature]^=1;
      CHECK(lc_verify(&context,p,sig,sizes.signature,message,mlen,domain,dlen,pk,sizes.public_key)==LC_E_REJECT);
    }
    observations++;
  }
  printf("{\"status\":\"PASS\",\"cases\":%u,\"entropy_requests\":%u,\"secret_entropy_bytes\":%u,\"secret_key_marked_each_case\":true}\n",observations,entropy_requests,secret_bytes);
  return 0;
}
