/* Ordinary fixed-input API regression. Original PQClean heap behavior retained. */
#include "latticecore.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {uint64_t state;int fail;} rng;
static int random_test(void*u,uint8_t*p,size_t n){rng*r=u;size_t i;if(r->fail)return -1;for(i=0;i<n;i++){r->state^=r->state<<13;r->state^=r->state>>7;r->state^=r->state<<17;p[i]=(uint8_t)r->state;}return 0;}
static int zero(const uint8_t*p,size_t n){while(n--)if(*p++)return 0;return 1;}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"line %d parameter %d\n",__LINE__,level);return 1;}}while(0)
static int test(int level,unsigned n){
 uint8_t workspace[64],pk[2592+32],sk[4896+32],ct[1568+32],sig[4627+32],ss[64],ss2[64],m[1024],d[255];
 lc_context c;lc_sizes z;rng r={0x73518346+(unsigned)level,0};unsigned i;
 memset(workspace,0xa5,sizeof workspace);memset(pk,0xa5,sizeof pk);memset(sk,0xa5,sizeof sk);memset(ct,0xa5,sizeof ct);memset(sig,0xa5,sizeof sig);memset(ss,0xa5,sizeof ss);memset(ss2,0xa5,sizeof ss2);memset(m,0x83,sizeof m);memset(d,0x43,sizeof d);
 CHECK(lc_get_sizes(level,&z)==0);CHECK(lc_context_init(&c,workspace+16,32,random_test,&r)==0);
 for(i=0;i<n;i++){
  size_t mn=i%2?sizeof m:0,dn=i%3?sizeof d:0;CHECK(lc_keypair(&c,level,pk,z.public_key,sk,z.secret_key)==0);
  if(z.ciphertext){CHECK(lc_encaps(&c,level,ct,z.ciphertext,ss,32,pk,z.public_key)==0);CHECK(lc_decaps(&c,level,ss2,32,ct,z.ciphertext,sk,z.secret_key)==0);CHECK(!memcmp(ss,ss2,32));ct[i%z.ciphertext]^=1;CHECK(lc_decaps(&c,level,ss2,32,ct,z.ciphertext,sk,z.secret_key)==0);CHECK(memcmp(ss,ss2,32)!=0);}
  else{CHECK(lc_sign(&c,level,sig,z.signature,m,mn,d,dn,sk,z.secret_key)==0);CHECK(lc_verify(&c,level,sig,z.signature,m,mn,d,dn,pk,z.public_key)==0);sig[i%z.signature]^=1;CHECK(lc_verify(&c,level,sig,z.signature,m,mn,d,dn,pk,z.public_key)==LC_E_REJECT);}
  CHECK(c.arena_high_water==0&&c.allocations==0&&c.allocation_failures==0);
 }
 CHECK(lc_keypair(&c,level,pk,z.public_key-1,sk,z.secret_key)==LC_E_LENGTH);
 CHECK(lc_keypair(&c,level,pk,z.public_key,pk,z.secret_key)==LC_E_ALIAS);
 CHECK(lc_keypair(&c,level,NULL,z.public_key,sk,z.secret_key)==LC_E_ARGUMENT);
 r.fail=1;CHECK(lc_keypair(&c,level,pk,z.public_key,sk,z.secret_key)==LC_E_RANDOM);CHECK(zero(pk,z.public_key)&&zero(sk,z.secret_key));
 for(i=0;i<32;i++){CHECK(pk[z.public_key+i]==0xa5);CHECK(sk[z.secret_key+i]==0xa5);if(z.ciphertext){CHECK(ct[z.ciphertext+i]==0xa5);CHECK(ss[32+i]==0xa5);CHECK(ss2[32+i]==0xa5);}else CHECK(sig[z.signature+i]==0xa5);}
 for(i=0;i<sizeof workspace;i++)CHECK(workspace[i]==0xa5);
 printf("{\"parameter\":%d,\"complete_sequences\":%u,\"status\":\"PASS\",\"caller_workspace_used\":false,\"heap_failure_recovery_tested\":false}\n",level,n);return 0;
}
int main(int argc,char**argv){int levels[]={512,768,1024,44,65,87};unsigned n=argc>1?(unsigned)strtoul(argv[1],NULL,10):100;unsigned i;for(i=0;i<6;i++)if(test(levels[i],n))return 1;return 0;}
