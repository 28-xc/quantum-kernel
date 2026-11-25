#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "latticecore.h"
typedef struct{uint64_t state;int fail;} rng;
static int test_random(void*u,uint8_t*p,size_t n){rng*r=u;size_t i;if(r->fail){if(n)p[0]=0x7e;return -1;}
 for(i=0;i<n;i++){r->state^=r->state<<13;r->state^=r->state>>7;r->state^=r->state<<17;p[i]=(uint8_t)r->state;}return 0;}
static int zeros(const uint8_t*p,size_t n){size_t i;for(i=0;i<n;i++)if(p[i])return 0;return 1;}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d parameter %d\n",__LINE__,level);return 1;}}while(0)
static int run(int level,unsigned count){
 lc_context ctx;lc_sizes z;rng r={0x274413579beefULL+(unsigned)level,0};
 uint8_t *raw=malloc(262144+65),*work=raw+33;
 uint8_t pk[2592+32],sk[4896+32],ct[1568+32],sig[4627+32],ss[64],ss2[64],msg[1032],domain[256];
 unsigned i;size_t high[3]={0,0,0};int rc;
 CHECK(raw);CHECK(lc_get_sizes(level,&z)==0);memset(raw,0xa5,262144+65);
 memset(pk,0xa5,sizeof pk);memset(sk,0xa5,sizeof sk);memset(ct,0xa5,sizeof ct);memset(sig,0xa5,sizeof sig);
 memset(ss,0xa5,sizeof ss);memset(ss2,0xa5,sizeof ss2);memset(msg,0x52,sizeof msg);memset(domain,0x81,sizeof domain);
 CHECK(lc_context_init(&ctx,work,262144,test_random,&r)==0);
 CHECK(lc_keypair(&ctx,level,pk,z.public_key,sk,z.secret_key)==0);high[0]=ctx.arena_high_water;
 if(z.ciphertext){
  CHECK(lc_encaps(&ctx,level,ct,z.ciphertext,ss,32,pk,z.public_key)==0);high[1]=ctx.arena_high_water;
  CHECK(lc_decaps(&ctx,level,ss2,32,ct,z.ciphertext,sk,z.secret_key)==0);high[2]=ctx.arena_high_water;
  CHECK(!memcmp(ss,ss2,32));ct[0]^=1;
  CHECK(lc_decaps(&ctx,level,ss2,32,ct,z.ciphertext,sk,z.secret_key)==0);CHECK(memcmp(ss,ss2,32)!=0);ct[0]^=1;
 }else{
  CHECK(lc_sign(&ctx,level,sig,z.signature,msg,1024,domain,255,sk,z.secret_key)==0);high[1]=ctx.arena_high_water;
  CHECK(lc_verify(&ctx,level,sig,z.signature,msg,1024,domain,255,pk,z.public_key)==0);high[2]=ctx.arena_high_water;
  msg[0]^=1;CHECK(lc_verify(&ctx,level,sig,z.signature,msg,1024,domain,255,pk,z.public_key)==LC_E_REJECT);msg[0]^=1;
  CHECK(lc_sign(&ctx,level,sig,z.signature,NULL,0,NULL,0,sk,z.secret_key)==0);
  CHECK(lc_verify(&ctx,level,sig,z.signature,NULL,0,NULL,0,pk,z.public_key)==0);
 }
 /* Random-length and mutation campaign. Each public operation is called
    count times per parameter; valid executions occur regularly, not only
    the argument rejection path. Every successful result is checked. */
 for(i=0;i<count;i++){
  size_t bad=(i%97==0)?0:1+i%31;
  rc=lc_keypair(&ctx,level,pk,z.public_key-bad,sk,z.secret_key);
  CHECK(rc==(bad?LC_E_LENGTH:LC_OK));
  if(z.ciphertext){
   rc=lc_encaps(&ctx,level,ct,z.ciphertext,ss,32,pk,z.public_key-bad);CHECK(rc==(bad?LC_E_LENGTH:LC_OK));
   if(!bad){CHECK(lc_decaps(&ctx,level,ss2,32,ct,z.ciphertext,sk,z.secret_key)==0);CHECK(!memcmp(ss,ss2,32));}
   rc=lc_decaps(&ctx,level,ss2,32,ct,z.ciphertext-bad,sk,z.secret_key);CHECK(rc==(bad?LC_E_LENGTH:LC_OK));
  }else{
   rc=lc_sign(&ctx,level,sig,z.signature,msg,1024,domain,i%256,sk,z.secret_key-bad);CHECK(rc==(bad?LC_E_LENGTH:LC_OK));
   if(!bad){CHECK(lc_verify(&ctx,level,sig,z.signature,msg,1024,domain,i%256,pk,z.public_key)==0);}
   /* Correct length corrupted signatures exercise the parser as well as
      length failures; corruption of ctilde cannot validate except negligibly. */
   if(!bad){sig[0]^=1;CHECK(lc_verify(&ctx,level,sig,z.signature,msg,1024,domain,i%256,pk,z.public_key)==LC_E_REJECT);sig[0]^=1;}
   rc=lc_verify(&ctx,level,sig,z.signature-bad,msg,1024,domain,i%256,pk,z.public_key);
   CHECK(rc==(bad?LC_E_LENGTH:LC_OK));
  }
 }
 CHECK(lc_keypair(&ctx,level,pk,z.public_key,pk,z.secret_key)==LC_E_ALIAS);
 CHECK(lc_keypair(&ctx,level,NULL,z.public_key,sk,z.secret_key)==LC_E_ARGUMENT);
 CHECK(lc_keypair(&ctx,level,work,z.public_key,sk,z.secret_key)==LC_E_ALIAS);
 r.fail=1;CHECK(lc_keypair(&ctx,level,pk,z.public_key,sk,z.secret_key)==LC_E_RANDOM);CHECK(zeros(pk,z.public_key)&&zeros(sk,z.secret_key));
 r.fail=0;CHECK(lc_keypair(&ctx,level,pk,z.public_key,sk,z.secret_key)==0);
 r.fail=1;
 if(z.ciphertext){CHECK(lc_encaps(&ctx,level,ct,z.ciphertext,ss,32,pk,z.public_key)==LC_E_RANDOM);CHECK(zeros(ct,z.ciphertext)&&zeros(ss,32));}
 else{CHECK(lc_sign(&ctx,level,sig,z.signature,msg,1024,NULL,0,sk,z.secret_key)==LC_E_RANDOM);CHECK(zeros(sig,z.signature));}
 r.fail=0;CHECK(lc_context_init(&ctx,work,32,test_random,&r)==0);
 CHECK(lc_keypair(&ctx,level,pk,z.public_key,sk,z.secret_key)==LC_E_WORKSPACE);CHECK(zeros(pk,z.public_key)&&zeros(sk,z.secret_key));
 CHECK(lc_context_init(&ctx,work,262144,test_random,&r)==0);
 CHECK(lc_keypair(&ctx,level,pk,z.public_key,sk,z.secret_key)==0);
 for(i=0;i<32;i++){CHECK(pk[z.public_key+i]==0xa5);CHECK(sk[z.secret_key+i]==0xa5);CHECK(raw[i]==0xa5);CHECK(work[262144+i]==0xa5);}
 if(z.ciphertext){for(i=0;i<32;i++){CHECK(ct[z.ciphertext+i]==0xa5);CHECK(ss[32+i]==0xa5);CHECK(ss2[32+i]==0xa5);}}
 else for(i=0;i<32;i++)CHECK(sig[z.signature+i]==0xa5);
 printf("{\"parameter\":%d,\"calls_per_operation\":%u,\"guard_bytes\":32,\"random_failure\":true,\"overlap_rejected\":true,\"oom_recovery\":true,\"initial_arena_highwater\":[%llu,%llu,%llu],\"status\":\"PASS\"}\n",level,count,(unsigned long long)high[0],(unsigned long long)high[1],(unsigned long long)high[2]);
 free(raw);return 0;
}
int main(int argc,char**argv){int levels[]={512,768,1024,44,65,87};unsigned n=argc>1?(unsigned)strtoul(argv[1],NULL,10):100000;int i;
 for(i=0;i<6;i++)if(run(levels[i],n))return 1;return 0;}
