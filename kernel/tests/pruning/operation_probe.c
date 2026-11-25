/* Published vectors exercise only retained operations; no setup key generation
 * or signing is required for an encapsulation/verification-only deployment. */
#include "latticecore.h"
#include "latticecore_pruned.h"
#include "vectors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef LC_PROBE_WORKSPACE
#define LC_PROBE_WORKSPACE 262144
#endif
static _Alignas(32) struct { unsigned char before[32], data[LC_PROBE_WORKSPACE], after[32]; } work;
#define OUTPUT(name,n) static struct {unsigned char before[32],data[n],after[32];} name
OUTPUT(o_pk,LC_TARGET_CAP_PK);OUTPUT(o_sk,LC_TARGET_CAP_SK);OUTPUT(o_ct,LC_TARGET_CAP_CT);OUTPUT(o_ss,LC_TARGET_CAP_SS);OUTPUT(o_sig,LC_TARGET_CAP_SIG);
static const unsigned char *coins;
static size_t coins_size, coins_used;
static int rng_fail, scenario;
static lc_context context;
static _Alignas(32) struct { unsigned char before[32], data[65536], after[32]; } call_stack;
static const lc_target_vector *active;
static size_t stack_peak;
extern int lc_memory_call_at(void*,uintptr_t,int(*)(void*));
static int random_bytes(void *u,unsigned char *out,size_t n){
 (void)u; if(rng_fail||coins_used>coins_size||n>coins_size-coins_used)return -1;
 memcpy(out,coins+coins_used,n);coins_used+=n;return 0;
}
static int call(lc_context *c,const lc_target_vector *v){
 int p=v->parameter;lc_sizes n={0};if(lc_get_sizes(p,&n)&&!scenario){/* omitted cells are checked by their API stub below */}

 if(!v->operation)return lc_keypair(c,p,scenario==4?o_sk.data:o_pk.data,scenario==3?n.public_key-1:sizeof(o_pk.data),o_sk.data,sizeof(o_sk.data));
 if(p>100){
  if(v->operation==1)return lc_encaps(c,p,o_ct.data,scenario==3?n.ciphertext-1:sizeof(o_ct.data),scenario==4?o_ct.data:o_ss.data,sizeof(o_ss.data),v->pk.p,v->pk.n);
  return lc_decaps(c,p,scenario==4?o_ct.data:o_ss.data,scenario==3?31:sizeof(o_ss.data),scenario==4?o_ct.data:v->ct.p,v->ct.n,v->sk.p,v->sk.n);
 }
 if(v->operation==1)return lc_sign(c,p,o_sig.data,scenario==3?n.signature-1:sizeof(o_sig.data),scenario==4?o_sig.data:v->message.p,scenario==4?1:v->message.n,v->domain.p,v->domain.n,v->sk.p,v->sk.n);
 return lc_verify(c,p,v->signature.p,scenario==3?v->signature.n-1:v->signature.n,scenario==4?v->pk.p:v->message.p,scenario==4?1:v->message.n,v->domain.p,v->domain.n,v->pk.p,v->pk.n);
}
static int invoke(void *unused){(void)unused;return call(&context,active);}
static int bounded_call(const lc_target_vector *v){
 size_t n;int rc;active=v;
 memset(call_stack.before,0x91,32);memset(call_stack.after,0x39,32);memset(call_stack.data,0xa5,sizeof(call_stack.data));
 rc=lc_memory_call_at(0,(uintptr_t)(call_stack.data+sizeof(call_stack.data)),invoke);
 for(n=0;n<32;n++)if(call_stack.before[n]!=0x91||call_stack.after[n]!=0x39)return LC_E_INTERNAL;
 for(n=0;n<sizeof(call_stack.data)&&call_stack.data[n]==0xa5;n++){}
 n=sizeof(call_stack.data)-n;if(n>stack_peak)stack_peak=n;
 return rc;
}
static int match(const lc_target_vector *v){
 if(!v->operation)return !memcmp(o_pk.data,v->expected0.p,v->expected0.n)&&!memcmp(o_sk.data,v->expected1.p,v->expected1.n);
 if(v->parameter>100){
  if(v->operation==1)return !memcmp(o_ct.data,v->expected0.p,v->expected0.n)&&!memcmp(o_ss.data,v->expected1.p,v->expected1.n);
  return !memcmp(o_ss.data,v->expected0.p,v->expected0.n);
 }
 return v->operation!=1||!memcmp(o_sig.data,v->expected0.p,v->expected0.n);
}
static int cleared(void){size_t j;for(j=0;j<sizeof(work.data);j++)if(work.data[j])return 0;return 1;}
static int guards(void){unsigned j;
#define CHECK(o) for(j=0;j<32;j++)if(o.before[j]!=0x91||o.after[j]!=0x39)return 0
 CHECK(work);CHECK(o_pk);CHECK(o_sk);CHECK(o_ct);CHECK(o_ss);CHECK(o_sig);
#undef CHECK
 return 1;}
static int outputs_zero(const lc_target_vector*v){
 lc_sizes n;size_t j;unsigned char *a=0,*b=0;size_t na=0,nb=0;lc_get_sizes(v->parameter,&n);
 if(!v->operation){a=o_pk.data;na=n.public_key;b=o_sk.data;nb=n.secret_key;}
 else if(v->parameter>100){a=o_ss.data;na=32;if(v->operation==1){b=o_ct.data;nb=n.ciphertext;}}
 else if(v->operation==1){a=o_sig.data;na=n.signature;}
 for(j=0;j<na;j++)if(a[j])return 0;for(j=0;j<nb;j++)if(b[j])return 0;return 1;
}
int main(int argc,char **argv){
 unsigned repeats=argc>1?(unsigned)strtoul(argv[1],0,10):1,i,r,checks=0;size_t peak=0;
 int present[6][3]={{0}};const int params[6]={512,768,1024,44,65,87};
 if(!repeats||repeats>10000)return 2;
#define INIT(o) memset(o.before,0x91,32);memset(o.after,0x39,32)
 INIT(work);INIT(o_pk);INIT(o_sk);INIT(o_ct);INIT(o_ss);INIT(o_sig);
#undef INIT
 for(i=0;i<LC_TARGET_VECTOR_COUNT;i++)for(r=0;r<6;r++)if(params[r]==target_vectors[i].parameter)present[r][target_vectors[i].operation]=1;
 for(r=0;r<repeats;r++)for(i=0;i<LC_TARGET_VECTOR_COUNT;i++){
  const lc_target_vector *v=target_vectors+i;int result;
  coins=v->coins.p;coins_size=v->coins.n;coins_used=0;rng_fail=0;
  if(lc_context_init(&context,work.data,sizeof(work.data),random_bytes,0))return 3;
  result=bounded_call(v);
  if(result!=(v->accepted?LC_OK:LC_E_REJECT)||!guards()||!cleared()||(v->accepted&&(!match(v)||coins_used!=coins_size)))return 4;
  if(context.arena_high_water>peak)peak=context.arena_high_water;
  checks++;
  if(r==0)printf("{\"event\":\"vector\",\"parameter\":%d,\"operation\":%d,\"tcId\":%u,\"accepted\":%d,\"arena_peak\":%zu}\n",v->parameter,v->operation,v->tc_id,v->accepted,context.arena_high_water);
 }
 /* Fixed legal-capacity errors followed by normal same-context recovery. */
 for(i=0;i<LC_TARGET_VECTOR_COUNT;i++)if(target_vectors[i].accepted){
  const lc_target_vector *v=target_vectors+i;int mode;
  for(mode=1;mode<=4;mode++){
   int expected,result;
   if(mode==1&&v->operation==2)continue;
   coins=v->coins.p;coins_size=v->coins.n;coins_used=0;rng_fail=mode==1;scenario=mode;
   if(lc_context_init(&context,work.data,mode==2?32:sizeof(work.data),random_bytes,0))return 6;
   expected=mode==1?LC_E_RANDOM:mode==2?LC_E_WORKSPACE:mode==3?LC_E_LENGTH:LC_E_ALIAS;
   result=bounded_call(v);
   if(result!=expected||!guards()||!cleared()||((mode==1||mode==2)&&!outputs_zero(v)))return 7;
   checks++;context.workspace_bytes=sizeof(work.data);rng_fail=0;scenario=0;coins_used=0;
   if(bounded_call(v)||!match(v)||coins_used!=coins_size||!guards()||!cleared())return 8;
   checks++;
  }
 }
 scenario=0;
 /* Omitted cells have an explicit API error and cannot consume entropy. */
 for(i=0;i<6;i++)for(r=0;r<3;r++)if(!present[i][r]){
  lc_target_vector v={0};v.parameter=params[i];v.operation=(int)r;coins_used=0;
  if(lc_context_init(&context,work.data,sizeof(work.data),random_bytes,0)||call(&context,&v)!=LC_E_UNSUPPORTED||coins_used||!guards())return 5;
  checks++;
 }
 /* Retained parameters of the other algorithm keep the original error. */
 for(i=0;i<6;i++){
  int p=params[i],kept=present[i][0]||present[i][1]||present[i][2];
  int expected=kept?LC_E_ARGUMENT:LC_E_UNSUPPORTED,a,b;
  coins_used=0;
  if(p>100){a=lc_sign(&context,p,0,0,0,0,0,0,0,0);b=lc_verify(&context,p,0,0,0,0,0,0,0,0);}
  else {a=lc_encaps(&context,p,0,0,0,0,0,0);b=lc_decaps(&context,p,0,0,0,0,0,0);}
  if(a!=expected||b!=expected||coins_used||!guards())return 9;
  checks+=2;
 }
 printf("{\"status\":\"PASS\",\"published_cases\":%u,\"repeats\":%u,\"checks\":%u,\"workspace_capacity\":%zu,\"maximum_arena\":%zu,\"context_bytes\":%zu}\n",(unsigned)LC_TARGET_VECTOR_COUNT,repeats,checks,sizeof(work.data),peak,sizeof(context));
 printf("{\"event\":\"stack\",\"reserved_bytes\":65536,\"observed_bytes\":%zu}\n",stack_peak);
 return 0;
}
