/* Offline, seeded API regression for our own locally generated objects.
 * This is bounded randomized regression, not coverage-guided fuzzing.
 * Every supplied pointer denotes an allocated accessible object. */
#include "latticecore.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WS 262144u
typedef struct {uint8_t *raw,*p;size_t n,prefix;} object;
typedef struct {uint64_t state,calls,bytes;int fail;} entropy;
static uint64_t schedule,initial_seed,digest;
static unsigned step;static int parameter;static const char *phase;
static object objects[14];static unsigned object_count;
static uint8_t *failure_input;static size_t failure_bytes;
static uint64_t next64(uint64_t *s){*s^=*s<<13;*s^=*s>>7;*s^=*s<<17;return *s;}
static int random_cb(void *v,uint8_t *p,size_t n){entropy*r=v;size_t i;r->calls++;r->bytes+=n;
 if(r->fail){if(n)p[0]=0x7e;return -1;}for(i=0;i<n;i++)p[i]=(uint8_t)next64(&r->state);return 0;}
static void absorb(const uint8_t*p,size_t n){while(n--){digest^=*p++;digest*=UINT64_C(1099511628211);}}
static int value(const uint8_t*p,size_t n,uint8_t v){while(n--)if(*p++!=v)return 0;return 1;}
static int failure(const char *expr,int line){FILE*f=fopen("failure.txt","wb");
 if(f){fprintf(f,"parameter=%d\nphase=%s\nstep=%u\nseed=%016llx\nschedule_state=%016llx\nline=%d\ncondition=%s\n",parameter,phase,step,(unsigned long long)initial_seed,(unsigned long long)schedule,line,expr);fclose(f);}
 if(failure_input&&failure_bytes){f=fopen("failure_input.bin","wb");if(f){fwrite(failure_input,1,failure_bytes,f);fclose(f);}}
 fprintf(stderr,"FAIL p=%d phase=%s step=%u line=%d condition=%s\n",parameter,phase,step,line,expr);return 1;}
#define CHECK(x) do{if(!(x))return failure(#x,__LINE__);}while(0)
static uint8_t* buffer(size_t n,int misalign){object*o=&objects[object_count++];o->prefix=misalign?33:32;o->n=n;o->p=NULL;o->raw=malloc(n+o->prefix+32);if(!o->raw)return NULL;memset(o->raw,0xa5,n+o->prefix+32);o->p=o->raw+o->prefix;return o->p;}
static int guards(void){unsigned i;for(i=0;i<object_count;i++){object*o=&objects[i];if(!value(o->raw,o->prefix,0xa5)||!value(o->p+o->n,32,0xa5))return 0;}return 1;}
static void mutation(uint8_t*out,const uint8_t*in,size_t n,unsigned kind){size_t i,j;memcpy(out,in,n);i=(size_t)(next64(&schedule)%n);
 switch(kind%4){case 0:out[i]^=(uint8_t)(1u<<(next64(&schedule)%8));break;
 case 1:j=i+1+(size_t)(next64(&schedule)%32);if(j>n)j=n;while(i<j)out[i++]=(uint8_t)next64(&schedule);break;
 case 2:out[i]=(next64(&schedule)&1)?0:255;break;
 default:for(i=0;i<n;i++)out[i]=(uint8_t)next64(&schedule);break;}}

static int run(int level,unsigned sequence_count,unsigned mutation_count){
 lc_context c;lc_sizes z;entropy r;uint8_t *work,*pk,*sk,*original,*out,*tmp_pk,*tmp_sk,*changed,*changed_pk,*ss,*ss2,*message,*domain,*alias;
 size_t n,ml=1024,dl=32;unsigned i,j;int rc;uint64_t before,counts[12]={0},accepted=0,rejected=0;
 parameter=level;phase="setup";step=0;object_count=0;failure_input=NULL;failure_bytes=0;
 schedule=initial_seed^(UINT64_C(0xd1b54a32d192ed03)*(unsigned)level);if(!schedule)schedule=1;
 r.state=schedule^UINT64_C(0x9e3779b97f4a7c15);r.calls=r.bytes=0;r.fail=0;digest=UINT64_C(1469598103934665603);
 CHECK(lc_get_sizes(level,&z)==0);n=z.ciphertext?z.ciphertext:z.signature;
 work=buffer(WS,1);pk=buffer(z.public_key,0);sk=buffer(z.secret_key,0);original=buffer(n,0);out=buffer(n,0);
 tmp_pk=buffer(z.public_key,0);tmp_sk=buffer(z.secret_key,0);changed=buffer(n,0);changed_pk=buffer(z.public_key,0);
 ss=buffer(32,0);ss2=buffer(32,0);message=buffer(4096,0);domain=buffer(256,0);alias=buffer(8192,0);
 for(i=0;i<object_count;i++){CHECK(objects[i].p);}
 memset(work,0,WS);memset(message,0x52,4096);memset(domain,0x81,256);
 CHECK(lc_context_init(&c,work,WS,random_cb,&r)==0);
 CHECK(lc_keypair(&c,level,pk,z.public_key,sk,z.secret_key)==0);absorb(pk,z.public_key);absorb(sk,z.secret_key);
 if(z.ciphertext){CHECK(lc_encaps(&c,level,original,n,ss,32,pk,z.public_key)==0);CHECK(lc_decaps(&c,level,ss2,32,original,n,sk,z.secret_key)==0);CHECK(!memcmp(ss,ss2,32));}
 else{CHECK(lc_sign(&c,level,original,n,message,ml,domain,dl,sk,z.secret_key)==0);CHECK(lc_verify(&c,level,original,n,message,ml,domain,dl,pk,z.public_key)==0);}
 absorb(original,n);
 phase="deterministic-boundaries";
 CHECK(lc_get_sizes(0,&z)==LC_E_ARGUMENT);CHECK(lc_get_sizes(level,&z)==0);CHECK(lc_get_sizes(level,NULL)==LC_E_ARGUMENT);
 CHECK(lc_context_init(NULL,work,WS,random_cb,&r)==LC_E_ARGUMENT);
 CHECK(lc_context_init(&c,NULL,WS,random_cb,&r)==LC_E_ARGUMENT);
 CHECK(lc_context_init(&c,work,0,random_cb,&r)==LC_E_ARGUMENT);
 CHECK(lc_context_init(&c,&c,sizeof c,random_cb,&r)==LC_E_ALIAS);
 before=r.calls;memset(tmp_pk,0x5a,z.public_key);memset(tmp_sk,0x5a,z.secret_key);
 CHECK(lc_keypair(&c,level,tmp_pk,z.public_key-1,tmp_sk,z.secret_key)==LC_E_LENGTH);
 CHECK(lc_keypair(&c,level,tmp_pk,z.public_key,tmp_sk,z.secret_key-1)==LC_E_LENGTH);
 CHECK(lc_keypair(&c,level,alias,z.public_key,alias,z.secret_key)==LC_E_ALIAS);
 CHECK(lc_keypair(&c,level,work,z.public_key,tmp_sk,z.secret_key)==LC_E_ALIAS);
 CHECK(lc_keypair(&c,level,NULL,z.public_key,tmp_sk,z.secret_key)==LC_E_ARGUMENT);
 CHECK(lc_keypair(NULL,level,tmp_pk,z.public_key,tmp_sk,z.secret_key)==LC_E_ARGUMENT);
 CHECK(r.calls==before&&value(tmp_pk,z.public_key,0x5a)&&value(tmp_sk,z.secret_key,0x5a));
 if(z.ciphertext){
  CHECK(lc_encaps(&c,level,alias,n,alias,32,pk,z.public_key)==LC_E_ALIAS);
  CHECK(lc_decaps(&c,level,alias,32,alias,n,sk,z.secret_key)==LC_E_ALIAS);
  CHECK(lc_encaps(&c,level,out,n,ss2,31,pk,z.public_key)==LC_E_LENGTH);
  CHECK(lc_decaps(&c,level,ss2,31,original,n,sk,z.secret_key)==LC_E_LENGTH);
  CHECK(lc_decaps(&c,level,ss2,32,original,n,sk,z.secret_key-1)==LC_E_LENGTH);
 }else{
  CHECK(lc_sign(&c,level,alias,n,message,ml,domain,dl,alias,z.secret_key)==LC_E_ALIAS);
  CHECK(lc_verify(&c,level,alias,n,message,ml,domain,dl,alias,z.public_key)==LC_E_ALIAS);
  CHECK(lc_sign(&c,level,out,n,message,ml,domain,256,sk,z.secret_key)==LC_E_LENGTH);
  CHECK(lc_verify(&c,level,original,n,message,ml,domain,256,pk,z.public_key)==LC_E_LENGTH);
  CHECK(lc_sign(&c,level,out,n,NULL,1,NULL,0,sk,z.secret_key)==LC_E_ARGUMENT);
  CHECK(lc_sign(&c,level,out,n,NULL,0,NULL,0,sk,z.secret_key)==0);
  CHECK(lc_verify(&c,level,out,n,NULL,0,NULL,0,pk,z.public_key)==0);
 }
 /* Exercise insufficient space at each algorithm operation and restore the same context. */
 CHECK(lc_context_init(&c,work,32,random_cb,&r)==0);
 CHECK(lc_keypair(&c,level,tmp_pk,z.public_key,tmp_sk,z.secret_key)==LC_E_WORKSPACE);
 CHECK(value(tmp_pk,z.public_key,0)&&value(tmp_sk,z.secret_key,0));
 if(z.ciphertext){CHECK(lc_encaps(&c,level,out,n,ss2,32,pk,z.public_key)==LC_E_WORKSPACE);CHECK(value(out,n,0)&&value(ss2,32,0));CHECK(lc_decaps(&c,level,ss2,32,original,n,sk,z.secret_key)==LC_E_WORKSPACE);CHECK(value(ss2,32,0));}
 else{CHECK(lc_sign(&c,level,out,n,message,ml,domain,dl,sk,z.secret_key)==LC_E_WORKSPACE);CHECK(value(out,n,0));CHECK(lc_verify(&c,level,original,n,message,ml,domain,dl,pk,z.public_key)==LC_E_WORKSPACE);}
 CHECK(lc_context_init(&c,work,WS,random_cb,&r)==0);
 phase="seeded-sequence";
 for(i=0;i<sequence_count;i++){
  unsigned action=(unsigned)(next64(&schedule)%12);step=i;counts[action]++;before=r.calls;failure_input=NULL;failure_bytes=0;
  memset(out,0x5a,n);memset(ss2,0x5a,32);
  switch(action){
  case 0:
   CHECK(lc_keypair(&c,level,pk,z.public_key,sk,z.secret_key)==0);absorb(pk,z.public_key);absorb(sk,z.secret_key);
   if(z.ciphertext)CHECK(lc_encaps(&c,level,original,n,ss,32,pk,z.public_key)==0);
   else{static const size_t lens[]={0,1,32,1024,4096};ml=lens[next64(&schedule)%5];dl=(size_t)(next64(&schedule)%256);CHECK(lc_sign(&c,level,original,n,message,ml,domain,dl,sk,z.secret_key)==0);}
   absorb(original,n);break;
  case 1:
   if(z.ciphertext){CHECK(lc_encaps(&c,level,original,n,ss,32,pk,z.public_key)==0);CHECK(lc_decaps(&c,level,ss2,32,original,n,sk,z.secret_key)==0);CHECK(!memcmp(ss,ss2,32));}
   else{CHECK(lc_sign(&c,level,original,n,message,ml,domain,dl,sk,z.secret_key)==0);CHECK(lc_verify(&c,level,original,n,message,ml,domain,dl,pk,z.public_key)==0);}
   absorb(original,n);break;
  case 2:
   if(z.ciphertext){CHECK(lc_decaps(&c,level,ss2,32,original,n,sk,z.secret_key)==0);CHECK(!memcmp(ss,ss2,32));absorb(ss2,32);}
   else CHECK(lc_verify(&c,level,original,n,message,ml,domain,dl,pk,z.public_key)==0);
   CHECK(r.calls==before);break;
  case 3:
   CHECK(lc_keypair(&c,level,tmp_pk,z.public_key-1-(next64(&schedule)%32),tmp_sk,z.secret_key)==LC_E_LENGTH);CHECK(r.calls==before);break;
  case 4:
   if(z.ciphertext)CHECK(lc_encaps(&c,level,out,n-1,ss2,32,pk,z.public_key)==LC_E_LENGTH);
   else CHECK(lc_sign(&c,level,out,n-1,message,ml,domain,dl,sk,z.secret_key)==LC_E_LENGTH);
   CHECK(r.calls==before&&value(out,n,0x5a));break;
  case 5:
   if(z.ciphertext)CHECK(lc_decaps(&c,level,ss2,32,original,n-1,sk,z.secret_key)==LC_E_LENGTH);
   else CHECK(lc_verify(&c,level,original,n-1,message,ml,domain,dl,pk,z.public_key)==LC_E_LENGTH);
   CHECK(r.calls==before&&value(ss2,32,0x5a));break;
  case 6:
   r.fail=1;CHECK(lc_keypair(&c,level,tmp_pk,z.public_key,tmp_sk,z.secret_key)==LC_E_RANDOM);r.fail=0;
   CHECK(value(tmp_pk,z.public_key,0)&&value(tmp_sk,z.secret_key,0)&&r.calls==before+1);break;
  case 7:
   r.fail=1;if(z.ciphertext){CHECK(lc_encaps(&c,level,out,n,ss2,32,pk,z.public_key)==LC_E_RANDOM);CHECK(value(ss2,32,0));}
   else CHECK(lc_sign(&c,level,out,n,message,ml,domain,dl,sk,z.secret_key)==LC_E_RANDOM);
   r.fail=0;CHECK(value(out,n,0)&&r.calls==before+1);break;
  case 8:
   CHECK(lc_keypair(&c,level,alias,z.public_key,alias+1,z.secret_key)==LC_E_ALIAS);CHECK(r.calls==before);break;
  case 9:
   CHECK(lc_context_init(&c,work,32,random_cb,&r)==0);CHECK(lc_keypair(&c,level,tmp_pk,z.public_key,tmp_sk,z.secret_key)==LC_E_WORKSPACE);
   CHECK(value(tmp_pk,z.public_key,0)&&value(tmp_sk,z.secret_key,0));CHECK(lc_context_init(&c,work,WS,random_cb,&r)==0);break;
  case 10:
   mutation(changed,original,n,(unsigned)next64(&schedule));failure_input=changed;failure_bytes=n;
   if(z.ciphertext){CHECK(lc_decaps(&c,level,ss2,32,changed,n,sk,z.secret_key)==0);absorb(ss2,32);}
   else{rc=lc_verify(&c,level,changed,n,message,ml,domain,dl,pk,z.public_key);CHECK(rc==LC_OK||rc==LC_E_REJECT);}break;
  default:
   CHECK(lc_keypair(&c,0,tmp_pk,z.public_key,tmp_sk,z.secret_key)==LC_E_ARGUMENT);CHECK(r.calls==before);break;
  }
  CHECK(guards());
  if(i%128==0){CHECK(c.arena_high_water<=WS);CHECK(value(work,c.arena_high_water,0));
   if(z.ciphertext){CHECK(lc_decaps(&c,level,ss2,32,original,n,sk,z.secret_key)==0);CHECK(!memcmp(ss,ss2,32));}
   else CHECK(lc_verify(&c,level,original,n,message,ml,domain,dl,pk,z.public_key)==0);}
 }
 phase="locally-derived-parser-mutations";
 for(i=0;i<mutation_count;i++){
  step=i;mutation(changed,original,n,i);failure_input=changed;failure_bytes=n;
  if(z.ciphertext){CHECK(lc_decaps(&c,level,ss2,32,changed,n,sk,z.secret_key)==0);CHECK(lc_decaps(&c,level,out,32,changed,n,sk,z.secret_key)==0);CHECK(!memcmp(out,ss2,32));absorb(ss2,32);}
  else{rc=lc_verify(&c,level,changed,n,message,ml,domain,dl,pk,z.public_key);CHECK(rc==LC_OK||rc==LC_E_REJECT);if(rc==0)accepted++;else rejected++;}
  mutation(changed_pk,pk,z.public_key,i+1);failure_input=changed_pk;failure_bytes=z.public_key;
  if(z.ciphertext){rc=lc_encaps(&c,level,out,n,ss2,32,changed_pk,z.public_key);CHECK(rc==LC_OK||rc==LC_E_REJECT);if(rc==0){accepted++;absorb(out,n);absorb(ss2,32);}else{rejected++;CHECK(value(out,n,0)&&value(ss2,32,0));}}
  else{rc=lc_verify(&c,level,original,n,message,ml,domain,dl,changed_pk,z.public_key);CHECK(rc==LC_OK||rc==LC_E_REJECT);}
  CHECK(guards());
  if(i%128==0){if(z.ciphertext){CHECK(lc_decaps(&c,level,ss2,32,original,n,sk,z.secret_key)==0);CHECK(!memcmp(ss,ss2,32));}else CHECK(lc_verify(&c,level,original,n,message,ml,domain,dl,pk,z.public_key)==0);}
 }
 for(j=0;j<12;j++)CHECK(counts[j]>0);
 printf("{\"parameter\":%d,\"seed\":\"%016llx\",\"sequence_steps\":%u,\"parser_mutations_each\":%u,\"actions\":[",level,(unsigned long long)initial_seed,sequence_count,mutation_count);
 for(j=0;j<12;j++)printf("%s%llu",j?",":"",(unsigned long long)counts[j]);
 printf("],\"mutated_primary_accepted\":%llu,\"mutated_primary_rejected\":%llu,\"entropy_calls\":%llu,\"transcript_fnv64\":\"%016llx\",\"status\":\"PASS\"}\n",(unsigned long long)accepted,(unsigned long long)rejected,(unsigned long long)r.calls,(unsigned long long)digest);fflush(stdout);
 for(j=0;j<object_count;j++){free(objects[j].raw);}
 return 0;
}
int main(int argc,char**argv){int levels[]={512,768,1024,44,65,87},i;unsigned seq,mut;
 if(argc!=4){fprintf(stderr,"usage: sequence seed_hex sequence_count mutation_count\n");return 2;}
 initial_seed=(uint64_t)strtoull(argv[1],NULL,16);seq=(unsigned)strtoul(argv[2],NULL,10);mut=(unsigned)strtoul(argv[3],NULL,10);
 if(!initial_seed||seq<128||seq>100000||mut<1||mut>1000000)return 2;
 for(i=0;i<6;i++){if(run(levels[i],seq,mut))return 1;}
 return 0;
}
