/* Linux/AArch64 finite timing screens of an UNMODIFIED loaded release ELF.
 * Platform port: dlopen/load-bias + actual-module validation, CPU affinity,
 * CLOCK_MONOTONIC_RAW nanoseconds. Old small/CRT modes explicitly rejected.
 * The private-RVA ABI is checked by independent functional oracles before use.
 * All inputs are prepared outside the timed region; the same address is used
 * for each timed operand. This is a detector, not a constant-time proof.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "latticecore.h"
#define ALIGN __attribute__((aligned(32)))
#define BATCH 1000
#define STRIDE 4096
#define WORK 262144
typedef int(*initfn)(lc_context*,void*,size_t,lc_random_fn,void*);
typedef int(*sizefn)(int,lc_sizes*);
typedef int(*keyfn)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t);
typedef int(*encfn)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t,const uint8_t*,size_t);
typedef int(*decfn)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
typedef void(*polyfn)(int32_t*);
typedef void(*pwfn)(int32_t*,const int32_t*);
typedef void(*kfn)(uint64_t*);
typedef void(*ntt16fn)(int16_t*,const int16_t*);
typedef void(*red16fn)(int16_t*);
typedef void(*cache16fn)(int16_t*,const int16_t*,const int16_t*);
typedef struct { ALIGN int16_t hat[256],cache[128]; } small_secret;
typedef struct { ALIGN int16_t h0[256],c0[128],h1[256],c1[128]; } crt_secret;
typedef struct { ALIGN int16_t h0[256],h1[256]; } challenge;
typedef int(*updatefn)(int32_t*,const int32_t*,const int16_t*,const small_secret*,int16_t*,int,int);
typedef void(*crtfn)(int32_t*,const challenge*,const crt_secret*,int16_t*,int16_t*);
static struct { polyfn ntt,intt;pwfn pw;kfn k1,k4;ntt16fn n3329,n769;red16fn r3329,r769;cache16fn c3329,c769;const int16_t*q3329,*q769;updatefn update;crtfn crt; } api;
static uint64_t rng_input,rng_class;
static uint64_t step(uint64_t*s){uint64_t x=*s;x^=x<<13;x^=x>>7;x^=x<<17;return *s=x;}
static uint32_t next(void){return (uint32_t)step(&rng_input);}
static int random_cb(void*u,uint8_t*p,size_t n){(void)u;while(n--)*p++=(uint8_t)next();return 0;}
static uint64_t hashbytes(uint64_t h,const void*p,size_t n){const uint8_t*b=p;while(n--){h^=*b++;h*=1099511628211ULL;}return h;}
static int desired_cpu=2;
static int bindcore(void){cpu_set_t available,only;
 if(desired_cpu<0||desired_cpu>=CPU_SETSIZE||sched_getaffinity(0,sizeof available,&available)||!CPU_ISSET(desired_cpu,&available))return -1;
 CPU_ZERO(&only);CPU_SET(desired_cpu,&only);if(sched_setaffinity(0,sizeof only,&only))return -1;
 if(sched_getaffinity(0,sizeof available,&available)||CPU_COUNT(&available)!=1||!CPU_ISSET(desired_cpu,&available))return -1;
 return desired_cpu;}
static uint64_t stamp(void){struct timespec t;
 __asm__ volatile("dsb ish; isb" ::: "memory");
 if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))abort();
 __asm__ volatile("dsb ish; isb" ::: "memory");
 return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;}
static void *aligned_alloc_local(size_t n,size_t a){void*p=NULL;return posix_memalign(&p,a,n)?NULL:p;}
static void wipe(void*p,size_t n){volatile unsigned char*b=p;while(n--)*b++=0;}
static char loaded_real[PATH_MAX];
static uintptr_t loaded_bias;
static int actual_module(void*p){Dl_info d;char path[PATH_MAX];return dladdr(p,&d)&&d.dli_fname&&realpath(d.dli_fname,path)&&!strcmp(path,loaded_real)&&(uintptr_t)d.dli_fbase==loaded_bias;}
static int32_t mod(int64_t x){x%=8380417;return (int32_t)(x<0?x+8380417:x);}
static void naive(int32_t out[256],const int16_t*a,const int16_t*b){
 memset(out,0,1024);for(int i=0;i<256;i++)for(int j=0;j<256;j++){
  int k=i+j;out[k&255]+=(k<256?1:-1)*(int32_t)a[i]*b[j];}}
static uint64_t rol(uint64_t x,unsigned s){return s?(x<<s)|(x>>(64-s)):x;}
static void keccak_ref(uint64_t*a){
 static const uint64_t rc[24]={1,0x8082,0x800000000000808aULL,0x8000000080008000ULL,0x808b,0x80000001,0x8000000080008081ULL,0x8000000000008009ULL,0x8a,0x88,0x80008009,0x8000000a,0x8000808b,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,0x8000000000008002ULL,0x8000000000000080ULL,0x800a,0x800000008000000aULL,0x8000000080008081ULL,0x8000000000008080ULL,0x80000001,0x8000000080008008ULL};
 static const unsigned r[25]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
 uint64_t c[5],d[5],b[25];for(int n=0;n<24;n++){
  for(int x=0;x<5;x++)c[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
  for(int x=0;x<5;x++)d[x]=c[(x+4)%5]^rol(c[(x+1)%5],1);
  for(int y=0;y<5;y++)for(int x=0;x<5;x++)b[y+5*((2*x+3*y)%5)]=rol(a[x+5*y]^d[x],r[x+5*y]);
  for(int y=0;y<5;y++)for(int x=0;x<5;x++)a[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]);
  a[0]^=rc[n];}}
static int symbols(uintptr_t dll,const char*path){FILE*f=fopen(path,"rb");char name[64];unsigned long long rva;if(!f)return -1;
 while(fscanf(f,"%63s %llx",name,&rva)==2){void*p=(void*)(dll+(uintptr_t)rva);if(!actual_module(p)){fclose(f);return -1;}
  if(!strcmp(name,"ntt"))api.ntt=(polyfn)p;else if(!strcmp(name,"intt"))api.intt=(polyfn)p;
  else if(!strcmp(name,"pw"))api.pw=(pwfn)p;else if(!strcmp(name,"k1"))api.k1=(kfn)p;else if(!strcmp(name,"k4"))api.k4=(kfn)p;
  else if(!strcmp(name,"n3329"))api.n3329=(ntt16fn)p;else if(!strcmp(name,"n769"))api.n769=(ntt16fn)p;
  else if(!strcmp(name,"r3329"))api.r3329=(red16fn)p;else if(!strcmp(name,"r769"))api.r769=(red16fn)p;
  else if(!strcmp(name,"c3329"))api.c3329=(cache16fn)p;else if(!strcmp(name,"c769"))api.c769=(cache16fn)p;
  else if(!strcmp(name,"q3329"))api.q3329=p;else if(!strcmp(name,"q769"))api.q769=p;
  else if(!strcmp(name,"update"))api.update=(updatefn)p;else if(!strcmp(name,"crt"))api.crt=(crtfn)p;
 }fclose(f);return 0;}
static int small_ready(void){return api.n3329&&api.r3329&&api.c3329&&api.q3329;}
static int crt_ready(void){return small_ready()&&api.n769&&api.r769&&api.c769&&api.q769;}
static void prepare_small(small_secret*s,const int16_t*raw){memcpy(s->hat,raw,512);api.r3329(s->hat);api.n3329(s->hat,api.q3329);api.c3329(s->cache,s->hat,api.q3329);}
static void prepare_crt(crt_secret*s,const int16_t*raw){memcpy(s->h0,raw,512);api.r3329(s->h0);api.n3329(s->h0,api.q3329);api.c3329(s->c0,s->h0,api.q3329);memcpy(s->h1,raw,512);api.r769(s->h1);api.n769(s->h1,api.q769);api.c769(s->c1,s->h1,api.q769);}
static void prepare_challenge(challenge*c,const int16_t*raw,int dual){memcpy(c->h0,raw,512);api.r3329(c->h0);api.n3329(c->h0,api.q3329);api.r3329(c->h0);if(dual){memcpy(c->h1,raw,512);api.r769(c->h1);api.n769(c->h1,api.q769);api.r769(c->h1);}}
/* Diagnostic dk_PKE: eta-bounded coefficients, FIPS-203 seven-stage NTT,
 * canonical 12-bit encoding. Public ek/H(ek)/z remain unchanged, so these
 * ARE NOT CLAIMED to be matching standard-generated key pairs. */
static void diagnostic_dkpke(uint8_t*p,int parameter){
 static int zeta[128];
 if(!zeta[1])for(int k=1;k<128;k++){int t=k,b=0,z=1;for(int j=0;j<7;j++){b=(b<<1)|(t&1);t>>=1;}for(int j=0;j<b;j++)z=z*17%3329;zeta[k]=z;}
 int eta=parameter==512?3:2,kdim=parameter==512?2:parameter==768?3:4;
 for(int pol=0;pol<kdim;pol++){
  int a[256];for(int j=0;j<256;j++)a[j]=((int)(next()%(2*eta+1))-eta+3329)%3329;
  int k=1;for(int len=128;len>=2;len>>=1)for(int start=0;start<256;start+=2*len){int z=zeta[k++];for(int j=start;j<start+len;j++){int t=z*a[j+len]%3329,v=a[j];a[j]=(v+t)%3329;a[j+len]=(v-t+3329)%3329;}}
  for(int j=0;j<128;j++){unsigned u=(unsigned)a[2*j],v=(unsigned)a[2*j+1];p[pol*384+3*j]=(uint8_t)u;p[pol*384+3*j+1]=(uint8_t)((u>>8)|(v<<4));p[pol*384+3*j+2]=(uint8_t)(v>>4);}
 }
}
enum { DECAP_KEY,DECAP_Z,DECAP_CT,DECAP_PKE,NTT_ETA,NTT_Y,POINTWISE,KECCAK1,KECCAK4,SMALL,SMALL_SUB,CRT };
static int small_mode(int mode){return mode==SMALL||mode==SMALL_SUB;}
static int mode_id(const char*s){const char*names[]={"decaps_key","decaps_z","decaps_ct","decaps_pke_diagnostic","ntt_eta","ntt_y","pointwise","keccak1","keccak4","small_update","small_subtract","crt_product"};for(int i=0;i<12;i++)if(!strcmp(s,names[i]))return i;return -1;}
int main(int argc,char**argv){
 /* dll bindings mode parameter samples seed positive output.csv; n=0 = oracle only */
 if(argc!=10)return 2;desired_cpu=atoi(argv[9]);
 int mode=mode_id(argv[3]),parameter=atoi(argv[4]),n=atoi(argv[5]),positive=atoi(argv[7]);
 rng_input=strtoull(argv[6],0,0);rng_class=rng_input^0x9e3779b97f4a7c15ULL;
 if(!rng_input||mode<0||mode>=SMALL||n<0||n>1000000||n%BATCH||positive<0||positive>1)return 3;
 int core=bindcore();if(core<0)return 4;void*dll=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!dll)return 5;
 struct link_map*map=NULL;char requested[PATH_MAX];
 if(!realpath(argv[1],requested)||dlinfo(dll,RTLD_DI_LINKMAP,&map)||!map||!realpath(map->l_name,loaded_real)||strcmp(requested,loaded_real))return 5;
 loaded_bias=(uintptr_t)map->l_addr;
 if(symbols(loaded_bias,argv[2]))return 5;
 initfn init=(initfn)dlsym(dll,"lc_context_init");sizefn sizes=(sizefn)dlsym(dll,"lc_get_sizes");
 keyfn key=(keyfn)dlsym(dll,"lc_keypair");encfn enc=(encfn)dlsym(dll,"lc_encaps");decfn dec=(decfn)dlsym(dll,"lc_decaps");
 if(!init||!sizes||!key||!enc||!dec)return 6;
 ALIGN uint8_t in[STRIDE],fixed[STRIDE],pk[1568],ct[1568],validct[1568],ss[32],expectedss[32];
 ALIGN int32_t result[256],operand[256],base[256]={0},expected[256];ALIGN int16_t raw[256],craw[256]={0},r1[256],r2[256];ALIGN challenge ch;
 lc_context ctx;lc_sizes sz;void*work=aligned_alloc_local(WORK,32);uint8_t*batch=aligned_alloc_local(BATCH*STRIDE,32);uint8_t(*pool)[3168]=aligned_alloc_local(257*3168,32);
 uint8_t cls[BATCH],tag[BATCH];uint64_t*times=calloc(n?n:1,sizeof(uint64_t));uint8_t*classes=calloc(n?n:1,1);uint8_t*norms=calloc(n?n:1,1);
 if(!work||!batch||!pool||!times||!classes||!norms)return 7;
 memset(fixed,0,sizeof fixed);size_t bytes=0;
 int eta=parameter==65?4:2,gamma=parameter==44?131072:524288,tau=parameter==44?39:parameter==65?49:60;
 int gamma2=parameter==44?95232:261888,beta=tau*eta,bound=mode==SMALL_SUB?gamma2-beta:gamma-beta;
 uint64_t checksum=0,inputs_hash=1469598103934665603ULL;volatile uint32_t sink=1;
 if(mode<=DECAP_PKE){
  if((parameter!=512&&parameter!=768&&parameter!=1024)||sizes(parameter,&sz))return 8;
  for(int k=0;k<(mode==DECAP_KEY?257:1);k++){
   if(init(&ctx,work,WORK,random_cb,0)||key(&ctx,parameter,pk,sz.public_key,pool[k],sz.secret_key)||enc(&ctx,parameter,validct,sz.ciphertext,expectedss,32,pk,sz.public_key)||dec(&ctx,parameter,ss,32,validct,sz.ciphertext,pool[k],sz.secret_key)||memcmp(ss,expectedss,32))return 9;
  }
  memcpy(fixed,pool[0],sz.secret_key);fixed[sz.secret_key-32]&=254;random_cb(0,ct,sz.ciphertext);bytes=sz.secret_key;
  if(mode==DECAP_CT)bytes=sz.ciphertext;
  if(mode==DECAP_PKE){
   if(init(&ctx,work,WORK,random_cb,0)||dec(&ctx,parameter,expectedss,32,ct,sz.ciphertext,fixed,sz.secret_key))return 19;
   for(int trial=0;trial<64;trial++){
    memcpy(in,fixed,bytes);diagnostic_dkpke(in,parameter);
    size_t dkpke=sz.secret_key-sz.public_key-64;
    for(size_t j=0;j<dkpke;j+=3)if((in[j]|((in[j+1]&15u)<<8))>=3329u||(unsigned)((in[j+1]>>4)|(in[j+2]<<4))>=3329u)return 20;
    if(init(&ctx,work,WORK,random_cb,0)||dec(&ctx,parameter,ss,32,ct,sz.ciphertext,in,sz.secret_key)||memcmp(ss,expectedss,32))return 21;
   }
  }
 }else{
  if(parameter!=44&&parameter!=65&&parameter!=87)return 10;
  if(mode==NTT_ETA||mode==NTT_Y){if(!api.ntt||!api.intt)return 11;bytes=1024;}
  else if(mode==POINTWISE){if(!api.pw)return 11;bytes=1024;for(int j=0;j<256;j++)operand[j]=(int32_t)(next()%8380417);}
  else if(mode==KECCAK1||mode==KECCAK4){if(!(mode==KECCAK1?api.k1:api.k4))return 11;bytes=mode==KECCAK1?200:800;}
  else {if(!small_ready()||(small_mode(mode)&&!api.update)||(mode==CRT&&(!api.crt||!crt_ready())))return 11;
   for(int j=0;j<tau;j++)craw[j]=(j&1)?-1:1;
   prepare_challenge(&ch,craw,mode==CRT);memset(raw,0,sizeof raw);
   if(small_mode(mode)){prepare_small((small_secret*)fixed,raw);bytes=sizeof(small_secret);}else{prepare_crt((crt_secret*)fixed,raw);bytes=sizeof(crt_secret);}
   if(mode==SMALL_SUB){for(int j=0;j<256;j++)base[j]=(int32_t)(next()%(unsigned)bound)-bound/2;base[0]=bound-1;}}
  /* Functional ABI/oracle check independent of timing and statistical classes. */
  for(int trial=0;trial<64;trial++){
   if(mode==NTT_ETA||mode==NTT_Y){for(int j=0;j<256;j++)expected[j]=result[j]=(int32_t)(next()%8380417);api.ntt(result);for(int j=0;j<256;j++)result[j]=mod(result[j]);api.intt(result);for(int j=0;j<256;j++)if(mod(result[j])!=mod((int64_t)expected[j]*4193792))return 12;}
   else if(mode==POINTWISE){for(int j=0;j<256;j++)expected[j]=result[j]=(int32_t)(next()%8380417);api.pw(result,operand);for(int j=0;j<256;j++)if(mod(result[j])!=mod((int64_t)mod((int64_t)expected[j]*operand[j])*8265825))return 13;}
   else if(mode==KECCAK1||mode==KECCAK4){random_cb(0,in,bytes);memcpy(fixed,in,bytes);for(unsigned j=0;j<bytes/200;j++)keccak_ref((uint64_t*)fixed+25*j);(mode==KECCAK1?api.k1:api.k4)((uint64_t*)in);if(memcmp(fixed,in,bytes))return 14;}
   else {for(int j=0;j<256;j++)raw[j]=small_mode(mode)?(int16_t)((int)(next()%(2*eta+1))-eta):(int16_t)((int)(next()%8192)-4095);naive(expected,craw,raw);
    if(small_mode(mode)){
     int expected_norm=0;for(int j=0;j<256;j++){expected[j]=base[j]+(mode==SMALL_SUB?-expected[j]:expected[j]);expected_norm|=abs(expected[j])>=bound;}
     prepare_small((small_secret*)in,raw);memcpy(result,base,sizeof base);
     int actual_norm=api.update(result,mode==SMALL_SUB?result:base,ch.h0,(small_secret*)in,r1,mode==SMALL_SUB,bound);
     if(actual_norm!=expected_norm)return 15;
    }else{prepare_crt((crt_secret*)in,raw);api.crt(result,&ch,(crt_secret*)in,r1,r2);}
    if(memcmp(result,expected,1024))return 16;}
  }if(mode==KECCAK1||mode==KECCAK4)memset(fixed,0,bytes);
 }
 if(!n){printf("{\"oracle\":\"PASS\",\"loaded_module_path_checked\":true,\"mode\":\"%s\",\"parameter\":%d,\"trials\":%d,\"cpu_logical\":%d}\n",argv[3],parameter,mode==DECAP_KEY?257:mode<DECAP_PKE?1:64,core);return 0;}
 FILE*out=fopen(argv[8],"wb");if(!out)return 18;
 fputs("class,elapsed_ns,norm_result\n",out);fflush(out);
 for(int block=-1;block<n/BATCH;block++){
  for(int j=0;j<BATCH;j++)cls[j]=(uint8_t)(j>=BATCH/2);
  for(int j=BATCH-1;j>0;j--){int k=(int)(step(&rng_class)%(j+1));uint8_t t=cls[j];cls[j]=cls[k];cls[k]=t;}
  for(int i=0;i<BATCH;i++){
   uint8_t*p=batch+(size_t)i*STRIDE;unsigned cl=cls[i];tag[i]=0;
   if(mode==DECAP_KEY){unsigned k=1+next()%256;memcpy(p,pool[cl?k:0],bytes);tag[i]=p[sz.secret_key-32]&1;}
   else if(mode==DECAP_Z){memcpy(p,fixed,bytes);uint8_t z[32];random_cb(0,z,32);if(cl)memcpy(p+bytes-32,z,32);tag[i]=p[bytes-32]&1;}
   else if(mode==DECAP_CT){random_cb(0,p,bytes);if(!cl)memcpy(p,validct,bytes);tag[i]=p[0]&1;}
   else if(mode==DECAP_PKE){memcpy(p,fixed,bytes);diagnostic_dkpke(p,parameter);if(!cl)memcpy(p,fixed,bytes);tag[i]=p[0]&1;}
   else if(mode==NTT_ETA||mode==NTT_Y||mode==POINTWISE){int32_t*a=(int32_t*)p;for(int j=0;j<256;j++){int32_t v=mode==POINTWISE?(int32_t)(next()%8380417):mode==NTT_ETA?(int32_t)(next()%(2*eta+1))-eta:gamma-(int32_t)(next()%(2*gamma));a[j]=cl?v:0;}tag[i]=(uint8_t)a[0]&1;}
   else if(mode==KECCAK1||mode==KECCAK4){random_cb(0,p,bytes);if(!cl)memcpy(p,fixed,bytes);tag[i]=p[0]&1;}
   else {for(int j=0;j<256;j++){int16_t v=small_mode(mode)?(int16_t)((int)(next()%(2*eta+1))-eta):(int16_t)((int)(next()%8192)-4095);raw[j]=cl?v:0;}tag[i]=(uint8_t)raw[0]&1;if(small_mode(mode))prepare_small((small_secret*)p,raw);else prepare_crt((crt_secret*)p,raw);}
   inputs_hash=hashbytes(inputs_hash,p,bytes);
  }
  for(int i=0;i<BATCH;i++){
   memcpy(in,batch+(size_t)i*STRIDE,bytes);if(mode==SMALL_SUB)memcpy(result,base,sizeof base);
   int rc=0;uint64_t t0=stamp();
   if(mode<=DECAP_PKE){rc=init(&ctx,work,WORK,random_cb,0);if(!rc)rc=dec(&ctx,parameter,ss,32,mode==DECAP_CT?in:ct,sz.ciphertext,mode==DECAP_CT?fixed:in,sz.secret_key);}
   else if(mode==NTT_ETA||mode==NTT_Y)api.ntt((int32_t*)in);
   else if(mode==POINTWISE)api.pw((int32_t*)in,operand);
   else if(mode==KECCAK1||mode==KECCAK4)(mode==KECCAK1?api.k1:api.k4)((uint64_t*)in);
   else if(small_mode(mode))rc=api.update(result,mode==SMALL_SUB?result:base,ch.h0,(small_secret*)in,r1,mode==SMALL_SUB,bound);
   else api.crt(result,&ch,(crt_secret*)in,r1,r2);
   /* Deliberately insecure detector control: a branch on a SECRET-derived
    * coefficient/state/z bit, not on the statistical class label. */
   if(positive&&tag[i])for(int j=0;j<4096;j++)sink=sink*1664525u+1013904223u;
   uint64_t t1=stamp();
   if(t1<t0||(!small_mode(mode)&&rc)||(small_mode(mode)&&(unsigned)rc>1)){
    if(block>=0){int k=block*BATCH+i;times[k]=t1-t0;classes[k]=cls[i];norms[k]=(uint8_t)rc;
     for(int j=block*BATCH;j<=k;j++)fprintf(out,"%u,%llu,%u\n",classes[j],(unsigned long long)times[j],norms[j]);}
    fflush(out);fclose(out);fprintf(stderr,"operation/timer failure mode=%s block=%d within=%d class=%u rc=%d backwards=%d\n",argv[3],block,i,cls[i],rc,t1<t0);return 17;
   }
   if(block>=0){int k=block*BATCH+i;times[k]=t1-t0;classes[k]=cls[i];norms[k]=(uint8_t)rc;}
   checksum+=(mode<=DECAP_PKE?ss[i%32]:mode>=SMALL?(uint32_t)result[i%256]:in[i%bytes])+sink;
  }
  if(block>=0){for(int j=block*BATCH;j<(block+1)*BATCH;j++)fprintf(out,"%u,%llu,%u\n",classes[j],(unsigned long long)times[j],norms[j]);fflush(out);}
 }
 if(fclose(out))return 18;
 printf("{\"loaded_module_path_checked\":true,\"mode\":\"%s\",\"parameter\":%d,\"samples\":%d,\"warmup\":1000,\"cpu_logical\":%d,\"positive_control\":%s,\"checksum\":%llu,\"input_fnv64\":\"%016llx\",\"key_pool_size\":%d,\"timer\":\"dsb-ish-isb-clock_gettime-MONOTONIC_RAW-ns\"}\n",argv[3],parameter,n,core,positive?"true":"false",(unsigned long long)checksum,(unsigned long long)inputs_hash,mode==DECAP_KEY?257:1);
 wipe(in,sizeof in);wipe(fixed,sizeof fixed);wipe(pool,257*3168);wipe(batch,BATCH*STRIDE);wipe(work,WORK);free(pool);free(batch);free(work);free(times);free(classes);free(norms);dlclose(dll);return 0;
}
