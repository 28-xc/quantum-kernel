/* Complete public operations under Linux process resource controls.
 * The deterministic byte stream is a test fixture, never a production RNG. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include "latticecore.h"
typedef struct {
 int (*init)(lc_context*,void*,size_t,lc_random_fn,void*);
 int (*sizes)(int,lc_sizes*);
 int (*key)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t);
 int (*enc)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t,const uint8_t*,size_t);
 int (*dec)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*sign)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*verify)(lc_context*,int,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
} API;
static uint64_t rng;
static int random_bytes(void *u,uint8_t *p,size_t n){(void)u;while(n--){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;*p++=(uint8_t)rng;}return 0;}
#ifndef LC_FIXTURE_HELPERS_ONLY
static uint64_t ns(clockid_t clock){struct timespec t;if(clock_gettime(clock,&t))exit(10);return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static uint64_t checksum(uint64_t h,const uint8_t*p,size_t n){while(n--){h^=*p++;h*=1099511628211ULL;}return h;}
int main(int argc,char **argv){
 if(argc!=9)return 2;
 int parameter=atoi(argv[2]),op=atoi(argv[3]),count=atoi(argv[4]),cpu=atoi(argv[6]);
 size_t capacity=strtoull(argv[5],0,0);rng=strtoull(argv[7],0,0);
 if(op<0||op>2||count<1||count>100000||!rng||capacity>262144||cpu<0||cpu>=CPU_SETSIZE)return 3;
 cpu_set_t set;CPU_ZERO(&set);CPU_SET(cpu,&set);if(sched_setaffinity(0,sizeof set,&set))return 4;
 void *h=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!h){fprintf(stderr,"%s\n",dlerror());return 5;}API a;
#define BIND(f,n) do{void*p=dlsym(h,n);if(!p)return 6;memcpy(&a.f,&p,sizeof p);}while(0)
 BIND(init,"lc_context_init");BIND(sizes,"lc_get_sizes");BIND(key,"lc_keypair");BIND(enc,"lc_encaps");BIND(dec,"lc_decaps");BIND(sign,"lc_sign");BIND(verify,"lc_verify");
#undef BIND
 lc_sizes z;if(a.sizes(parameter,&z))return 7;
 void *work=0;if(posix_memalign(&work,32,capacity?capacity:32))return 8;
 uint8_t pk[2592],sk[4896],ct[1568],ss[32],expected[32],sig[4627],msg[32],domain[16];
 memset(msg,0x3a,sizeof msg);memset(domain,0x65,sizeof domain);
 lc_context c;int rc=a.init(&c,work,capacity,random_bytes,0);
 if(!rc)rc=a.key(&c,parameter,pk,z.public_key,sk,z.secret_key);
 if(rc){printf("{\"status\":\"ALGORITHM_RETURN\",\"return_code\":%d,\"workspace_bytes\":%zu}\n",rc,capacity);free(work);dlclose(h);return rc==LC_E_WORKSPACE?20:21;}
 if(parameter>100){rc=a.enc(&c,parameter,ct,z.ciphertext,expected,32,pk,z.public_key);if(!rc)rc=a.dec(&c,parameter,ss,32,ct,z.ciphertext,sk,z.secret_key);if(rc||memcmp(ss,expected,32))return 22;}
 else {rc=a.sign(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,sk,z.secret_key);if(!rc)rc=a.verify(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,pk,z.public_key);if(rc)return 23;}
 FILE *out=fopen(argv[8],"wb");if(!out)return 9;fputs("iteration,wall_ns,cpu_ns,return_code,workspace_used\n",out);
 /* Buffer measurements until completion: no file writes between operations. */
 uint64_t *wall=calloc((size_t)count+32,sizeof *wall),*usedcpu=calloc((size_t)count+32,sizeof *usedcpu);
 if(!wall||!usedcpu)return 8;
 uint64_t digest=1469598103934665603ULL;size_t peak=0;uint64_t session0=ns(CLOCK_MONOTONIC),cpu0=ns(CLOCK_PROCESS_CPUTIME_ID);
 for(int i=-32;i<count;i++){
  uint64_t p0=ns(CLOCK_PROCESS_CPUTIME_ID),t0=ns(CLOCK_MONOTONIC);
  rc=a.init(&c,work,capacity,random_bytes,0);
  if(!rc){
   if(op==0)rc=a.key(&c,parameter,pk,z.public_key,sk,z.secret_key);
   else if(parameter>100){if(op==1)rc=a.enc(&c,parameter,ct,z.ciphertext,ss,32,pk,z.public_key);else rc=a.dec(&c,parameter,ss,32,ct,z.ciphertext,sk,z.secret_key);}
   else if(op==1)rc=a.sign(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,sk,z.secret_key);
   else rc=a.verify(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,pk,z.public_key);
  }
  uint64_t t1=ns(CLOCK_MONOTONIC),p1=ns(CLOCK_PROCESS_CPUTIME_ID);
  if(rc){fprintf(stderr,"operation returned %d at %d\n",rc,i);return 24;}
  if(i>=0){wall[i]=t1-t0;usedcpu[i]=p1-p0;}
  if(c.arena_high_water>peak)peak=c.arena_high_water;
  const uint8_t *data=op==0?pk:parameter>100?ss:sig;size_t bytes=op==0?z.public_key:parameter>100?32:z.signature;
  digest=checksum(digest,data,bytes);
 }
 uint64_t session1=ns(CLOCK_MONOTONIC),cpu1=ns(CLOCK_PROCESS_CPUTIME_ID);
 if(parameter>100){if(op==0){rc=a.enc(&c,parameter,ct,z.ciphertext,expected,32,pk,z.public_key);if(!rc)rc=a.dec(&c,parameter,ss,32,ct,z.ciphertext,sk,z.secret_key);if(!rc&&memcmp(ss,expected,32))rc=1;}else if(op==1){rc=a.dec(&c,parameter,expected,32,ct,z.ciphertext,sk,z.secret_key);if(!rc&&memcmp(ss,expected,32))rc=1;}else if(memcmp(ss,expected,32))rc=1;}
 else {if(op==0)rc=a.sign(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,sk,z.secret_key);if(!rc)rc=a.verify(&c,parameter,sig,z.signature,msg,sizeof msg,domain,sizeof domain,pk,z.public_key);}
 if(rc)return 25;
 for(int i=0;i<count;i++)fprintf(out,"%d,%llu,%llu,0,%zu\n",i,(unsigned long long)wall[i],(unsigned long long)usedcpu[i],peak);
 if(fclose(out))return 26;
 struct rusage usage;if(getrusage(RUSAGE_SELF,&usage))return 27;
 char group[1024]={0};FILE*g=fopen("/proc/self/cgroup","r");if(g){if(!fgets(group,sizeof group,g))group[0]=0;fclose(g);}group[strcspn(group,"\r\n")]=0;
 printf("{\"status\":\"PASS\",\"parameter\":%d,\"operation\":%d,\"samples\":%d,\"warmup\":32,\"workspace_bytes\":%zu,\"workspace_peak\":%zu,\"ru_maxrss_kib\":%ld,\"cpu_logical\":%d,\"session_wall_ns\":%llu,\"session_cpu_ns\":%llu,\"checksum_fnv64\":\"%016llx\",\"cgroup\":\"%s\",\"message_bytes\":32,\"context_bytes\":16}\n",parameter,op,count,capacity,peak,usage.ru_maxrss,sched_getcpu(),(unsigned long long)(session1-session0),(unsigned long long)(cpu1-cpu0),(unsigned long long)digest,group);
 volatile uint8_t *wipe=work;for(size_t i=0;i<capacity;i++)wipe[i]=0;wipe=sk;for(size_t i=0;i<sizeof sk;i++)wipe[i]=0;
 free(work);free(wall);free(usedcpu);dlclose(h);return 0;
}

#endif
