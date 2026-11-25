/* Serialized-key device enrollment example and bounded workload.
 * The authority signs the device's fresh ML-KEM public key. The receiver
 * verifies that certificate before encapsulation; the device decapsulates.
 * Both roles execute sequentially in one process and share a workspace.
 * seed=0 uses the OS random source. A nonzero seed selects a test fixture.
 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "latticecore.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <sched.h>
#include <time.h>
#endif

typedef struct {
 int (*init)(lc_context*,void*,size_t,lc_random_fn,void*);
 int (*sizes)(int,lc_sizes*);
 int (*key)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t);
 int (*enc)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t,const uint8_t*,size_t);
 int (*dec)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*sign)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*verify)(lc_context*,int,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
} api;
typedef struct {uint64_t state,requests,bytes;} test_entropy;
static int random_fixture(void*v,uint8_t*p,size_t n){
 test_entropy*r=v;r->requests++;r->bytes+=n;
 while(n--){r->state^=r->state<<13;r->state^=r->state>>7;r->state^=r->state<<17;*p++=(uint8_t)r->state;}return 0;
}
static void wipe(void*p,size_t n){volatile uint8_t*q=p;while(n--)*q++=0;}
static uint64_t digest(uint64_t h,const uint8_t*p,size_t n){while(n--){h^=*p++;h*=UINT64_C(1099511628211);}return h;}
static uint64_t now(void){
#ifdef _WIN32
 LARGE_INTEGER t,f;QueryPerformanceCounter(&t);QueryPerformanceFrequency(&f);
 return (uint64_t)((long double)t.QuadPart*1000000000.0L/f.QuadPart);
#else
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))exit(10);
 return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;
#endif
}
static int pin(int cpu){
#ifdef _WIN32
 if(cpu<0||cpu>=64)return 1;
 return SetThreadAffinityMask(GetCurrentThread(),(DWORD_PTR)UINT64_C(1)<<cpu)?0:1;
#else
 cpu_set_t set;if(cpu<0||cpu>=CPU_SETSIZE)return 1;
 CPU_ZERO(&set);CPU_SET(cpu,&set);return sched_setaffinity(0,sizeof set,&set);
#endif
}
int main(int argc,char**argv){
 if(argc!=10){fputs("enrollment library kem_parameter dsa_parameter workspace_bytes samples fresh_identity seed cpu output.csv\n",stderr);return 2;}
 int kem=atoi(argv[2]),dsa=atoi(argv[3]),count=atoi(argv[5]),fresh=atoi(argv[6]),cpu=atoi(argv[8]);
 size_t capacity=(size_t)strtoull(argv[4],NULL,10);test_entropy rng={strtoull(argv[7],NULL,10),0,0};
 if(count<1||count>10000||capacity<32||capacity>262144||(fresh!=0&&fresh!=1)||pin(cpu))return 3;
 api a;
#ifdef _WIN32
 HMODULE handle=LoadLibraryA(argv[1]);if(!handle)return 4;
#define BIND(f,n) do{FARPROC p=GetProcAddress(handle,n);if(!p)return 5;memcpy(&a.f,&p,sizeof p);}while(0)
#else
 void*handle=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!handle){fputs(dlerror(),stderr);return 4;}
#define BIND(f,n) do{void*p=dlsym(handle,n);if(!p)return 5;memcpy(&a.f,&p,sizeof p);}while(0)
#endif
 BIND(init,"lc_context_init");BIND(sizes,"lc_get_sizes");BIND(key,"lc_keypair");BIND(enc,"lc_encaps");BIND(dec,"lc_decaps");BIND(sign,"lc_sign");BIND(verify,"lc_verify");
#undef BIND
 lc_sizes k,s;if(a.sizes(kem,&k)||a.sizes(dsa,&s)||!k.ciphertext||!s.signature)return 6;
 static const uint8_t domain[]="A1-27 device enrollment v1";
 size_t io=k.public_key+k.secret_key+k.ciphertext+64+s.public_key+s.secret_key+s.signature;
 uint8_t*data=malloc(io);uint8_t*raw=malloc(capacity+31);
 if(!data||!raw){free(data);free(raw);return 7;}
 void*work=(void*)(((uintptr_t)raw+31)&~(uintptr_t)31);
 uint8_t *kpk=data,*ksk=kpk+k.public_key,*ct=ksk+k.secret_key,*ss=ct+k.ciphertext,*ss2=ss+32;
 uint8_t *spk=ss2+32,*ssk=spk+s.public_key,*sig=ssk+s.secret_key;
 memset(data,0,io);memset(work,0,capacity);
 lc_context c;lc_random_fn random=rng.state?random_fixture:NULL;
 int exit_code=0;uint64_t*elapsed=NULL;size_t*peaks=NULL;
 int rc=a.init(&c,work,capacity,random,&rng);if(rc){exit_code=8;goto cleanup;}
 if(!fresh){rc=a.key(&c,dsa,spk,s.public_key,ssk,s.secret_key);if(rc){exit_code=8;goto cleanup;}}
 elapsed=calloc((size_t)count+16,sizeof *elapsed);peaks=calloc((size_t)count+16,sizeof *peaks);
 if(!elapsed||!peaks){exit_code=7;goto cleanup;}
 uint64_t hash=UINT64_C(1469598103934665603),batch_start=now();
 for(int i=-16;i<count;i++){
  if(i==0)batch_start=now();
  size_t high=0;uint64_t start=now();
#define STEP(call) do{rc=(call);if(rc){fprintf(stderr,"step failure %d at iteration %d line %d\n",rc,i,__LINE__);exit_code=9;goto cleanup;}if(c.arena_high_water>high)high=c.arena_high_water;}while(0)
  STEP(a.init(&c,work,capacity,random,&rng));
  if(fresh)STEP(a.key(&c,dsa,spk,s.public_key,ssk,s.secret_key));
  STEP(a.key(&c,kem,kpk,k.public_key,ksk,k.secret_key));
  STEP(a.sign(&c,dsa,sig,s.signature,kpk,k.public_key,domain,sizeof domain-1,ssk,s.secret_key));
  STEP(a.verify(&c,dsa,sig,s.signature,kpk,k.public_key,domain,sizeof domain-1,spk,s.public_key));
  STEP(a.enc(&c,kem,ct,k.ciphertext,ss,32,kpk,k.public_key));
  STEP(a.dec(&c,kem,ss2,32,ct,k.ciphertext,ksk,k.secret_key));
  if(memcmp(ss,ss2,32)){fputs("shared secret mismatch\n",stderr);exit_code=11;goto cleanup;}
  /* Retire the ephemeral secret key inside the workload boundary. */
  wipe(ksk,k.secret_key);
  if(fresh)wipe(ssk,s.secret_key);
  wipe(ss,32);wipe(ss2,32);
  uint64_t stop=now();
  elapsed[i+16]=stop-start;peaks[i+16]=high;
  hash=digest(hash,kpk,k.public_key);hash=digest(hash,ct,k.ciphertext);hash=digest(hash,sig,s.signature);
#undef STEP
 }
 uint64_t batch_end=now();
 FILE*f=fopen(argv[9],"wb");if(!f){exit_code=12;goto cleanup;}
 fputs("iteration,phase,elapsed_ns,workspace_used_bytes\n",f);
 for(int i=-16;i<count;i++)fprintf(f,"%d,%s,%llu,%zu\n",i,i<0?"warmup":"measurement",(unsigned long long)elapsed[i+16],peaks[i+16]);
 if(fclose(f)){exit_code=13;goto cleanup;}
 printf("{\"status\":\"PASS\",\"workload\":\"certificate_then_kem_exchange\",\"kem\":%d,\"dsa\":%d,\"samples\":%d,\"warmup\":16,\"fresh_authority_identity\":%s,\"workspace_bytes\":%zu,\"serialized_object_bytes\":%zu,\"context_bytes\":%zu,\"test_entropy\":%s,\"entropy_requests\":%llu,\"entropy_bytes\":%llu,\"batch_wall_ns\":%llu,\"transcript_fnv64\":\"%016llx\",\"certificate_message_bytes\":%zu,\"domain_bytes\":%zu}\n",kem,dsa,count,fresh?"true":"false",capacity,io,sizeof c,random?"true":"false",(unsigned long long)rng.requests,(unsigned long long)rng.bytes,(unsigned long long)(batch_end-batch_start),(unsigned long long)hash,k.public_key,sizeof domain-1);
cleanup:
 wipe(work,capacity);wipe(data,io);wipe(&rng,sizeof rng);free(raw);free(data);free(elapsed);free(peaks);
#ifdef _WIN32
 FreeLibrary(handle);
#else
 dlclose(handle);
#endif
 return exit_code;
}
