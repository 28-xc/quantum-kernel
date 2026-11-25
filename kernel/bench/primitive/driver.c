/* Supplemental arithmetic primitive oracles and batch timing.
 * Existing algorithm archive symbols and the canonical research component are
 * distinct builds. No result here is an end-to-end algorithm measurement. */
#define _GNU_SOURCE
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#else
#include <sched.h>
#include <time.h>
#endif
#include "lc_poly.h"
#include "actual_backend.h"
#define N 256
#define GUARD UINT32_C(0x96a127dd)
typedef struct {
 uint32_t before[8];KVectors a,b;KCaches cache;KPoly ko;DPoly da,db;
 uint32_t ca[N],cb[N],co[N],raw_a[4][N],raw_b[4][N];uint32_t after[8];
} ALIGN State;
static uint64_t rng;
static uint32_t next(void){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return (uint32_t)rng;}
static uint32_t mod(int64_t x,uint32_t q){x%=q;return (uint32_t)(x<0?x+q:x);}
static void oracle(uint32_t *out,const uint32_t *a,const uint32_t *b,uint32_t q){
 int64_t acc[N]={0};for(int i=0;i<N;i++)for(int j=0;j<N;j++){int k=i+j;acc[k&255]+=(k<N?1:-1)*(int64_t)a[i]*b[j];}
 for(int i=0;i<N;i++)out[i]=mod(acc[i],q);
}
static int guards(const State *s){for(int i=0;i<8;i++)if(s->before[i]!=GUARD||s->after[i]!=GUARD)return 0;return 1;}
static void prepare(State *s,uint32_t q,int op,int k,int kind){
 memset(s,0,sizeof(*s));for(int i=0;i<8;i++)s->before[i]=s->after[i]=GUARD;
 int rank=LC_ACTUAL_BACKEND&&q==3329&&op==4?k:1;
 for(int v=0;v<rank;v++)for(int i=0;i<N;i++){
  s->raw_a[v][i]=kind==1?0:kind==2?q-1:next()%q;
  s->raw_b[v][i]=kind==1?1:kind==2?q-1:next()%q;
 }
 if(kind==3){memset(s->raw_a,0,sizeof s->raw_a);memset(s->raw_b,0,sizeof s->raw_b);s->raw_a[0][255]=s->raw_b[0][1]=1;}
 memcpy(s->ca,s->raw_a[0],sizeof s->ca);memcpy(s->cb,s->raw_b[0],sizeof s->cb);
#if LC_ACTUAL_BACKEND
 if(q==3329){
  for(int v=0;v<k;v++){
   KPoly *a=kp(&s->a,k,v),*b=kp(&s->b,k,v);
   for(int i=0;i<N;i++){a->coeffs[i]=(int16_t)s->raw_a[v][i];b->coeffs[i]=(int16_t)s->raw_b[v][i];}
   if(op==3&&v==0){kn(a);kr(a);}
   if(op==4){kn(a);kr(a);kn(b);kmc(kc(&s->cache,k,v),b);}
  }
 }else{
  for(int i=0;i<N;i++){s->da.coeffs[i]=(int32_t)s->raw_a[0][i];s->db.coeffs[i]=(int32_t)s->raw_b[0][i];}
  if(op==3||op==4){dn(&s->da);dr(&s->da);}
  if(op==4){dn(&s->db);dr(&s->db);}
 }
#else
 (void)k;
 if(op==3||op==4)lc_poly_ntt(q,s->ca);
 if(op==4)lc_poly_ntt(q,s->cb);
#endif
}
static int operation(State *s,uint32_t q,int op,int k){
#if LC_ACTUAL_BACKEND
 if(q==3329){
  if(op==2)kn(kp(&s->a,k,0));
  else if(op==3)ki(kp(&s->a,k,0));
  else if(op==4)kd(&s->ko,&s->a,&s->b,&s->cache,k);
  else if(op==5){kn(kp(&s->a,k,0));kr(kp(&s->a,k,0));kn(kp(&s->b,k,0));kmc(kc(&s->cache,k,0),kp(&s->b,k,0));kd(&s->ko,&s->a,&s->b,&s->cache,k);ki(&s->ko);kr(&s->ko);}
  else return -1;
 }else{
  if(op==2)dn(&s->da);else if(op==3)di(&s->da);else if(op==4)dp(&s->da,&s->db);
  else if(op==5){dn(&s->da);dn(&s->db);dp(&s->da,&s->db);di(&s->da);dr(&s->da);}else return -1;
 }
 return 0;
#else
 (void)k;
 switch(op){case 0:return lc_poly_add(q,s->co,s->ca,s->cb);case 1:return lc_poly_sub(q,s->co,s->ca,s->cb);case 2:return lc_poly_ntt(q,s->ca);case 3:return lc_poly_intt(q,s->ca);case 4:return lc_poly_basemul(q,s->co,s->ca,s->cb);case 5:return lc_poly_mul(q,s->co,s->ca,s->cb);default:return -1;}
#endif
}
static uint32_t coefficient(State *s,uint32_t q,int op,int k,int i){
#if LC_ACTUAL_BACKEND
 if(q==3329)return mod(op<4?kp(&s->a,k,0)->coeffs[i]:s->ko.coeffs[i],q);
 return mod(s->da.coeffs[i],q);
#else
 (void)q;(void)k;return op==2||op==3?s->ca[i]:s->co[i];
#endif
}
static int check(State *s,uint32_t q,int op,int k){
 uint32_t expected[N],extra[N];if(!guards(s))return 1;
 if(op==0||op==1){for(int i=0;i<N;i++)expected[i]=mod((int64_t)s->raw_a[0][i]+(op?-(int64_t)s->raw_b[0][i]:s->raw_b[0][i]),q);}
 else if(op==2){
  memcpy(expected,s->raw_a[0],sizeof expected);lc_poly_ntt(q,expected);
#if LC_ACTUAL_BACKEND
  if(q==3329){KPoly order;for(int i=0;i<N;i++)order.coeffs[i]=(int16_t)expected[i];kperm(&order);for(int i=0;i<N;i++)expected[i]=(uint16_t)order.coeffs[i];}
  else{DPoly order;for(int i=0;i<N;i++)order.coeffs[i]=(int32_t)expected[i];dperm(&order);for(int i=0;i<N;i++)expected[i]=(uint32_t)order.coeffs[i];}
#endif
 }
 else if(op==3){uint32_t scale=LC_ACTUAL_BACKEND?(q==3329?2285:4193792):1;for(int i=0;i<N;i++)expected[i]=mod((int64_t)s->raw_a[0][i]*scale,q);}
 else{
  memset(expected,0,sizeof expected);int rank=LC_ACTUAL_BACKEND&&q==3329&&op==4?k:1;
  for(int v=0;v<rank;v++){oracle(extra,s->raw_a[v],s->raw_b[v],q);for(int i=0;i<N;i++)expected[i]=(expected[i]+extra[i])%q;}
  if(op==4){
#if LC_ACTUAL_BACKEND
   if(q==3329){ki(&s->ko);kr(&s->ko);}else{di(&s->da);dr(&s->da);}
#else
   lc_poly_intt(q,s->co);
#endif
  }
 }
 for(int i=0;i<N;i++)if(coefficient(s,q,op,k,i)!=expected[i])return 2;
 return guards(s)?0:3;
}
static int verification(int cases,uint64_t seed){
 rng=seed;State s;int executed=0;
 for(int family=0;family<2;family++){
  uint32_t q=family?8380417:3329;
  for(int op=LC_ACTUAL_BACKEND?2:0;op<6;op++)for(int k=2;k<=(LC_ACTUAL_BACKEND&&q==3329&&op==4?4:2);k++)for(int n=0;n<cases;n++){
   prepare(&s,q,op,k,n<4?n:0);if(operation(&s,q,op,k)||check(&s,q,op,k)){fprintf(stderr,"oracle mismatch q=%u op=%d rank=%d case=%d\n",q,op,k,n);return 1;}executed++;
  }
 }
 printf("{\"status\":\"PASS\",\"component\":\"%s\",\"cases\":%d,\"cases_per_operation\":%d,\"seed\":%" PRIu64 ",\"schoolbook_accumulator\":\"signed 64 bit; <=256*(q-1)^2 per product\",\"canaries\":true,\"roundtrip_scale\":\"%s\"}\n",LC_ACTUAL_BACKEND?"actual_archive_backend":"canonical_research_component",executed,cases,seed,LC_ACTUAL_BACKEND?"R=2^16 mod3329 or 2^32 mod8380417":"1, without Montgomery scale");return 0;
}
static uint64_t ticks(void){
#ifdef _WIN32
 LARGE_INTEGER t;if(!QueryPerformanceCounter(&t))abort();return (uint64_t)t.QuadPart;
#else
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))abort();return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;
#endif
}
static uint64_t frequency(void){
#ifdef _WIN32
 LARGE_INTEGER f;if(!QueryPerformanceFrequency(&f))abort();return (uint64_t)f.QuadPart;
#else
 return UINT64_C(1000000000);
#endif
}
static int pin(int cpu){
#ifdef _WIN32
 DWORD_PTR allowed,system;if(cpu<0||cpu>=64||!GetProcessAffinityMask(GetCurrentProcess(),&allowed,&system)||!(allowed&((DWORD_PTR)1<<cpu)))return 0;
 return SetThreadAffinityMask(GetCurrentThread(),(DWORD_PTR)1<<cpu)!=0;
#else
 cpu_set_t s;if(cpu<0||cpu>=CPU_SETSIZE)return 0;CPU_ZERO(&s);CPU_SET(cpu,&s);return sched_setaffinity(0,sizeof s,&s)==0;
#endif
}
static void *alloc_aligned(size_t n){
#ifdef _WIN32
 return _aligned_malloc(n,32);
#else
 return aligned_alloc(32,n);
#endif
}
static void free_aligned(void *p){
#ifdef _WIN32
 _aligned_free(p);
#else
 free(p);
#endif
}
int main(int argc,char **argv){
 if(argc==4&&!strcmp(argv[1],"--verify")){int n=atoi(argv[2]);uint64_t seed=strtoull(argv[3],0,10);if(n<4||n>10000||!seed)return 2;return verification(n,seed);}
 if(argc==2&&!strcmp(argv[1],"--negative-control")){
  State s;rng=517;prepare(&s,8380417,5,2,0);if(operation(&s,8380417,5,2))return 2;
#if LC_ACTUAL_BACKEND
  s.da.coeffs[0]^=1;
#else
  s.co[0]^=1;
#endif
  if(!check(&s,8380417,5,2))return 3;
  puts("{\"status\":\"PASS_DETECTED_WRONG_OUTPUT\",\"oracle\":\"independent_schoolbook\"}");return 0;
 }
 if(argc!=10||strcmp(argv[1],"--measure")){fputs("--verify cases seed | --negative-control | --measure q op rank batches calls seed cpu new.csv\n",stderr);return 2;}
 uint32_t q=(uint32_t)strtoul(argv[2],0,10);int op=atoi(argv[3]),k=atoi(argv[4]),batches=atoi(argv[5]),calls=atoi(argv[6]),cpu=atoi(argv[8]);rng=strtoull(argv[7],0,10);
 if((q!=3329&&q!=8380417)||op<(LC_ACTUAL_BACKEND?2:0)||op>5||k<2||k>4||((q!=3329||op!=4)&&k!=2)||batches<1||batches>1000||calls<1||calls>1000||!rng||!pin(cpu))return 3;
 FILE *old=fopen(argv[9],"rb");if(old){fclose(old);return 4;}
 State *original=alloc_aligned((size_t)calls*sizeof(State)),*work=alloc_aligned((size_t)calls*sizeof(State));if(!original||!work)return 5;
 FILE *f=fopen(argv[9],"wb");if(!f)return 6;fputs("batch,warmup,calls,elapsed_ticks,tick_frequency,batch_mean_ns,checksum,status\n",f);uint64_t freq=frequency(),checksum=0;int status=0;
 for(int b=-10;b<batches;b++){
  for(int i=0;i<calls;i++)prepare(original+i,q,op,k,0);
  memcpy(work,original,(size_t)calls*sizeof(State));
  uint64_t t0=ticks();for(int i=0;i<calls;i++)status|=operation(work+i,q,op,k);uint64_t t1=ticks();
  for(int i=0;i<calls;i++){checksum+=coefficient(work+i,q,op,k,(i+b+10)%N);if(!guards(work+i))status|=1;}
  fprintf(f,"%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%.9f,%" PRIu64 ",%d\n",b,b<0,calls,t1-t0,freq,(double)(t1-t0)*1e9/freq/calls,checksum,status);
  if(status)break;
 }
 fclose(f);free_aligned(original);free_aligned(work);
 printf("{\"status\":\"%s\",\"component\":\"%s\",\"q\":%u,\"op\":%d,\"rank\":%d,\"batches\":%d,\"warmup_batches_retained\":10,\"calls_per_batch\":%d,\"cpu\":%d,\"frequency\":%" PRIu64 ",\"not_individual_call_percentiles\":true,\"not_end_to_end\":true,\"checksum\":%" PRIu64 "}\n",status?"FAIL":"PASS",LC_ACTUAL_BACKEND?"actual_archive_backend":"canonical_research_component",q,op,k,batches,calls,cpu,freq,checksum);return status?7:0;
}
