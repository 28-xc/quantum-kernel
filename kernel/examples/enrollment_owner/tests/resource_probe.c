/* SPDX-License-Identifier: Apache-2.0
 * The ordinary and reused layouts run the same fixed-pool workload above a
 * protected stack boundary. The external controller owns only measurements. */
struct job;
static void application_calls(struct job*);
static void run_calls(struct job*) __attribute__((unused));
#define R2_RESOURCE_RUN_CALLS(j) application_calls(j)
#define main single_resource_probe_main
#include "resources_pq/probe.c"
#undef main
#include "application.h"
#ifndef _WIN32
#include <time.h>
#endif
static app_state *active;
static uint64_t batch_ticks,batch_frequency;
static unsigned iterations,timing_enabled;
static uint64_t ticks(void){
#ifdef _WIN32
 LARGE_INTEGER t;if(!QueryPerformanceCounter(&t))abort();return (uint64_t)t.QuadPart;
#else
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))abort();return (uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;
#endif
}
__attribute__((noinline)) static int application_batch(job*j){
 (void)j;uint64_t start=timing_enabled?ticks():0;
 /* The preallocated pool and resolved function addresses are inputs. All
    application-state initialization and context preparation occur here. */
 app_api selected=active->api;
 active=app_open(active,active->pool_bytes,&selected,active->kem,active->dsa,
                 active->layout,active->fresh,active->workspace_bytes,active->entropy);
 if(!active)return LC_E_INTERNAL;
 int rc=app_prepare(active);
 for(unsigned i=0;!rc&&i<iterations;i++)rc=app_flow(active);
 app_finish(active);
 if(timing_enabled)batch_ticks=ticks()-start;
 return rc;
}
static void application_calls(job*j){
 if(j->control)controlled(j,j->control==1?empty_call:j->control==2?overflow_call:heap_control);
 else controlled(j,application_batch);
}
static app_api application_api(const api*a){
 app_api b={a->init,a->sizes,a->key,a->enc,a->dec,a->sign,a->verify};return b;
}
static size_t app_globals(void){return sizeof active+sizeof batch_ticks+sizeof batch_frequency+sizeof iterations+sizeof timing_enabled;}
static int setup(job*j,const app_api*a,int kem,int dsa,int layout,int fresh,size_t capacity,uint64_t seed){
 size_t n=app_pool_bytes(a,kem,dsa,layout,capacity);if(!n||!workspace(j,n))return 0;
 active=app_open(j->arena,j->capacity,a,kem,dsa,layout,fresh,capacity,seed);return active!=NULL;
}
int main(int argc,char**argv){
#ifdef _WIN32
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
#endif
 if(argc!=14&&argc!=15){fputs("owner_resource library kem dsa layout fresh workspace stack globals seed iterations timing control heap_capacity [application_module_globals]\n",stderr);return 2;}
 int kem=atoi(argv[2]),dsa=atoi(argv[3]),layout=atoi(argv[4]),fresh=atoi(argv[5]);
 size_t work=strtoull(argv[6],NULL,10),stack=strtoull(argv[7],NULL,10),globals=strtoull(argv[8],NULL,10);
 uint64_t seed=strtoull(argv[9],NULL,10);iterations=(unsigned)strtoul(argv[10],NULL,10);timing_enabled=(unsigned)strtoul(argv[11],NULL,10);int control=atoi(argv[12]);size_t heap_capacity=strtoull(argv[13],NULL,10);size_t module_globals=argc==15?strtoull(argv[14],NULL,10):0;
 if(!seed||!iterations||iterations>10000||timing_enabled>1||stack<256||stack>262144||stack%16||control<0||control>3)return 3;
 job*j=calloc(1,sizeof *j);if(!j)return 4;if(!load(&j->a,argv[1]))return 5;
 j->stack_target=stack;j->seed=seed;j->marker=seed&1?0xa5:0x5a;j->control=control;
#ifdef _WIN32
 if(!memory_image_inventory((HMODULE)j->a.handle)||!memory_audit_install((HMODULE)j->a.handle))return 6;
 LARGE_INTEGER freq;if(!QueryPerformanceFrequency(&freq))return 6;batch_frequency=(uint64_t)freq.QuadPart;
 if(!SetProcessAffinityMask(GetCurrentProcess(),(DWORD_PTR)4))return 6;
#else
#define APP_HOOK(f,n) do{void*p=dlsym(RTLD_DEFAULT,n);if(!p||sizeof p!=sizeof f)return 6;memcpy(&f,&p,sizeof p);}while(0)
 APP_HOOK(heap_reset,"r2_heap_reset");APP_HOOK(heap_enable,"r2_heap_enable");APP_HOOK(heap_snapshot,"r2_heap_snapshot");
 APP_HOOK(control_calloc,"calloc");APP_HOOK(control_realloc,"realloc");APP_HOOK(control_free,"free");
#undef APP_HOOK
 batch_frequency=1000000000;
#endif
 app_api a=application_api(&j->a);
 /* The paired ordinary-layout transcript is an external qualification oracle.
    No raw key, signature or shared-secret value is exported. */
 unsigned timed=timing_enabled;timing_enabled=0;
 if(!setup(j,&a,kem,dsa,APP_SEPARATE,fresh,262144,seed)||application_batch(j))return 7;
 uint64_t expected=active->transcript;free_workspace(j);timing_enabled=timed;
 if(!setup(j,&a,kem,dsa,layout,fresh,work,seed))return 7;
#ifndef _WIN32
 heap_reset();
#endif
 int wr;
#ifdef _WIN32
 audit_active=1;HANDLE thread=CreateThread(NULL,1048576,worker,j,STACK_SIZE_PARAM_IS_A_RESERVATION,NULL);if(!thread)return 8;
 WaitForSingleObject(thread,INFINITE);DWORD code;GetExitCodeThread(thread,&code);CloseHandle(thread);wr=(int)code;audit_active=0;if(audit_tlsalloc_calls)j->guard_error=7;
 j->heap[0]=audit_calls;j->heap[1]=audit_free_calls;j->heap[2]=audit_live;j->heap[3]=audit_peak;j->heap[4]=audit_errors;
#else
 wr=worker(j);heap_snapshot(j->heap);
#endif
 int clear=1;for(size_t i=0;i<active->object_bytes;i++)if(active->objects[i])clear=0;
 for(size_t i=0;i<active->workspace_bytes;i++)if(active->work[i])clear=0;
 int matched=active->transcript==expected;
 int integrity=wr||j->guard_error||!guards(j)||j->heap[4]||active->high>active->workspace_bytes;
 if(!control&&!j->rc&&(!matched||active->flows!=iterations||j->heap[3]>heap_capacity||!clear||active->entropy))integrity=1;
 if(!control&&j->rc&&j->rc!=LC_E_WORKSPACE)integrity=1;
 printf("{\"status\":\"%s\",\"kem\":%d,\"dsa\":%d,\"layout\":%d,\"fresh_identity\":%d,\"rc\":%d,\"iterations\":%u,\"completed_flows\":%" PRIu64 ",\"last_flow_operations\":%d,\"transcript\":\"%016" PRIx64 "\",\"transcript_matches\":%s,\"seed\":%" PRIu64 ",\"pool_bytes\":%zu,\"application_state_bytes\":%zu,\"serialized_owner_bytes\":%zu,\"workspace_bytes\":%zu,\"workspace_high_water\":%zu,\"stack_reserved_bytes\":%zu,\"stack_watermark_bytes\":%zu,\"library_globals_tls_bytes\":%zu,\"application_globals_bytes\":%zu,\"application_module_globals_bytes\":%zu,\"charged_bytes\":%zu,\"outside_heap_peak\":%" PRIu64 ",\"guards_ok\":%s,\"cleared\":%s,\"timed\":%s,\"batch_ticks\":%" PRIu64 ",\"frequency\":%" PRIu64 ",\"heap_errors\":%" PRIu64 "}\n",
 integrity?"INVALID":j->rc==LC_E_WORKSPACE?"WORKSPACE_INSUFFICIENT":"PASS",kem,dsa,layout,fresh,j->rc,iterations,active->flows,active->completed,active->transcript,matched?"true":"false",seed,active->pool_bytes,sizeof *active,active->object_bytes,active->workspace_bytes,active->high,stack,j->observed,globals,app_globals(),module_globals,active->pool_bytes+stack+globals+app_globals()+module_globals+heap_capacity,j->heap[3],guards(j)?"true":"false",clear?"true":"false",timing_enabled?"true":"false",batch_ticks,batch_frequency,j->heap[4]);
#ifdef _WIN32
 printf("{\"event\":\"heap_lifetime\",\"reserved_bound\":%zu,\"peak_requested\":%zu,\"retained_requested\":%zu,\"allocations\":%zu,\"frees\":%zu,\"tls_slot_allocations\":%zu,\"hooks\":%zu,\"unsupported\":%zu}\n",heap_capacity,audit_peak,audit_live,audit_calls,audit_free_calls,audit_tlsalloc_calls,audit_hooked,audit_unsupported);
#else
 printf("{\"event\":\"heap_lifetime\",\"reserved_bound\":%zu,\"peak_requested\":%zu,\"retained_requested\":%zu,\"allocations\":%zu,\"frees\":%zu,\"tls_slot_allocations\":%zu,\"hooks\":%zu,\"unsupported\":%zu}\n",heap_capacity,(size_t)j->heap[3],(size_t)j->heap[2],(size_t)j->heap[0],(size_t)j->heap[1],(size_t)0,(size_t)4,(size_t)0);
#endif
 app_close(active);active=NULL;free_workspace(j);free(j);return integrity?9:0;
}
