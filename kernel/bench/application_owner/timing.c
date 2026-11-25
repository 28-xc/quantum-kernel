/* SPDX-License-Identifier: Apache-2.0
 * One complete application batch, including final app_close. Pool allocation,
 * the independent wide-workspace receipt, and post-call checks are external. */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "application.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#endif

typedef struct { void *allocation; uint8_t *pool; size_t bytes; } pool_owner;
typedef struct { uint64_t transcript, flows; unsigned completed; int rc; } receipt;
static uint64_t frequency;
static int measured;
static uint64_t counter(void) {
#ifdef _WIN32
    LARGE_INTEGER value;
    if (!QueryPerformanceCounter(&value)) abort();
    return (uint64_t)value.QuadPart;
#else
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &value)) abort();
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
#endif
}
static int integer(const char *text, uint64_t *value) {
    char *end;
    if (!text[0]) return 0;
    for (const char *p=text; *p; p++) if (*p<'0'||*p>'9') return 0;
    errno=0; unsigned long long n=strtoull(text,&end,10);
    if (errno||*end) return 0;
    *value=(uint64_t)n; return 1;
}
static int load(app_api *api, const char *path) {
#ifdef _WIN32
    HMODULE module=LoadLibraryA(path);
    if (!module) return 0;
#define LOAD(field,name) do { FARPROC p=GetProcAddress(module,name); if(!p||sizeof p!=sizeof api->field)return 0; memcpy(&api->field,&p,sizeof p); } while(0)
#else
    void *module=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if (!module) return 0;
#define LOAD(field,name) do { void *p=dlsym(module,name); if(!p||sizeof p!=sizeof api->field)return 0; memcpy(&api->field,&p,sizeof p); } while(0)
#endif
    LOAD(init,"lc_context_init"); LOAD(sizes,"lc_get_sizes"); LOAD(key,"lc_keypair");
    LOAD(enc,"lc_encaps"); LOAD(dec,"lc_decaps"); LOAD(sign,"lc_sign"); LOAD(verify,"lc_verify");
#undef LOAD
    return 1;
}
static pool_owner allocate(size_t bytes) {
    pool_owner p={0};
    if (!bytes||bytes>SIZE_MAX-95) return p;
    p.allocation=malloc(bytes+95);
    if (!p.allocation) return p;
    p.pool=(uint8_t *)(((uintptr_t)p.allocation+63)&~(uintptr_t)31);
    p.bytes=bytes;
    memset(p.pool-32,0xa5,32); memset(p.pool,0,bytes); memset(p.pool+bytes,0x5a,32);
    return p;
}
static int intact(const pool_owner *p) {
    for (size_t i=0;i<32;i++) if((p->pool-32)[i]!=0xa5||p->pool[p->bytes+i]!=0x5a)return 0;
    return 1;
}
static int zero(const pool_owner *p) {
    uint8_t value=0;
    for(size_t i=0;i<p->bytes;i++) value|=p->pool[i];
    return value==0;
}
static receipt run(pool_owner *pool,const app_api *api,int kem,int dsa,int layout,int fresh,
                   size_t workspace,uint64_t seed,unsigned flows,uint64_t *elapsed) {
    receipt result={0};
    uint64_t begin=measured?counter():0;
    app_state *state=app_open(pool->pool,pool->bytes,api,kem,dsa,layout,fresh,workspace,seed);
    if (!state) result.rc=LC_E_INTERNAL;
    else {
        result.rc=app_prepare(state);
        for(unsigned i=0;!result.rc&&i<flows;i++) result.rc=app_flow(state);
        app_finish(state);
        /* Capture only public receipt fields before final metadata erasure. */
        result.transcript=state->transcript; result.flows=state->flows;
        result.completed=(unsigned)state->completed;
        app_close(state);
    }
    if (measured) *elapsed=counter()-begin;
    return result;
}
int main(int argc,char **argv) {
    /* library kem dsa layout fresh workspace seed flows cpu mode(0 verify/1 measure) */
    if(argc!=11) return 2;
    uint64_t v[9];
    for(int i=0;i<9;i++) if(!integer(argv[i+2],&v[i])) return 2;
    int kem=(int)v[0],dsa=(int)v[1],layout=(int)v[2],fresh=(int)v[3];
    if(!((v[0]==512&&v[1]==44)||(v[0]==768&&v[1]==65)||(v[0]==1024&&v[1]==87))||v[2]>1||v[3]>1||v[4]<32||v[4]>1048576||v[4]%32||!v[5]||!(v[6]==1||v[6]==200)||v[7]>1048575||v[8]>1)return 2;
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    if(v[7]>=sizeof(DWORD_PTR)*8||!SetProcessAffinityMask(GetCurrentProcess(),(DWORD_PTR)1<<v[7]))return 3;
    LARGE_INTEGER f; if(!QueryPerformanceFrequency(&f))return 3; frequency=(uint64_t)f.QuadPart;
#else
    if(v[7]>=CPU_SETSIZE)return 3;
    cpu_set_t cpus;CPU_ZERO(&cpus);CPU_SET((unsigned)v[7],&cpus);
    if(sched_setaffinity(0,sizeof cpus,&cpus))return 3;
    frequency=UINT64_C(1000000000);
#endif
    app_api api;
    if(!load(&api,argv[1]))return 4;
    size_t workspace=(size_t)v[4]; uint64_t seed=v[5]; unsigned flows=(unsigned)v[6];
    pool_owner reference=allocate(app_pool_bytes(&api,kem,dsa,APP_SEPARATE,262144));
    if(!reference.pool)return 5;
    uint64_t unused=0; measured=0;
    receipt oracle=run(&reference,&api,kem,dsa,APP_SEPARATE,fresh,262144,seed,flows,&unused);
    int oracle_ok=!oracle.rc&&oracle.flows==flows&&intact(&reference)&&zero(&reference);
    free(reference.allocation);
    if(!oracle_ok)return 6;
    pool_owner current=allocate(app_pool_bytes(&api,kem,dsa,layout,workspace));
    if(!current.pool)return 5;
    uint64_t elapsed=0;measured=(int)v[8];
    receipt actual=run(&current,&api,kem,dsa,layout,fresh,workspace,seed,flows,&elapsed);
    int guards=intact(&current),cleared=zero(&current);
    int matches=actual.transcript==oracle.transcript&&actual.flows==oracle.flows&&actual.completed==oracle.completed;
    int ok=!actual.rc&&actual.flows==flows&&actual.completed==(unsigned)(5+fresh)&&guards&&cleared&&matches;
    printf("{\"status\":\"%s\",\"kem\":%d,\"dsa\":%d,\"layout\":%d,\"fresh_identity\":%d,\"rc\":%d,\"iterations\":%u,\"completed_flows\":%" PRIu64 ",\"last_flow_operations\":%u,\"transcript\":\"%016" PRIx64 "\",\"transcript_matches\":%s,\"seed\":%" PRIu64 ",\"pool_bytes\":%zu,\"workspace_bytes\":%zu,\"guards_ok\":%s,\"cleared\":%s,\"timed\":%s,\"batch_ticks\":%" PRIu64 ",\"frequency\":%" PRIu64 ",\"cpu\":%" PRIu64 ",\"heap_instrumented\":false,\"final_close_included\":true}\n",
           ok?"PASS":"INVALID",kem,dsa,layout,fresh,actual.rc,flows,actual.flows,actual.completed,actual.transcript,
           matches?"true":"false",seed,current.bytes,workspace,guards?"true":"false",cleared?"true":"false",
           measured?"true":"false",elapsed,frequency,v[7]);
    free(current.allocation);
    return ok?0:7;
}
