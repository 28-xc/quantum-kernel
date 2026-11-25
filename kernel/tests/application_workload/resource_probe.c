/* A complete certificate-and-KEM exchange in one fixed mutable-data pool,
 * with the complete application call running above a protected stack bound. */
struct job;
static void application_calls(struct job *);
static void run_calls(struct job *) __attribute__((unused));
#define R2_RESOURCE_RUN_CALLS(j) application_calls(j)
#define main single_resource_probe_main
#include "../resources/probe.c"
#undef main

typedef struct {
 api a;lc_context context;lc_sizes kem_sizes,dsa_sizes;
 int kem,dsa,completed,rc;uint64_t random_state,requests,random_bytes,transcript;
 uint8_t *objects,*work;size_t io_bytes,workspace_bytes,high;
} application_state;
static application_state *application;
static int application_rng(void*u,uint8_t*p,size_t n){
 application_state*s=u;s->requests++;s->random_bytes+=n;
 while(n--){s->random_state^=s->random_state<<13;s->random_state^=s->random_state>>7;s->random_state^=s->random_state<<17;*p++=(uint8_t)s->random_state;}return 0;
}
static uint64_t public_digest(uint64_t h,const uint8_t*p,size_t n){while(n--){h^=*p++;h*=UINT64_C(1099511628211);}return h;}
__attribute__((noinline)) static int application_flow(job*j){
 (void)j;application_state*s=application;lc_sizes*k=&s->kem_sizes,*d=&s->dsa_sizes;
 uint8_t*kpk=s->objects,*ksk=kpk+k->public_key,*ct=ksk+k->secret_key,*ss=ct+k->ciphertext,*ss2=ss+32;
 uint8_t*spk=ss2+32,*ssk=spk+d->public_key,*sig=ssk+d->secret_key;
 static const uint8_t domain[]="A1-27 device enrollment v1";
 s->completed=0;s->high=0;s->transcript=0;
 s->rc=s->a.init(&s->context,s->work,s->workspace_bytes,application_rng,s);if(s->rc)goto cleanup;
#define APP_STEP(call) do{s->rc=(call);if(s->context.arena_high_water>s->high)s->high=s->context.arena_high_water;if(s->rc)goto cleanup;s->completed++;}while(0)
 APP_STEP(s->a.key(&s->context,s->dsa,spk,d->public_key,ssk,d->secret_key));
 APP_STEP(s->a.key(&s->context,s->kem,kpk,k->public_key,ksk,k->secret_key));
 APP_STEP(s->a.sign(&s->context,s->dsa,sig,d->signature,kpk,k->public_key,domain,sizeof domain-1,ssk,d->secret_key));
 APP_STEP(s->a.verify(&s->context,s->dsa,sig,d->signature,kpk,k->public_key,domain,sizeof domain-1,spk,d->public_key));
 APP_STEP(s->a.enc(&s->context,s->kem,ct,k->ciphertext,ss,32,kpk,k->public_key));
 APP_STEP(s->a.dec(&s->context,s->kem,ss2,32,ct,k->ciphertext,ksk,k->secret_key));
 if(memcmp(ss,ss2,32)){s->rc=LC_E_INTERNAL;goto cleanup;}
 s->transcript=public_digest(UINT64_C(1469598103934665603),kpk,k->public_key);
 s->transcript=public_digest(s->transcript,ct,k->ciphertext);
 s->transcript=public_digest(s->transcript,sig,d->signature);
cleanup:
 erase(ksk,k->secret_key);erase(ss,64);erase(ssk,d->secret_key);erase(s->work,s->workspace_bytes);
 return s->rc;
#undef APP_STEP
}
static void application_calls(job*j){
 if(j->control)controlled(j,j->control==1?empty_call:j->control==2?overflow_call:heap_control);
 else controlled(j,application_flow);
}
static size_t align32(size_t n){return (n+31)&~(size_t)31;}
static int setup_application(job*j,size_t pool,int kem,int dsa,uint64_t seed){
 lc_sizes k,d;if(j->a.sizes(kem,&k)||j->a.sizes(dsa,&d)||!k.ciphertext||!d.signature)return 0;
 size_t io=k.public_key+k.secret_key+k.ciphertext+64+d.public_key+d.secret_key+d.signature;
 size_t objects_offset=align32(sizeof(application_state)),work_offset=align32(objects_offset+io);
 if(pool<work_offset+32||!workspace(j,pool))return 0;
 application=(application_state*)j->arena;memset(application,0,sizeof *application);
 application->a=j->a;application->kem_sizes=k;application->dsa_sizes=d;application->kem=kem;application->dsa=dsa;
 application->random_state=seed;application->objects=j->arena+objects_offset;application->work=j->arena+work_offset;
 application->io_bytes=io;application->workspace_bytes=pool-work_offset;memset(application->objects,0,io);return 1;
}
int main(int argc,char**argv){
#ifdef _WIN32
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
#endif
 if(argc!=9){fputs("application_resource library kem dsa total_budget stack globals seed control\n",stderr);return 2;}
 int kem=atoi(argv[2]),dsa=atoi(argv[3]),control=atoi(argv[8]);
 size_t budget=strtoull(argv[4],NULL,10),stack=strtoull(argv[5],NULL,10),globals=strtoull(argv[6],NULL,10);
 uint64_t seed=strtoull(argv[7],NULL,10);
 if(!seed||budget>1048576||stack<256||stack>65536||stack%16||control<0||control>3||budget<=stack+globals+sizeof application)return 3;
 job*j=calloc(1,sizeof *j);if(!j)return 4;if(!load(&j->a,argv[1]))return 5;
 j->stack_target=stack;j->seed=seed;j->marker=seed&1?0xa5:0x5a;j->control=control;
#ifdef _WIN32
 if(!memory_image_inventory((HMODULE)j->a.handle)||!memory_audit_install((HMODULE)j->a.handle))return 6;
#else
#define APP_HOOK(f,n) do{void*p=dlsym(RTLD_DEFAULT,n);if(!p||sizeof p!=sizeof f)return 6;memcpy(&f,&p,sizeof p);}while(0)
 APP_HOOK(heap_reset,"r2_heap_reset");APP_HOOK(heap_enable,"r2_heap_enable");APP_HOOK(heap_snapshot,"r2_heap_snapshot");
 APP_HOOK(control_calloc,"calloc");APP_HOOK(control_realloc,"realloc");APP_HOOK(control_free,"free");
#undef APP_HOOK
#endif
 /* The reference transcript is produced outside the bounded execution. */
 if(!setup_application(j,262144,kem,dsa,seed)||application_flow(j))return 7;
 uint64_t expected=application->transcript;free_workspace(j);
 size_t pool=(budget-stack-globals-sizeof application)&~(size_t)31;
 if(!setup_application(j,pool,kem,dsa,seed)){
  printf("{\"status\":\"POOL_TOO_SMALL\",\"budget_bytes\":%zu,\"pool_bytes\":%zu}\n",budget,pool);return 0;
 }
#ifndef _WIN32
 heap_reset();
#endif
 printf("{\"event\":\"application_start\",\"budget_bytes\":%zu,\"pool_bytes\":%zu,\"stack_bytes\":%zu,\"control\":%d}\n",budget,pool,stack,control);fflush(stdout);
 int wr;
#ifdef _WIN32
 HANDLE thread=CreateThread(NULL,131072,worker,j,STACK_SIZE_PARAM_IS_A_RESERVATION,NULL);if(!thread)return 8;
 WaitForSingleObject(thread,INFINITE);DWORD code;GetExitCodeThread(thread,&code);CloseHandle(thread);wr=(int)code;
 j->heap[0]=audit_calls;j->heap[1]=audit_free_calls;j->heap[2]=audit_live;j->heap[3]=audit_peak;j->heap[4]=audit_errors;
#else
 wr=worker(j);heap_snapshot(j->heap);
#endif
 int integrity=wr||j->guard_error||!guards(j)||j->heap[4]||application->high>application->workspace_bytes;
 int matched=application->transcript==expected;
 if(!control&&j->rc==0&&(application->completed!=6||!matched||j->heap[3]))integrity=1;
 if(!control&&j->rc!=0&&j->rc!=LC_E_WORKSPACE)integrity=1;
 printf("{\"event\":\"application_result\",\"status\":\"%s\",\"kem\":%d,\"dsa\":%d,\"seed\":%" PRIu64 ",\"control\":%d,\"rc\":%d,\"completed_operations\":%d,\"transcript_matches\":%s,\"total_budget_bytes\":%zu,\"charged_bytes\":%zu,\"pool_bytes\":%zu,\"application_state_bytes\":%zu,\"serialized_object_bytes\":%zu,\"workspace_bytes\":%zu,\"workspace_high_water_bytes\":%zu,\"stack_reserved_bytes\":%zu,\"stack_watermark_bytes\":%zu,\"globals_and_tls_bytes\":%zu,\"application_pointer_bytes\":%zu,\"external_heap_peak_bytes\":%" PRIu64 ",\"canaries_ok\":%s,\"guard_error\":%d,\"heap_errors\":%" PRIu64 ",\"os_stack_mapping_bytes\":%zu}\n",
  integrity?"INVALID":j->rc==LC_E_WORKSPACE?"WORKSPACE_INSUFFICIENT":"PASS",kem,dsa,seed,control,j->rc,application->completed,matched?"true":"false",budget,pool+stack+globals+sizeof application,pool,sizeof *application,application->io_bytes,application->workspace_bytes,application->high,stack,j->observed,globals,sizeof application,j->heap[3],guards(j)?"true":"false",j->guard_error,j->heap[4],j->os_reserved);
 free_workspace(j);free(j);application=NULL;return integrity?9:0;
}
