/* Public-API resource probe. Product binaries are loaded unchanged.
 * A protected lower stack boundary is enforced for every call. This is a
 * finite-input operating envelope, never a whole-input static stack proof. */
#define _GNU_SOURCE
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#else
#include <dlfcn.h>
#include <link.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>
#endif
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "latticecore.h"
#ifdef _WIN32
#include "windows_heap_audit.h"
#endif
typedef struct {
 int (*init)(lc_context*,void*,size_t,lc_random_fn,void*);
 int (*sizes)(int,lc_sizes*);
 int (*key)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t);
 int (*enc)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t,const uint8_t*,size_t);
 int (*dec)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*sign)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*verify)(lc_context*,int,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 void *handle;
} api;
typedef struct { uint8_t pk[2592],sk[4896],ct[1568],ss[32],ss2[32],sig[4627]; } outputs;
typedef struct job {
 api a;lc_context context;lc_sizes sizes;int level,op,requested_op,control,rc,guard_error,init_rc;
 uint64_t seed;uint8_t coins[64],message[1024],marker;outputs out,want;
 uint8_t *allocation,*arena;size_t capacity,stack_target;
 int step_rc[3],step_match[3],step_clear[3],step_wiped[3];size_t step_high[3],step_watermark[3],step_nonzero[3],step_changed_nonzero[3];
 size_t high,init_watermark,observed,allocation_failures;
 uintptr_t lower,top,protected_start,original_base;
 size_t protected_bytes,os_reserved,os_committed,original_stack_limit,os_page;int original_stack_limit_known;
 size_t image_mapped,image_rw,image_ro,original_stack_mapped;int image_mapping_known;
 uint64_t heap[5];int heap_available;
} job;
#ifndef R2_RESOURCE_RUN_CALLS
#define R2_RESOURCE_RUN_CALLS(j) run_calls(j)
#endif
extern int lc_memory_call_at(job*,uintptr_t,int(*)(job*));
#ifndef _WIN32
static void (*heap_reset)(void),(*heap_enable)(int),(*heap_snapshot)(uint64_t*);
static void *(*control_calloc)(size_t,size_t),*(*control_realloc)(void*,size_t);
static void (*control_free)(void*);
typedef struct {uintptr_t base,lo[32],hi[32];size_t n,page;} image_ranges;
static int image_phdr(struct dl_phdr_info*info,size_t bytes,void*arg){(void)bytes;image_ranges*x=arg;if((uintptr_t)info->dlpi_addr!=x->base)return 0;
 for(unsigned i=0;i<info->dlpi_phnum;i++){
  if(info->dlpi_phdr[i].p_type==PT_LOAD){if(x->n==32)return 1;uintptr_t a=x->base+info->dlpi_phdr[i].p_vaddr,b=a+info->dlpi_phdr[i].p_memsz;x->lo[x->n]=a&~(uintptr_t)(x->page-1);x->hi[x->n]=(b+x->page-1)&~(uintptr_t)(x->page-1);x->n++;}
 }
 return 1;
}
static int image_mappings(job*j){Dl_info d;image_ranges x={0};void *symbol=dlsym(j->a.handle,"lc_keypair");long page=sysconf(_SC_PAGESIZE);if(page<=0||!dladdr(symbol,&d))return 0;x.base=(uintptr_t)d.dli_fbase;x.page=(size_t)page;dl_iterate_phdr(image_phdr,&x);if(!x.n)return 0;
 for(size_t i=0;i<x.n;i++)for(size_t k=i+1;k<x.n;k++)if(x.lo[k]<x.lo[i]){uintptr_t t=x.lo[i];x.lo[i]=x.lo[k];x.lo[k]=t;t=x.hi[i];x.hi[i]=x.hi[k];x.hi[k]=t;}
 size_t count=0;for(size_t i=0;i<x.n;i++){if(count&&x.lo[i]<=x.hi[count-1]){if(x.hi[i]>x.hi[count-1])x.hi[count-1]=x.hi[i];}else{x.lo[count]=x.lo[i];x.hi[count]=x.hi[i];count++;}}
 FILE*f=fopen("/proc/self/maps","r");if(!f)return 0;char line[8192];while(fgets(line,sizeof line,f)){uintptr_t lo,hi;char permissions[5];if(sscanf(line,"%" SCNxPTR "-%" SCNxPTR " %4s",&lo,&hi,permissions)!=3)continue;if(strstr(line,"[stack]"))j->original_stack_mapped+=hi-lo;
  for(size_t i=0;i<count;i++){uintptr_t a=lo>x.lo[i]?lo:x.lo[i],b=hi<x.hi[i]?hi:x.hi[i];if(b>a){j->image_mapped+=b-a;if(permissions[1]=='w')j->image_rw+=b-a;else j->image_ro+=b-a;}}
 }fclose(f);return j->image_mapped>0;
}
#endif
static void erase(void*p,size_t n){volatile uint8_t*q=p;while(n--)*q++=0;}
static uint64_t state;
static void fill(uint8_t*p,size_t n){while(n--){state^=state<<13;state^=state>>7;state^=state<<17;*p++=(uint8_t)state;}}
static int random_bytes(void*u,uint8_t*p,size_t n){if(n>64)return -1;memcpy(p,u,n);return 0;}
static void *sym(void*h,const char*n){
#ifdef _WIN32
 return (void*)(uintptr_t)GetProcAddress((HMODULE)h,n);
#else
 return dlsym(h,n);
#endif
}
static int load(api*a,const char*path){
#ifdef _WIN32
 a->handle=(void*)LoadLibraryA(path);
#else
 a->handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);
#endif
 if(!a->handle)return 0;
#define BIND(f,n) do{void*p=sym(a->handle,n);if(!p||sizeof(p)!=sizeof(a->f))return 0;memcpy(&a->f,&p,sizeof p);}while(0)
 BIND(init,"lc_context_init");BIND(sizes,"lc_get_sizes");BIND(key,"lc_keypair");BIND(enc,"lc_encaps");BIND(dec,"lc_decaps");BIND(sign,"lc_sign");BIND(verify,"lc_verify");
#undef BIND
 return sym(a->handle,"lc_error_string")!=NULL;
}
static int workspace(job*j,size_t n){
#ifdef _WIN32
 j->allocation=_aligned_malloc(n+64,32);
#else
 void *p=NULL;if(posix_memalign(&p,32,n+64))return 0;j->allocation=p;
#endif
 if(!j->allocation)return 0;
 j->arena=j->allocation+32;j->capacity=n;
 memset(j->allocation,0xa7,32);memset(j->arena,0xcc,n);memset(j->arena+n,0xb9,32);return 1;
}
static void free_workspace(job*j){if(j->allocation){erase(j->allocation,j->capacity+64);
#ifdef _WIN32
 _aligned_free(j->allocation);
#else
 free(j->allocation);
#endif
 j->allocation=NULL;}}
static int guards(job*j){for(size_t i=0;i<32;i++)if(j->allocation[i]!=0xa7||j->arena[j->capacity+i]!=0xb9)return 0;return 1;}
__attribute__((noinline)) static int invoke(job*j){
 if(j->op==-1)return j->a.init(&j->context,j->arena,j->capacity,random_bytes,j->coins);
 lc_sizes*z=&j->sizes;outputs*b=&j->out;
 if(j->op==0)return j->a.key(&j->context,j->level,b->pk,z->public_key,b->sk,z->secret_key);
 if(j->level>100&&j->op==1)return j->a.enc(&j->context,j->level,b->ct,z->ciphertext,b->ss,32,b->pk,z->public_key);
 if(j->level>100)return j->a.dec(&j->context,j->level,b->ss2,32,b->ct,z->ciphertext,b->sk,z->secret_key);
 if(j->op==1)return j->a.sign(&j->context,j->level,b->sig,z->signature,j->message,sizeof j->message,NULL,0,b->sk,z->secret_key);
 return j->a.verify(&j->context,j->level,b->sig,z->signature,j->message,sizeof j->message,NULL,0,b->pk,z->public_key);
}
static void reset_outputs(job*j){lc_sizes*z=&j->sizes;outputs*b=&j->out;
 if(j->op==0){memset(b->pk,0xe1,z->public_key);memset(b->sk,0xe1,z->secret_key);}
 else if(j->level>100&&j->op==1){memset(b->ct,0xe1,z->ciphertext);memset(b->ss,0xe1,32);}
 else if(j->level>100)memset(b->ss2,0xe1,32);
 else if(j->op==1)memset(b->sig,0xe1,z->signature);
}
static int output_match(job*j){lc_sizes*z=&j->sizes;outputs*a=&j->out,*b=&j->want;
 if(j->op==0)return !memcmp(a->pk,b->pk,z->public_key)&&!memcmp(a->sk,b->sk,z->secret_key);
 if(j->level>100&&j->op==1)return !memcmp(a->ct,b->ct,z->ciphertext)&&!memcmp(a->ss,b->ss,32);
 if(j->level>100)return !memcmp(a->ss2,b->ss,32);
 return j->op==2||!memcmp(a->sig,b->sig,z->signature);
}
static int zeros(const uint8_t*p,size_t n){uint8_t x=0;while(n--)x|=*p++;return x==0;}
static int outputs_clear(job*j){lc_sizes*z=&j->sizes;outputs*b=&j->out;
 if(j->op==0)return zeros(b->pk,z->public_key)&&zeros(b->sk,z->secret_key);
 if(j->level>100&&j->op==1)return zeros(b->ct,z->ciphertext)&&zeros(b->ss,32);
 if(j->level>100)return zeros(b->ss2,32);
 return j->op==2||zeros(b->sig,z->signature);
}
__attribute__((noinline)) static int empty_call(job*j){__asm__ volatile(""::"r"(j):"memory");return 0;}
__attribute__((noinline)) static int overflow_call(job*j){volatile uint8_t x[49152];for(size_t i=0;i<sizeof x;i++)x[i]=(uint8_t)i;__asm__ volatile(""::"r"(j),"r"(&x[0]):"memory");return x[0];}
static int heap_control(job*j){(void)j;
#ifdef _WIN32
 return memory_heap_control(j);
#else
 void*p=control_calloc(4,16);if(!p)return -990;void*q=control_realloc(p,96);if(!q){control_free(p);return -991;}control_free(q);return 0;
#endif
}
static void audit_enable(int yes){
#ifdef _WIN32
 audit_active=yes;
#else
 if(heap_enable)heap_enable(yes);
#endif
}
static size_t controlled(job*j,int(*call)(job*)){
 for(uintptr_t p=j->lower;p<j->top;p++)*(volatile uint8_t*)p=j->marker;
 __asm__ volatile("":::"memory");audit_enable(1);j->rc=lc_memory_call_at(j,j->top,call);audit_enable(0);__asm__ volatile("":::"memory");
 uintptr_t p;for(p=j->lower;p<j->top;p++)if(*(volatile uint8_t*)p!=j->marker)break;
 size_t depth=p==j->top?0:j->top-p;if(depth>j->observed)j->observed=depth;return depth;
}
static void run_calls(job*j){
 j->op=-1;j->init_watermark=controlled(j,invoke);j->init_rc=j->rc;if(j->rc)return;
 if(j->control){j->op=0;controlled(j,j->control==1?empty_call:j->control==2?overflow_call:heap_control);return;}
 int first=j->requested_op==3?0:j->requested_op,last=j->requested_op==3?2:j->requested_op;
 for(int op=first;op<=last;op++){
  j->op=op;reset_outputs(j);j->step_watermark[op]=controlled(j,invoke);j->step_rc[op]=j->rc;
  j->step_high[op]=j->context.arena_high_water;if(j->step_high[op]>j->high)j->high=j->step_high[op];
  j->allocation_failures+=j->context.allocation_failures;
  j->step_match[op]=j->rc?0:output_match(j);j->step_clear[op]=j->rc==LC_E_WORKSPACE?outputs_clear(j):-1;
  j->step_wiped[op]=j->step_high[op]<=j->capacity&&zeros(j->arena,j->step_high[op]);
  if(j->step_high[op]<=j->capacity)for(size_t i=0;i<j->step_high[op];i++)if(j->arena[i]){j->step_nonzero[op]++;if(j->arena[i]!=0xcc)j->step_changed_nonzero[op]++;}
  if(j->rc||!j->step_match[op]||j->step_high[op]>j->capacity||j->step_changed_nonzero[op])break;
 }
}
#ifdef _WIN32
__attribute__((noinline)) static void precommit(void){volatile uint8_t x[73728];for(size_t i=0;i<sizeof x;i++)x[i]=0x39;__asm__ volatile(""::"r"(&x[0]):"memory");}
static DWORD WINAPI worker(void *arg){job*j=arg;DWORD old;MEMORY_BASIC_INFORMATION mb;uintptr_t sp,p;precommit();__asm__ volatile("mov %%rsp,%0":"=r"(sp));
 j->original_base=(uintptr_t)((PNT_TIB)NtCurrentTeb())->StackBase;
 if(!VirtualQuery((void*)sp,&mb,sizeof mb)){j->guard_error=1;return 1;}
 j->protected_start=(uintptr_t)mb.AllocationBase;j->os_reserved=j->original_base-j->protected_start;
 j->lower=(sp-256-j->stack_target)&~(uintptr_t)4095;j->top=j->lower+j->stack_target;
 j->protected_bytes=j->lower-j->protected_start;j->os_page=4096;
 if(j->lower<=j->protected_start||j->top>=sp){j->guard_error=2;return 2;}
 if(!VirtualAlloc((void*)j->protected_start,j->protected_bytes,MEM_COMMIT,PAGE_READWRITE)||!VirtualProtect((void*)j->protected_start,j->protected_bytes,PAGE_NOACCESS,&old)){j->guard_error=3;return 3;}
 for(p=j->protected_start;p<j->original_base;){if(!VirtualQuery((void*)p,&mb,sizeof mb)){j->guard_error=4;return 4;}if(mb.State==MEM_COMMIT)j->os_committed+=mb.RegionSize;p=(uintptr_t)mb.BaseAddress+mb.RegionSize;}
 R2_RESOURCE_RUN_CALLS(j);if(!VirtualProtect((void*)j->protected_start,j->protected_bytes,PAGE_READWRITE,&old)){j->guard_error=5;return 5;}return 0;
}
#else
static uintptr_t signal_low,signal_high;
static void fault_handler(int sig,siginfo_t*info,void*unused){(void)unused;char line[160];size_t n=0;const char *s="{\"event\":\"stack_fault\",\"protected_region_hit\":";while(*s)line[n++]=*s++;
 uintptr_t addr=(uintptr_t)info->si_addr;s=addr>=signal_low&&addr<signal_high?"true":"false";while(*s)line[n++]=*s++;
 s=",\"address_hex\":\"";while(*s)line[n++]=*s++;for(int i=(int)(2*sizeof(uintptr_t))-1;i>=0;i--)line[n++]="0123456789abcdef"[(addr>>(4*i))&15];line[n++]='"';line[n++]='}';line[n++]='\n';
 size_t sent=0;while(sent<n){ssize_t count=write(STDOUT_FILENO,line+sent,n-sent);if(count>0)sent+=(size_t)count;else if(count<0&&errno==EINTR)continue;else break;}_exit(128+sig);
}
static int worker(job*j){long page=sysconf(_SC_PAGESIZE);if(page<=0)return 1;j->os_page=(size_t)page;
 size_t rw=(j->stack_target+j->os_page-1)/j->os_page*j->os_page;j->protected_bytes=1048576;j->os_reserved=j->protected_bytes+rw+j->os_page;j->os_committed=rw;
 void *p=mmap(NULL,j->os_reserved,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(p==MAP_FAILED)return 2;
 j->protected_start=(uintptr_t)p;j->lower=(uintptr_t)p+j->protected_bytes;j->top=j->lower+j->stack_target;
 if(mprotect((void*)j->lower,rw,PROT_READ|PROT_WRITE))return 3;
 void*alt=mmap(NULL,65536,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(alt==MAP_FAILED)return 4;
 stack_t ss={0};ss.ss_sp=alt;ss.ss_size=65536;if(sigaltstack(&ss,NULL))return 5;
 struct sigaction sa;memset(&sa,0,sizeof sa);sa.sa_sigaction=fault_handler;sa.sa_flags=SA_SIGINFO|SA_ONSTACK;sigemptyset(&sa.sa_mask);if(sigaction(SIGSEGV,&sa,NULL)||sigaction(SIGBUS,&sa,NULL))return 6;
 signal_low=j->protected_start;signal_high=j->lower;struct rlimit limit;if(!getrlimit(RLIMIT_STACK,&limit)){j->original_stack_limit=(size_t)limit.rlim_cur;j->original_stack_limit_known=limit.rlim_cur!=RLIM_INFINITY;}
 R2_RESOURCE_RUN_CALLS(j);ss.ss_flags=SS_DISABLE;if(sigaltstack(&ss,NULL))return 7;munmap(alt,65536);munmap(p,j->os_reserved);return 0;
}
#endif
int main(int argc,char**argv){
#ifdef _WIN32
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
#endif
 if(argc!=8){fputs("probe library parameter operation arena_bytes stack_bytes seed control\n",stderr);return 2;}
 job*j=calloc(1,sizeof *j);if(!j)return 3;j->level=atoi(argv[2]);j->requested_op=atoi(argv[3]);size_t cap=(size_t)strtoull(argv[4],NULL,10);j->stack_target=(size_t)strtoull(argv[5],NULL,10);j->seed=strtoull(argv[6],NULL,10);j->control=atoi(argv[7]);
 for(int i=0;i<3;i++)j->step_rc[i]=j->step_match[i]=j->step_clear[i]=j->step_wiped[i]=-999;
 if(j->requested_op<0||j->requested_op>3||cap<32||cap>1048576||cap%32||j->stack_target<256||j->stack_target>65536||j->stack_target%16||!j->seed||j->control<0||j->control>3)return 4;
 if(!load(&j->a,argv[1])||j->a.sizes(j->level,&j->sizes))return 5;
#ifdef _WIN32
 if(!memory_image_inventory((HMODULE)j->a.handle)||!memory_audit_install((HMODULE)j->a.handle))return 6;
 j->heap_available=1;
#else
#define HOOK(f,n) do{void*p=dlsym(RTLD_DEFAULT,n);if(!p||sizeof p!=sizeof f)return 6;memcpy(&f,&p,sizeof p);}while(0)
 HOOK(heap_reset,"r2_heap_reset");HOOK(heap_enable,"r2_heap_enable");HOOK(heap_snapshot,"r2_heap_snapshot");HOOK(control_calloc,"calloc");HOOK(control_realloc,"realloc");HOOK(control_free,"free");j->heap_available=1;
#undef HOOK
 j->image_mapping_known=image_mappings(j);
#endif
 state=j->seed;fill(j->coins,sizeof j->coins);fill(j->message,sizeof j->message);j->marker=(j->seed&1)?0xa5:0x5a;
 if(!workspace(j,262144))return 7;
 j->op=-1;if(invoke(j))return 8;
 for(int i=0;i<3;i++){j->op=i;if(invoke(j))return 9;}
 if(j->level>100&&memcmp(j->out.ss,j->out.ss2,32))return 10;
 memcpy(&j->want,&j->out,sizeof j->want);free_workspace(j);
 if(!workspace(j,cap))return 11;
#ifndef _WIN32
 heap_reset();
#endif
 printf("{\"event\":\"trial_start\",\"parameter\":%d,\"operation\":%d,\"arena_bytes\":%zu,\"stack_bytes\":%zu,\"seed\":%" PRIu64 ",\"control\":%d}\n",j->level,j->requested_op,cap,j->stack_target,j->seed,j->control);fflush(stdout);
 int worker_rc;
#ifdef _WIN32
 HANDLE thread=CreateThread(NULL,131072,worker,j,STACK_SIZE_PARAM_IS_A_RESERVATION,NULL);if(!thread)return 12;WaitForSingleObject(thread,INFINITE);DWORD code;GetExitCodeThread(thread,&code);CloseHandle(thread);worker_rc=(int)code;
 j->heap[0]=audit_calls;j->heap[1]=audit_free_calls;j->heap[2]=audit_live;j->heap[3]=audit_peak;j->heap[4]=audit_errors;
#else
 worker_rc=worker(j);heap_snapshot(j->heap);
#endif
 int canary=guards(j),zero=j->high<=cap?zeros(j->arena,j->high):0,measured_rc=j->rc;size_t changed_nonzero=0;
 if(j->high<=cap)for(size_t i=0;i<j->high;i++)if(j->arena[i]&&j->arena[i]!=0xcc)changed_nonzero++;
 free_workspace(j);
 /* Recovery is separate from the measured call; keep the same lc_context
  * object and restore valid serialized inputs before the complete sequence. */
 int recovery=1;if(!workspace(j,262144))return 13;memcpy(&j->out,&j->want,sizeof j->out);j->op=-1;if(invoke(j))recovery=0;
 for(int i=0;i<3&&recovery;i++){j->op=i;reset_outputs(j);if(invoke(j)||!output_match(j))recovery=0;}if(!guards(j))recovery=0;
 printf("{\"event\":\"trial_result\",\"schema\":\"resources.r2.v1\",\"parameter\":%d,\"operation\":%d,\"control\":%d,\"seed\":%" PRIu64 ",\"rc\":%d,\"worker_rc\":%d,\"guard_error\":%d,\"init_rc\":%d,\"arena_reserved_bytes\":%zu,\"arena_high_water_bytes\":%zu,\"arena_alignment_bytes\":32,\"context_bytes\":%zu,\"context_in_measured_stack\":false,\"stack_enforced_bytes\":%zu,\"stack_watermark_observed_bytes\":%zu,\"init_watermark_bytes\":%zu,\"os_stack_or_guard_mapping_reserved_bytes\":%zu,\"os_enabled_or_committed_stack_pages_bytes\":%zu,\"protected_lower_bytes\":%zu,\"os_page_bytes\":%zu,\"canaries_ok\":%s,\"released_prefix_all_zero\":%s,\"recovery_full_sequence_ok\":%s,\"allocation_failures\":%zu,\"outside_heap_calls\":%" PRIu64 ",\"outside_heap_frees\":%" PRIu64 ",\"outside_heap_live_requested_bytes\":%" PRIu64 ",\"outside_heap_peak_requested_bytes\":%" PRIu64 ",\"heap_audit_errors\":%" PRIu64 ",\"message_bytes\":1024,\"rng_mode\":\"caller_supplied_test_entropy\",\"physical_ram_measured\":false",
 j->level,j->requested_op,j->control,j->seed,measured_rc,worker_rc,j->guard_error,j->init_rc,cap,j->high,sizeof(lc_context),j->stack_target,j->observed,j->init_watermark,j->os_reserved,j->os_committed,j->protected_bytes,j->os_page,canary?"true":"false",zero?"true":"false",recovery?"true":"false",j->allocation_failures,j->heap[0],j->heap[1],j->heap[2],j->heap[3],j->heap[4]);
 printf(",\"released_prefix_changed_nonzero_bytes\":%zu",changed_nonzero);
 const char*fields[]={"step_rc","step_outputs_match","step_failure_outputs_zero","step_arena_high_water","step_stack_watermark","step_released_prefix_zero","step_nonzero_bytes","step_changed_nonzero_bytes"};
 for(int f=0;f<8;f++){printf(",\"%s\":[",fields[f]);for(int i=0;i<3;i++){if(i)putchar(',');if(j->step_rc[i]==-999||(f==2&&j->step_clear[i]<0))fputs("null",stdout);else if(f==0)printf("%d",j->step_rc[i]);else if(f==1)printf("%d",j->step_match[i]);else if(f==2)printf("%d",j->step_clear[i]);else if(f==5)printf("%d",j->step_wiped[i]);else if(f==6)printf("%zu",j->step_nonzero[i]);else if(f==7)printf("%zu",j->step_changed_nonzero[i]);else printf("%zu",f==3?j->step_high[i]:j->step_watermark[i]);}putchar(']');}
#ifdef _WIN32
 printf(",\"heap_positive_control_mode\":\"%s\"",audit_positive_control_local?"standalone_accounting_no_target_allocator_imports":"target_allocator_IAT_or_no_control");
 printf(",\"platform_stack_model\":\"Windows dedicated thread with protected lower region\",\"os_original_stack_limit_bytes\":null,\"image_mapped_bytes\":%zu,\"image_committed_bytes\":%zu,\"image_writable_mapping_bytes\":%zu,\"image_readonly_mapping_bytes\":%zu,\"heap_hooks\":%zu,\"heap_unhandled_imports\":%zu",image_size,image_committed,image_writable,image_readonly,audit_hooked,audit_unsupported);
#else
 fputs(",\"platform_stack_model\":\"Linux mmap independent stack and protected lower region\",\"os_original_stack_limit_bytes\":",stdout);if(j->original_stack_limit_known)printf("%zu",j->original_stack_limit);else fputs("null",stdout);fputs(",\"signal_alternate_stack_bytes\":65536",stdout);
 if(j->image_mapping_known)printf(",\"image_mapped_bytes\":%zu,\"image_writable_mapping_bytes\":%zu,\"image_readonly_mapping_bytes\":%zu,\"original_stack_mapped_bytes\":%zu",j->image_mapped,j->image_rw,j->image_ro,j->original_stack_mapped);else fputs(",\"image_mapped_bytes\":null,\"image_writable_mapping_bytes\":null,\"image_readonly_mapping_bytes\":null,\"original_stack_mapped_bytes\":null",stdout);
#endif
 puts("}");
 int bad=worker_rc||j->guard_error||j->init_rc||!canary||j->high>cap||changed_nonzero||!recovery||j->heap[4]||j->heap[2]||(j->control&&measured_rc);
 if(!j->control)for(int i=0;i<3;i++){if(j->step_high[i]>cap||j->step_changed_nonzero[i])bad=1;if(j->step_rc[i]==0&&j->step_match[i]!=1)bad=1;if(j->step_rc[i]==LC_E_WORKSPACE&&j->step_clear[i]!=1)bad=1;if(j->step_rc[i]!=-999&&j->step_rc[i]!=0&&j->step_rc[i]!=LC_E_WORKSPACE)bad=1;}
 free_workspace(j);erase(&j->out,sizeof j->out);erase(&j->want,sizeof j->want);erase(j->coins,sizeof j->coins);
#ifdef _WIN32
 FreeLibrary((HMODULE)j->a.handle);
#else
 dlclose(j->a.handle);
#endif
 erase(j,sizeof *j);free(j);return bad?14:0;
}
