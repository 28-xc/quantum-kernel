/* User-mode sampling of this program's own worker thread only.
 * This never opens or reads another process. Only instruction offsets inside
 * the explicitly loaded test core are retained; registers, stack contents,
 * key material and external instruction addresses are not recorded.
 * The observer perturbs execution. Its samples are for hotspot attribution,
 * not for reporting elapsed-time speedups. */
#define main serialized_driver_unused_main
#include "driver.c"
#undef main
#ifndef _WIN32
#error This sampler uses the Windows x64 thread context ABI
#endif
typedef struct {uint64_t ticks;uintptr_t offset;} SAMPLE;
typedef struct {
 HANDLE worker,go,ready;volatile LONG stop;SAMPLE *samples;size_t count,capacity;
 uintptr_t image_base;size_t image_bytes;DWORD_PTR observer_mask;
 unsigned context_failures,resume_failures,dropped;int delay_fault;
} OBSERVER;
static DWORD WINAPI observe(void *arg) {
 OBSERVER *o=arg;LARGE_INTEGER due;HANDLE timer=NULL;
 if(!SetThreadAffinityMask(GetCurrentThread(),o->observer_mask))return 1;
 timer=CreateWaitableTimerExA(NULL,NULL,0x00000002,TIMER_ALL_ACCESS);
 if(!timer)return 2;
 due.QuadPart=-10000;
 if(!SetWaitableTimer(timer,&due,1,NULL,NULL,FALSE)){CloseHandle(timer);return 3;}
 if(!SetEvent(o->ready)){CloseHandle(timer);return 4;}
 if(WaitForSingleObject(o->go,10000)!=WAIT_OBJECT_0){CloseHandle(timer);return 4;}
 if(o->delay_fault)Sleep(1000);
 while(!InterlockedCompareExchange(&o->stop,0,0)) {
  if(WaitForSingleObject(timer,2000)!=WAIT_OBJECT_0){CancelWaitableTimer(timer);CloseHandle(timer);return 5;}
  if(InterlockedCompareExchange(&o->stop,0,0))break;
  CONTEXT c __attribute__((aligned(16)));memset(&c,0,sizeof c);c.ContextFlags=CONTEXT_CONTROL;
  if(SuspendThread(o->worker)==(DWORD)-1){o->context_failures++;continue;}
  BOOL ok=GetThreadContext(o->worker,&c);
  /* Main is this same worker and cannot recover if it remains suspended.
   * Exit only this disposable process; never free live shared state. */
  if(ResumeThread(o->worker)==(DWORD)-1){o->resume_failures++;ExitProcess(73);}
  uintptr_t ip=ok?(uintptr_t)c.Rip:0;SecureZeroMemory(&c,sizeof c);
  if(!ok){o->context_failures++;continue;}
  if(o->count<o->capacity) {
   SAMPLE *s=&o->samples[o->count++];s->ticks=ticks();
   s->offset=ip>=o->image_base&&ip-o->image_base<o->image_bytes?ip-o->image_base:0;
  } else o->dropped++;
 }
 CancelWaitableTimer(timer);CloseHandle(timer);return 0;
}
static int image_range(HMODULE module,uintptr_t *base,size_t *bytes) {
 IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER*)module;
 if(!module||dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<0||dos->e_lfanew>4096)return 0;
 IMAGE_NT_HEADERS64 *nt=(IMAGE_NT_HEADERS64*)((uintptr_t)module+(uintptr_t)dos->e_lfanew);
 if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||nt->OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC)return 0;
 *base=(uintptr_t)module;*bytes=nt->OptionalHeader.SizeOfImage;return *bytes>0;
}
static int module_path(HMODULE module,char *out,size_t size) {
 WCHAR wide[32768];DWORD n=GetModuleFileNameW(module,wide,32768);
 if(!n||n>=32768)return 0;
 return WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,-1,out,(int)size,NULL,NULL)>0;
}
static int actual_crypto(char *out,size_t size) {
 extern const char *(*__imp_OpenSSL_version)(int);HMODULE module=NULL;
 if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCWSTR)(uintptr_t)__imp_OpenSSL_version,&module))return 0;
 return module_path(module,out,size);
}
static int start_observer(OBSERVER *o,int observer_cpu,HANDLE *thread) {
 DWORD_PTR allowed,system;
 if(observer_cpu<0||observer_cpu>63||!GetProcessAffinityMask(GetCurrentProcess(),&allowed,&system)||!(allowed&((DWORD_PTR)1<<observer_cpu)))return 0;
 o->capacity=120000;o->samples=calloc(o->capacity,sizeof(SAMPLE));o->observer_mask=(DWORD_PTR)1<<observer_cpu;
 /* Duplicate only this exact worker; no caller-supplied process/thread ID. */
 if(!DuplicateHandle(GetCurrentProcess(),GetCurrentThread(),GetCurrentProcess(),&o->worker,THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,0))return 0;
 o->go=CreateEventA(NULL,TRUE,FALSE,NULL);o->ready=CreateEventA(NULL,TRUE,FALSE,NULL);
 if(!o->samples||!o->go||!o->ready)return 0;
 *thread=CreateThread(NULL,0,observe,o,0,NULL);if(!*thread)return 0;
 HANDLE handles[2]={o->ready,*thread};
 if(WaitForMultipleObjects(2,handles,FALSE,5000)!=WAIT_OBJECT_0)return 0;
 return SetEvent(o->go)!=0;
}
static DWORD join_observer(OBSERVER *o,HANDLE *thread,DWORD timeout) {
 DWORD result=0;if(!*thread)return 0;InterlockedExchange(&o->stop,1);if(o->go)SetEvent(o->go);
 /* Never close/free storage after a timeout while the observer could live. */
 if(WaitForSingleObject(*thread,timeout)!=WAIT_OBJECT_0)ExitProcess(72);
 if(!GetExitCodeThread(*thread,&result))ExitProcess(74);
 CloseHandle(*thread);*thread=NULL;return result;
}
static void free_observer(OBSERVER *o) {
 if(o->ready)CloseHandle(o->ready);
 if(o->go)CloseHandle(o->go);
 if(o->worker)CloseHandle(o->worker);
 free(o->samples);
}
static int save_samples(const char *path,const OBSERVER *o,size_t *core) {
 FILE *f=fopen(path,"wb");if(!f)return 0;fputs("sample_id,observer_qpc,core_instruction_rva\n",f);*core=0;
 for(size_t i=0;i<o->count;i++){const SAMPLE *s=&o->samples[i];fprintf(f,"%zu,%" PRIu64 ",%" PRIuPTR "\n",i,s->ticks,s->offset);if(s->offset)(*core)++;}
 return fclose(f)==0;
}
static int fresh_output(const char *path){FILE *f=fopen(path,"rb");if(f){fclose(f);return 0;}return 1;}
static volatile uint64_t positive_counter;
__attribute__((noinline)) void lc_profile_positive_control(uint64_t until) {
 while(ticks()<until)for(unsigned i=0;i<10000;i++)positive_counter=positive_counter*UINT64_C(6364136223846793005)+1;
}
static int self_test(const char *mode,int cpu,int observer_cpu,const char *output) {
 OBSERVER o={0};HANDLE thread=NULL;size_t core=0;int rc=0;void *outside=NULL;
 if(!pin_cpu(cpu)||observer_cpu==cpu||!fresh_output(output))return 3;
 if(strcmp(mode,"positive")&&strcmp(mode,"outside")&&strcmp(mode,"observer_timeout"))return 3;
 if(!image_range(GetModuleHandleW(NULL),&o.image_base,&o.image_bytes))return 8;
 if(!strcmp(mode,"outside")){outside=VirtualAlloc(NULL,4096,MEM_RESERVE,PAGE_NOACCESS);if(!outside)return 9;o.image_base=(uintptr_t)outside;o.image_bytes=4096;}
 o.delay_fault=!strcmp(mode,"observer_timeout");
 if(!start_observer(&o,observer_cpu,&thread)){rc=10;goto done;}
 lc_profile_positive_control(ticks()+frequency()/(o.delay_fault?50:4));
 if(join_observer(&o,&thread,o.delay_fault?50:5000)||o.context_failures||o.resume_failures||o.dropped)rc=13;
 if(!save_samples(output,&o,&core))rc=15;
 if(!rc&&(o.count<20||(!strcmp(mode,"positive")&&core<20)||(!strcmp(mode,"outside")&&core!=0)))rc=16;
 printf("{\"status\":\"%s\",\"mode\":",rc?"FAIL":"PASS");json_string(mode);printf(",\"samples\":%zu,\"core_samples\":%zu,\"outside_core_samples\":%zu,\"dropped\":%u,\"context_failures\":%u,\"measurement_class\":\"self_sampling_control_not_performance\"}\n",o.count,core,o.count-core,o.dropped,o.context_failures);
done:
 join_observer(&o,&thread,5000);free_observer(&o);if(outside)VirtualFree(outside,0,MEM_RELEASE);return rc;
}
int main(int argc,char **argv) {
 if(argc==6&&!strcmp(argv[1],"--self-test"))return self_test(argv[2],atoi(argv[3]),atoi(argv[4]),argv[5]);
 if(argc!=10){fputs("usage: profile_windows library parameter operation count seed worker_cpu observer_cpu output.csv expected_openssl_version\ncount 0 checks API without sampling; --self-test {positive|outside|observer_timeout} worker_cpu observer_cpu output.csv\n",stderr);return 2;}
 int p=atoi(argv[2]),op=atoi(argv[3]),count=atoi(argv[4]),cpu=atoi(argv[6]),observer_cpu=atoi(argv[7]);uint64_t seed=strtoull(argv[5],NULL,10);
 if(!algorithm(p)||op<0||op>2||(count!=0&&(count<100||count>1000000))||!seed||observer_cpu<0||observer_cpu>=64||observer_cpu==cpu||!pin_cpu(cpu))return 3;
 if(!fresh_output(argv[8]))return 4;
 unsigned long expected=!strcmp(argv[9],"3.6.4")?0x30600040L:!strcmp(argv[9],"3.6.0")?0x30600000L:0;
 if(!expected||OPENSSL_VERSION_NUMBER!=expected||OpenSSL_version_num()!=expected)return 17;
 LC l={0};OS o={0};lc_sizes z;TEST_INPUT in={0};OUTPUT out={0},check={0};OBSERVER observer={0};HANDLE thread=NULL;int rc=0,completed=0,observer_started=0;DWORD thread_rc=0;size_t core=0;char crypto[4096]={0},library[4096]={0};
 if(!load_lc(&l,argv[1],262144)||l.sizes(p,&z)||!init_os(&o,p,"none")||!actual_crypto(crypto,sizeof crypto)||!module_path((HMODULE)l.handle,library,sizeof library)){rc=5;goto done;}
 prng=seed;in.mn=1024;in.dn=0;fill(in.coins,64);fill(in.msg,in.mn);
 if(lattice_call(&l,p,0,&z,&in,&out)||openssl_call(&o,p,0,&z,&in,&check)||!equal(p,0,&z,&out,&check)){rc=6;goto done;}
 memcpy(in.pk,out.pk,z.public_key);memcpy(in.sk,out.sk,z.secret_key);
 if(transcript(&l,p,&z,&in)||!negatives(&o,&l,p,&z,&in)){rc=7;goto done;}
 if(!image_range((HMODULE)l.handle,&observer.image_base,&observer.image_bytes)){rc=8;goto done;}
 if(count){if(!start_observer(&observer,observer_cpu,&thread)){rc=10;goto done;}observer_started=1;}
 for(int i=0;i<(count?count:1);i++){fill(in.coins,64);if(lattice_call(&l,p,op,&z,&in,&out)||!arena_guards(&l)){rc=11;break;}completed++;}
 thread_rc=join_observer(&observer,&thread,5000);
 if(thread_rc||observer.context_failures||observer.resume_failures||observer.dropped)rc=13;
 if(!rc&&(openssl_call(&o,p,op,&z,&in,&check)||!equal(p,op,&z,&out,&check)||current_cpu()!=cpu))rc=14;
done:
 if(thread){thread_rc=join_observer(&observer,&thread,5000);if(thread_rc&&!rc)rc=13;}
 /* Save every acquired sample after the observer has provably exited, even
  * for insufficient coverage or a later functional-check failure. */
 if(observer_started||!count){if(!save_samples(argv[8],&observer,&core)&&!rc)rc=15;}
 if(!rc&&count&&core<20)rc=16;
 printf("{\"status\":\"%s\",\"exit_code\":%d,\"parameter\":%d,\"operation\":%d,\"iterations\":%d,\"completed\":%d,\"seed\":%" PRIu64 ",\"worker_cpu\":%d,\"observer_cpu\":%d,\"samples\":%zu,\"core_samples\":%zu,\"outside_core_samples\":%zu,\"dropped\":%u,\"context_failures\":%u,\"resume_failures\":%u,\"timer_period_ms\":1,\"qpc_frequency\":%" PRIu64 ",\"image_bytes\":%zu,\"library\":",rc?"FAIL":"PASS",rc,p,op,count,completed,seed,cpu,observer_cpu,observer.count,core,observer.count-core,observer.dropped,observer.context_failures,observer.resume_failures,frequency(),observer.image_bytes);json_string(library);printf(",\"openssl_library\":");json_string(crypto);printf(",\"openssl_version\":");json_string(OpenSSL_version(OPENSSL_VERSION));printf(",\"measurement_class\":\"%s\"}\n",count?"perturbing_instruction_sampling_only":"crypto_verification_without_sampling");
 free_observer(&observer);
 free_os(&o);OPENSSL_cleanse(&in,sizeof in);OPENSSL_cleanse(&out,sizeof out);OPENSSL_cleanse(&check,sizeof check);
 if(l.raw){OPENSSL_cleanse(l.raw,l.capacity+128);free(l.raw);}if(l.handle)FreeLibrary((HMODULE)l.handle);
 if(rc)fprintf(stderr,"own-thread profiler failed: %d\n",rc);
 return rc;
}
