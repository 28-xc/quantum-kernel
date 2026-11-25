/* The target library is unchanged. Only the resource instrument has a
 * six-parameter sequence wrapper, outside its protected algorithm stack. */
struct job;
static void common_calls(struct job *);
static void run_calls(struct job *) __attribute__((unused));
#define R2_RESOURCE_RUN_CALLS(j) common_calls(j)
#define main resource_single_probe_main
#include "probe.c"
#undef main
typedef struct {int parameter,operation,rc,match,clear;size_t high,watermark,changed_nonzero;} common_row;
typedef struct {
 outputs expected[6];uint8_t coins[6][64],message[6][1024];
 common_row rows[18];int order,count,completed,init_calls,identity_ok,stopped;
} common_state;
static common_state *common;
static const int parameters[6]={512,768,1024,44,65,87};
static const int orders[2][6]={{0,3,1,4,2,5},{5,2,4,1,3,0}};
static void common_calls(job*j){
 common->completed=0;common->init_calls=0;common->identity_ok=1;common->stopped=0;
 j->op=-1;common->init_calls++;j->init_watermark=controlled(j,invoke);j->init_rc=j->rc;if(j->rc)return;
 if(j->control){controlled(j,j->control==1?empty_call:j->control==2?overflow_call:heap_control);return;}
 for(int i=0;i<common->count;i++){
  int slot=orders[common->order][i];j->level=parameters[slot];
  if(j->a.sizes(j->level,&j->sizes)){j->rc=LC_E_INTERNAL;common->stopped=1;return;}
  memcpy(j->coins,common->coins[slot],64);memcpy(j->message,common->message[slot],1024);memcpy(&j->want,&common->expected[slot],sizeof j->want);
  for(int op=0;op<3;op++){
   if(j->context.workspace!=j->arena||j->context.workspace_bytes!=j->capacity||j->context.random!=random_bytes||j->context.random_user!=j->coins){common->identity_ok=0;common->stopped=1;j->rc=LC_E_INTERNAL;return;}
   j->op=op;reset_outputs(j);common_row*r=&common->rows[common->completed];r->parameter=j->level;r->operation=op;r->watermark=controlled(j,invoke);r->rc=j->rc;
   r->high=j->context.arena_high_water;r->match=!j->rc&&output_match(j);r->clear=j->rc==LC_E_WORKSPACE?outputs_clear(j):-1;
   if(r->high>j->high)j->high=r->high;
   j->allocation_failures+=j->context.allocation_failures;r->changed_nonzero=0;
   if(r->high<=j->capacity)for(size_t k=0;k<r->high;k++)if(j->arena[k]&&j->arena[k]!=0xcc)r->changed_nonzero++;
   common->completed++;
   if(j->rc||!r->match||r->high>j->capacity||r->changed_nonzero||!guards(j)){common->stopped=1;return;}
  }
 }
}
static int execute_common_worker(job*j){
#ifdef _WIN32
 HANDLE thread=CreateThread(NULL,131072,worker,j,STACK_SIZE_PARAM_IS_A_RESERVATION,NULL);if(!thread)return 12;WaitForSingleObject(thread,INFINITE);DWORD code;GetExitCodeThread(thread,&code);CloseHandle(thread);return (int)code;
#else
 return worker(j);
#endif
}
int main(int argc,char**argv){
#ifdef _WIN32
 SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
#endif
 if(argc!=8){fputs("common_probe library arena stack seed order parameter_count control\n",stderr);return 2;}
 job*j=calloc(1,sizeof *j);common=calloc(1,sizeof *common);if(!j||!common)return 3;
 size_t cap=(size_t)strtoull(argv[2],NULL,10);j->stack_target=(size_t)strtoull(argv[3],NULL,10);j->seed=strtoull(argv[4],NULL,10);common->order=atoi(argv[5]);common->count=atoi(argv[6]);j->control=atoi(argv[7]);
 if(cap<32||cap>1048576||cap%32||j->stack_target<256||j->stack_target>65536||j->stack_target%16||!j->seed||common->order<0||common->order>1||(common->count!=3&&common->count!=6)||j->control<0||j->control>3)return 4;
 if(!load(&j->a,argv[1]))return 5;
#ifdef _WIN32
 if(!memory_image_inventory((HMODULE)j->a.handle)||!memory_audit_install((HMODULE)j->a.handle))return 6;
#else
#define COMMON_HOOK(f,n) do{void*p=dlsym(RTLD_DEFAULT,n);if(!p||sizeof p!=sizeof f)return 6;memcpy(&f,&p,sizeof p);}while(0)
 COMMON_HOOK(heap_reset,"r2_heap_reset");COMMON_HOOK(heap_enable,"r2_heap_enable");COMMON_HOOK(heap_snapshot,"r2_heap_snapshot");COMMON_HOOK(control_calloc,"calloc");COMMON_HOOK(control_realloc,"realloc");COMMON_HOOK(control_free,"free");
#undef COMMON_HOOK
 j->image_mapping_known=image_mappings(j);
#endif
 j->marker=(j->seed&1)?0xa5:0x5a;
 /* Reference outputs and serialized inputs are harness memory, prepared
  * outside the fixed resource experiment and never printed. */
 for(int slot=0;slot<6;slot++){
  j->level=parameters[slot];if(j->a.sizes(j->level,&j->sizes))return 7;
  state=j->seed+(uint64_t)j->level*65537;fill(j->coins,64);fill(j->message,1024);memcpy(common->coins[slot],j->coins,64);memcpy(common->message[slot],j->message,1024);
  if(!workspace(j,262144))return 8;
  j->op=-1;if(invoke(j))return 9;
  for(int op=0;op<3;op++){j->op=op;if(invoke(j))return 10;}
  if(j->level>100&&memcmp(j->out.ss,j->out.ss2,32))return 11;
  memcpy(&common->expected[slot],&j->out,sizeof j->out);free_workspace(j);
 }
 if(!workspace(j,cap))return 12;
#ifndef _WIN32
 heap_reset();
#endif
 printf("{\"event\":\"common_start\",\"arena_bytes\":%zu,\"stack_bytes\":%zu,\"seed\":%" PRIu64 ",\"order\":%d,\"parameter_count\":%d,\"control\":%d}\n",cap,j->stack_target,j->seed,common->order,common->count,j->control);fflush(stdout);
 int worker_rc=execute_common_worker(j),measured_rc=j->rc,measured_init_rc=j->init_rc,measured_guard_error=j->guard_error,canary=guards(j);common_state saved=*common;
#ifdef _WIN32
 j->heap[0]=audit_calls;j->heap[1]=audit_free_calls;j->heap[2]=audit_live;j->heap[3]=audit_peak;j->heap[4]=audit_errors;
#else
 heap_snapshot(j->heap);
#endif
 size_t high=j->high,observed=j->observed,measured_reserved=j->os_reserved,measured_enabled=j->os_committed,measured_allocation_failures=j->allocation_failures;int recovery=1;free_workspace(j);
 /* A separate recovery phase reinitializes the same context object once
  * with a large arena, then repeats the whole sequence under the same guard. */
 if(!workspace(j,262144))return 13;
 int old_control=j->control;j->control=0;j->high=0;j->observed=0;
 if(!old_control&&(execute_common_worker(j)||j->rc||common->completed!=3*common->count||common->init_calls!=1||!common->identity_ok||!guards(j)))recovery=0;
 j->control=old_control;
 printf("{\"event\":\"common_result\",\"schema\":\"resources.common_context.r2.v1\",\"rc\":%d,\"worker_rc\":%d,\"guard_error\":%d,\"arena_reserved_bytes\":%zu,\"stack_enforced_bytes\":%zu,\"context_bytes\":%zu,\"context_in_measured_stack\":false,\"context_init_calls\":%d,\"context_and_arena_identity_stable\":%s,\"completed_operations\":%d,\"expected_operations\":%d,\"arena_high_water_observed_bytes\":%zu,\"stack_watermark_observed_bytes\":%zu,\"canaries_ok\":%s,\"same_context_reinitialized_recovery_ok\":%s,\"outside_heap_calls\":%" PRIu64 ",\"outside_heap_peak_requested_bytes\":%" PRIu64 ",\"heap_errors\":%" PRIu64 ",\"os_stack_mapping_reserved_bytes\":%zu,\"os_enabled_stack_pages_bytes\":%zu,\"physical_RAM_measured\":false,\"order\":%d,\"parameter_count\":%d,\"seed\":%" PRIu64 ",\"control\":%d,\"init_rc\":%d,\"allocation_failures\":%zu,\"recovery_executed\":%s,\"rows\":[",measured_rc,worker_rc,measured_guard_error,cap,j->stack_target,sizeof j->context,saved.init_calls,saved.identity_ok?"true":"false",saved.completed,3*saved.count,high,observed,canary?"true":"false",recovery?"true":"false",j->heap[0],j->heap[3],j->heap[4],measured_reserved,measured_enabled,saved.order,saved.count,j->seed,j->control,measured_init_rc,measured_allocation_failures,old_control?"false":"true");
 int bad=worker_rc||measured_init_rc||measured_guard_error||j->guard_error||!canary||high>cap||!recovery||j->heap[2]||j->heap[4]||saved.init_calls!=1||!saved.identity_ok;
 for(int i=0;i<saved.completed;i++){
  common_row*r=&saved.rows[i];if(i)putchar(',');printf("{\"parameter\":%d,\"operation\":%d,\"rc\":%d,\"output_matches\":%s,\"failure_outputs_cleared\":",r->parameter,r->operation,r->rc,r->match?"true":"false");if(r->clear<0)fputs("null",stdout);else fputs(r->clear?"true":"false",stdout);
  printf(",\"arena_high_water_bytes\":%zu,\"stack_watermark_bytes\":%zu,\"changed_nonzero_released_bytes\":%zu}",r->high,r->watermark,r->changed_nonzero);
  if(r->high>cap||r->changed_nonzero||(r->rc==0&&!r->match)||(r->rc==LC_E_WORKSPACE&&r->clear!=1)||(r->rc&&r->rc!=LC_E_WORKSPACE))bad=1;
 }
 fputs("]",stdout);
#ifdef _WIN32
 printf(",\"heap_positive_control_mode\":\"%s\",\"heap_hooks\":%zu,\"heap_unhandled_imports\":%zu",audit_positive_control_local?"standalone_accounting_no_target_allocator_imports":"target_allocator_IAT_or_no_control",audit_hooked,audit_unsupported);
#endif
 puts("}");if(!old_control&&measured_rc==0&&saved.completed!=3*saved.count)bad=1;if(old_control&&measured_rc)bad=1;
 free_workspace(j);erase(common,sizeof *common);free(common);erase(&saved,sizeof saved);
#ifdef _WIN32
 FreeLibrary((HMODULE)j->a.handle);
#else
 dlclose(j->a.handle);
#endif
 erase(j,sizeof *j);free(j);return bad?14:0;
}
