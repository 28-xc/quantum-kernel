#include "target.h"
#include "../../configs/pruned/latticecore_pruned.h"
#include "vectors.h"
#include <string.h>

/* Every declared section below is counted once in the ELF ledger. */
#define GUARDED(name,n) static struct { uint8_t pre[32],bytes[n],post[32]; } name __attribute__((section(".caller_io"),aligned(32)))
GUARDED(pk,LC_TARGET_CAP_PK); GUARDED(sk,LC_TARGET_CAP_SK); GUARDED(ct,LC_TARGET_CAP_CT); GUARDED(sig,LC_TARGET_CAP_SIG);
GUARDED(ss,LC_TARGET_CAP_SS);
static struct { uint8_t pre[32],bytes[LC_TARGET_WORKSPACE],post[32]; } work __attribute__((section(".arena"),aligned(32)));
static lc_context context;
typedef struct { const uint8_t *bytes; size_t n,pos; int fail; } entropy_state;
static entropy_state entropy;
static unsigned failures,case_count;
static size_t maximum_stack,maximum_arena;
static const lc_target_vector *active;
static int scenario;

static int supplied(void *user,uint8_t *out,size_t n) {
  entropy_state *e=user;
  if(e->fail || e->pos>e->n || n>e->n-e->pos) return -1;
  memcpy(out,e->bytes+e->pos,n);e->pos+=n;return 0;
}
static int equal_fill(const uint8_t *p,size_t n,uint8_t b){while(n--)if(*p++!=b)return 0;return 1;}
static void paint_stack(void){memset(__test_stack_bottom,0xa5,(size_t)(__test_stack_top-__test_stack_bottom));}
static size_t stack_used(void){
  uint8_t *p=__test_stack_bottom;
  while(p<__test_stack_top && *p==0xa5)p++;
  return (size_t)(__test_stack_top-p);
}
static int guards(void){
#define CHECK(x) if(!equal_fill(x.pre,32,0xa5)||!equal_fill(x.post,32,0xa5))return 0
  CHECK(pk);CHECK(sk);CHECK(ct);CHECK(sig);CHECK(ss);CHECK(work);
#undef CHECK
  return equal_fill(__test_stack_bottom,32,0xa5);
}
static void prepare(const lc_target_vector *v,int which){
  active=v;scenario=which;
  memset(&pk,0xa5,sizeof(pk));memset(&sk,0xa5,sizeof(sk));memset(&ct,0xa5,sizeof(ct));
  memset(&sig,0xa5,sizeof(sig));memset(&ss,0xa5,sizeof(ss));memset(&work,0xa5,sizeof(work));
  entropy.bytes=v->coins.p;entropy.n=v->coins.n;entropy.pos=0;entropy.fail=which==1;
  if(which==6){
    /* Recover the same context object after errors; no re-initialization. */
    context.workspace=work.bytes;context.workspace_bytes=sizeof(work.bytes);
    context.random=supplied;context.random_user=&entropy;
  } else if(lc_context_init(&context,work.bytes,which==2?32:sizeof(work.bytes),supplied,&entropy))target_fault();
  if(which==5)context.random=0;
  paint_stack();
}
static int call_active(void *unused){
  const lc_target_vector *v=active;lc_sizes n;int p=v->parameter;(void)unused;
  if(lc_get_sizes(p,&n))return -99;
  if(v->operation==0)return lc_keypair(&context,p,scenario==4?sk.bytes:pk.bytes,scenario==3?n.public_key-1:sizeof(pk.bytes),
       sk.bytes,sizeof(sk.bytes));
  if(p>100){
    if(v->operation==1)return lc_encaps(&context,p,ct.bytes,scenario==3?n.ciphertext-1:sizeof(ct.bytes),
      scenario==4?ct.bytes:ss.bytes,32,v->pk.p,v->pk.n);
    return lc_decaps(&context,p,scenario==4?ct.bytes:ss.bytes,scenario==3?31:32,
      scenario==4?ct.bytes:v->ct.p,v->ct.n,v->sk.p,v->sk.n);
  }
  if(v->operation==1)return lc_sign(&context,p,sig.bytes,scenario==3?n.signature-1:sizeof(sig.bytes),
    scenario==4?sig.bytes:v->message.p,scenario==4?1:v->message.n,
    v->domain.p,v->domain.n,v->sk.p,v->sk.n);
  return lc_verify(&context,p,v->signature.p,scenario==3?v->signature.n-1:v->signature.n,
    scenario==4?v->pk.p:v->message.p,scenario==4?1:v->message.n,
    v->domain.p,v->domain.n,v->pk.p,v->pk.n);
}
static int outputs_match(const lc_target_vector *v){
  if(v->operation==0)return !memcmp(pk.bytes,v->expected0.p,v->expected0.n)&&!memcmp(sk.bytes,v->expected1.p,v->expected1.n);
  if(v->parameter>100){
    if(v->operation==1)return !memcmp(ct.bytes,v->expected0.p,v->expected0.n)&&!memcmp(ss.bytes,v->expected1.p,v->expected1.n);
    return !memcmp(ss.bytes,v->expected0.p,v->expected0.n);
  }
  return v->operation!=1 || !memcmp(sig.bytes,v->expected0.p,v->expected0.n);
}
static int outputs_zero(const lc_target_vector *v){
  lc_sizes n;lc_get_sizes(v->parameter,&n);
  if(v->operation==0)return equal_fill(pk.bytes,n.public_key,0)&&equal_fill(sk.bytes,n.secret_key,0);
  if(v->parameter>100){
    if(v->operation==1)return equal_fill(ct.bytes,n.ciphertext,0)&&equal_fill(ss.bytes,32,0);
    return equal_fill(ss.bytes,32,0);
  }
  return v->operation!=1||equal_fill(sig.bytes,n.signature,0);
}
static void emit_case(unsigned index,const char *kind,int rc,int ok,size_t used){
  target_text("{\"event\":\"case\",\"index\":");target_uint(index);
  target_text(",\"parameter\":");target_uint((unsigned)active->parameter);
  target_text(",\"operation\":");target_uint((unsigned)active->operation);
  target_text(",\"tcId\":");target_uint(active->tc_id);
  target_text(",\"kind\":\"");target_text(kind);target_text("\",\"rc\":");target_int(rc);
  target_text(",\"ok\":");target_text(ok?"true":"false");
  target_text(",\"arena_highwater_bytes\":");target_uint((uint32_t)context.arena_high_water);
  target_text(",\"stack_watermark_bytes\":");target_uint((uint32_t)used);
  target_text(",\"allocation_failures\":");target_uint((uint32_t)context.allocation_failures);
  target_text("}\n");
  case_count++;if(!ok)failures++;
  if(used>maximum_stack)maximum_stack=used;
  if(context.arena_high_water>maximum_arena)maximum_arena=context.arena_high_water;
}
static void one(unsigned i,int which,const char *kind){
  const lc_target_vector *v=target_vectors+i;int rc,expected,ok;size_t used;
  prepare(v,which);rc=target_call(call_active,0);used=stack_used();
  expected=which==1||which==5?LC_E_RANDOM:which==2?LC_E_WORKSPACE:
    which==3?LC_E_LENGTH:which==4?LC_E_ALIAS:v->accepted?LC_OK:LC_E_REJECT;
  ok=rc==expected&&guards();
  if((!which||which==6)&&v->accepted)ok=ok&&outputs_match(v)&&entropy.pos==entropy.n;
  if(which==1||which==2||which==5)ok=ok&&outputs_zero(v);
  emit_case(i,kind,rc,ok,used);
}
static void field(const char *s,size_t n){target_text(s);target_uint((uint32_t)n);}
static void memory_ledger(void){
  target_text("{\"event\":\"layout\"");
  field(",\"pointer_bits\":",8*sizeof(void*));
  field(",\"code_and_rodata_load_bytes\":",(size_t)(__code_end-__code_start));
  field(",\"data_bytes\":",(size_t)(__data_end-__data_start));
  field(",\"bss_excluding_arena_io_stacks_bytes\":",(size_t)(__bss_end-__bss_start));
  field(",\"arena_reservation_with_guards_bytes\":",(size_t)(__arena_end-__arena_start));
  field(",\"workspace_capacity_bytes\":",sizeof(work.bytes));
  field(",\"caller_io_reservation_with_guards_bytes\":",(size_t)(__io_end-__io_start));
  field(",\"test_stack_reservation_bytes\":",(size_t)(__test_stack_top-__test_stack_bottom));
  field(",\"control_stack_reservation_bytes\":",(size_t)(__control_stack_top-__control_stack_bottom));
  field(",\"context_bytes_in_bss\":",sizeof(context));
  field(",\"writable_image_span_bytes\":",(size_t)(__ram_end-__ram_start));
  target_text(",\"heap_bytes\":0,\"timing_collected\":false}\n");
}
#ifndef LC_TARGET_OPERATION_MASK
#define LC_TARGET_OPERATION_MASK 262143u
#endif
static void capability_checks(void){
  static const int parameters[6]={512,768,1024,44,65,87};
  unsigned i,op,count=0;int rc,ok=1;
  for(i=0;i<6;i++)for(op=0;op<3;op++){
    int p=parameters[i];
    if(LC_TARGET_OPERATION_MASK&(1u<<(3*i+op)))continue;
    if(op==0)rc=lc_keypair(0,p,0,0,0,0);
    else if(p>100&&op==1)rc=lc_encaps(0,p,0,0,0,0,0,0);
    else if(p>100)rc=lc_decaps(0,p,0,0,0,0,0,0);
    else if(op==1)rc=lc_sign(0,p,0,0,0,0,0,0,0,0);
    else rc=lc_verify(0,p,0,0,0,0,0,0,0,0);
    count++;if(rc!=LC_E_UNSUPPORTED)ok=0;
  }
  for(i=0;i<6;i++){
    int p=parameters[i],a,b;
    int expected=(LC_TARGET_OPERATION_MASK&(7u<<(3*i)))?LC_E_ARGUMENT:LC_E_UNSUPPORTED;
    if(p>100){a=lc_sign(0,p,0,0,0,0,0,0,0,0);b=lc_verify(0,p,0,0,0,0,0,0,0,0);}
    else {a=lc_encaps(0,p,0,0,0,0,0,0);b=lc_decaps(0,p,0,0,0,0,0,0);}
    if(a!=expected||b!=expected)ok=0;
  }
  target_text("{\"event\":\"excluded_operations\",\"cases\":");target_uint(count);
  target_text(",\"cross_algorithm_argument_cases\":12,\"ok\":");target_text(ok?"true":"false");target_text("}\n");
  if(!ok)failures++;
}
int target_main(void){
  unsigned i;size_t size=(size_t)(__test_stack_top-__test_stack_bottom);int positive;
  target_text("{\"event\":\"begin\",\"schema\":1,\"target\":\"" LC_TARGET_NAME "\",\"rng\":\"test_callback_only\"}\n");
  memory_ledger();
  capability_checks();
  paint_stack();__test_stack_bottom[64]=0;positive=stack_used()==size-64;
  target_text("{\"event\":\"watermark_positive_control\",\"ok\":");target_text(positive?"true":"false");target_text("}\n");if(!positive)failures++;
  for(i=0;i<LC_TARGET_VECTOR_COUNT;i++){
    const lc_target_vector *v=target_vectors+i;
    one(i,0,v->accepted?"acvp_positive":"acvp_negative");
    if(!v->accepted)continue;
    one(i,3,"short_length");one(i,4,"alias");one(i,2,"workspace_exhaustion");
    if(v->operation==0||v->operation==1){one(i,1,"rng_failure");one(i,5,"missing_rng");}
    one(i,6,"recovery_after_errors");
  }
  target_text("{\"event\":\"summary\",\"cases\":");target_uint(case_count);
  field(",\"failures\":",failures);field(",\"maximum_observed_test_stack_bytes\":",maximum_stack);
  field(",\"maximum_observed_arena_bytes\":",maximum_arena);
  target_text(",\"timing_collected\":false}\n");return failures?1:0;
}
