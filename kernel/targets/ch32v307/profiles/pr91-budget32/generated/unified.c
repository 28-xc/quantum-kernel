/* External research adapter; upstream PR91 sources are not edited.
 * Complete PR91 calls execute on caller-owned stack storage, which is erased
 * after every ordinary return. This module serializes DSA calls, so the RNG
 * bridge needs neither hidden heap storage nor a persistent secret copy.
 * No asynchronous exception/cancellation cleanup guarantee is claimed. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdatomic.h>
#include "lc_dsa_api.h"
#include "stack_bounds.h"

#define DECL(M) \
extern int pqcrystals_dilithium##M##_lowram_keypair(uint8_t*,uint8_t*); \
extern int pqcrystals_dilithium##M##_lowram_signature(uint8_t*,size_t*,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*); \
extern int pqcrystals_dilithium##M##_lowram_verify(const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*)
DECL(2); DECL(3); DECL(5);
typedef struct {
 int level,op,rc,rng_calls,rng_bad;
 uint8_t *pk,*sk,*sig;
 const uint8_t *msg,*ctx,*rnd,*input_key,*input_sig;
 size_t msg_bytes,ctx_bytes,sig_bytes;
} pr91_job;
static atomic_flag call_lock=ATOMIC_FLAG_INIT;
static pr91_job * volatile active_job;
static void wipe(void*p,size_t n){volatile uint8_t*q=p;while(n--)*q++=0;}
extern int lc_memory_call_at(void*,uintptr_t,int(*)(void*));
void pr91_call_randombytes(uint8_t*out,size_t n){
 pr91_job*j=active_job;
 if(!j||!j->rnd||n!=32||j->rng_calls){if(j)j->rng_bad=1;memset(out,0,n);return;}
 memcpy(out,j->rnd,32);j->rng_calls++;
}
static int invoke(void*p){
 pr91_job*j=p;size_t n=0;
#define CALL(M) do { \
 if(j->op==0)j->rc=pqcrystals_dilithium##M##_lowram_keypair(j->pk,j->sk); \
 else if(j->op==1){j->rc=pqcrystals_dilithium##M##_lowram_signature(j->sig,&n,j->msg,j->msg_bytes,j->ctx,j->ctx_bytes,j->input_key);if(!j->rc&&n!=j->sig_bytes)j->rc=-1;} \
 else j->rc=pqcrystals_dilithium##M##_lowram_verify(j->input_sig,j->sig_bytes,j->msg,j->msg_bytes,j->ctx,j->ctx_bytes,j->input_key); \
 }while(0)
 if(j->level==44)CALL(2);else if(j->level==65)CALL(3);else CALL(5);
 if(j->op!=2&&(j->rng_calls!=1||j->rng_bad))j->rc=-1;
 return j->rc;
}
static int slot(int level){return level==44?0:level==65?1:level==87?2:-1;}
size_t lc_dsa_size(int level,int kind){static const size_t z[3][3]={{1312,2560,2420},{1952,4032,3309},{2592,4896,4627}};int i=slot(level);return i<0||kind<0||kind>2?0:z[i][kind];}
int lc_dsa_native_enabled(void){return 0;}
int lc_dsa_lowram_enabled(void){return 1;}
/* 32 bytes at each end remain outside the alternate stack. 31 extra bytes
 * cover arbitrary caller alignment; all bytes included in high-water are wiped. */
size_t lc_dsa_workspace_bound(int level,int op){int i=slot(level);return i<0||op<0||op>2?0:pr91_stack_bounds[i][op]+96;}
#if PR91_DIAGNOSTIC
#if defined(_WIN32)
#define DIAG __declspec(dllexport)
#else
#define DIAG __attribute__((visibility("default")))
#endif
static size_t diagnostic[3][3];
DIAG size_t pr91_stack_observed(int level,int op){int i=slot(level);return i<0||op<0||op>2?0:diagnostic[i][op];}
DIAG size_t pr91_workspace_required(int level,int op){return lc_dsa_workspace_bound(level,op);}
#endif
static int run(pr91_job*j,void*w,size_t n,lc_dsa_stats*s){
 size_t bound=lc_dsa_workspace_bound(j->level,j->op),cap=bound?bound-96:0;int rc;
 uintptr_t raw=(uintptr_t)w,low=(raw+31)&~(uintptr_t)31;
 memset(s,0,sizeof *s);s->arena_capacity=n;
 if(!bound||!w||raw>UINTPTR_MAX-n||n<bound){s->allocation_failures=1;return -1;}
 uint8_t *bottom=(uint8_t*)low+32,*top=bottom+cap;
 memset((void*)low,0xA6,32);memset(top,0x6A,32);
#if PR91_DIAGNOSTIC
 memset(bottom,0xA5,cap);
#endif
 while(atomic_flag_test_and_set_explicit(&call_lock,memory_order_acquire)){}
 active_job=j;
 rc=lc_memory_call_at(j,(uintptr_t)top,invoke);
 active_job=NULL;
 atomic_flag_clear_explicit(&call_lock,memory_order_release);
#if PR91_DIAGNOSTIC
 size_t z=0;while(z<cap&&bottom[z]==0xA5)z++;
 size_t depth=cap-z;int i=slot(j->level);
 if(depth>diagnostic[i][j->op])diagnostic[i][j->op]=depth;
#endif
 unsigned damaged=0;for(size_t k=0;k<32;k++)damaged|=((uint8_t*)low)[k]^0xA6,damaged|=top[k]^0x6A;
 /* Wipe guards, alignment padding, stack, spill slots and unused capacity. */
 wipe(w,bound);s->arena_high_water=bound;s->allocations=1;
 if(damaged){s->lifo_errors=1;return -1;}return rc;
}
int lc_dsa_keypair_seed(int l,uint8_t*pk,uint8_t*sk,const uint8_t seed[32],void*w,size_t n,lc_dsa_stats*s){pr91_job j={0};j.level=l;j.op=0;j.pk=pk;j.sk=sk;j.rnd=seed;int r=run(&j,w,n,s);wipe(&j,sizeof j);return r;}
int lc_dsa_sign_seed(int l,uint8_t*sig,const uint8_t*m,size_t mn,const uint8_t*c,size_t cn,const uint8_t rnd[32],const uint8_t*sk,void*w,size_t n,lc_dsa_stats*s){pr91_job j={0};j.level=l;j.op=1;j.sig=sig;j.msg=m;j.msg_bytes=mn;j.ctx=c;j.ctx_bytes=cn;j.rnd=rnd;j.input_key=sk;j.sig_bytes=lc_dsa_size(l,2);int r=run(&j,w,n,s);wipe(&j,sizeof j);return r;}
int lc_dsa_verify(int l,const uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*c,size_t cn,const uint8_t*pk,void*w,size_t n,lc_dsa_stats*s){pr91_job j={0};j.level=l;j.op=2;j.input_sig=sig;j.sig_bytes=sn;j.msg=m;j.msg_bytes=mn;j.ctx=c;j.ctx_bytes=cn;j.input_key=pk;int r=run(&j,w,n,s);wipe(&j,sizeof j);return r;}
