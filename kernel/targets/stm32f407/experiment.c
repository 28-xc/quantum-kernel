#include "board.h"
#include "latticecore.h"
#include "vectors.h"
#include <string.h>

enum { KEY=1, SECOND=2, THIRD=4, TAMPER=8, CLEAN=16, RNG_FAIL=32,
       LENGTH=64, CAPACITY=128, RECOVER=256, ALIAS=512 };
/* Entire transaction storage is accounted in the link map, including demo I/O. */
static struct {uint8_t before[32],data[ARENA_BYTES],after[32];} guarded __attribute__((aligned(32),section(".ccm")));
#define arena guarded.data
extern uint8_t __stack_guard_bottom[];
#if PROFILE==3
unsigned reference_heap_peak(void);
void reference_heap_reset_peak(void);
#endif
static struct {
    uint8_t pk[LC_TARGET_CAP_PK], sk[LC_TARGET_CAP_SK], ct[LC_TARGET_CAP_CT];
    uint8_t ss[32], ss2[32], sig[LC_TARGET_CAP_SIG], message[256], context[256];
} io;
static lc_context ctx;
typedef struct {uint32_t state[4]; int source; const uint8_t *fixed; size_t left;} entropy_source;
static entropy_source random_state;
static unsigned zeroed(const void *p,size_t n) {
    const uint8_t *b=p;unsigned v=0;
    for(size_t i=0;i<n;i++)v|=b[i];
    return v==0;
}
static uint32_t rotate(uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
/* Public seeded test corpus only. Live cryptographic randomness is furnished by the hardware RNG. */
static uint32_t trial_word(entropy_source *e) {
    uint32_t *s=e->state;uint32_t out=rotate(s[1]*5u,7)*9u,t=s[1]<<9;
    s[2]^=s[0];s[3]^=s[1];s[1]^=s[2];s[0]^=s[3];s[2]^=t;s[3]=rotate(s[3],11);
    return out;
}
static void initialize_stream(entropy_source *e,const m4_request *q,uint32_t domain) {
    memset(e,0,sizeof(*e));memcpy(e->state,q->w+4,16);
    e->state[0]^=domain;e->state[3]^=0x9e3779b9u;
    if(!(e->state[0]|e->state[1]|e->state[2]|e->state[3]))e->state[0]=1;
    for(int i=0;i<16;i++)trial_word(e);
}
static int hw_word(uint32_t *word) {
    REG(0x40023834)|=1u<<6;(void)REG(0x40023834);
    REG(0x50060800)|=4u;
    for(unsigned i=0;i<500000u;i++) {
        uint32_t s=REG(0x50060804);
        if(s&0x66u)return -1;
        if(s&1u){*word=REG(0x50060808);return 0;}
    }
    return -1;
}
static int random_bytes(void *user,uint8_t *out,size_t n) {
    entropy_source *e=user;
    if(e->source==3)return -1;
    if(e->source==2){if(n>e->left)return -1;if(n)memcpy(out,e->fixed,n);e->fixed+=n;e->left-=n;return 0;}
    while(n){uint32_t x;
        if(e->source==1){if(hw_word(&x))return -1;}else x=trial_word(e);
        size_t take=n>4?4:n;memcpy(out,&x,take);out+=take;n-=take;x=0;
    }
    return 0;
}
static int exact(const uint8_t *p,size_t n,lc_vector_bytes v){return n==v.n&&!memcmp(p,v.p,n);}
static int clean_arena(void){return zeroed(arena,sizeof(arena));}
static int guards_ok(void){
    unsigned bad=0;
    for(size_t i=0;i<32;i++)bad|=(guarded.before[i]^0xc3u)|(guarded.after[i]^0x3cu);
    for(size_t i=0;i<64;i++)bad|=__stack_guard_bottom[i]^0xa5u;
    return bad==0;
}
static void reset_stack_measurement(void) {
#if defined(__arm__)
    uintptr_t sp;
    __asm__ volatile("mrs %0,msp":"=r"(sp));
    uint8_t *p=(uint8_t*)__stack_bottom;
    for(; (uintptr_t)p+128u<sp; ++p)*p=0xa5;
#endif
}
static void finish_slot(m4_response *r,unsigned slot,int rc,uint32_t start,uint32_t end){
    r->w[24+slot]=(uint32_t)rc;r->w[28+slot]=end-start;r->w[32+slot]=(uint32_t)ctx.arena_high_water;
    r->w[57+slot]=stack_used();
}
static void kat(m4_response *r) {
    unsigned mask=0;
    for(unsigned i=0;i<LC_TARGET_VECTOR_COUNT;i++){
        const lc_target_vector *v=target_vectors+i;
        unsigned slot=v->accepted?(unsigned)v->operation:3;
        random_state.source=2;random_state.fixed=v->coins.p;random_state.left=v->coins.n;
        int rc;reset_stack_measurement();uint32_t start=cycle_stamp();
        if(v->operation==0)rc=lc_keypair(&ctx,PARAM,io.pk,sizeof(io.pk),io.sk,sizeof(io.sk));
#if PARAM>100
        else if(v->operation==1)rc=lc_encaps(&ctx,PARAM,io.ct,sizeof(io.ct),io.ss,32,v->pk.p,v->pk.n);
        else rc=lc_decaps(&ctx,PARAM,io.ss,32,v->ct.p,v->ct.n,v->sk.p,v->sk.n);
#else
        else if(v->operation==1)rc=lc_sign(&ctx,PARAM,io.sig,sizeof(io.sig),v->message.p,v->message.n,v->domain.p,v->domain.n,v->sk.p,v->sk.n);
        else rc=lc_verify(&ctx,PARAM,v->signature.p,v->signature.n,v->message.p,v->message.n,v->domain.p,v->domain.n,v->pk.p,v->pk.n);
#endif
        uint32_t end=cycle_stamp();finish_slot(r,slot,rc,start,end);
        r->w[44+slot]=v->tc_id;
        int ok=rc==(v->accepted?LC_OK:LC_E_REJECT)&&!random_state.left;
        if(v->operation==0)ok=ok&&exact(io.pk,sizeof(io.pk),v->expected0)&&exact(io.sk,sizeof(io.sk),v->expected1);
#if PARAM>100
        else if(v->operation==1)ok=ok&&exact(io.ct,sizeof(io.ct),v->expected0)&&exact(io.ss,32,v->expected1);
        else ok=ok&&exact(io.ss,32,v->expected0);
#else
        else if(v->operation==1)ok=ok&&exact(io.sig,sizeof(io.sig),v->expected0);
#endif
        if(ok)mask|=1u<<slot;
    }
    r->w[23]=mask;r->w[48]=LC_TARGET_VECTOR_COUNT;
}
static void run_live(const m4_request *q,m4_response *r) {
    size_t m=q->w[11],d=q->w[12],budget=q->w[10];unsigned mask=0;
    int insufficient=(q->w[14]&1)!=0;
    if(!budget||budget>sizeof(arena)||m>sizeof(io.message)||d>255||q->w[13]>1)return;
    entropy_source input;
    initialize_stream(&input,q,0x4d534747);random_bytes(&input,io.message,m);random_bytes(&input,io.context,d);clear_bytes(&input,sizeof(input));
    initialize_stream(&random_state,q,0x454e5452);random_state.source=(int)q->w[13];
    lc_context_init(&ctx,arena,budget,random_bytes,&random_state);
    r->w[41]=budget;r->w[42]=m;r->w[43]=d;r->w[48]=q->w[13];
    if(insufficient){
        int rc=lc_keypair(&ctx,PARAM,io.pk,sizeof(io.pk),io.sk,sizeof(io.sk));
        r->w[44]=rc;
        if(rc==LC_E_WORKSPACE && zeroed(io.pk,sizeof(io.pk))&&zeroed(io.sk,sizeof(io.sk)))mask|=CAPACITY;
        initialize_stream(&random_state,q,0x454e5452);random_state.source=(int)q->w[13];
        lc_context_init(&ctx,arena,sizeof(arena),random_bytes,&random_state);
    }
    int clean=1,rc;
    for(unsigned slot=0;slot<4;slot++){
        if(slot==3){
#if PARAM>100
            io.ct[0]^=1u;
#else
            io.sig[0]^=1u;
#endif
        }
        reset_stack_measurement();uint32_t start=cycle_stamp();
        if(slot==0)rc=lc_keypair(&ctx,PARAM,io.pk,sizeof(io.pk),io.sk,sizeof(io.sk));
#if PARAM>100
        else if(slot==1)rc=lc_encaps(&ctx,PARAM,io.ct,sizeof(io.ct),io.ss,32,io.pk,sizeof(io.pk));
        else rc=lc_decaps(&ctx,PARAM,io.ss2,32,io.ct,sizeof(io.ct),io.sk,sizeof(io.sk));
#else
        else if(slot==1)rc=lc_sign(&ctx,PARAM,io.sig,sizeof(io.sig),io.message,m,io.context,d,io.sk,sizeof(io.sk));
        else rc=lc_verify(&ctx,PARAM,io.sig,sizeof(io.sig),io.message,m,io.context,d,io.pk,sizeof(io.pk));
#endif
        uint32_t end=cycle_stamp();finish_slot(r,slot,rc,start,end);
        clean&=clean_arena();
        if(slot==0){if(rc==LC_OK)mask|=KEY;if(insufficient)r->w[45]=rc;r->w[49]=m4_checksum(io.pk,sizeof(io.pk));}
        if(slot==1){if(rc==LC_OK)mask|=SECOND;
#if PARAM>100
            r->w[50]=m4_checksum(io.ct,sizeof(io.ct));
#else
            r->w[50]=m4_checksum(io.sig,sizeof(io.sig));
#endif
        }
#if PARAM>100
        if(slot==2&&rc==LC_OK&&!memcmp(io.ss,io.ss2,32))mask|=THIRD;
        if(slot==3&&rc==LC_OK&&memcmp(io.ss,io.ss2,32))mask|=TAMPER;
#else
        if(slot==2&&rc==LC_OK)mask|=THIRD;
        if(slot==3&&rc==LC_E_REJECT)mask|=TAMPER;
#endif
        if(slot<3&&rc!=LC_OK)break;
    }
    if(insufficient&&(mask&(KEY|SECOND|THIRD|TAMPER))==15)mask|=RECOVER;
    if(q->w[2]==M4_BOUNDARY){
#if PARAM>100
        io.pk[0]=0xff;io.pk[1]|=0x0f;
        r->w[53]=lc_encaps(&ctx,PARAM,io.ct,sizeof(io.ct),io.ss,32,io.pk,sizeof(io.pk));
        r->w[61]=lc_decaps(&ctx,PARAM,io.ss2,32,io.ct,sizeof(io.ct)-1,io.sk,sizeof(io.sk));
#else
        io.sig[sizeof(io.sig)-1]=0xff;
        r->w[53]=lc_verify(&ctx,PARAM,io.sig,sizeof(io.sig),io.message,m,io.context,d,io.pk,sizeof(io.pk));
        r->w[61]=lc_sign(&ctx,PARAM,io.sig,sizeof(io.sig),io.message,m,io.context,256,io.sk,sizeof(io.sk));
#endif
        initialize_stream(&random_state,q,0x414c4947);
        lc_context_init(&ctx,arena+1,sizeof(arena)-1,random_bytes,&random_state);
        r->w[54]=lc_keypair(&ctx,PARAM,io.pk,sizeof(io.pk),io.sk,sizeof(io.sk));
    }
    random_state.source=3;memset(io.pk,0xa7,sizeof(io.pk));memset(io.sk,0xa7,sizeof(io.sk));
    rc=lc_keypair(&ctx,PARAM,io.pk,sizeof(io.pk),io.sk,sizeof(io.sk));r->w[46]=rc;
    if(rc==LC_E_RANDOM&&zeroed(io.pk,sizeof(io.pk))&&zeroed(io.sk,sizeof(io.sk)))mask|=RNG_FAIL;
    rc=lc_keypair(&ctx,PARAM,io.pk,sizeof(io.pk)-1,io.sk,sizeof(io.sk));r->w[47]=rc;
    if(rc==LC_E_LENGTH)mask|=LENGTH;
    rc=lc_keypair(&ctx,PARAM,io.sk,sizeof(io.pk),io.sk,sizeof(io.sk));r->w[51]=rc;
    if(rc==LC_E_ALIAS)mask|=ALIAS;
    clear_bytes(&io,sizeof(io));clear_bytes(&random_state,sizeof(random_state));
    if(clean&&zeroed(&io,sizeof(io))&&zeroed(&random_state,sizeof(random_state)))mask|=CLEAN;
    r->w[23]=mask;
}
void experiment(const m4_request *q,m4_response *r) {
    if(q->w[8]!=PARAM||q->w[9]!=PROFILE)return;
    if(lc_context_init(&ctx,arena,sizeof(arena),random_bytes,&random_state)!=LC_OK)return;
    memset(guarded.before,0xc3,sizeof(guarded.before));memset(guarded.after,0x3c,sizeof(guarded.after));
#if PROFILE==3
    reference_heap_reset_peak();
#endif
    if(q->w[2]==M4_KAT)kat(r);
    else if(q->w[2]==M4_RUN||q->w[2]==M4_BOUNDARY||q->w[2]==M4_TIMING)run_live(q,r);
    clear_bytes(&io,sizeof(io));clear_bytes(&random_state,sizeof(random_state));clear_bytes(arena,sizeof(arena));clear_bytes(&ctx,sizeof(ctx));
    r->w[52]=guards_ok();
#if PROFILE==3
    r->w[62]=reference_heap_peak();
#endif
}

