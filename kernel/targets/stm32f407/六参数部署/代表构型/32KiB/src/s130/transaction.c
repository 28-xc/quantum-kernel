
extern int a127_kat_key(unsigned,const unsigned char*,int,unsigned char*,const unsigned char*,const unsigned char*,unsigned char*);
extern int a127_kat_kem_key(unsigned,const unsigned char*,const unsigned char*,const unsigned char*,unsigned char*);
extern int a127_kat_sig(unsigned,const unsigned char*,const unsigned char*,const unsigned char*,unsigned,const unsigned char*,unsigned,const unsigned char*,const unsigned char*,unsigned char*);
typedef long long int int64_t;
typedef long long unsigned int uint64_t;
typedef int64_t int_least64_t;
typedef uint64_t uint_least64_t;
typedef int64_t int_fast64_t;
typedef uint64_t uint_fast64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef int32_t int_least32_t;
typedef uint32_t uint_least32_t;
typedef int32_t int_fast32_t;
typedef uint32_t uint_fast32_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int16_t int_least16_t;
typedef uint16_t uint_least16_t;
typedef int16_t int_fast16_t;
typedef uint16_t uint_fast16_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef int8_t int_least8_t;
typedef uint8_t uint_least8_t;
typedef int8_t int_fast8_t;
typedef uint8_t uint_fast8_t;
typedef int intptr_t;
typedef unsigned int uintptr_t;
typedef long long int intmax_t;
typedef long long unsigned int uintmax_t;
typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
enum { M4_HELLO=1,M4_RUN=2,M4_KAT=3,M4_BOUNDARY=4,M4_CLOCK=5,M4_RETURN_DFU=6,M4_TIMING=7,M4_POLY=8 };
typedef struct {uint32_t w[16];} m4_request;
typedef struct {uint32_t w[64];} m4_response;
void experiment(const m4_request*,m4_response*);
void hardware_info(m4_response*);
void clear_bytes(void*,size_t);
uint32_t m4_checksum(const void*,size_t);
void reset_to_dfu(void) __attribute__((noreturn));
uint32_t stack_used(void);
uint32_t cycle_stamp(void);
void board_start(void) __attribute__((noreturn));
extern uint32_t __stack_bottom[],__stack_top[];
enum { LC_OK=0, LC_E_ARGUMENT=-1, LC_E_LENGTH=-2, LC_E_ALIAS=-3,
       LC_E_RANDOM=-4, LC_E_WORKSPACE=-5, LC_E_REJECT=-6, LC_E_INTERNAL=-7 };
typedef int (*lc_random_fn)(void *user,uint8_t *out,size_t bytes);
typedef struct {
  void *workspace;
  size_t workspace_bytes;
  lc_random_fn random;
  void *random_user;
  size_t arena_high_water, allocations, allocation_failures;
  int last_error;
} lc_context;
typedef struct { size_t public_key,secret_key,ciphertext,shared_secret,signature; } lc_sizes;
__attribute__((externally_visible)) int lc_get_sizes(int parameter,lc_sizes *sizes);
__attribute__((externally_visible)) int lc_context_init(lc_context *ctx,void *workspace,size_t bytes,
                    lc_random_fn random,void *random_user);
__attribute__((externally_visible)) int lc_keypair(lc_context *ctx,int parameter,uint8_t *pk,size_t pk_capacity,
               uint8_t *sk,size_t sk_capacity);
__attribute__((externally_visible)) int lc_encaps(lc_context *ctx,int parameter,uint8_t *ct,size_t ct_capacity,
              uint8_t *ss,size_t ss_capacity,const uint8_t *pk,size_t pk_bytes);
__attribute__((externally_visible)) int lc_decaps(lc_context *ctx,int parameter,uint8_t *ss,size_t ss_capacity,
              const uint8_t *ct,size_t ct_bytes,const uint8_t *sk,size_t sk_bytes);
__attribute__((externally_visible)) int lc_sign(lc_context *ctx,int parameter,uint8_t *sig,size_t sig_capacity,
            const uint8_t *message,size_t message_bytes,const uint8_t *domain,
            size_t domain_bytes,const uint8_t *sk,size_t sk_bytes);
__attribute__((externally_visible)) int lc_verify(lc_context *ctx,int parameter,const uint8_t *sig,size_t sig_bytes,
              const uint8_t *message,size_t message_bytes,const uint8_t *domain,
              size_t domain_bytes,const uint8_t *pk,size_t pk_bytes);
__attribute__((externally_visible)) const char *lc_error_string(int status);

typedef struct {uint32_t state[4]; int source; const uint8_t *fixed; size_t left;} entropy_source;
struct io_512 {uint8_t pk[800], sk[1632], ct[768], ss[32], ss2[32], sig[1], message[256], context[256];};
struct io_768 {uint8_t pk[1184], sk[2400], ct[1088], ss[32], ss2[32], sig[1], message[256], context[256];};
struct io_1024 {uint8_t pk[1568], sk[3168], ct[1568], ss[32], ss2[32], sig[1], message[256], context[256];};
struct io_44 {uint8_t pk[1312], sk[2560], ct[1], ss[32], ss2[32], sig[2420], message[256], context[256];};
struct io_65 {uint8_t pk[1952], sk[4032], ct[1], ss[32], ss2[32], sig[3309], message[256], context[256];};
struct io_87 {uint8_t pk[2592], sk[4896], ct[1], ss[32], ss2[32], sig[4627], message[256], context[256];};
union transaction_views {
 struct {struct {uint8_t before[32],data[5120],after[32];} guarded; uint8_t io_lower[16];struct io_512 io;uint8_t io_upper[16];} c512_compact;
 struct {struct {uint8_t before[32],data[5120],after[32];} guarded; uint8_t io_lower[16];struct io_512 io;uint8_t io_upper[16];} c512_cached;
 struct {struct {uint8_t before[32],data[6656],after[32];} guarded; uint8_t io_lower[16];struct io_768 io;uint8_t io_upper[16];} c768_compact;
 struct {struct {uint8_t before[32],data[6656],after[32];} guarded; uint8_t io_lower[16];struct io_768 io;uint8_t io_upper[16];} c768_cached;
 struct {struct {uint8_t before[32],data[8448],after[32];} guarded; uint8_t io_lower[16];struct io_1024 io;uint8_t io_upper[16];} c1024_compact;
 struct {struct {uint8_t before[32],data[8448],after[32];} guarded; uint8_t io_lower[16];struct io_1024 io;uint8_t io_upper[16];} c1024_cached;
 struct {struct {uint8_t before[32],data[7168],after[32];} guarded; uint8_t io_lower[16];struct io_44 io;uint8_t io_upper[16];} c44_compact;
 struct {struct {uint8_t before[32],data[21408],after[32];} guarded; uint8_t io_lower[16];struct io_44 io;uint8_t io_upper[16];} c44_cached;
 struct {struct {uint8_t before[32],data[8672],after[32];} guarded; uint8_t io_lower[16];struct io_65 io;uint8_t io_upper[16];} c65_compact;
 struct {struct {uint8_t before[32],data[18240],after[32];} guarded; uint8_t io_lower[16];struct io_65 io;uint8_t io_upper[16];} c65_cached;
 struct {struct {uint8_t before[32],data[7008],after[32];} guarded; uint8_t io_lower[16];struct io_87 io;uint8_t io_upper[16];} c87_compact;
 struct {struct {uint8_t before[32],data[15584],after[32];} guarded; uint8_t io_lower[16];struct io_87 io;uint8_t io_upper[16];} c87_cached;
};
extern union transaction_views combined_storage;
extern lc_context active_context;
extern entropy_source active_entropy;
void unified_hello(m4_response*);
void unified_hash(m4_response*);
int unified_select(const m4_request*,m4_response*);
void unified_idle(void);
void selected_layout(const m4_request*,m4_response*);
enum { LC_RESOURCE_FIXED=0, LC_RESOURCE_FULL_MATRIX=1,
       LC_RESOURCE_FIVE_ROWS=2 };
enum { LC_RESOURCE_E_UNSUPPORTED=-8 };
typedef struct {
  size_t minimum_workspace_bytes, preferred_workspace_bytes;
  size_t alignment, public_context_bytes, caller_plan_bytes;
  unsigned adaptive, exact_workspace_bound;
} lc_resource_requirements;
typedef struct {
  size_t workspace_bytes, alignment_padding, usable_workspace_bytes;
  size_t required_workspace_bytes, matrix_cache_bytes, saved_input_bytes;
  unsigned mode, cached_rows, cached_polynomials;
} lc_resource_plan;
__attribute__((externally_visible)) int lc_resource_query(int parameter,int operation,
    lc_resource_requirements *requirements);
__attribute__((externally_visible)) int lc_resource_make_plan(int parameter,int operation,
    const void *workspace,size_t bytes,lc_resource_plan *plan);
__attribute__((externally_visible)) int lc_resource_algorithm_bytes(size_t workspace_bytes,
    size_t stack_bytes,size_t other_bytes,size_t *total_bytes);
typedef struct { const uint8_t *p; unsigned n; } lc_vector_bytes;
typedef struct { int parameter,operation,accepted; unsigned tc_id; lc_vector_bytes coins; lc_vector_bytes pk; lc_vector_bytes sk; lc_vector_bytes ct; lc_vector_bytes signature; lc_vector_bytes message; lc_vector_bytes domain; lc_vector_bytes expected0; lc_vector_bytes expected1; } lc_target_vector;
extern size_t lc_f407_usable_requirement(int,int,size_t);
typedef struct {unsigned short p,s,cap,nvec,io_size,pk_len,sk_len,ct_len,sig_len;
uint8_t *area,*pk,*sk,*ct,*ss,*ss2,*sig,*message,*context; const lc_target_vector *vectors;
 __typeof__(&lc_context_init) init;
 __typeof__(&lc_keypair) key;
 __typeof__(&lc_encaps) enc;
 __typeof__(&lc_decaps) dec;
 __typeof__(&lc_sign) sign;
 __typeof__(&lc_verify) verify;
 __typeof__(&lc_resource_query) query;
 __typeof__(&lc_resource_make_plan) plan;
 __typeof__(&lc_f407_usable_requirement) requirement;
} f407_route;
void run_kem(const f407_route*,const m4_request*,m4_response*);
void run_dsa(const f407_route*,const m4_request*,m4_response*);
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

enum { KEY=1, SECOND=2, THIRD=4, TAMPER=8, CLEAN=16, RNG_FAIL=32,
       LENGTH=64, CAPACITY=128, RECOVER=256, ALIAS=512 };
extern uint8_t __stack_guard_bottom[];
static unsigned zeroed(const void *p,size_t n) {
    const uint8_t *b=p;unsigned v=0;
    for(size_t i=0;i<n;i++)v|=b[i];
    return v==0;
}
static uint32_t rotate(uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
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
    (*(volatile uint32_t *)(uintptr_t)(0x40023834))|=1u<<6;(void)(*(volatile uint32_t *)(uintptr_t)(0x40023834));
    (*(volatile uint32_t *)(uintptr_t)(0x50060800))|=4u;
    for(unsigned i=0;i<500000u;i++) {
        uint32_t s=(*(volatile uint32_t *)(uintptr_t)(0x50060804));
        if(s&0x66u)return -1;
        if(s&1u){*word=(*(volatile uint32_t *)(uintptr_t)(0x50060808));return 0;}
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
static int clean_arena(const f407_route *route){return zeroed((route->area),(route->cap));}
static int guards_ok(const f407_route *route){
    unsigned bad=0;
    for(size_t i=0;i<32;i++)bad|=((route->area-32)[i]^0xc3u)|((route->area+route->cap)[i]^0x3cu);
    for(size_t i=0;i<64;i++)bad|=__stack_guard_bottom[i]^0xa5u;
    return bad==0;
}
static void reset_stack_measurement(void) {
    uintptr_t sp;
    __asm__ volatile("mov %0,sp":"=r"(sp));
    uint8_t *p=(uint8_t*)__stack_bottom;
    for(; (uintptr_t)p+128u<sp; ++p)*p=0xa5;
}
static void finish_slot(m4_response *r,unsigned slot,int rc,uint32_t start,uint32_t end){
    r->w[24+slot]=(uint32_t)rc;r->w[28+slot]=end-start;r->w[32+slot]=(uint32_t)active_context.arena_high_water;
    r->w[57+slot]=stack_used();
}
static void fixture_input(const f407_route *route,const lc_target_vector *v){if(route->p<100){if(v->operation==2)a127_kat_key(route->p,v->pk.p,-1,route->area,0,0,route->pk);else if(v->operation==1)a127_kat_key(route->p,v->sk.p,0,route->area,0,0,route->sk);}}
static __attribute__((noinline)) int fixture_call(const f407_route *route,const lc_target_vector*v){if(v->operation==0)return route->key(&active_context,(route->p),(route->pk),(route->pk_len),(route->sk),(route->sk_len));
if(route->p<100){if(v->operation==1)return route->sign(&active_context,(route->p),(route->sig),(route->sig_len),v->message.p,v->message.n,v->domain.p,v->domain.n,route->sk,v->sk.n);
        else return route->verify(&active_context,(route->p),v->signature.p,v->signature.n,v->message.p,v->message.n,v->domain.p,v->domain.n,route->pk,v->pk.n);}else{if(v->operation==1)return route->enc(&active_context,(route->p),(route->ct),(route->ct_len),(route->ss),32,v->pk.p,v->pk.n);
        else return route->dec(&active_context,(route->p),(route->ss),32,v->ct.p,v->ct.n,v->sk.p,v->sk.n);}}
static __attribute__((noinline)) int fixture_output(const f407_route *route,const lc_target_vector*v){
if(route->p<100){if(v->operation==0)return a127_kat_key(route->p,v->coins.p,1,route->area,route->pk,route->sk,0);if(v->operation==1)return a127_kat_sig(route->p,v->expected0.p,route->sk,v->message.p,v->message.n,v->domain.p,v->domain.n,v->coins.p,route->sig,route->area);return 1;}
if(v->operation==0)return a127_kat_kem_key(route->p,v->coins.p,route->pk,route->sk,route->area);if(v->operation==1)return exact((route->ct),(route->ct_len),v->expected0)&&exact((route->ss),32,v->expected1);return exact((route->ss),32,v->expected0);
}
static __attribute__((noinline)) void kat(const f407_route *route,m4_response *r) {
    unsigned mask=0;
    for(unsigned i=0;i<(route->nvec);i++){
        const lc_target_vector *v=(route->vectors)+i;
        unsigned slot=v->accepted?(unsigned)v->operation:3;
        fixture_input(route,v);
        active_entropy.source=2;active_entropy.fixed=v->coins.p;active_entropy.left=v->coins.n;
        int rc;reset_stack_measurement();uint32_t start=cycle_stamp();
        rc=fixture_call(route,v);
        uint32_t end=cycle_stamp();finish_slot(r,slot,rc,start,end);
        r->w[44+slot]=v->tc_id;
        int ok=rc==(v->accepted?LC_OK:LC_E_REJECT)&&!active_entropy.left;
        ok=ok&&fixture_output(route,v);
        if(ok)mask|=1u<<slot;
    }
    r->w[23]=mask;r->w[48]=(route->nvec);
}
void cap_run_live(const f407_route*,const m4_request*,m4_response*);

extern uint8_t __image_bytes[], __reserved_ram[];
static int repeated_value(const uint8_t *data,size_t count,uint8_t value) {
    uint8_t change=0;
    for(size_t i=0;i<count;i++)change|=data[i]^value;
    return change==0;
}
static __attribute__((noinline)) void contract_record(const f407_route *route,const m4_request *q,m4_response *r) {
    unsigned op=q->w[11],off=q->w[12],n=q->w[10];
    if(off>=32u || op>=3u){r->w[24]=r->w[25]=(uint32_t)LC_E_ARGUMENT;return;}
    uint8_t *w=(route->area)+off;
    lc_resource_requirements req; lc_resource_plan plan;
    int qr=route->query((route->p),(int)op,&req);
    int pr=route->plan((route->p),(int)op,w,n,&plan);
    r->w[24]=qr;r->w[25]=pr;r->w[41]=req.minimum_workspace_bytes;
    r->w[42]=req.preferred_workspace_bytes;r->w[43]=req.alignment;
    r->w[44]=plan.alignment_padding;r->w[45]=plan.usable_workspace_bytes;
    size_t need=route->requirement((route->p),op,(0u-(uintptr_t)w)&31u);
    r->w[46]=need;r->w[47]=need+((0u-(uintptr_t)w)&31u);
    r->w[48]=(route->io_size);r->w[49]=(uintptr_t)__reserved_ram;
    r->w[50]=(uintptr_t)__stack_top-(uintptr_t)__stack_bottom;
    r->w[51]=(route->io_size)+(route->cap+64u)+32u; r->w[53]=plan.required_workspace_bytes;
    r->w[54]=req.public_context_bytes;r->w[57]=req.caller_plan_bytes;r->w[58]=n;
    r->w[59]=req.adaptive;r->w[60]=req.exact_workspace_bound;
    r->w[61]=sizeof(combined_storage);r->w[62]=(uintptr_t)__image_bytes;
    if(q->w[2]==13){r->w[23]=qr==LC_OK;return;}
    if(qr!=LC_OK || (pr!=LC_OK && pr!=LC_E_WORKSPACE) ||
       n>(route->cap)-off || !n){r->w[26]=(uint32_t)LC_E_ARGUMENT;return;}
    const lc_target_vector *v=0;
    for(unsigned i=0;i<(route->nvec);i++)
        if((route->vectors)[i].operation==(int)op && (route->vectors)[i].accepted){v=(route->vectors)+i;break;}
    if(!v){r->w[26]=(uint32_t)LC_E_ARGUMENT;return;}
    memset(route->pk,0xa7,(route->io_size));fixture_input(route,v);memset((route->area),0x69,(route->cap));memset(w,0,n);
    active_entropy.source=2;active_entropy.fixed=v->coins.p;active_entropy.left=v->coins.n;
    if(route->init(&active_context,w,n,random_bytes,&active_entropy)!=LC_OK){r->w[26]=(uint32_t)LC_E_ARGUMENT;return;}
    reset_stack_measurement();uint32_t t=cycle_stamp();int err;
    err=fixture_call(route,v);
    r->w[28]=cycle_stamp()-t;r->w[26]=(uint32_t)err;r->w[32]=active_context.arena_high_water;
    r->w[33]=stack_used();r->w[34]=v->tc_id;r->w[35]=v->coins.n-active_entropy.left;
    int clean=zeroed(w,n)&&repeated_value((route->area),off,0x69)&&repeated_value(w+n,(route->cap)-off-n,0x69);
    int correct=err==pr;
    if(!err)correct&=fixture_output(route,v);
    else if(op==0)correct&=zeroed(route->pk,route->pk_len)&&zeroed(route->sk,route->sk_len);
    else if(route->p>100)correct&=(op==2||zeroed(route->ct,route->ct_len))&&zeroed(route->ss,32);
    else if(op==1)correct&=zeroed(route->sig,route->sig_len);
    r->w[27]=correct;r->w[29]=clean;r->w[23]=correct&&clean&&active_entropy.left==0;
}
void run_dsa(const f407_route *route,const m4_request *q,m4_response *r) {
    if(q->w[8]!=(route->p)||q->w[9]!=(route->s))return;
    if(route->init(&active_context,(route->area),(route->cap),random_bytes,&active_entropy)!=LC_OK)return;
    memset((route->area-32),0xc3,32u);memset((route->area+route->cap),0x3c,32u);
    if(q->w[2]==13||q->w[2]==14)contract_record(route,q,r);
    else if(q->w[2]==M4_KAT)kat(route,r);
    else if(q->w[2]==M4_RUN||q->w[2]==M4_BOUNDARY||q->w[2]==M4_TIMING)cap_run_live(route,q,r);
    clear_bytes(route->pk,(route->io_size));clear_bytes(&active_entropy,sizeof(active_entropy));clear_bytes((route->area),(route->cap));clear_bytes(&active_context,sizeof(active_context));
    r->w[52]=guards_ok(route);
}
__attribute__((noinline)) void cap_run_live(const f407_route *route,const m4_request *q,m4_response *r){

    size_t m=q->w[11],d=q->w[12],budget=q->w[10];unsigned mask=0;
    int insufficient=(q->w[14]&1)!=0;
    if(!budget||budget>(route->cap)||m>256u||d>255||q->w[13]>1)return;
    entropy_source input;
    initialize_stream(&input,q,0x4d534747);random_bytes(&input,(route->message),m);random_bytes(&input,(route->context),d);clear_bytes(&input,sizeof(input));
    initialize_stream(&active_entropy,q,0x454e5452);active_entropy.source=(int)q->w[13];
    route->init(&active_context,(route->area),budget,random_bytes,&active_entropy);
    r->w[41]=budget;r->w[42]=m;r->w[43]=d;r->w[48]=q->w[13];
    if(insufficient){
        int rc=route->key(&active_context,(route->p),(route->pk),(route->pk_len),(route->sk),(route->sk_len));
        r->w[44]=rc;
        if(rc==LC_E_WORKSPACE && zeroed((route->pk),(route->pk_len))&&zeroed((route->sk),(route->sk_len)))mask|=CAPACITY;
        initialize_stream(&active_entropy,q,0x454e5452);active_entropy.source=(int)q->w[13];
        route->init(&active_context,(route->area),(route->cap),random_bytes,&active_entropy);
    }
    int clean=1,rc;
    for(unsigned slot=0;slot<4;slot++){
        if(slot==3){
if(route->p<100){
            (route->sig)[0]^=1u;
}else{
            (route->ct)[0]^=1u;
}
        }
        reset_stack_measurement();uint32_t start=cycle_stamp();
        if(slot==0)rc=route->key(&active_context,(route->p),(route->pk),(route->pk_len),(route->sk),(route->sk_len));
else {
if(route->p<100){
        if(slot==1)rc=route->sign(&active_context,(route->p),(route->sig),(route->sig_len),(route->message),m,(route->context),d,(route->sk),(route->sk_len));
        else rc=route->verify(&active_context,(route->p),(route->sig),(route->sig_len),(route->message),m,(route->context),d,(route->pk),(route->pk_len));
}else{
        if(slot==1)rc=route->enc(&active_context,(route->p),(route->ct),(route->ct_len),(route->ss),32,(route->pk),(route->pk_len));
        else rc=route->dec(&active_context,(route->p),(route->ss2),32,(route->ct),(route->ct_len),(route->sk),(route->sk_len));
}
}
        uint32_t end=cycle_stamp();finish_slot(r,slot,rc,start,end);
        clean&=clean_arena(route);
        if(slot==0){if(rc==LC_OK)mask|=KEY;if(insufficient)r->w[45]=rc;r->w[49]=m4_checksum((route->pk),(route->pk_len));}
        if(slot==1){if(rc==LC_OK)mask|=SECOND;
if(route->p<100){
            r->w[50]=m4_checksum((route->sig),(route->sig_len));
}else{
            r->w[50]=m4_checksum((route->ct),(route->ct_len));
}
        }
if(route->p<100){
        if(slot==2&&rc==LC_OK)mask|=THIRD;
        if(slot==3&&rc==LC_E_REJECT)mask|=TAMPER;
}else{
        if(slot==2&&rc==LC_OK&&!memcmp((route->ss),(route->ss2),32))mask|=THIRD;
        if(slot==3&&rc==LC_OK&&memcmp((route->ss),(route->ss2),32))mask|=TAMPER;
}
        if(slot<3&&rc!=LC_OK)break;
    }
    if(insufficient&&(mask&(KEY|SECOND|THIRD|TAMPER))==15)mask|=RECOVER;
    if(q->w[2]==M4_BOUNDARY){
if(route->p<100){
        (route->sig)[(route->sig_len)-1]=0xff;
        r->w[53]=route->verify(&active_context,(route->p),(route->sig),(route->sig_len),(route->message),m,(route->context),d,(route->pk),(route->pk_len));
        r->w[61]=route->sign(&active_context,(route->p),(route->sig),(route->sig_len),(route->message),m,(route->context),256,(route->sk),(route->sk_len));
}else{
        (route->pk)[0]=0xff;(route->pk)[1]|=0x0f;
        r->w[53]=route->enc(&active_context,(route->p),(route->ct),(route->ct_len),(route->ss),32,(route->pk),(route->pk_len));
        r->w[61]=route->dec(&active_context,(route->p),(route->ss2),32,(route->ct),(route->ct_len)-1,(route->sk),(route->sk_len));
}
        initialize_stream(&active_entropy,q,0x414c4947);
        route->init(&active_context,(route->area)+1,(route->cap)-1,random_bytes,&active_entropy);
        r->w[54]=route->key(&active_context,(route->p),(route->pk),(route->pk_len),(route->sk),(route->sk_len));
    }
    active_entropy.source=3;memset((route->pk),0xa7,(route->pk_len));memset((route->sk),0xa7,(route->sk_len));
    rc=route->key(&active_context,(route->p),(route->pk),(route->pk_len),(route->sk),(route->sk_len));r->w[46]=rc;
    if(rc==LC_E_RANDOM&&zeroed((route->pk),(route->pk_len))&&zeroed((route->sk),(route->sk_len)))mask|=RNG_FAIL;
    rc=route->key(&active_context,(route->p),(route->pk),(route->pk_len)-1,(route->sk),(route->sk_len));r->w[47]=rc;
    if(rc==LC_E_LENGTH)mask|=LENGTH;
    rc=route->key(&active_context,(route->p),(route->sk),(route->pk_len),(route->sk),(route->sk_len));r->w[51]=rc;
    if(rc==LC_E_ALIAS)mask|=ALIAS;
    clear_bytes(route->pk,(route->io_size));clear_bytes(&active_entropy,sizeof(active_entropy));
    if(clean&&zeroed(route->pk,(route->io_size))&&zeroed(&active_entropy,sizeof(active_entropy)))mask|=CLEAN;
    r->w[23]=mask;
}
