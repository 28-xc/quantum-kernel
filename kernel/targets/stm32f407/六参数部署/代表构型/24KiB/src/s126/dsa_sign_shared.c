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

struct lc_dsa_arena;
typedef struct {
    uint8_t *pending;
    uint32_t pending_nonce;
    unsigned can_look_ahead;
    uint8_t *output;
} a127_pending;
enum { D_SEED,D_MATRIX,D_ACACHE,D_PENDING,D_S1,D_T0,D_S2,D_COUNT };
typedef struct {
    void *slot[D_COUNT];
    a127_pending look;
} a127_sign_state;
typedef struct {
    uint16_t k,l,signature_bytes,limit,bytes[D_COUNT];
    void *(*allocate)(struct lc_dsa_arena *,size_t);
    void (*release)(struct lc_dsa_arena *,void *,size_t);
    void (*unpack)(a127_sign_state *,const uint8_t *);
    void (*hash3)(uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t);
    void (*matrix)(a127_sign_state *);
    int (*candidate)(a127_sign_state *,uint8_t *,uint16_t,struct lc_dsa_arena *);
} a127_sign_route;
int a127_sign_message(const a127_sign_route*,uint8_t*,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,const uint8_t*,int,struct lc_dsa_arena*);
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
static void wipe(void *p,size_t n){memset(p,0,n);__asm__ volatile(""::"r"(p):"memory");}
int a127_sign_message(const a127_sign_route *route,uint8_t *sig,const uint8_t *message,size_t length,
                      const uint8_t *prefix,size_t prefix_length,const uint8_t *randomizer,
                      const uint8_t *sk,int external_mu,struct lc_dsa_arena *arena){
    a127_sign_state state={0};int rc=-2;
    for(unsigned i=0;i<D_COUNT;i++){
        if(route->bytes[i]){
            state.slot[i]=route->allocate(arena,route->bytes[i]);
            if(!state.slot[i])goto done;
        }
    }
    route->unpack(&state,sk);
    uint8_t *seed=(uint8_t*)state.slot[D_SEED];
    uint8_t *tr=seed+32,*key=tr+64,*mu=key+32,*rho_prime=mu+64;
    if(external_mu)memcpy(mu,message,64);
    else route->hash3(mu,64,tr,64,prefix,prefix_length,message,length);
    route->hash3(rho_prime,64,key,32,randomizer,32,mu,64);
    route->matrix(&state);
    state.look.output=sig;state.look.pending=state.slot[D_PENDING];state.look.pending_nonce=4294967295U;
    for(unsigned attempt=0;attempt<route->limit;attempt++){
        uint16_t kappa=(uint16_t)(attempt*route->l);
        state.look.can_look_ahead=
            attempt+1u<route->limit && (uint32_t)kappa+2u*route->l-1u<=65535U;
        rc=route->candidate(&state,sig,kappa,arena);
        if(rc!=-1)goto done;
    }
    rc=-4;
done:
    if(rc)wipe(sig,route->signature_bytes);
    for(unsigned i=D_COUNT;i-- >0;){
        if(state.slot[i]){wipe(state.slot[i],route->bytes[i]);route->release(arena,state.slot[i],route->bytes[i]);}
    }
    wipe(&state,sizeof(state));
    return rc;
}
