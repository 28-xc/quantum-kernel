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
typedef struct {
    uint16_t k,l,pk_bytes,sk_bytes,eta_bytes,z_bytes,challenge_bytes,w_bytes;
    uint16_t key_storage[6], verify_storage[6],matrix_tmp_offset;
    void *(*allocate)(struct lc_dsa_arena*,size_t);
    void (*release)(struct lc_dsa_arena*,void*,size_t);
    void (*hash)(uint8_t*,size_t,const uint8_t*,size_t);
    void (*matrix_init)(void*,const uint8_t*);
    void (*prepare_s)(void*,void*,const uint8_t*,unsigned,uint8_t*);
    void (*keyrow)(void*,void*,void*,const uint8_t*,void*,unsigned,uint8_t*);
    void (*finish_keyrow)(void*,void*,const uint8_t*,unsigned,uint8_t*,uint8_t*,uint8_t*);
    int (*unpack_z)(void*,void*,const uint8_t*,unsigned);
    void (*make_mu)(uint8_t*,const uint8_t*,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
    void (*start_verify)(void*,void*,void*,const uint8_t*,const uint8_t*,const uint8_t*);
    int (*verifyrow)(void*,void*,void*,void*,void*,const uint8_t*,const uint8_t*,unsigned);
    void (*absorb_row)(void*,const uint8_t*,size_t);
    int (*finish_verify)(void*,uint8_t*,const uint8_t*,size_t);
    void (*finish_hash)(void*);
} a127_dsa_route;
int a127_dsa_keygen(const a127_dsa_route*,uint8_t*,uint8_t*,const uint8_t*,struct lc_dsa_arena*);
int a127_dsa_verify(const a127_dsa_route*,const uint8_t*,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,int,struct lc_dsa_arena*);
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
static void secure_clear(void *p,size_t n){memset(p,0,n);__asm__ volatile(""::"r"(p):"memory");}
static int acquire_all(const a127_dsa_route *r,struct lc_dsa_arena *arena,const uint16_t size[6],void *objects[6]){
    int ok=1;
    for(unsigned i=0;i<6;i++){objects[i]=r->allocate(arena,size[i]);ok&=objects[i]!=0;}
    return ok;
}
static void release_all(const a127_dsa_route *r,struct lc_dsa_arena *arena,const uint16_t size[6],void *objects[6]){
    for(unsigned i=6;i-- >0;){if(objects[i]){secure_clear(objects[i],size[i]);r->release(arena,objects[i],size[i]);}}
}
int a127_dsa_keygen(const a127_dsa_route *r,uint8_t *pk,uint8_t *sk,const uint8_t *seed,struct lc_dsa_arena *arena){
    void *a[6];int rc=-2;
    if(!acquire_all(r,arena,r->key_storage,a))goto end;
    uint8_t *expanded=a[0],*input=a[1],*tr=a[2],*s1=a[3],*mat=a[4],*row=a[5];
    void *tmp=mat+r->matrix_tmp_offset;const uint8_t *rho_prime=expanded+32;
    memcpy(input,seed,32);input[32]=r->k;input[33]=r->l;r->hash(expanded,128,input,34);
    if(r->prepare_s)for(unsigned i=0;i<r->l;i++)r->prepare_s(s1,tmp,rho_prime,i,sk+128+i*r->eta_bytes);
    memcpy(pk,expanded,32);r->matrix_init(mat,expanded);
    for(unsigned i=0;i<r->k;i++){
        r->keyrow(row,mat,s1,rho_prime,tmp,i,sk);
        r->finish_keyrow(row,tmp,rho_prime,r->l+i,
            sk+128+(r->l+i)*r->eta_bytes,pk+32+i*320,sk+128+(r->l+r->k)*r->eta_bytes+i*416);
    }
    r->hash(tr,64,pk,r->pk_bytes);memcpy(sk,expanded,32);memcpy(sk+32,expanded+96,32);memcpy(sk+64,tr,64);rc=0;
end:
    release_all(r,arena,r->key_storage,a);
    if(rc){secure_clear(pk,r->pk_bytes);secure_clear(sk,r->sk_bytes);}
    return rc;
}
int a127_dsa_verify(const a127_dsa_route *r,const uint8_t *sig,const uint8_t *msg,size_t length,
                    const uint8_t *pre,size_t prelen,const uint8_t *pre1,size_t prelen1,
                    const uint8_t *pk,int external_mu,struct lc_dsa_arena *arena){
    void *a[6];int rc=-2,hash_live=0;
    if(!acquire_all(r,arena,r->verify_storage,a))goto end;
    uint8_t *state=a[0],*mu=a[1],*z=a[2],*cp=a[3],*mat=a[4],*w=a[5];void *tmp=mat+r->matrix_tmp_offset;
    rc=-6;
    for(unsigned i=0;i<r->l;i++)if(r->unpack_z(tmp,z,sig+r->challenge_bytes+i*r->z_bytes,i))goto end;
    if(external_mu)memcpy(mu,msg,64);
    else{
        uint8_t hpk[64] __attribute__((aligned(32)));r->hash(hpk,64,pk,r->pk_bytes);
        r->make_mu(mu,hpk,pre,prelen,pre1,prelen1,msg,length);secure_clear(hpk,sizeof(hpk));
    }
    r->start_verify(state,cp,mat,mu,pk,sig);hash_live=1;
    for(unsigned i=0;i<r->k;i++){
        if(r->verifyrow(w,mat,z,cp,tmp,sig,pk,i))goto end;
        r->absorb_row(state,tmp,r->w_bytes);
    }
    rc=r->finish_verify(state,mu,sig,r->challenge_bytes);
end:
    if(hash_live)r->finish_hash(a[0]);
    release_all(r,arena,r->verify_storage,a);return rc;
}
