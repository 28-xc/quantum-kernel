typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
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

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
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
int lc_system_random(uint8_t *out, size_t bytes);
typedef struct {
    uint64_t ctx[26];
} shake128incctx;
typedef struct {
    uint64_t ctx[25];
} shake128ctx;
typedef struct {
    uint64_t ctx[26];
} shake256incctx;
typedef struct {
    uint64_t ctx[25];
} shake256ctx;
typedef struct {
    uint64_t ctx[26];
} sha3_256incctx;
typedef struct {
    uint64_t ctx[26];
} sha3_384incctx;
typedef struct {
    uint64_t ctx[26];
} sha3_512incctx;
void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen);
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state);
void shake128_ctx_release(shake128ctx *state);
void shake128_ctx_clone(shake128ctx *dest, const shake128ctx *src);
void cshake128_simple_absorb(shake128ctx *state, uint16_t cstm, const uint8_t *input, size_t inlen);
void cshake128_simple_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state);
void cshake128_simple(uint8_t *output, size_t outlen, uint16_t cstm, const uint8_t *input, size_t inlen);
void shake128_inc_init(shake128incctx *state);
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen);
void shake128_inc_finalize(shake128incctx *state);
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state);
void shake128_inc_ctx_clone(shake128incctx* dest, const shake128incctx *src);
void shake128_inc_ctx_release(shake128incctx *state);
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen);
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state);
void shake256_ctx_release(shake256ctx *state);
void shake256_ctx_clone(shake256ctx *dest, const shake256ctx *src);
void cshake256_simple_absorb(shake256ctx *state, uint16_t cstm, const uint8_t *input, size_t inlen);
void cshake256_simple_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state);
void cshake256_simple(uint8_t *output, size_t outlen, uint16_t cstm, const uint8_t *input, size_t inlen);
void shake256_inc_init(shake256incctx *state);
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(shake256incctx *state);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state);
void shake256_inc_ctx_clone(shake256incctx* dest, const shake256incctx *src);
void shake256_inc_ctx_release(shake256incctx *state);
void shake128(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen);
void shake256(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen);
void sha3_256_inc_init(sha3_256incctx *state);
void sha3_256_inc_absorb(sha3_256incctx *state, const uint8_t *input, size_t inlen);
void sha3_256_inc_finalize(uint8_t *output, sha3_256incctx *state);
void sha3_256_inc_ctx_clone(sha3_256incctx *dest, const sha3_256incctx *src);
void sha3_256_inc_ctx_release(sha3_256incctx *state);
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_384_inc_init(sha3_384incctx *state);
void sha3_384_inc_absorb(sha3_384incctx *state, const uint8_t *input, size_t inlen);
void sha3_384_inc_finalize(uint8_t *output, sha3_384incctx *state);
void sha3_384_inc_ctx_clone(sha3_384incctx *dest, const sha3_384incctx *src);
void sha3_384_inc_ctx_release(sha3_384incctx *state);
void sha3_384(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_512_inc_init(sha3_512incctx *state);
void sha3_512_inc_absorb(sha3_512incctx *state, const uint8_t *input, size_t inlen);
void sha3_512_inc_finalize(uint8_t *output, sha3_512incctx *state);
void sha3_512_inc_ctx_clone(sha3_512incctx *dest, const sha3_512incctx *src);
void sha3_512_inc_ctx_release(sha3_512incctx *state);
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);
typedef uint32_t jmp_buf[10];
int setjmp(jmp_buf) __attribute__((returns_twice));
void longjmp(jmp_buf,int) __attribute__((noreturn));
void *malloc(size_t);
void free(void *);
void abort(void) __attribute__((noreturn));
void exit(int) __attribute__((noreturn));
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign(uint8_t *sm, size_t *smlen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign(uint8_t *sm, size_t *smlen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign(uint8_t *sm, size_t *smlen,
                                      const uint8_t *m, size_t mlen,
                                      const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *pk);

typedef struct {const void *p;size_t n;} region;
typedef struct entropy_frame {jmp_buf escape;const uint8_t *bytes;size_t length,used;} entropy_frame;
static entropy_frame *current_entropy;
static void erase(void *p,size_t n){volatile uint8_t *v=p;while(n--)*v++=0;}
static int kem(int p){return p==512||p==768||p==1024;}
static int dsa(int p){return p==44||p==65||p==87;}
static int overlaps(region a,region b){uintptr_t x=(uintptr_t)a.p,y=(uintptr_t)b.p;if(!a.n||!b.n)return 0;return x<=y?y-x<a.n:x-y<b.n;}
static int validate(lc_context*c,region*r,size_t n){
 size_t i,j;if(!c||!c->workspace||!c->workspace_bytes)return LC_E_ARGUMENT;
 r[n++]=(region){c->workspace,c->workspace_bytes};r[n++]=(region){c,sizeof(*c)};
 for(i=0;i<n;i++){
  if((!r[i].p&&r[i].n)||r[i].n>4294967295U -(uintptr_t)r[i].p)return LC_E_ARGUMENT;
  for(j=0;j<i;j++)if(overlaps(r[i],r[j]))return LC_E_ALIAS;
 }
 c->arena_high_water=c->allocations=c->allocation_failures=0;c->last_error=0;return 0;
}
int lc_get_sizes(int p,lc_sizes*s){
 if(!s)return LC_E_ARGUMENT;memset(s,0,sizeof(*s));
 switch(p){
 case 512:s->public_key=800;s->secret_key=1632;s->ciphertext=768;break;
 case 768:s->public_key=1184;s->secret_key=2400;s->ciphertext=1088;break;
 case 1024:s->public_key=1568;s->secret_key=3168;s->ciphertext=1568;break;
 case 44:s->public_key=1312;s->secret_key=2560;s->signature=2420;break;
 case 65:s->public_key=1952;s->secret_key=4032;s->signature=3309;break;
 case 87:s->public_key=2592;s->secret_key=4896;s->signature=4627;break;
 default:return LC_E_ARGUMENT;
 }if(kem(p))s->shared_secret=32;return 0;
}
int lc_context_init(lc_context*c,void*w,size_t n,lc_random_fn f,void*u){
 if(!c||!w||!n||n>4294967295U -(uintptr_t)w)return LC_E_ARGUMENT;
 if(overlaps((region){c,sizeof(*c)},(region){w,n}))return LC_E_ALIAS;
 memset(c,0,sizeof(*c));c->workspace=w;c->workspace_bytes=n;c->random=f;c->random_user=u;return 0;
}
int randombytes(uint8_t*out,size_t n){
 entropy_frame*f=current_entropy;
 if(!f)abort();
 if(n>f->length-f->used)longjmp(f->escape,1);
 memcpy(out,f->bytes+f->used,n);f->used+=n;return 0;
}
void pqc_nonce_guard(unsigned nonce,unsigned width){
 if(!current_entropy)abort();
 if(nonce>=(65535u-width)/width)longjmp(current_entropy->escape,2);
}
static int canonical_pk(const uint8_t*pk,size_t n){
 size_t i;unsigned bad=0;
 for(i=0;i<n-32;i+=3){unsigned a=(pk[i]|((unsigned)pk[i+1]<<8))&4095u;unsigned b=(pk[i+1]>>4)|((unsigned)pk[i+2]<<4);bad|=(a>=3329u)|(b>=3329u);}
 return bad==0;
}
static int checked_dk(const uint8_t*sk,const lc_sizes*z){
 uint8_t h[32];size_t i;unsigned bad=0;size_t offset=z->secret_key-z->public_key-64;
 sha3_256(h,sk+offset,z->public_key);
 for(i=0;i<32;i++)bad|=(unsigned)(h[i]^sk[z->secret_key-64+i]);
 erase(h,sizeof(h));return bad==0;
}
static int raw_keypair(int p,uint8_t*pk,uint8_t*sk){(void)p;return crypto_sign_keypair(pk,sk);}
static int raw_enc(int p,uint8_t*ct,uint8_t*ss,const uint8_t*pk){(void)p;return LC_E_ARGUMENT;}
static int raw_dec(int p,uint8_t*ss,const uint8_t*ct,const uint8_t*sk){(void)p;return LC_E_ARGUMENT;}
static int raw_sign(int p,uint8_t*sig,size_t*sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*sk){(void)p;return crypto_sign_signature_ctx(sig,sn,m,mn,d,dn,sk);}
static int raw_verify(int p,const uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*pk){(void)p;return crypto_sign_verify_ctx(sig,sn,m,mn,d,dn,pk);}
static int small_workspace(lc_context *c,size_t count) {
  uint8_t temporary[64]; int rc=0;
  if(count) rc=c->random?c->random(c->random_user,temporary,count):lc_system_random(temporary,count);
  erase(temporary,sizeof(temporary)); c->allocation_failures=rc?0:1;
  return rc?LC_E_RANDOM:LC_E_WORKSPACE;
}
static int execute(lc_context*c,int p,int op,const lc_sizes*z,uint8_t*out1,uint8_t*out2,const uint8_t*in1,const uint8_t*in2,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn){
 uint8_t *entropy;size_t n=op==0?(kem(p)?64u:32u):(op==1?32u:0u);size_t sn=0;
 entropy_frame frame;entropy_frame*previous=current_entropy;int result;
 size_t pad=(0u-(uintptr_t)c->workspace)&31u;
 if(c->workspace_bytes<pad || c->workspace_bytes-pad<64) return small_workspace(c,n);
 entropy=(uint8_t*)c->workspace+pad;c->arena_high_water=pad+64;c->allocations=1;
 if(n&&(c->random?c->random(c->random_user,entropy,n):lc_system_random(entropy,n))){erase(entropy,64);return LC_E_RANDOM;}
 frame.bytes=entropy;frame.length=n;frame.used=0;current_entropy=&frame;
 switch(setjmp(frame.escape)){
 case 0:
  if(op==0)result=raw_keypair(p,out1,out2);
  else if(kem(p)&&op==1)result=canonical_pk(in1,z->public_key)?raw_enc(p,out1,out2,in1):-1;
  else if(kem(p))result=checked_dk(in2,z)?raw_dec(p,out1,in1,in2):-1;
  else if(op==1){result=raw_sign(p,out1,&sn,m,mn,d,dn,in1);if(!result&&sn!=z->signature)result=-1;}
  else result=raw_verify(p,in1,z->signature,m,mn,d,dn,in2);
  result=result?LC_E_REJECT:LC_OK;
  if(result==0&&frame.used!=n)result=LC_E_INTERNAL;
  break;
 case 2:result=LC_E_REJECT;break;
 default:result=LC_E_INTERNAL;break;
 }
 current_entropy=previous;
 erase(&frame,sizeof(frame));erase(entropy,64);return result;
}
int lc_keypair(lc_context*c,int p,uint8_t*pk,size_t pn,uint8_t*sk,size_t sn){
 lc_sizes z;region r[4];int e;if(lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(pn<z.public_key||sn<z.secret_key)return LC_E_LENGTH;
 r[0]=(region){pk,pn};r[1]=(region){sk,sn};if((e=validate(c,r,2)))return e;
 e=execute(c,p,0,&z,pk,sk,((void*)0),((void*)0),((void*)0),0,((void*)0),0);if(e){erase(pk,z.public_key);erase(sk,z.secret_key);}c->last_error=e;return e;
}
int lc_encaps(lc_context*c,int p,uint8_t*ct,size_t cn,uint8_t*ss,size_t sn,const uint8_t*pk,size_t pn){
 lc_sizes z;region r[5];int e;if(!kem(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(cn<z.ciphertext||sn<32||pn!=z.public_key)return LC_E_LENGTH;
 r[0]=(region){ct,cn};r[1]=(region){ss,sn};r[2]=(region){pk,pn};if((e=validate(c,r,3)))return e;
 e=execute(c,p,1,&z,ct,ss,pk,((void*)0),((void*)0),0,((void*)0),0);if(e){erase(ct,z.ciphertext);erase(ss,32);}c->last_error=e;return e;
}
int lc_decaps(lc_context*c,int p,uint8_t*ss,size_t sn,const uint8_t*ct,size_t cn,const uint8_t*sk,size_t kn){
 lc_sizes z;region r[5];int e;if(!kem(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn<32||cn!=z.ciphertext||kn!=z.secret_key)return LC_E_LENGTH;
 r[0]=(region){ss,sn};r[1]=(region){ct,cn};r[2]=(region){sk,kn};if((e=validate(c,r,3)))return e;
 e=execute(c,p,2,&z,ss,((void*)0),ct,sk,((void*)0),0,((void*)0),0);if(e)erase(ss,32);c->last_error=e;return e;
}
int lc_sign(lc_context*c,int p,uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*sk,size_t kn){
 lc_sizes z;region r[6];int e;if(!dsa(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn<z.signature||kn!=z.secret_key||dn>255)return LC_E_LENGTH;
 r[0]=(region){sig,sn};r[1]=(region){m,mn};r[2]=(region){d,dn};r[3]=(region){sk,kn};if((e=validate(c,r,4)))return e;
 e=execute(c,p,1,&z,sig,((void*)0),sk,((void*)0),m,mn,d,dn);if(e)erase(sig,z.signature);c->last_error=e;return e;
}
int lc_verify(lc_context*c,int p,const uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*pk,size_t pn){
 lc_sizes z;region r[6];int e;if(!dsa(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn!=z.signature||pn!=z.public_key||dn>255)return LC_E_LENGTH;
 r[0]=(region){sig,sn};r[1]=(region){m,mn};r[2]=(region){d,dn};r[3]=(region){pk,pn};if((e=validate(c,r,4)))return e;
 e=execute(c,p,2,&z,((void*)0),((void*)0),sig,pk,m,mn,d,dn);c->last_error=e;return e;
}
const char*lc_error_string(int e){switch(e){case 0:return "success";case -1:return "invalid argument";case -2:return "invalid length";case -3:return "overlapping objects";case -4:return "random source failed";case -5:return "insufficient workspace";case -6:return "operation rejected";default:return "internal invariant failure";}}
