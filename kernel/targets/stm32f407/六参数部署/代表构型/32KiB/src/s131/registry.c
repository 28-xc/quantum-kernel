

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
extern __typeof__(lc_context_init) pqm16_lc_context_init;
extern __typeof__(lc_context_init) pqm17_lc_context_init;
extern __typeof__(lc_context_init) pqm24_lc_context_init;
extern __typeof__(lc_context_init) pqm25_lc_context_init;
extern __typeof__(lc_context_init) pqm28_lc_context_init;
extern __typeof__(lc_context_init) pqm29_lc_context_init;
extern __typeof__(lc_context_init) pqm3_lc_context_init;
extern __typeof__(lc_context_init) pqm4_lc_context_init;
extern __typeof__(lc_context_init) pqm51_lc_context_init;
extern __typeof__(lc_context_init) pqm52_lc_context_init;
extern __typeof__(lc_context_init) pqm8_lc_context_init;
extern __typeof__(lc_context_init) pqm9_lc_context_init;
extern __typeof__(lc_decaps) pqm16_lc_decaps;
extern __typeof__(lc_decaps) pqm17_lc_decaps;
extern __typeof__(lc_decaps) pqm24_lc_decaps;
extern __typeof__(lc_decaps) pqm25_lc_decaps;
extern __typeof__(lc_decaps) pqm28_lc_decaps;
extern __typeof__(lc_decaps) pqm29_lc_decaps;
extern __typeof__(lc_decaps) pqm3_lc_decaps;
extern __typeof__(lc_decaps) pqm4_lc_decaps;
extern __typeof__(lc_decaps) pqm51_lc_decaps;
extern __typeof__(lc_decaps) pqm52_lc_decaps;
extern __typeof__(lc_decaps) pqm8_lc_decaps;
extern __typeof__(lc_decaps) pqm9_lc_decaps;
extern __typeof__(lc_encaps) pqm16_lc_encaps;
extern __typeof__(lc_encaps) pqm17_lc_encaps;
extern __typeof__(lc_encaps) pqm24_lc_encaps;
extern __typeof__(lc_encaps) pqm25_lc_encaps;
extern __typeof__(lc_encaps) pqm28_lc_encaps;
extern __typeof__(lc_encaps) pqm29_lc_encaps;
extern __typeof__(lc_encaps) pqm3_lc_encaps;
extern __typeof__(lc_encaps) pqm4_lc_encaps;
extern __typeof__(lc_encaps) pqm51_lc_encaps;
extern __typeof__(lc_encaps) pqm52_lc_encaps;
extern __typeof__(lc_encaps) pqm8_lc_encaps;
extern __typeof__(lc_encaps) pqm9_lc_encaps;
extern __typeof__(lc_f407_usable_requirement) pqm10_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm11_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm13_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm2_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm34_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm47_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm48_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm49_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm56_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm57_lc_f407_usable_requirement;
extern __typeof__(lc_f407_usable_requirement) pqm5_lc_f407_usable_requirement;
extern __typeof__(lc_keypair) pqm16_lc_keypair;
extern __typeof__(lc_keypair) pqm17_lc_keypair;
extern __typeof__(lc_keypair) pqm24_lc_keypair;
extern __typeof__(lc_keypair) pqm25_lc_keypair;
extern __typeof__(lc_keypair) pqm28_lc_keypair;
extern __typeof__(lc_keypair) pqm29_lc_keypair;
extern __typeof__(lc_keypair) pqm3_lc_keypair;
extern __typeof__(lc_keypair) pqm4_lc_keypair;
extern __typeof__(lc_keypair) pqm51_lc_keypair;
extern __typeof__(lc_keypair) pqm52_lc_keypair;
extern __typeof__(lc_keypair) pqm8_lc_keypair;
extern __typeof__(lc_keypair) pqm9_lc_keypair;
extern __typeof__(lc_resource_make_plan) pqm36_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm37_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm38_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm39_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm40_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm41_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm42_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm43_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm44_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm45_lc_resource_make_plan;
extern __typeof__(lc_resource_make_plan) pqm46_lc_resource_make_plan;
extern __typeof__(lc_resource_query) pqm36_lc_resource_query;
extern __typeof__(lc_resource_query) pqm37_lc_resource_query;
extern __typeof__(lc_resource_query) pqm38_lc_resource_query;
extern __typeof__(lc_resource_query) pqm39_lc_resource_query;
extern __typeof__(lc_resource_query) pqm40_lc_resource_query;
extern __typeof__(lc_resource_query) pqm41_lc_resource_query;
extern __typeof__(lc_resource_query) pqm42_lc_resource_query;
extern __typeof__(lc_resource_query) pqm43_lc_resource_query;
extern __typeof__(lc_resource_query) pqm44_lc_resource_query;
extern __typeof__(lc_resource_query) pqm45_lc_resource_query;
extern __typeof__(lc_resource_query) pqm46_lc_resource_query;
extern __typeof__(lc_sign) pqm16_lc_sign;
extern __typeof__(lc_sign) pqm17_lc_sign;
extern __typeof__(lc_sign) pqm24_lc_sign;
extern __typeof__(lc_sign) pqm25_lc_sign;
extern __typeof__(lc_sign) pqm28_lc_sign;
extern __typeof__(lc_sign) pqm29_lc_sign;
extern __typeof__(lc_sign) pqm3_lc_sign;
extern __typeof__(lc_sign) pqm4_lc_sign;
extern __typeof__(lc_sign) pqm51_lc_sign;
extern __typeof__(lc_sign) pqm52_lc_sign;
extern __typeof__(lc_sign) pqm8_lc_sign;
extern __typeof__(lc_sign) pqm9_lc_sign;
extern __typeof__(lc_verify) pqm16_lc_verify;
extern __typeof__(lc_verify) pqm17_lc_verify;
extern __typeof__(lc_verify) pqm24_lc_verify;
extern __typeof__(lc_verify) pqm25_lc_verify;
extern __typeof__(lc_verify) pqm28_lc_verify;
extern __typeof__(lc_verify) pqm29_lc_verify;
extern __typeof__(lc_verify) pqm3_lc_verify;
extern __typeof__(lc_verify) pqm4_lc_verify;
extern __typeof__(lc_verify) pqm51_lc_verify;
extern __typeof__(lc_verify) pqm52_lc_verify;
extern __typeof__(lc_verify) pqm8_lc_verify;
extern __typeof__(lc_verify) pqm9_lc_verify;
extern const lc_target_vector unified_vectors512[];
static const f407_route cfg_c512_compact={.p=512,.s=1,.cap=sizeof(combined_storage.c512_compact.guarded.data),.nvec=3,.io_size=sizeof(combined_storage.c512_compact.io),
.pk_len=sizeof(combined_storage.c512_compact.io.pk),
.sk_len=sizeof(combined_storage.c512_compact.io.sk),
.ct_len=sizeof(combined_storage.c512_compact.io.ct),
.sig_len=sizeof(combined_storage.c512_compact.io.sig),
.pk=combined_storage.c512_compact.io.pk,
.sk=combined_storage.c512_compact.io.sk,
.ct=combined_storage.c512_compact.io.ct,
.ss=combined_storage.c512_compact.io.ss,
.ss2=combined_storage.c512_compact.io.ss2,
.sig=combined_storage.c512_compact.io.sig,
.message=combined_storage.c512_compact.io.message,
.context=combined_storage.c512_compact.io.context,
.area=combined_storage.c512_compact.guarded.data,.vectors=unified_vectors512,
.init=pqm16_lc_context_init,
.dec=pqm16_lc_decaps,
.enc=pqm16_lc_encaps,
.key=pqm16_lc_keypair,
.sign=pqm16_lc_sign,
.verify=pqm16_lc_verify,
.requirement=pqm57_lc_f407_usable_requirement,
.plan=pqm46_lc_resource_make_plan,
.query=pqm46_lc_resource_query,
};
void run_c512_compact(const m4_request *q,m4_response *r){run_dsa(&cfg_c512_compact,q,r);}
extern const lc_target_vector unified_vectors512[];
static const f407_route cfg_c512_cached={.p=512,.s=2,.cap=sizeof(combined_storage.c512_cached.guarded.data),.nvec=3,.io_size=sizeof(combined_storage.c512_cached.io),
.pk_len=sizeof(combined_storage.c512_cached.io.pk),
.sk_len=sizeof(combined_storage.c512_cached.io.sk),
.ct_len=sizeof(combined_storage.c512_cached.io.ct),
.sig_len=sizeof(combined_storage.c512_cached.io.sig),
.pk=combined_storage.c512_cached.io.pk,
.sk=combined_storage.c512_cached.io.sk,
.ct=combined_storage.c512_cached.io.ct,
.ss=combined_storage.c512_cached.io.ss,
.ss2=combined_storage.c512_cached.io.ss2,
.sig=combined_storage.c512_cached.io.sig,
.message=combined_storage.c512_cached.io.message,
.context=combined_storage.c512_cached.io.context,
.area=combined_storage.c512_cached.guarded.data,.vectors=unified_vectors512,
.init=pqm17_lc_context_init,
.dec=pqm17_lc_decaps,
.enc=pqm17_lc_encaps,
.key=pqm17_lc_keypair,
.sign=pqm17_lc_sign,
.verify=pqm17_lc_verify,
.requirement=pqm57_lc_f407_usable_requirement,
.plan=pqm46_lc_resource_make_plan,
.query=pqm46_lc_resource_query,
};
void run_c512_cached(const m4_request *q,m4_response *r){run_dsa(&cfg_c512_cached,q,r);}
extern const lc_target_vector unified_vectors768[];
static const f407_route cfg_c768_compact={.p=768,.s=1,.cap=sizeof(combined_storage.c768_compact.guarded.data),.nvec=3,.io_size=sizeof(combined_storage.c768_compact.io),
.pk_len=sizeof(combined_storage.c768_compact.io.pk),
.sk_len=sizeof(combined_storage.c768_compact.io.sk),
.ct_len=sizeof(combined_storage.c768_compact.io.ct),
.sig_len=sizeof(combined_storage.c768_compact.io.sig),
.pk=combined_storage.c768_compact.io.pk,
.sk=combined_storage.c768_compact.io.sk,
.ct=combined_storage.c768_compact.io.ct,
.ss=combined_storage.c768_compact.io.ss,
.ss2=combined_storage.c768_compact.io.ss2,
.sig=combined_storage.c768_compact.io.sig,
.message=combined_storage.c768_compact.io.message,
.context=combined_storage.c768_compact.io.context,
.area=combined_storage.c768_compact.guarded.data,.vectors=unified_vectors768,
.init=pqm8_lc_context_init,
.dec=pqm8_lc_decaps,
.enc=pqm8_lc_encaps,
.key=pqm8_lc_keypair,
.sign=pqm8_lc_sign,
.verify=pqm8_lc_verify,
.requirement=pqm10_lc_f407_usable_requirement,
.plan=pqm38_lc_resource_make_plan,
.query=pqm38_lc_resource_query,
};
void run_c768_compact(const m4_request *q,m4_response *r){run_dsa(&cfg_c768_compact,q,r);}
extern const lc_target_vector unified_vectors768[];
static const f407_route cfg_c768_cached={.p=768,.s=2,.cap=sizeof(combined_storage.c768_cached.guarded.data),.nvec=3,.io_size=sizeof(combined_storage.c768_cached.io),
.pk_len=sizeof(combined_storage.c768_cached.io.pk),
.sk_len=sizeof(combined_storage.c768_cached.io.sk),
.ct_len=sizeof(combined_storage.c768_cached.io.ct),
.sig_len=sizeof(combined_storage.c768_cached.io.sig),
.pk=combined_storage.c768_cached.io.pk,
.sk=combined_storage.c768_cached.io.sk,
.ct=combined_storage.c768_cached.io.ct,
.ss=combined_storage.c768_cached.io.ss,
.ss2=combined_storage.c768_cached.io.ss2,
.sig=combined_storage.c768_cached.io.sig,
.message=combined_storage.c768_cached.io.message,
.context=combined_storage.c768_cached.io.context,
.area=combined_storage.c768_cached.guarded.data,.vectors=unified_vectors768,
.init=pqm9_lc_context_init,
.dec=pqm9_lc_decaps,
.enc=pqm9_lc_encaps,
.key=pqm9_lc_keypair,
.sign=pqm9_lc_sign,
.verify=pqm9_lc_verify,
.requirement=pqm47_lc_f407_usable_requirement,
.plan=pqm42_lc_resource_make_plan,
.query=pqm42_lc_resource_query,
};
void run_c768_cached(const m4_request *q,m4_response *r){run_dsa(&cfg_c768_cached,q,r);}
extern const lc_target_vector unified_vectors1024[];
static const f407_route cfg_c1024_compact={.p=1024,.s=1,.cap=sizeof(combined_storage.c1024_compact.guarded.data),.nvec=3,.io_size=sizeof(combined_storage.c1024_compact.io),
.pk_len=sizeof(combined_storage.c1024_compact.io.pk),
.sk_len=sizeof(combined_storage.c1024_compact.io.sk),
.ct_len=sizeof(combined_storage.c1024_compact.io.ct),
.sig_len=sizeof(combined_storage.c1024_compact.io.sig),
.pk=combined_storage.c1024_compact.io.pk,
.sk=combined_storage.c1024_compact.io.sk,
.ct=combined_storage.c1024_compact.io.ct,
.ss=combined_storage.c1024_compact.io.ss,
.ss2=combined_storage.c1024_compact.io.ss2,
.sig=combined_storage.c1024_compact.io.sig,
.message=combined_storage.c1024_compact.io.message,
.context=combined_storage.c1024_compact.io.context,
.area=combined_storage.c1024_compact.guarded.data,.vectors=unified_vectors1024,
.init=pqm4_lc_context_init,
.dec=pqm4_lc_decaps,
.enc=pqm4_lc_encaps,
.key=pqm4_lc_keypair,
.sign=pqm4_lc_sign,
.verify=pqm4_lc_verify,
.requirement=pqm13_lc_f407_usable_requirement,
.plan=pqm40_lc_resource_make_plan,
.query=pqm40_lc_resource_query,
};
void run_c1024_compact(const m4_request *q,m4_response *r){run_dsa(&cfg_c1024_compact,q,r);}
extern const lc_target_vector unified_vectors1024[];
static const f407_route cfg_c1024_cached={.p=1024,.s=2,.cap=sizeof(combined_storage.c1024_cached.guarded.data),.nvec=3,.io_size=sizeof(combined_storage.c1024_cached.io),
.pk_len=sizeof(combined_storage.c1024_cached.io.pk),
.sk_len=sizeof(combined_storage.c1024_cached.io.sk),
.ct_len=sizeof(combined_storage.c1024_cached.io.ct),
.sig_len=sizeof(combined_storage.c1024_cached.io.sig),
.pk=combined_storage.c1024_cached.io.pk,
.sk=combined_storage.c1024_cached.io.sk,
.ct=combined_storage.c1024_cached.io.ct,
.ss=combined_storage.c1024_cached.io.ss,
.ss2=combined_storage.c1024_cached.io.ss2,
.sig=combined_storage.c1024_cached.io.sig,
.message=combined_storage.c1024_cached.io.message,
.context=combined_storage.c1024_cached.io.context,
.area=combined_storage.c1024_cached.guarded.data,.vectors=unified_vectors1024,
.init=pqm3_lc_context_init,
.dec=pqm3_lc_decaps,
.enc=pqm3_lc_encaps,
.key=pqm3_lc_keypair,
.sign=pqm3_lc_sign,
.verify=pqm3_lc_verify,
.requirement=pqm11_lc_f407_usable_requirement,
.plan=pqm39_lc_resource_make_plan,
.query=pqm39_lc_resource_query,
};
void run_c1024_cached(const m4_request *q,m4_response *r){run_dsa(&cfg_c1024_cached,q,r);}
extern const lc_target_vector unified_vectors44[];
static const f407_route cfg_c44_compact={.p=44,.s=1,.cap=sizeof(combined_storage.c44_compact.guarded.data),.nvec=4,.io_size=sizeof(combined_storage.c44_compact.io),
.pk_len=sizeof(combined_storage.c44_compact.io.pk),
.sk_len=sizeof(combined_storage.c44_compact.io.sk),
.ct_len=sizeof(combined_storage.c44_compact.io.ct),
.sig_len=sizeof(combined_storage.c44_compact.io.sig),
.pk=combined_storage.c44_compact.io.pk,
.sk=combined_storage.c44_compact.io.sk,
.ct=combined_storage.c44_compact.io.ct,
.ss=combined_storage.c44_compact.io.ss,
.ss2=combined_storage.c44_compact.io.ss2,
.sig=combined_storage.c44_compact.io.sig,
.message=combined_storage.c44_compact.io.message,
.context=combined_storage.c44_compact.io.context,
.area=combined_storage.c44_compact.guarded.data,.vectors=unified_vectors44,
.init=pqm51_lc_context_init,
.dec=pqm51_lc_decaps,
.enc=pqm51_lc_encaps,
.key=pqm51_lc_keypair,
.sign=pqm51_lc_sign,
.verify=pqm51_lc_verify,
.requirement=pqm49_lc_f407_usable_requirement,
.plan=pqm44_lc_resource_make_plan,
.query=pqm44_lc_resource_query,
};
void run_c44_compact(const m4_request *q,m4_response *r){run_dsa(&cfg_c44_compact,q,r);}
extern const lc_target_vector unified_vectors44[];
static const f407_route cfg_c44_cached={.p=44,.s=2,.cap=sizeof(combined_storage.c44_cached.guarded.data),.nvec=4,.io_size=sizeof(combined_storage.c44_cached.io),
.pk_len=sizeof(combined_storage.c44_cached.io.pk),
.sk_len=sizeof(combined_storage.c44_cached.io.sk),
.ct_len=sizeof(combined_storage.c44_cached.io.ct),
.sig_len=sizeof(combined_storage.c44_cached.io.sig),
.pk=combined_storage.c44_cached.io.pk,
.sk=combined_storage.c44_cached.io.sk,
.ct=combined_storage.c44_cached.io.ct,
.ss=combined_storage.c44_cached.io.ss,
.ss2=combined_storage.c44_cached.io.ss2,
.sig=combined_storage.c44_cached.io.sig,
.message=combined_storage.c44_cached.io.message,
.context=combined_storage.c44_cached.io.context,
.area=combined_storage.c44_cached.guarded.data,.vectors=unified_vectors44,
.init=pqm52_lc_context_init,
.dec=pqm52_lc_decaps,
.enc=pqm52_lc_encaps,
.key=pqm52_lc_keypair,
.sign=pqm52_lc_sign,
.verify=pqm52_lc_verify,
.requirement=pqm48_lc_f407_usable_requirement,
.plan=pqm43_lc_resource_make_plan,
.query=pqm43_lc_resource_query,
};
void run_c44_cached(const m4_request *q,m4_response *r){run_dsa(&cfg_c44_cached,q,r);}
extern const lc_target_vector unified_vectors65[];
static const f407_route cfg_c65_compact={.p=65,.s=1,.cap=sizeof(combined_storage.c65_compact.guarded.data),.nvec=4,.io_size=sizeof(combined_storage.c65_compact.io),
.pk_len=sizeof(combined_storage.c65_compact.io.pk),
.sk_len=sizeof(combined_storage.c65_compact.io.sk),
.ct_len=sizeof(combined_storage.c65_compact.io.ct),
.sig_len=sizeof(combined_storage.c65_compact.io.sig),
.pk=combined_storage.c65_compact.io.pk,
.sk=combined_storage.c65_compact.io.sk,
.ct=combined_storage.c65_compact.io.ct,
.ss=combined_storage.c65_compact.io.ss,
.ss2=combined_storage.c65_compact.io.ss2,
.sig=combined_storage.c65_compact.io.sig,
.message=combined_storage.c65_compact.io.message,
.context=combined_storage.c65_compact.io.context,
.area=combined_storage.c65_compact.guarded.data,.vectors=unified_vectors65,
.init=pqm24_lc_context_init,
.dec=pqm24_lc_decaps,
.enc=pqm24_lc_encaps,
.key=pqm24_lc_keypair,
.sign=pqm24_lc_sign,
.verify=pqm24_lc_verify,
.requirement=pqm2_lc_f407_usable_requirement,
.plan=pqm36_lc_resource_make_plan,
.query=pqm36_lc_resource_query,
};
void run_c65_compact(const m4_request *q,m4_response *r){run_dsa(&cfg_c65_compact,q,r);}
extern const lc_target_vector unified_vectors65[];
static const f407_route cfg_c65_cached={.p=65,.s=2,.cap=sizeof(combined_storage.c65_cached.guarded.data),.nvec=4,.io_size=sizeof(combined_storage.c65_cached.io),
.pk_len=sizeof(combined_storage.c65_cached.io.pk),
.sk_len=sizeof(combined_storage.c65_cached.io.sk),
.ct_len=sizeof(combined_storage.c65_cached.io.ct),
.sig_len=sizeof(combined_storage.c65_cached.io.sig),
.pk=combined_storage.c65_cached.io.pk,
.sk=combined_storage.c65_cached.io.sk,
.ct=combined_storage.c65_cached.io.ct,
.ss=combined_storage.c65_cached.io.ss,
.ss2=combined_storage.c65_cached.io.ss2,
.sig=combined_storage.c65_cached.io.sig,
.message=combined_storage.c65_cached.io.message,
.context=combined_storage.c65_cached.io.context,
.area=combined_storage.c65_cached.guarded.data,.vectors=unified_vectors65,
.init=pqm25_lc_context_init,
.dec=pqm25_lc_decaps,
.enc=pqm25_lc_encaps,
.key=pqm25_lc_keypair,
.sign=pqm25_lc_sign,
.verify=pqm25_lc_verify,
.requirement=pqm34_lc_f407_usable_requirement,
.plan=pqm41_lc_resource_make_plan,
.query=pqm41_lc_resource_query,
};
void run_c65_cached(const m4_request *q,m4_response *r){run_dsa(&cfg_c65_cached,q,r);}
extern const lc_target_vector unified_vectors87[];
static const f407_route cfg_c87_compact={.p=87,.s=1,.cap=sizeof(combined_storage.c87_compact.guarded.data),.nvec=4,.io_size=sizeof(combined_storage.c87_compact.io),
.pk_len=sizeof(combined_storage.c87_compact.io.pk),
.sk_len=sizeof(combined_storage.c87_compact.io.sk),
.ct_len=sizeof(combined_storage.c87_compact.io.ct),
.sig_len=sizeof(combined_storage.c87_compact.io.sig),
.pk=combined_storage.c87_compact.io.pk,
.sk=combined_storage.c87_compact.io.sk,
.ct=combined_storage.c87_compact.io.ct,
.ss=combined_storage.c87_compact.io.ss,
.ss2=combined_storage.c87_compact.io.ss2,
.sig=combined_storage.c87_compact.io.sig,
.message=combined_storage.c87_compact.io.message,
.context=combined_storage.c87_compact.io.context,
.area=combined_storage.c87_compact.guarded.data,.vectors=unified_vectors87,
.init=pqm28_lc_context_init,
.dec=pqm28_lc_decaps,
.enc=pqm28_lc_encaps,
.key=pqm28_lc_keypair,
.sign=pqm28_lc_sign,
.verify=pqm28_lc_verify,
.requirement=pqm5_lc_f407_usable_requirement,
.plan=pqm37_lc_resource_make_plan,
.query=pqm37_lc_resource_query,
};
void run_c87_compact(const m4_request *q,m4_response *r){run_dsa(&cfg_c87_compact,q,r);}
extern const lc_target_vector unified_vectors87[];
static const f407_route cfg_c87_cached={.p=87,.s=2,.cap=sizeof(combined_storage.c87_cached.guarded.data),.nvec=4,.io_size=sizeof(combined_storage.c87_cached.io),
.pk_len=sizeof(combined_storage.c87_cached.io.pk),
.sk_len=sizeof(combined_storage.c87_cached.io.sk),
.ct_len=sizeof(combined_storage.c87_cached.io.ct),
.sig_len=sizeof(combined_storage.c87_cached.io.sig),
.pk=combined_storage.c87_cached.io.pk,
.sk=combined_storage.c87_cached.io.sk,
.ct=combined_storage.c87_cached.io.ct,
.ss=combined_storage.c87_cached.io.ss,
.ss2=combined_storage.c87_cached.io.ss2,
.sig=combined_storage.c87_cached.io.sig,
.message=combined_storage.c87_cached.io.message,
.context=combined_storage.c87_cached.io.context,
.area=combined_storage.c87_cached.guarded.data,.vectors=unified_vectors87,
.init=pqm29_lc_context_init,
.dec=pqm29_lc_decaps,
.enc=pqm29_lc_encaps,
.key=pqm29_lc_keypair,
.sign=pqm29_lc_sign,
.verify=pqm29_lc_verify,
.requirement=pqm56_lc_f407_usable_requirement,
.plan=pqm45_lc_resource_make_plan,
.query=pqm45_lc_resource_query,
};
void run_c87_cached(const m4_request *q,m4_response *r){run_dsa(&cfg_c87_cached,q,r);}
