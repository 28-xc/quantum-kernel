
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
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
union transaction_views combined_storage __attribute__((aligned(32),section(".ccm")));
lc_context active_context; entropy_source active_entropy;
typedef void (*entry_fn)(const m4_request*,m4_response*);
typedef struct {unsigned p,st,bytes,io_bytes,active_bytes;uint8_t *lo,*hi;entry_fn run;} config;
void run_c512_compact(const m4_request*,m4_response*);
void run_c512_cached(const m4_request*,m4_response*);
void run_c768_compact(const m4_request*,m4_response*);
void run_c768_cached(const m4_request*,m4_response*);
void run_c1024_compact(const m4_request*,m4_response*);
void run_c1024_cached(const m4_request*,m4_response*);
void run_c44_compact(const m4_request*,m4_response*);
void run_c44_cached(const m4_request*,m4_response*);
void run_c65_compact(const m4_request*,m4_response*);
void run_c65_cached(const m4_request*,m4_response*);
void run_c87_compact(const m4_request*,m4_response*);
void run_c87_cached(const m4_request*,m4_response*);
static const config entries[]={
 {512,1,5120,sizeof(combined_storage.c512_compact.io),sizeof(combined_storage.c512_compact),combined_storage.c512_compact.io_lower,combined_storage.c512_compact.io_upper,run_c512_compact},
 {512,2,5120,sizeof(combined_storage.c512_cached.io),sizeof(combined_storage.c512_cached),combined_storage.c512_cached.io_lower,combined_storage.c512_cached.io_upper,run_c512_cached},
 {768,1,6656,sizeof(combined_storage.c768_compact.io),sizeof(combined_storage.c768_compact),combined_storage.c768_compact.io_lower,combined_storage.c768_compact.io_upper,run_c768_compact},
 {768,2,6656,sizeof(combined_storage.c768_cached.io),sizeof(combined_storage.c768_cached),combined_storage.c768_cached.io_lower,combined_storage.c768_cached.io_upper,run_c768_cached},
 {1024,1,8448,sizeof(combined_storage.c1024_compact.io),sizeof(combined_storage.c1024_compact),combined_storage.c1024_compact.io_lower,combined_storage.c1024_compact.io_upper,run_c1024_compact},
 {1024,2,8448,sizeof(combined_storage.c1024_cached.io),sizeof(combined_storage.c1024_cached),combined_storage.c1024_cached.io_lower,combined_storage.c1024_cached.io_upper,run_c1024_cached},
 {44,1,7168,sizeof(combined_storage.c44_compact.io),sizeof(combined_storage.c44_compact),combined_storage.c44_compact.io_lower,combined_storage.c44_compact.io_upper,run_c44_compact},
 {44,2,21408,sizeof(combined_storage.c44_cached.io),sizeof(combined_storage.c44_cached),combined_storage.c44_cached.io_lower,combined_storage.c44_cached.io_upper,run_c44_cached},
 {65,1,8672,sizeof(combined_storage.c65_compact.io),sizeof(combined_storage.c65_compact),combined_storage.c65_compact.io_lower,combined_storage.c65_compact.io_upper,run_c65_compact},
 {65,2,18240,sizeof(combined_storage.c65_cached.io),sizeof(combined_storage.c65_cached),combined_storage.c65_cached.io_lower,combined_storage.c65_cached.io_upper,run_c65_cached},
 {87,1,7008,sizeof(combined_storage.c87_compact.io),sizeof(combined_storage.c87_compact),combined_storage.c87_compact.io_lower,combined_storage.c87_compact.io_upper,run_c87_compact},
 {87,2,15584,sizeof(combined_storage.c87_cached.io),sizeof(combined_storage.c87_cached),combined_storage.c87_cached.io_lower,combined_storage.c87_cached.io_upper,run_c87_cached},
};
void unified_hello(m4_response *r){r->w[23]=1;r->w[41]=1431193905u;r->w[42]=12;r->w[43]=63;r->w[44]=6;}
static const config *choose(const m4_request *q){for(unsigned i=0;i<sizeof(entries)/sizeof(entries[0]);i++)if(entries[i].p==q->w[8] && entries[i].st==q->w[9])return &entries[i];return 0;}
int unified_select(const m4_request *q,m4_response *r){const config *v=choose(q);if(!v)return 0;r->w[12]=v->p;r->w[13]=v->st;r->w[38]=v->bytes;return 1;}
void selected_layout(const m4_request *q,m4_response *r){const config *v=choose(q);if(!v)return;r->w[12]=v->p;r->w[13]=v->st;r->w[23]=1;r->w[38]=v->bytes;r->w[41]=v->bytes;r->w[42]=v->io_bytes;r->w[43]=v->active_bytes;r->w[44]=sizeof(combined_storage);r->w[45]=96;}
void unified_idle(void){clear_bytes(&combined_storage,sizeof(combined_storage));clear_bytes(&active_context,sizeof(active_context));clear_bytes(&active_entropy,sizeof(active_entropy));}
void experiment(const m4_request *q,m4_response *r){const config *v=choose(q);if(!v){if(q->w[2]==13||q->w[2]==14){unsigned standard=q->w[8]==512||q->w[8]==768||q->w[8]==1024||q->w[8]==44||q->w[8]==65||q->w[8]==87;r->w[24]=r->w[25]=(uint32_t)(standard&&q->w[11]<3?-8:-1);}return;}r->w[12]=v->p;r->w[13]=v->st;r->w[38]=v->bytes;memset(v->lo,0x69,16);memset(v->hi,0x96,16);v->run(q,r);unsigned diff=0;for(unsigned j=0;j<16;j++)diff|=(v->lo[j]^0x69)|(v->hi[j]^0x96);r->w[52]&=(diff==0);unified_idle();}
