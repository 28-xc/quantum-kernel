extern void two66(void*,void*);extern void three66(void*,void*,void*);
extern unsigned a127_three_block(unsigned,const unsigned char*,unsigned char*,const int*,unsigned char*,const int*,unsigned char*,const int*,unsigned);
enum { A127_TRIAL_CACHE_B=12*768 };
extern void a127_extract_words(const void*,void*,unsigned);
extern void two34(void*,void*); extern void four34(void*,void*,void*,void*);
extern void four(void*,void*,void*,void*);
/* a127_minimum_low_bits */
extern void two(void*,void*);
extern void pqm46_KeccakF1600_StateExtractBytes(const void*,unsigned char*,unsigned,unsigned);
extern void pqm46_KeccakF1600_StateXORBytes(void*,const unsigned char*,unsigned,unsigned);
extern void pqm46_KeccakF1600_StatePermute(void*);
extern void pqcrystals_dilithium_ntt(int*);extern void pqcrystals_dilithium_invntt_tomont(int*);extern void pqcrystals_dilithium_asm_pointwise_montgomery(int*,const int*,const int*);
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
static const a127_dsa_route selected_dsa_route;
struct lc_dsa_arena {
  uint8_t *base;
  size_t capacity, used, peak, front_pad, allocations, failures, lifo_errors;
};
void *lc_dsa_alloc(struct lc_dsa_arena *a, size_t bytes);
void lc_dsa_free(struct lc_dsa_arena *a, void *ptr, size_t bytes);
int lc_dsa_system_random(uint8_t *out, size_t bytes);
typedef enum
{
  MLD_SYS_CAP_X86_64_AVX2,
  MLD_SYS_CAP_AARCH64_NEON,
  MLD_SYS_CAP_AARCH64_SHA3,
  MLD_SYS_CAP_ARMV81M_MVE
} mld_sys_cap;
__attribute__((warn_unused_result))
static inline int mld_sys_check_capability(mld_sys_cap cap)
{
  (void)cap;
  return 1;
}
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
__attribute__((warn_unused_result))
static inline uint16_t mld_sign_hook_resume(
    struct lc_dsa_arena * context
)
{
  ((void)(context));
  return 0;
}
__attribute__((warn_unused_result))
static inline int mld_sign_hook_attempt (uint16_t attempt, struct lc_dsa_arena * context)
{
  ((void)attempt);
  ((void)(context));
  return 0;
}
static inline void mld_sign_hook_finish (uint16_t attempt, struct lc_dsa_arena * context)
{
  ((void)attempt);
  ((void)(context));
}
__attribute__((warn_unused_result))
static inline int64_t mld_value_barrier_i64(int64_t b)
{
  __asm__ volatile("" : "+r"(b));
  return b;
}
__attribute__((warn_unused_result))
static inline uint32_t mld_value_barrier_u32(uint32_t b)
{
  __asm__ volatile("" : "+r"(b));
  return b;
}
__attribute__((warn_unused_result))
static inline uint8_t mld_value_barrier_u8(uint8_t b)
{
  __asm__ volatile("" : "+r"(b));
  return b;
}
__attribute__((warn_unused_result))
static inline __attribute__((always_inline)) int32_t mld_cast_uint32_to_int32(uint32_t x)
{
  return (int32_t)x;
}
__attribute__((warn_unused_result))
static inline __attribute__((always_inline)) uint32_t mld_cast_int64_to_uint32(int64_t x)
{
  return (uint32_t)(x & (int64_t)4294967295U);
}
__attribute__((warn_unused_result))
static inline __attribute__((always_inline)) uint32_t mld_cast_int32_to_uint32(int32_t x)
{
  return mld_cast_int64_to_uint32((int64_t)x);
}
__attribute__((warn_unused_result))
static inline int32_t mld_ct_sel_int32(int32_t a, int32_t b, uint32_t cond)
{
  uint32_t au = mld_cast_int32_to_uint32(a);
  uint32_t bu = mld_cast_int32_to_uint32(b);
  uint32_t res = bu ^ (mld_value_barrier_u32(cond) & (au ^ bu));
  return mld_cast_uint32_to_int32(res);
}
__attribute__((warn_unused_result))
static inline uint32_t mld_ct_cmask_nonzero_u32(uint32_t x)
{
  int64_t tmp = mld_value_barrier_i64(-((int64_t)x));
  tmp >>= 32;
  return mld_cast_int64_to_uint32(tmp);
}
__attribute__((warn_unused_result))
static inline uint8_t mld_ct_cmask_nonzero_u8(uint8_t x)
{
  uint32_t mask = mld_ct_cmask_nonzero_u32((uint32_t)x);
  return (uint8_t)(mask & 0xFF);
}
__attribute__((warn_unused_result))
static inline uint32_t mld_ct_cmask_neg_i32(int32_t x)
{
  int64_t tmp = mld_value_barrier_i64((int64_t)x);
  tmp >>= 31;
  return mld_cast_int64_to_uint32(tmp);
}
__attribute__((warn_unused_result))
static inline int32_t mld_ct_abs_i32(int32_t x)
{
  return mld_ct_sel_int32(-x, x, mld_ct_cmask_neg_i32(x));
}
__attribute__((warn_unused_result))
static inline uint8_t mld_ct_memcmp(const uint8_t *a, const uint8_t *b,
                                        const size_t len)
{
  uint8_t r = 0, s = 0;
  unsigned i;
  for (i = 0; i < len; i++)
  {
    r |= a[i] ^ b[i];
    s ^= a[i] ^ b[i];
  }
  return (mld_value_barrier_u8(mld_ct_cmask_nonzero_u8(r) ^ s) ^ s);
}
static inline void mld_zeroize(void *ptr, size_t len)
{
  memset(ptr, 0, len);
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
}
extern int lcbase65_empty_cu_ct;
extern int lcbase65_empty_cu_debug;
__attribute__((warn_unused_result))
static inline int32_t mld_montgomery_reduce(int64_t a)
{
  const uint64_t QINV = 58728449;
  const uint32_t a_reduced = mld_cast_int64_to_uint32(a);
  const uint32_t a_inverted = (a_reduced * QINV) & 4294967295U;
  const int32_t t = mld_cast_uint32_to_int32(a_inverted);
  int64_t r;
  do { } while (0);
  r = a - (int64_t)t * 8380417;
  r = r >> 32;
  return (int32_t)r;
}
static inline int32_t a127_m4_mont_product(int32_t x,int32_t y) {
    uint32_t low; int32_t high,correction;
    __asm__("smull %0,%1,%2,%3" : "=&r"(low),"=&r"(high) : "r"(x),"r"(y));
    uint32_t m=low*58728449u;
    __asm__("smmul %0,%1,%2" : "=r"(correction) : "r"(m),"r"((int32_t)8380417));
    return high-correction;
}

__attribute__((warn_unused_result))
static inline int32_t mld_reduce32(int32_t a)
{
  int32_t t;
  t = (a + ((int32_t)1 << 22)) >> 23;
  t = a - t * 8380417;
  do { } while (0);
  return t;
}
__attribute__((warn_unused_result))
static inline int32_t mld_caddq(int32_t a)
{
  return mld_ct_sel_int32(a + 8380417, a, mld_ct_cmask_neg_i32(a));
}
static inline void mld_power2round65(int32_t *a0, int32_t *a1, int32_t a)
{
  *a1 = (a + (1 << (13 - 1)) - 1) >> 13;
  *a0 = a - (*a1 << 13);
}
static inline void mld_decompose65(int32_t *a0, int32_t *a1, int32_t a)
{
    const uint32_t adjusted=(uint32_t)a+261887u;
    const uint32_t n=(uint32_t)(((uint64_t)adjusted*537395713u)>>48);
    const uint32_t wrap=(n+48u)>>6;
    *a1=(int32_t)(n-16u*wrap);
    *a0=(int32_t)((uint32_t)a-n*523776u-wrap);
}
__attribute__((warn_unused_result))
static inline unsigned int mld_make_hint65(int32_t a0, int32_t a1)
{
  if (a0 > ((8380417 - 1) / 32) || a0 < -((8380417 - 1) / 32) ||
      (a0 == -((8380417 - 1) / 32) && a1 != 0))
  {
    return 1;
  }
  return 0;
}
__attribute__((warn_unused_result))
static inline int32_t mld_use_hint65(int32_t a, int32_t hint)
{
  int32_t a0, a1;
  mld_decompose65(&a0, &a1, a);
  if (hint == 0)
  {
    return a1;
  }
  if (a0 > 0)
  {
    return (a1 + 1) & 15;
  }
  else
  {
    return (a1 - 1) & 15;
  }
}
typedef struct
{
  int32_t coeffs[256];
} __attribute__((aligned(32))) mld_poly;
void lcbase_poly_reduce(mld_poly *a)
 ;
void lcbase_poly_caddq(mld_poly *a)
 ;
void lcbase_poly_add(mld_poly *r, const mld_poly *b)
 ;
void lcbase_poly_sub(mld_poly *r, const mld_poly *b)
 ;
void lcbase_poly_shiftl(mld_poly *a)
 ;
void lcbase_poly_ntt(mld_poly *a)
 ;
void lcbase_poly_invntt_tomont(mld_poly *a)
 ;
void lcbase_poly_pointwise_montgomery(mld_poly *a, const mld_poly *b)
 ;
void lcbase_poly_power2round(mld_poly *a1, mld_poly *a0, const mld_poly *a)
 ;
void lcbase_poly_uniform(mld_poly *a, const uint8_t seed[32 + 2])
 ;
void lcbase_polyt1_pack(uint8_t r[320], const mld_poly *a)
 ;
void lcbase_polyt1_unpack(mld_poly *r, const uint8_t a[320])
 ;
void lcbase_polyt0_pack(uint8_t r[416], const mld_poly *a)
 ;
void lcbase_polyt0_unpack(mld_poly *r, const uint8_t a[416])
 ;
__attribute__((warn_unused_result))
uint32_t lcbase_poly_chknorm(const mld_poly *a, int32_t B)
 ;
void lcbase_polyw1_pack_88(uint8_t r[192],
                        const mld_poly *a)
 ;
void lcbase_polyw1_pack_32(uint8_t r[128],
                        const mld_poly *a)
 ;
void lcbase_polyw1_unpack_88(mld_poly *r,
                          const uint8_t a[192])
 ;
void lcbase_polyw1_unpack_32(mld_poly *r,
                          const uint8_t a[128])
 ;
void lcbase65_poly_decompose(mld_poly *a1, mld_poly *a0)
 ;
void lcbase65_poly_use_hint(mld_poly *a, const mld_poly *h)
 ;
void lcbase65_poly_uniform_eta_4x(mld_poly *r0, mld_poly *r1, mld_poly *r2,
                             mld_poly *r3, const uint8_t seed[64],
                             uint8_t nonce0, uint8_t nonce1, uint8_t nonce2,
                             uint8_t nonce3)
 ;
void lcbase65_poly_uniform_eta(mld_poly *r, const uint8_t seed[64],
                          uint8_t nonce)
 ;
void lcbase65_poly_uniform_gamma1(mld_poly *a, const uint8_t seed[64],
                             uint16_t nonce)
 ;
void lcbase65_poly_challenge(mld_poly *c, const uint8_t seed[48])
 ;
void lcbase65_polyeta_pack(uint8_t r[128], const mld_poly *a)
 ;
void lcbase65_polyeta_unpack(mld_poly *r, const uint8_t a[128])
 ;
void lcbase65_polyz_pack(uint8_t r[640], const mld_poly *a)
 ;
void lcbase65_polyz_unpack(mld_poly *r, const uint8_t a[640])
 ;
static inline void lcbase65_polyw1_pack(uint8_t r[128],
                                       const mld_poly *a)
{
  lcbase_polyw1_pack_32(r, a);
}
static inline void lcbase65_polyw1_unpack(
    mld_poly *r, const uint8_t a[128])
{
  lcbase_polyw1_unpack_32(r, a);
}
typedef struct
{
  mld_poly vec[5];
} mld_polyvecl65;
void lcbase65_polyvecl_ntt(mld_polyvecl65 *v)
 ;
__attribute__((warn_unused_result))
uint32_t lcbase65_polyvecl_chknorm(const mld_polyvecl65 *v, int32_t B)
 ;
typedef struct
{
  mld_poly vec[6];
} mld_polyveck65;
void lcbase65_polyveck_reduce(mld_polyveck65 *v)
 ;
void lcbase65_polyveck_caddq(mld_polyveck65 *v)
 ;
void lcbase65_polyveck_invntt_tomont(mld_polyveck65 *v)
 ;
__attribute__((warn_unused_result))
uint32_t lcbase65_polyveck_chknorm(const mld_polyveck65 *v, int32_t B)
 ;
void lcbase65_polyveck_decompose_pack_w1(
    uint8_t r[6 * 128], mld_polyveck65 *v0,
    mld_poly *scratch)
 ;
void lcbase65_polyveck_pack_eta(uint8_t r[6 * 128],
                           const mld_polyveck65 *p)
 ;
void lcbase65_polyvecl_pack_eta(uint8_t r[5 * 128],
                           const mld_polyvecl65 *p)
 ;
void lcbase65_polyvecl_unpack_eta(
    mld_polyvecl65 *p, const uint8_t r[5 * 128])
 ;
void lcbase65_polyvecl_unpack_z(mld_polyvecl65 *z,
                           const uint8_t r[5 * 640])
 ;
void lcbase65_polyveck_unpack_eta(
    mld_polyveck65 *p, const uint8_t r[6 * 128])
 ;
typedef struct
{
  uint64_t s[25];
  unsigned int pos;
} mld_shake128ctx;
typedef struct
{
  uint64_t s[25];
  unsigned int pos;
} mld_shake256ctx;
void lcbase_shake128_init(mld_shake128ctx *state)
 ;
void lcbase_shake128_absorb(mld_shake128ctx *state, const uint8_t *in,
                         size_t inlen)
 ;
void lcbase_shake128_finalize(mld_shake128ctx *state)
 ;
void lcbase_shake128_squeeze(uint8_t *out, size_t outlen, mld_shake128ctx *state)
 ;
void lcbase_shake128_release(mld_shake128ctx *state)
 ;
void lcbase_shake256_init(mld_shake256ctx *state)
 ;
void lcbase_shake256_absorb(mld_shake256ctx *state, const uint8_t *in,
                         size_t inlen)
 ;
void lcbase_shake256_finalize(mld_shake256ctx *state)
 ;
void lcbase_shake256_squeeze(uint8_t *out, size_t outlen, mld_shake256ctx *state)
 ;
void lcbase_shake256_release(mld_shake256ctx *state)
 ;
void lcbase_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
 ;
typedef struct
{
  mld_polyvecl65 vec;
} mld_sk_s1hat_eager65;
typedef struct
{
  mld_polyveck65 vec;
} mld_sk_s2hat_eager65;
typedef struct
{
  mld_polyveck65 vec;
} mld_sk_t0hat_eager65;
typedef struct
{
  const uint8_t *packed;
} mld_sk_s1hat_lazy65;
typedef struct
{
  const uint8_t *packed;
} mld_sk_s2hat_lazy65;
typedef struct
{
  const uint8_t *packed;
} mld_sk_t0hat_lazy65;
typedef struct
{
  mld_polyvecl65 vec;
} mld_yvec_eager65;
typedef mld_polyvecl65 mld_yvec_scratch_eager65;
typedef struct
{
  const uint8_t *rhoprime;
  uint16_t kappa;
} mld_yvec_lazy65;
typedef mld_poly mld_yvec_scratch_lazy65;
static inline void mld_unpack_sk_s1hat_lazy65(
    mld_sk_s1hat_lazy65 *s1,
    const uint8_t packed_s1[5 * 128])
  {
  s1->packed = packed_s1;
}
static inline void mld_sk_s1hat_get_poly_lazy65(mld_poly *buf,
                                                  const mld_sk_s1hat_lazy65 *s1,
                                                  unsigned int i)
{
  lcbase65_polyeta_unpack(buf, s1->packed + i * 128);
  lcbase_poly_ntt(buf);
}
static inline void mld_unpack_sk_s2hat_lazy65(
    mld_sk_s2hat_lazy65 *s2,
    const uint8_t packed_s2[6 * 128])
  {
  s2->packed = packed_s2;
}
static inline void mld_sk_s2hat_get_poly_lazy65(mld_poly *buf,
                                                  const mld_sk_s2hat_lazy65 *s2,
                                                  unsigned int i)
{
  lcbase65_polyeta_unpack(buf, s2->packed + i * 128);
  lcbase_poly_ntt(buf);
}
static inline void mld_unpack_sk_t0hat_lazy65(
    mld_sk_t0hat_lazy65 *t0,
    const uint8_t packed_t0[6 * 416])
  {
  t0->packed = packed_t0;
}
static inline void mld_sk_t0hat_get_poly_lazy65(mld_poly *buf,
                                                  const mld_sk_t0hat_lazy65 *t0,
                                                  unsigned int i)
{
  lcbase_polyt0_unpack(buf, t0->packed + i * 416);
  lcbase_poly_ntt(buf);
}
static inline void mld_yvec_init_lazy65(
    mld_yvec_lazy65 *y, const uint8_t rhoprime[64], uint16_t kappa
)
{
  y->rhoprime = rhoprime;
  y->kappa = kappa;
}
static inline void mld_yvec_get_poly_lazy65(mld_poly *buf,
                                              const mld_yvec_lazy65 *y,
                                              unsigned int i)
{
  lcbase65_poly_uniform_gamma1(buf, y->rhoprime, (uint16_t)(y->kappa + i));
}
typedef struct
{
  mld_poly cur;
  uint8_t rho[32];
  uint8_t (*cache)[256*24/8];
  unsigned cache_ready;
} mld_polymat_lazy65;
static inline void mld_poly_permute_bitrev_to_custom_optional65(mld_poly *p)
{
  (void)p;
}
void lcbase65_polyvec_matrix_expand_lazy(mld_polymat_lazy65 *mat,
                                    const uint8_t rho[32])
 ;
void lcbase65_polyvec_matrix_pointwise_montgomery_row_lazy(mld_poly *t_row,
                                                      mld_polymat_lazy65 *mat,
                                                      const mld_polyvecl65 *v,
                                                      unsigned int i)
 ;
void lcbase65_polyvec_matrix_pointwise_montgomery_yvec_lazy(
    mld_polyveck65 *w, mld_polymat_lazy65 *mat, const mld_yvec_lazy65 *y,
    mld_yvec_scratch_lazy65 *scratch)
 ;
typedef mld_sk_s1hat_lazy65 mld_sk_s1hat65;
typedef mld_sk_s2hat_lazy65 mld_sk_s2hat65;
typedef mld_sk_t0hat_lazy65 mld_sk_t0hat65;
typedef mld_polymat_lazy65 mld_polymat65;
typedef mld_yvec_lazy65 mld_yvec65;
typedef mld_yvec_scratch_lazy65 mld_yvec_scratch65;
void lcbase65_pack_sk_s1(uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))],
                    const mld_polyvecl65 *s1)
 ;
void lcbase65_pack_sk_rho_key_tr_s2(uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))],
                               const uint8_t rho[32],
                               const uint8_t tr[64],
                               const uint8_t key[32],
                               const mld_polyveck65 *s2)
 ;
void lcbase65_pack_sig_c(uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))],
                    const uint8_t c[48])
 ;
__attribute__((warn_unused_result))
int lcbase65_pack_sig_h(uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const mld_polyveck65 *w0,
                   const uint8_t w1_packed[6 * 128],
                   mld_poly *scratch)
 ;
void lcbase65_pack_sig_z(uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const mld_poly *zi,
                    unsigned i)
 ;
void lcbase65_unpack_pk_t1(mld_poly *t1,
                      const uint8_t pk[((0 + 32) + (6 * 320))],
                      unsigned int i)
 ;
void lcbase65_unpack_sk(uint8_t rho[32], uint8_t tr[64],
                   uint8_t key[32], mld_sk_t0hat65 *t0,
                   mld_sk_s1hat65 *s1, mld_sk_s2hat65 *s2,
                   const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))])
 ;
__attribute__((warn_unused_result))
int lcbase65_sig_unpack_hints(mld_poly *h, const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))],
                         unsigned int i)
 ;
void lcbase65_unpack_pk_t1(mld_poly *t1,
                      const uint8_t pk[((0 + 32) + (6 * 320))],
                      unsigned int i)
{
  lcbase_polyt1_unpack(t1, pk + (0 + 32) + i * 320);
}
void lcbase65_pack_sk_s1(uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))],
                    const mld_polyvecl65 *s1)
{
  lcbase65_polyvecl_pack_eta(sk + (((0 + 32) + 32) + 64), s1);
}
void lcbase65_pack_sk_rho_key_tr_s2(uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))],
                               const uint8_t rho[32],
                               const uint8_t tr[64],
                               const uint8_t key[32],
                               const mld_polyveck65 *s2)
{
  memcpy(sk + 0, rho, 32);
  memcpy(sk + (0 + 32), key, 32);
  memcpy(sk + ((0 + 32) + 32), tr, 64);
  lcbase65_polyveck_pack_eta(sk + ((((0 + 32) + 32) + 64) + (5 * 128)), s2);
}
void lcbase65_unpack_sk(uint8_t rho[32], uint8_t tr[64],
                   uint8_t key[32], mld_sk_t0hat65 *t0,
                   mld_sk_s1hat65 *s1, mld_sk_s2hat65 *s2,
                   const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))])
{
  memcpy(rho, sk + 0, 32);
  memcpy(key, sk + (0 + 32), 32);
  memcpy(tr, sk + ((0 + 32) + 32), 64);
  mld_unpack_sk_s1hat_lazy65(s1, sk + (((0 + 32) + 32) + 64));
  mld_unpack_sk_s2hat_lazy65(s2, sk + ((((0 + 32) + 32) + 64) + (5 * 128)));
  mld_unpack_sk_t0hat_lazy65(t0, sk + (((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)));
}
void lcbase65_pack_sig_c(uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))],
                    const uint8_t c[48])
{
  memcpy(sig, c, 48);
}
int lcbase65_pack_sig_h(uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const mld_polyveck65 *w0,
                   const uint8_t w1_packed[6 * 128],
                   mld_poly *scratch)
{
  unsigned int j, k, n;
  uint8_t *sig_h = sig + ((0 + 48) + (5 * 640));
  memset(sig_h, 0, (55 + 6));
  n = 0;
  for (k = 0; k < 6; k++)
  {
    lcbase65_polyw1_unpack(scratch, w1_packed + k * 128);
    for (j = 0; j < 256; j++)
    {
      const unsigned int hint_bit =
          mld_make_hint65(w0->vec[k].coeffs[j], scratch->coeffs[j]);
      if (hint_bit)
      {
        if (n == 55)
        {
          return (-1);
        }
        sig_h[n] = (uint8_t)j;
        n++;
      }
    }
    sig_h[55 + k] = (uint8_t)n;
  }
  return 0;
}
void lcbase65_pack_sig_z(uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const mld_poly *zi,
                    unsigned i)
{
  lcbase65_polyz_pack(sig + (0 + 48) + i * 640, zi);
}
int lcbase65_sig_unpack_hints(mld_poly *h, const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))],
                         unsigned int i)
{
  const uint8_t *packed_hints = sig + ((0 + 48) + (5 * 640));
  const unsigned int old_hint_count =
      (i == 0) ? 0 : packed_hints[55 + i - 1];
  const unsigned int new_hint_count = packed_hints[55 + i];
  unsigned int j;
  if (new_hint_count < old_hint_count || new_hint_count > 55)
  {
    return (-1);
  }
  memset(h, 0, sizeof(mld_poly));
  for (j = old_hint_count; j < new_hint_count; j++)
  {
    if (j > old_hint_count && packed_hints[j] <= packed_hints[j - 1])
    {
      return (-1);
    }
    h->coeffs[packed_hints[j]] = 1;
  }
  if (i == 6 - 1)
  {
    for (j = new_hint_count; j < 55; j++)
    {
      if (packed_hints[j] != 0)
      {
        return (-1);
      }
    }
  }
                                                                             ;
  return 0;
}
static unsigned lc_reject_compact24(uint8_t *p,unsigned count,unsigned source,unsigned bytes) {
  unsigned pos=source,end=source+bytes;
  while(count<256 && pos+3<=end) {
    uint32_t x=(uint32_t)p[pos]|((uint32_t)p[pos+1]<<8)|((uint32_t)p[pos+2]<<16);
    pos+=3;x&=0x7fffffu;
    if(x<8380417u) {p[3*count]=(uint8_t)x;p[3*count+1]=(uint8_t)(x>>8);p[3*count+2]=(uint8_t)(x>>16);count++;}
  }
  return count;
}
static void lc_expand_unsigned24(int32_t *out) {
  uint8_t *p=(uint8_t*)out;
  for(unsigned i=256;i-- >0;) {
    uint32_t x=(uint32_t)p[3*i]|((uint32_t)p[3*i+1]<<8)|((uint32_t)p[3*i+2]<<16);
    out[i]=(int32_t)x;
  }
}
static void lc_expand_gamma(int32_t *out,unsigned bits,int32_t gamma) {
  (void)bits;
  unsigned char *bytes=(unsigned char*)out;
  for(unsigned block=128;block-- >0;){
    const unsigned char *in=bytes+block*5;
    uint32_t a; __builtin_memcpy(&a,in,4);
    const uint32_t b=in[4];
    out[block*2+1]=gamma-(int32_t)(((a>>20)|(b<<12))&1048575u);
    out[block*2+0]=gamma-(int32_t)(a&1048575u);
  }
}
static int32_t lc_load_signed24(const uint8_t *p) {
  uint32_t low;__asm__("ldrh %0,[%1]":"=r"(low):"r"(p):"memory");uint32_t x=low|((uint32_t)p[2]<<16);
  return (int32_t)(x&0x7fffffu)-(int32_t)(x&0x800000u);
}
static void lc_store_signed24(uint8_t *p,int32_t v) {
  uint32_t x=(uint32_t)v;__asm__("strh %1,[%0]"::"r"(p),"r"(x):"memory");p[2]=(uint8_t)(x>>16);
}
void lcbase_keccakf1600_extract_bytes(uint64_t *state, unsigned char *data,
                                   unsigned offset, unsigned length)
 ;
void lcbase_keccakf1600_xor_bytes(uint64_t *state, const unsigned char *data,
                               unsigned offset, unsigned length)
 ;
void lcbase_keccakf1600x4_extract_bytes(uint64_t *state, unsigned char *data0,
                                     unsigned char *data1, unsigned char *data2,
                                     unsigned char *data3, unsigned offset,
                                     unsigned length)
 ;
void lcbase_keccakf1600x4_xor_bytes(uint64_t *state, const unsigned char *data0,
                                 const unsigned char *data1,
                                 const unsigned char *data2,
                                 const unsigned char *data3, unsigned offset,
                                 unsigned length)
 ;
void lcbase_keccakf1600x4_permute(uint64_t *state)
 ;
void lcbase_keccakf1600_permute(uint64_t *state)
 ;
typedef struct
{
  uint64_t ctx[25 *
               4];
} mld_shake128x4ctx;
typedef struct
{
  uint64_t ctx[25 *
               4];
} mld_shake256x4ctx;
void lcbase_shake256x4_absorb_once(mld_shake256x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen)
 ;
void lcbase_shake256x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mld_shake256x4ctx *state)
 ;
void lcbase_shake256x4_init(mld_shake256x4ctx *state);
void lcbase_shake256x4_release(mld_shake256x4ctx *state);
static const int32_t mld_zetas[256] = {
    0, 25847, -2608894, -518909, 237124, -777960, -876248,
    466468, 1826347, 2353451, -359251, -2091905, 3119733, -2884855,
    3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672,
    1757237, -19422, 4010497, 280005, 2706023, 95776, 3077325,
    3530437, -1661693, -3592148, -2537516, 3915439, -3861115, -3043716,
    3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267,
    -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596,
    811944, 531354, 954230, 3881043, 3900724, -2556880, 2071892,
    -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144,
    -3157330, -3632928, 126922, 3412210, -983419, 2147896, 2715295,
    -2967645, -3693493, -411027, -2477047, -671102, -1228525, -22981,
    -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944,
    508951, 3097992, 44288, -1100098, 904516, 3958618, -3724342,
    -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856,
    189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589,
    1341330, 1285669, -1584928, -812732, -1439742, -3019102, -3881060,
    -3628969, 3839961, 2091667, 3407706, 2316500, 3817976, -3342478,
    2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181,
    -3520352, -3759364, -1197226, -3193378, 900702, 1859098, 909542,
    819034, 495491, -1613174, -43260, -522500, -655327, -3122442,
    2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044,
    2842341, 2691481, -2590150, 1265009, 4055324, 1247620, 2486353,
    1595974, -3767016, 1250494, 2635921, -3548272, -2994039, 1869119,
    1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100,
    1312455, 3306115, -1962642, -1279661, 1917081, -2546312, -1374803,
    1500165, 777191, 2235880, 3406031, -542412, -2831860, -1671176,
    -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395,
    2454455, -164721, 1957272, 3369112, 185531, -1207385, -3183426,
    162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107,
    -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333,
    -260646, -3833893, -2939036, -2235985, -420899, -2286327, 183443,
    -976891, 1612842, -3545687, -554416, 3919660, -48306, -1362209,
    3937738, 1400424, -846154, 1976782,
};
void lcbase_poly_reduce(mld_poly *a)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    a->coeffs[i] = mld_reduce32(a->coeffs[i]);
  }
  do { } while (0);
}
static void mld_poly_caddq_c(mld_poly *a)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    a->coeffs[i] = mld_caddq(a->coeffs[i]);
  }
  do { } while (0);
}
void lcbase_poly_caddq(mld_poly *a)
{
  mld_poly_caddq_c(a);
}
void lcbase_poly_add(mld_poly *r, const mld_poly *b)
{
  unsigned int i;
  for (i = 0; i < 256; i++)
  {
    r->coeffs[i] = r->coeffs[i] + b->coeffs[i];
  }
}
void lcbase_poly_sub(mld_poly *r, const mld_poly *b)
{
  unsigned int i;
  do { } while (0);
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    r->coeffs[i] = r->coeffs[i] - b->coeffs[i];
  }
  do { } while (0);
}
void lcbase_poly_shiftl(mld_poly *a)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    a->coeffs[i] *= (1 << 13);
  }
  do { } while (0);
}
static inline int32_t mld_fqmul(int32_t a, int32_t b)
{
  return a127_m4_mont_product(a,b);
}
static inline void mld_ntt_butterfly_block(int32_t r[256],
                                               const int32_t zeta,
                                               const unsigned start,
                                               const unsigned len,
                                               const uint32_t bound)
{
  unsigned j;
  ((void)bound);
  for (j = start; j < start + len; j++)
  {
    int32_t t;
    t = mld_fqmul(r[j + len], zeta);
    r[j + len] = r[j] - t;
    r[j] = r[j] + t;
  }
}
static inline void mld_ntt_layer(int32_t r[256], const unsigned layer)
{
  unsigned start, k, len;
  k = 1u << (layer - 1);
  len = (unsigned)256 >> layer;
  for (start = 0; start < 256; start += 2 * len)
  {
    int32_t zeta = mld_zetas[k++];
    mld_ntt_butterfly_block(r, zeta, start, len, layer * ((5 * 8380417 + 3) / 4));
  }
}
static void mld_poly_ntt_c(mld_poly *a)
{
  unsigned int layer;
  int32_t *r;
  do { } while (0);
  r = a->coeffs;
  for (layer = 1; layer < 9; layer++)
  {
    mld_ntt_layer(r, layer);
  }
  do { } while (0);
}
void lcbase_poly_ntt(mld_poly *a)
{pqcrystals_dilithium_ntt(a->coeffs);}
static inline int32_t mld_fqscale(int32_t a)
{
  const int32_t f = 41978;
  return a127_m4_mont_product(a,f);
}
static inline void mld_invntt_layer(int32_t r[256], unsigned layer)
{
  unsigned start, k, len;
  len = (unsigned)256 >> layer;
  k = (1u << layer) - 1;
  for (start = 0; start < 256; start += 2 * len)
  {
    unsigned j;
    int32_t zeta = -mld_zetas[k--];
    for (j = start; j < start + len; j++)
    {
      int32_t t = r[j];
      r[j] = t + r[j + len];
      r[j + len] = t - r[j + len];
      r[j + len] = mld_fqmul(r[j + len], zeta);
    }
  }
}
static void mld_poly_invntt_tomont_c(mld_poly *a)
{
  unsigned int layer, j;
  int32_t *r;
  do { } while (0);
  r = a->coeffs;
  for (layer = 8; layer >= 1; layer--)
  {
    mld_invntt_layer(r, layer);
  }
  for (j = 0; j < 256; j++)
  {
    r[j] = mld_fqscale(r[j]);
  }
  do { } while (0);
}
void lcbase_poly_invntt_tomont(mld_poly *a)
{pqcrystals_dilithium_invntt_tomont(a->coeffs);}
static void mld_poly_pointwise_montgomery_c(mld_poly *a,
                                                         const mld_poly *b)
{
  unsigned int i;
  do { } while (0);
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    a->coeffs[i] = mld_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
  }
  do { } while (0);
}
void lcbase_poly_pointwise_montgomery(mld_poly *a, const mld_poly *b)
{pqcrystals_dilithium_asm_pointwise_montgomery(a->coeffs,a->coeffs,b->coeffs);}
void lcbase_poly_power2round(mld_poly *a1, mld_poly *a0, const mld_poly *a)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    mld_power2round65(&a0->coeffs[i], &a1->coeffs[i], a->coeffs[i]);
  }
  do { } while (0);
  do { } while (0);
}
static unsigned int mld_rej_uniform_c(int32_t *a,
                                                   unsigned int target,
                                                   unsigned int offset,
                                                   const uint8_t *buf,
                                                   unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t;
  do { } while (0);
  ctr = offset;
  pos = 0;
  while (ctr < target && pos + 3 <= buflen)
  {
    t = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;
    if (t < 8380417)
    {
      a[ctr++] = (int32_t)t;
    }
  }
  do { } while (0);
  return ctr;
}
static unsigned int mld_rej_uniform(int32_t *a, unsigned int target,
                                    unsigned int offset, const uint8_t *buf,
                                    unsigned int buflen)
{
  return mld_rej_uniform_c(a, target, offset, buf, buflen);
}
void lcbase_poly_uniform(mld_poly *a, const uint8_t seed[32 + 2])
{
  __attribute__((aligned(32))) uint8_t buf[168];
  mld_shake128ctx state;
  unsigned ctr=0;
  lcbase_shake128_init(&state);do { lcbase_shake128_absorb(&state, seed, 32 +2); lcbase_shake128_finalize(&state); } while (0);
  do {
    lcbase_shake128_squeeze(buf, (1) * 168, &state);
    ctr=mld_rej_uniform(a->coeffs,256,ctr,buf,sizeof(buf));
  } while(ctr<256);
  lcbase_shake128_release(&state);mld_zeroize(buf,sizeof(buf));
  do { } while (0);
}
void lcbase_polyt1_pack(uint8_t r[320], const mld_poly *a)
{
for(unsigned i=0;i<256;i+=4){
unsigned x0=(uint32_t)a->coeffs[i+0]&1023u;
unsigned x1=(uint32_t)a->coeffs[i+1]&1023u;
unsigned x2=(uint32_t)a->coeffs[i+2]&1023u;
unsigned x3=(uint32_t)a->coeffs[i+3]&1023u;
unsigned w0=(x0<<0)|(x1<<10)|(x2<<20)|(x3<<30);
__asm__("str %1,[%0]"::"r"(r+0),"r"(w0):"memory");
unsigned w4=(x3>>2);
r[4]=(uint8_t)w4;
r+=5;
}
}
void lcbase_polyt1_unpack(mld_poly *r, const uint8_t a[320])
{
for(unsigned i=0;i<256;i+=4){
uint32_t x0;__asm__("ldr %0,[%1]":"=r"(x0):"r"(a+0):"memory");
uint32_t x1=a[4];
r->coeffs[i+0]=(int32_t)((x0>>0)&1023u);
r->coeffs[i+1]=(int32_t)((x0>>10)&1023u);
r->coeffs[i+2]=(int32_t)((x0>>20)&1023u);
r->coeffs[i+3]=(int32_t)(((x0>>30)|(x1<<2))&1023u);
a+=5;
}
}
void lcbase_polyt0_pack(uint8_t r[416], const mld_poly *a)
{
for(unsigned i=0;i<256;i+=8){
unsigned x0=(4096u-(uint32_t)a->coeffs[i+0])&8191u;
unsigned x1=(4096u-(uint32_t)a->coeffs[i+1])&8191u;
unsigned x2=(4096u-(uint32_t)a->coeffs[i+2])&8191u;
unsigned x3=(4096u-(uint32_t)a->coeffs[i+3])&8191u;
unsigned x4=(4096u-(uint32_t)a->coeffs[i+4])&8191u;
unsigned x5=(4096u-(uint32_t)a->coeffs[i+5])&8191u;
unsigned x6=(4096u-(uint32_t)a->coeffs[i+6])&8191u;
unsigned x7=(4096u-(uint32_t)a->coeffs[i+7])&8191u;
unsigned w0=(x0<<0)|(x1<<13)|(x2<<26);
__asm__("str %1,[%0]"::"r"(r+0),"r"(w0):"memory");
unsigned w4=(x2>>6)|(x3<<7)|(x4<<20);
__asm__("str %1,[%0]"::"r"(r+4),"r"(w4):"memory");
unsigned w8=(x4>>12)|(x5<<1)|(x6<<14)|(x7<<27);
__asm__("str %1,[%0]"::"r"(r+8),"r"(w8):"memory");
unsigned w12=(x7>>5);
r[12]=(uint8_t)w12;
r+=13;
}
}
void lcbase_polyt0_unpack(mld_poly *r, const uint8_t a[416])
{
for(unsigned i=0;i<256;i+=8){
uint32_t x0;__asm__("ldr %0,[%1]":"=r"(x0):"r"(a+0):"memory");
uint32_t x1;__asm__("ldr %0,[%1]":"=r"(x1):"r"(a+4):"memory");
uint32_t x2;__asm__("ldr %0,[%1]":"=r"(x2):"r"(a+8):"memory");
uint32_t x3=a[12];
r->coeffs[i+0]=4096-(int32_t)((x0>>0)&8191u);
r->coeffs[i+1]=4096-(int32_t)((x0>>13)&8191u);
r->coeffs[i+2]=4096-(int32_t)(((x0>>26)|(x1<<6))&8191u);
r->coeffs[i+3]=4096-(int32_t)((x1>>7)&8191u);
r->coeffs[i+4]=4096-(int32_t)(((x1>>20)|(x2<<12))&8191u);
r->coeffs[i+5]=4096-(int32_t)((x2>>1)&8191u);
r->coeffs[i+6]=4096-(int32_t)((x2>>14)&8191u);
r->coeffs[i+7]=4096-(int32_t)(((x2>>27)|(x3<<5))&8191u);
a+=13;
}
}
static uint32_t mld_poly_chknorm_c(const mld_poly *a, int32_t B)
{
  unsigned int i;
  uint32_t t = 0;
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    do { } while (0);
    do { } while (0);
    t |= mld_ct_cmask_neg_i32(B - 1 - mld_ct_abs_i32(a->coeffs[i]));
  }
  return t;
}
uint32_t lcbase_poly_chknorm(const mld_poly *a, int32_t B)
{
  return mld_poly_chknorm_c(a, B);
}
void lcbase_polyw1_pack_88(uint8_t r[192],
                        const mld_poly *a)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 256 / 4; i++)
  {
    r[3 * i + 0] = (uint8_t)((a->coeffs[4 * i + 0]) & 0xFF);
    r[3 * i + 0] |= (uint8_t)((a->coeffs[4 * i + 1] << 6) & 0xFF);
    r[3 * i + 1] = (uint8_t)((a->coeffs[4 * i + 1] >> 2) & 0xFF);
    r[3 * i + 1] |= (uint8_t)((a->coeffs[4 * i + 2] << 4) & 0xFF);
    r[3 * i + 2] = (uint8_t)((a->coeffs[4 * i + 2] >> 4) & 0xFF);
    r[3 * i + 2] |= (uint8_t)((a->coeffs[4 * i + 3] << 2) & 0xFF);
  }
}
void lcbase_polyw1_pack_32(uint8_t r[128],
                        const mld_poly *a)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 256 / 2; i++)
  {
    r[i] =
        (uint8_t)((a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4)) & 0xFF);
  }
}
void lcbase_polyw1_unpack_88(mld_poly *r,
                          const uint8_t a[192])
{
  unsigned int i;
  for (i = 0; i < 256 / 4; i++)
  {
    r->coeffs[4 * i + 0] = a[3 * i + 0] & 0x3F;
    r->coeffs[4 * i + 1] =
        ((a[3 * i + 0] >> 6) | ((int32_t)a[3 * i + 1] << 2)) & 0x3F;
    r->coeffs[4 * i + 2] =
        ((a[3 * i + 1] >> 4) | ((int32_t)a[3 * i + 2] << 4)) & 0x3F;
    r->coeffs[4 * i + 3] = a[3 * i + 2] >> 2;
  }
  do { } while (0);
}
void lcbase_polyw1_unpack_32(mld_poly *r,
                          const uint8_t a[128])
{
  unsigned int i;
  for (i = 0; i < 256 / 2; i++)
  {
    r->coeffs[2 * i + 0] = a[i] & 0x0F;
    r->coeffs[2 * i + 1] = a[i] >> 4;
  }
  do { } while (0);
}
static
void mld_poly_decompose_c65(mld_poly *a1, mld_poly *a0)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    mld_decompose65(&a0->coeffs[i], &a1->coeffs[i], a0->coeffs[i]);
  }
  do { } while (0);
  do { } while (0);
}
void lcbase65_poly_decompose(mld_poly *a1, mld_poly *a0)
{
  mld_poly_decompose_c65(a1, a0);
}
static void mld_poly_use_hint_c65(mld_poly *a, const mld_poly *h)
{
  unsigned int i;
  do { } while (0);
  do { } while (0);
  for (i = 0; i < 256; i++)
  {
    a->coeffs[i] = mld_use_hint65(a->coeffs[i], h->coeffs[i]);
  }
  do { } while (0);
}
void lcbase65_poly_use_hint(mld_poly *a, const mld_poly *h)
{
  mld_poly_use_hint_c65(a, h);
}
static unsigned int mld_rej_eta_c65(int32_t *a, unsigned int target,
                                               unsigned int offset,
                                               const uint8_t *buf,
                                               unsigned int buflen)
{
  unsigned int ctr, pos;
  int t_valid;
  uint32_t t0, t1;
  do { } while (0);
  ctr = offset;
  pos = 0;
  while (ctr < target && pos < buflen)
  {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;
    t_valid = t0 < 9;
    do { } while (0);
    if (t_valid)
    {
      a[ctr++] = 4 - (int32_t)t0;
    }
    t_valid = t1 < 9;
    do { } while (0);
    if (t_valid && ctr < target)
    {
      a[ctr++] = 4 - (int32_t)t1;
    }
  }
  do { } while (0);
  return ctr;
}
static unsigned int mld_rej_eta65(int32_t *a, unsigned int target,
                                unsigned int offset, const uint8_t *buf,
                                unsigned int buflen)
{
  return mld_rej_eta_c65(a, target, offset, buf, buflen);
}
void lcbase65_poly_uniform_eta_4x(mld_poly *r0, mld_poly *r1, mld_poly *r2,
                             mld_poly *r3, const uint8_t seed[64],
                             uint8_t nonce0, uint8_t nonce1, uint8_t nonce2,
                             uint8_t nonce3)
{
  __attribute__((aligned(32))) uint8_t buf[4][((((2 * 136) + (32 - 1)) / 32) * 32)];
  __attribute__((aligned(32))) uint8_t extseed[4][((((64 + 2) + (32 - 1)) / 32) * 32)];
  unsigned ctr[4];
  mld_shake256x4ctx state;
  unsigned buflen;
  memcpy(extseed[0], seed, 64);
  memcpy(extseed[1], seed, 64);
  memcpy(extseed[2], seed, 64);
  memcpy(extseed[3], seed, 64);
  extseed[0][64] = nonce0;
  extseed[1][64] = nonce1;
  extseed[2][64] = nonce2;
  extseed[3][64] = nonce3;
  extseed[0][64 + 1] = 0;
  extseed[1][64 + 1] = 0;
  extseed[2][64 + 1] = 0;
  extseed[3][64 + 1] = 0;
  lcbase_shake256x4_init((&state));
  lcbase_shake256x4_absorb_once((&state), (extseed)[0], (extseed)[1], (extseed)[2], (extseed)[3], (64 + 2));
  lcbase_shake256x4_squeezeblocks((buf)[0], (buf)[1], (buf)[2], (buf)[3], (2), (&state));
  buflen = 2 * 136;
  ctr[0] = mld_rej_eta65(r0->coeffs, 256, 0, buf[0], buflen);
  ctr[1] = mld_rej_eta65(r1->coeffs, 256, 0, buf[1], buflen);
  ctr[2] = mld_rej_eta65(r2->coeffs, 256, 0, buf[2], buflen);
  ctr[3] = mld_rej_eta65(r3->coeffs, 256, 0, buf[3], buflen);
  buflen = 136;
  while (ctr[0] < 256 || ctr[1] < 256 || ctr[2] < 256 ||
         ctr[3] < 256)
  {
    lcbase_shake256x4_squeezeblocks((buf)[0], (buf)[1], (buf)[2], (buf)[3], (1), (&state));
    ctr[0] = mld_rej_eta65(r0->coeffs, 256, ctr[0], buf[0], buflen);
    ctr[1] = mld_rej_eta65(r1->coeffs, 256, ctr[1], buf[1], buflen);
    ctr[2] = mld_rej_eta65(r2->coeffs, 256, ctr[2], buf[2], buflen);
    ctr[3] = mld_rej_eta65(r3->coeffs, 256, ctr[3], buf[3], buflen);
  }
  lcbase_shake256x4_release((&state));
  do { } while (0);
  do { } while (0);
  do { } while (0);
  do { } while (0);
  mld_zeroize(buf, sizeof(buf));
  mld_zeroize(extseed, sizeof(extseed));
}
void lcbase65_poly_uniform_eta(mld_poly *r, const uint8_t seed[64],
                          uint8_t nonce)
{
  __attribute__((aligned(32))) uint8_t
      buf[2 * 136];
  __attribute__((aligned(32))) uint8_t extseed[64 + 2];
  unsigned ctr;
  mld_shake256ctx state;
  unsigned buflen;
  memcpy(extseed, seed, 64);
  extseed[64] = nonce;
  extseed[64 + 1] = 0;
  lcbase_shake256_init(&state);
  do { lcbase_shake256_absorb(&state, extseed, 64 + 2); lcbase_shake256_finalize(&state); } while (0);
  lcbase_shake256_squeeze(buf, (2) * 136, &state);
  buflen = 2 * 136;
  ctr = mld_rej_eta65(r->coeffs, 256, 0, buf, buflen);
  buflen = 136;
  while (ctr < 256)
  {
    lcbase_shake256_squeeze(buf, (1) * 136, &state);
    ctr = mld_rej_eta65(r->coeffs, 256, ctr, buf, buflen);
  }
  lcbase_shake256_release(&state);
  do { } while (0);
  mld_zeroize(buf, sizeof(buf));
  mld_zeroize(extseed, sizeof(extseed));
}
void lcbase65_poly_uniform_gamma1(mld_poly *a, const uint8_t seed[64],
                             uint16_t nonce)
{
  uint8_t *buf=(uint8_t*)a;
  __attribute__((aligned(32))) uint8_t extseed[64 + 2];
  mld_shake256ctx state;
  memcpy(extseed, seed, 64);
  extseed[64] = (uint8_t)(nonce & 0xFF);
  extseed[64 + 1] = (uint8_t)(nonce >> 8);
  lcbase_shake256_init(&state);
  do { lcbase_shake256_absorb(&state, extseed, 64 + 2); lcbase_shake256_finalize(&state); } while (0);
  lcbase_shake256_squeeze(buf, (((640 + 136 - 1) / 136)) * 136, &state);
  lc_expand_gamma(a->coeffs,((int32_t)1 << 19)==(1<<17)?18:20,((int32_t)1 << 19));
  lcbase_shake256_release(&state);
  do { } while (0);
  mld_zeroize(extseed, sizeof(extseed));
}
extern void a127_mask_bytes(void*,void*,const unsigned char*,uint16_t,uint16_t);
static void lc_two_masks(mld_poly *a,mld_poly *b,const uint8_t seed[64],uint16_t na,uint16_t nb){a127_mask_bytes(a,b,seed,na,nb);lc_expand_gamma(a->coeffs,20,524288);lc_expand_gamma(b->coeffs,20,524288);}


void lcbase65_poly_challenge(mld_poly *c, const uint8_t seed[48])
{
  unsigned int i, j, pos;
  uint64_t signs;
  uint64_t offset;
  __attribute__((aligned(32))) uint8_t buf[136];
  mld_shake256ctx state;
  lcbase_shake256_init(&state);
  lcbase_shake256_absorb(&state, seed, 48);
  lcbase_shake256_finalize(&state);
  lcbase_shake256_squeeze(buf, 136, &state);
  signs = 0;
  for (i = 0; i < 8; i++)
  {
    signs |= (uint64_t)buf[i] << 8 * i;
  }
  pos = 8;
  memset(c, 0, sizeof(mld_poly));
  for (i = 256 - 49; i < 256; i++)
  {
    do
    {
      if (pos >= 136)
      {
        lcbase_shake256_squeeze(buf, 136, &state);
        pos = 0;
      }
      j = buf[pos++];
    } while (j > i);
    c->coeffs[i] = c->coeffs[j];
    offset = 2 * (signs & 1);
    c->coeffs[j] = 1 - (int32_t)offset;
    signs >>= 1;
  }
  do { } while (0);
  lcbase_shake256_release(&state);
  mld_zeroize(buf, sizeof(buf));
  mld_zeroize(&signs, sizeof(signs));
}
void lcbase65_polyeta_pack(uint8_t r[128], const mld_poly *a)
{
for(unsigned i=0;i<256;i+=8){
unsigned x0=(4u-(uint32_t)a->coeffs[i+0])&15u;
unsigned x1=(4u-(uint32_t)a->coeffs[i+1])&15u;
unsigned x2=(4u-(uint32_t)a->coeffs[i+2])&15u;
unsigned x3=(4u-(uint32_t)a->coeffs[i+3])&15u;
unsigned x4=(4u-(uint32_t)a->coeffs[i+4])&15u;
unsigned x5=(4u-(uint32_t)a->coeffs[i+5])&15u;
unsigned x6=(4u-(uint32_t)a->coeffs[i+6])&15u;
unsigned x7=(4u-(uint32_t)a->coeffs[i+7])&15u;
unsigned w0=(x0<<0)|(x1<<4)|(x2<<8)|(x3<<12)|(x4<<16)|(x5<<20)|(x6<<24)|(x7<<28);
__asm__("str %1,[%0]"::"r"(r+0),"r"(w0):"memory");
r+=4;
}
}
void lcbase65_polyeta_unpack(mld_poly *r, const uint8_t a[128])
{
for(unsigned i=0;i<256;i+=8){unsigned x;
__asm__("ldr %0,[%1]":"=r"(x):"r"(a):"memory");a+=4;
r->coeffs[i+0]=4-(int)((x>>0)&15u);
r->coeffs[i+1]=4-(int)((x>>4)&15u);
r->coeffs[i+2]=4-(int)((x>>8)&15u);
r->coeffs[i+3]=4-(int)((x>>12)&15u);
r->coeffs[i+4]=4-(int)((x>>16)&15u);
r->coeffs[i+5]=4-(int)((x>>20)&15u);
r->coeffs[i+6]=4-(int)((x>>24)&15u);
r->coeffs[i+7]=4-(int)((x>>28)&15u);
}
}
void lcbase65_polyz_pack(uint8_t r[640], const mld_poly *a)
{
  unsigned int i;
  uint32_t t[4];
  do { } while (0);
  for (i = 0; i < 256 / 2; i++)
  {
    t[0] = (uint32_t)(((int32_t)1 << 19) - a->coeffs[2 * i + 0]);
    t[1] = (uint32_t)(((int32_t)1 << 19) - a->coeffs[2 * i + 1]);
    r[5 * i + 0] = (uint8_t)((t[0]) & 0xFF);
    r[5 * i + 1] = (uint8_t)((t[0] >> 8) & 0xFF);
    r[5 * i + 2] = (uint8_t)((t[0] >> 16) & 0xFF);
    r[5 * i + 2] |= (uint8_t)((t[1] << 4) & 0xFF);
    r[5 * i + 3] = (uint8_t)((t[1] >> 4) & 0xFF);
    r[5 * i + 4] = (uint8_t)((t[1] >> 12) & 0xFF);
  }
}
static void mld_polyz_unpack_c65(
    mld_poly *r, const uint8_t a[640])
{
  unsigned int i;
  for (i = 0; i < 256 / 2; i++)
  {
    r->coeffs[2 * i + 0] = a[5 * i + 0];
    r->coeffs[2 * i + 0] |= (int32_t)a[5 * i + 1] << 8;
    r->coeffs[2 * i + 0] |= (int32_t)a[5 * i + 2] << 16;
    r->coeffs[2 * i + 0] &= 0xFFFFF;
    r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
    r->coeffs[2 * i + 1] |= (int32_t)a[5 * i + 3] << 4;
    r->coeffs[2 * i + 1] |= (int32_t)a[5 * i + 4] << 12;
    r->coeffs[2 * i + 0] = ((int32_t)1 << 19) - r->coeffs[2 * i + 0];
    r->coeffs[2 * i + 1] = ((int32_t)1 << 19) - r->coeffs[2 * i + 1];
  }
  do { } while (0);
}
void lcbase65_polyz_unpack(mld_poly *r, const uint8_t a[640])
{
  mld_polyz_unpack_c65(r, a);
}
void lcbase65_polyvecl_ntt(mld_polyvecl65 *v)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 5; i++)
  {
    lcbase_poly_ntt(&v->vec[i]);
  }
  do { } while (0);
}
uint32_t lcbase65_polyvecl_chknorm(const mld_polyvecl65 *v, int32_t bound)
{
  unsigned int i;
  uint32_t t = 0;
  do { } while (0);
  for (i = 0; i < 5; i++)
  {
    t |= lcbase_poly_chknorm(&v->vec[i], bound);
  }
  return t;
}
void lcbase65_polyveck_reduce(mld_polyveck65 *v)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 6; i++)
  {
    lcbase_poly_reduce(&v->vec[i]);
  }
  do { } while (0);
}
void lcbase65_polyveck_caddq(mld_polyveck65 *v)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 6; i++)
  {
    lcbase_poly_caddq(&v->vec[i]);
  }
  do { } while (0);
}
void lcbase65_polyveck_invntt_tomont(mld_polyveck65 *v)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 6; i++)
  {
    lcbase_poly_invntt_tomont(&v->vec[i]);
  }
  do { } while (0);
}
uint32_t lcbase65_polyveck_chknorm(const mld_polyveck65 *v, int32_t bound)
{
  unsigned int i;
  uint32_t t = 0;
  do { } while (0);
  for (i = 0; i < 6; i++)
  {
    t |= lcbase_poly_chknorm(&v->vec[i], bound);
  }
  return t;
}
void lcbase65_polyveck_decompose_pack_w1(
    uint8_t r[6 * 128], mld_polyveck65 *v0,
    mld_poly *scratch)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 6; i++)
  {
    lcbase65_poly_decompose(scratch, &v0->vec[i]);
    lcbase65_polyw1_pack(&r[i * 128], scratch);
  }
  do { } while (0);
}
void lcbase65_polyveck_pack_eta(uint8_t r[6 * 128],
                           const mld_polyveck65 *p)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 6; i++)
  {
    lcbase65_polyeta_pack(&r[i * 128], &p->vec[i]);
  }
}
void lcbase65_polyvecl_pack_eta(uint8_t r[5 * 128],
                           const mld_polyvecl65 *p)
{
  unsigned int i;
  do { } while (0);
  for (i = 0; i < 5; i++)
  {
    lcbase65_polyeta_pack(&r[i * 128], &p->vec[i]);
  }
}
void lcbase65_polyvecl_unpack_eta(
    mld_polyvecl65 *p, const uint8_t r[5 * 128])
{
  unsigned int i;
  for (i = 0; i < 5; i++)
  {
    lcbase65_polyeta_unpack(&p->vec[i], r + i * 128);
  }
  do { } while (0);
}
void lcbase65_polyvecl_unpack_z(mld_polyvecl65 *z,
                           const uint8_t r[5 * 640])
{
  unsigned int i;
  for (i = 0; i < 5; i++)
  {
    lcbase65_polyz_unpack(&z->vec[i], r + i * 640);
  }
  do { } while (0);
}
void lcbase65_polyveck_unpack_eta(
    mld_polyveck65 *p, const uint8_t r[6 * 128])
{
  unsigned int i;
  for (i = 0; i < 6; i++)
  {
    lcbase65_polyeta_unpack(&p->vec[i], r + i * 128);
  }
  do { } while (0);
}
static inline void mld_polymat_expand_entry65(
    mld_poly *p, uint8_t seed_ext[((((32 + 2) + (32 - 1)) / 32) * 32)], uint8_t l,
    uint8_t k)
{
  seed_ext[32 + 0] = l;
  seed_ext[32 + 1] = k;
  lcbase_poly_uniform(p, seed_ext);
  mld_poly_permute_bitrev_to_custom_optional65(p);
}
void lcbase65_polyvec_matrix_expand_lazy(mld_polymat_lazy65 *mat,
                                    const uint8_t rho[32])
{
  memcpy(mat->rho, rho, 32);
  mat->cache_ready = 0;
  mat->cache = ((void*)0);
}
void lcbase65_polyvec_matrix_pointwise_montgomery_row_lazy(mld_poly *t_row,
                                                      mld_polymat_lazy65 *mat,
                                                      const mld_polyvecl65 *v,
                                                      unsigned int i)
{
  unsigned int l;
  __attribute__((aligned(32))) uint8_t seed_ext[((((32 + 2) + (32 - 1)) / 32) * 32)];
  memcpy(seed_ext, mat->rho, 32);
  mld_polymat_expand_entry65(t_row, seed_ext, 0, (uint8_t)i);
  lcbase_poly_pointwise_montgomery(t_row, &v->vec[0]);
  for (l = 1; l < 5; l++)
  {
    mld_polymat_expand_entry65(&mat->cur, seed_ext, (uint8_t)l, (uint8_t)i);
    lcbase_poly_pointwise_montgomery(&mat->cur, &v->vec[l]);
    lcbase_poly_add(t_row, &mat->cur);
  }
  lcbase_poly_reduce(t_row);
  mld_zeroize(seed_ext, sizeof(seed_ext));
}
static inline void lc_polymat_cache_store(mld_polymat_lazy65 *mat,
                                             unsigned index,const mld_poly *p) {
  uint8_t *out=mat->cache[index];
  for(unsigned j=0;j<256;j++) {
    uint32_t u=(uint32_t)p->coeffs[j];
    out[3*j]=(uint8_t)u;out[3*j+1]=(uint8_t)(u>>8);out[3*j+2]=(uint8_t)(u>>16);
  }
}
static void lc_polymat_sign_entry(mld_poly *p,mld_polymat_lazy65 *mat,
    uint8_t *seed_ext,unsigned l,unsigned k) {
  const unsigned index=l*6 +k;
  if(mat->cache==((void*)0)) {
    mld_polymat_expand_entry65(p,seed_ext,(uint8_t)l,(uint8_t)k);
    return;
  }
  if(index<((12 < 6*5) ? 12 : 6*5) && mat->cache_ready) {
    const uint8_t *in=mat->cache[index];
    for(unsigned j=0;j<256;j++)
      p->coeffs[j]=(int32_t)((uint32_t)in[3*j]|((uint32_t)in[3*j+1]<<8)|((uint32_t)in[3*j+2]<<16));
    return;
  }
  mld_polymat_expand_entry65(p,seed_ext,(uint8_t)l,(uint8_t)k);
  if(index<((12 < 6*5) ? 12 : 6*5)) {
    lc_polymat_cache_store(mat,index,p);
  }
}
void lcbase65_polyvec_matrix_pointwise_montgomery_yvec_lazy(
    mld_polyveck65 *w, mld_polymat_lazy65 *mat, const mld_yvec_lazy65 *y,
    mld_yvec_scratch_lazy65 *scratch)
{
  unsigned int k, l;
  __attribute__((aligned(32))) uint8_t seed_ext[((((32 + 2) + (32 - 1)) / 32) * 32)];
  memcpy(seed_ext, mat->rho, 32);
  for (l = 0; l < 5; l++)
  {
    mld_yvec_get_poly_lazy65(scratch, y, l);
    lcbase_poly_ntt(scratch);
    for (k = 0; k < 6; k++)
    {
      if (l == 0)
      {
        lc_polymat_sign_entry(&w->vec[k],mat,seed_ext,0,k);
        lcbase_poly_pointwise_montgomery(&w->vec[k], scratch);
      }
      else
      {
        lc_polymat_sign_entry(&mat->cur,mat,seed_ext,l,k);
        lcbase_poly_pointwise_montgomery(&mat->cur, scratch);
        lcbase_poly_add(&w->vec[k], &mat->cur);
      }
    }
  }
  mld_zeroize(seed_ext, sizeof(seed_ext));
  mat->cache_ready=1;
  lcbase65_polyveck_reduce(w);
  lcbase65_polyveck_invntt_tomont(w);
}
__attribute__((warn_unused_result))
int lcbase65_keypair_internal (uint8_t pk[((0 + 32) + (6 * 320))], uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], const uint8_t seed[32], struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_keypair (uint8_t pk[((0 + 32) + (6 * 320))], uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_signature_internal (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen, const uint8_t rnd[32], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], int externalmu, struct lc_dsa_arena * context)
                                                                   ;
__attribute__((warn_unused_result))
int lcbase65_signature (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_signature_extmu (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t mu[64], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_verify_internal (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen, const uint8_t pk[((0 + 32) + (6 * 320))], int externalmu, struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_verify (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t pk[((0 + 32) + (6 * 320))], struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_verify_extmu (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t mu[64], const uint8_t pk[((0 + 32) + (6 * 320))], struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_signature_pre_hash_internal (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], int hashalg, struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_verify_pre_hash_internal (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t pk[((0 + 32) + (6 * 320))], int hashalg, struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_signature_pre_hash_shake256 (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
int lcbase65_verify_pre_hash_shake256 (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t pk[((0 + 32) + (6 * 320))], struct lc_dsa_arena * context)
 ;
__attribute__((warn_unused_result))
size_t lcbase65_prepare_domain_separation_prefix(
    uint8_t prefix[(2 + 255 + 11 + 64)], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen, int hashalg)
 ;
__attribute__((warn_unused_result))
int lcbase65_pk_from_sk (uint8_t pk[((0 + 32) + (6 * 320))], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
 ;
static inline unsigned lc_make_hint_secret(int32_t low,uint32_t high_nonzero) {
  uint32_t above=mld_ct_cmask_neg_i32(((8380417 - 1) / 32)-low);
  uint32_t below=mld_ct_cmask_neg_i32(low+((8380417 - 1) / 32));
  uint32_t equal=~mld_ct_cmask_nonzero_u32((uint32_t)(low+((8380417 - 1) / 32)));
  uint32_t nonzero=mld_ct_cmask_nonzero_u32(high_nonzero);
  return (above|below|(equal&nonzero))&1u;
}
static unsigned lc_hint_weight_exceeds(const uint8_t *flags, size_t rows,
                                      size_t stride, unsigned omega) {
  uint32_t weight = 0;
  for (size_t k = 0; k < rows; k++) {
    const uint8_t *p = flags + k * stride;
    for (size_t j = 0; j < 32; j += 4) {
      uint32_t x;
      memcpy(&x, p + j, sizeof(x));
      x -= (x >> 1) & 0x55555555U;
      x = (x & 0x33333333U) +
          ((x >> 2) & 0x33333333U);
      x = (x + (x >> 4)) & 0x0f0f0f0fU;
      weight += (x * 0x01010101U) >> 24;
    }
  }
  return weight > omega;
}
static void lc_pack_w0_row(uint8_t *out, const mld_poly *poly) {
for(unsigned i=0;i<256;i+=8){
uint32_t x0=(uint32_t)poly->coeffs[i+0]&524287u;
uint32_t x1=(uint32_t)poly->coeffs[i+1]&524287u;
uint32_t x2=(uint32_t)poly->coeffs[i+2]&524287u;
uint32_t x3=(uint32_t)poly->coeffs[i+3]&524287u;
uint32_t x4=(uint32_t)poly->coeffs[i+4]&524287u;
uint32_t x5=(uint32_t)poly->coeffs[i+5]&524287u;
uint32_t x6=(uint32_t)poly->coeffs[i+6]&524287u;
uint32_t x7=(uint32_t)poly->coeffs[i+7]&524287u;
__asm__("str %1,[%0]"::"r"(out+0),"r"((uint32_t)((x0)|(x1<<19))):"memory");
__asm__("str %1,[%0]"::"r"(out+4),"r"((uint32_t)((x1>>13)|(x2<<6)|(x3<<25))):"memory");
__asm__("str %1,[%0]"::"r"(out+8),"r"((uint32_t)((x3>>7)|(x4<<12)|(x5<<31))):"memory");
__asm__("str %1,[%0]"::"r"(out+12),"r"((uint32_t)((x5>>1)|(x6<<18))):"memory");
uint32_t last=(x6>>14)|(x7<<5);
__asm__("strh %1,[%0]"::"r"(out+16),"r"(last):"memory");
out[18]=(uint8_t)(last>>16);
out+=19;
}
}
static void lc_unpack_w0_row(mld_poly *poly, const uint8_t *in) {
for(unsigned i=0;i<256;i+=8){
uint32_t w0;__asm__("ldr %0,[%1]":"=r"(w0):"r"(in+0):"memory");
uint32_t w1;__asm__("ldr %0,[%1]":"=r"(w1):"r"(in+4):"memory");
uint32_t w2;__asm__("ldr %0,[%1]":"=r"(w2):"r"(in+8):"memory");
uint32_t w3;__asm__("ldr %0,[%1]":"=r"(w3):"r"(in+12):"memory");
uint32_t w4;__asm__("ldrh %0,[%1]":"=r"(w4):"r"(in+16):"memory");
w4|=((uint32_t)in[18])<<16;
uint32_t x0=w0;poly->coeffs[i+0]=(int32_t)(x0&262143u)-(int32_t)(x0&262144u);
uint32_t x1=(w0>>19)|(w1<<13);poly->coeffs[i+1]=(int32_t)(x1&262143u)-(int32_t)(x1&262144u);
uint32_t x2=w1>>6;poly->coeffs[i+2]=(int32_t)(x2&262143u)-(int32_t)(x2&262144u);
uint32_t x3=(w1>>25)|(w2<<7);poly->coeffs[i+3]=(int32_t)(x3&262143u)-(int32_t)(x3&262144u);
uint32_t x4=w2>>12;poly->coeffs[i+4]=(int32_t)(x4&262143u)-(int32_t)(x4&262144u);
uint32_t x5=(w2>>31)|(w3<<1);poly->coeffs[i+5]=(int32_t)(x5&262143u)-(int32_t)(x5&262144u);
uint32_t x6=(w3>>18)|(w4<<14);poly->coeffs[i+6]=(int32_t)(x6&262143u)-(int32_t)(x6&262144u);
uint32_t x7=w4>>5;poly->coeffs[i+7]=(int32_t)(x7&262143u)-(int32_t)(x7&262144u);
in+=19;
}
}
typedef struct { __attribute__((aligned(32))) uint8_t bytes[(6*((256*19/8)+(256/8)))+sizeof(mld_poly)]; } lc_sign_w0_storage;
_Static_assert(((6*((256*19/8)+(256/8)))>((6 -1)*(3*256))?(6*((256*19/8)+(256/8))):((6 -1)*(3*256)))+sizeof(mld_shake256ctx)<=sizeof(lc_sign_w0_storage),"stream hash must fit beyond compact rows and last NTT row");
_Static_assert(((6*((256*19/8)+(256/8)))>((6 -1)*(3*256))?(6*((256*19/8)+(256/8))):((6 -1)*(3*256)))%_Alignof(mld_shake256ctx)==0,"stream hash offset alignment");
_Static_assert(_Alignof(lc_sign_w0_storage)>=_Alignof(mld_shake256ctx),"stream hash storage alignment");
typedef uint8_t lc_packed_vecl[5][(3*256)];
typedef char lc_packed_w_fit[0 || sizeof(lc_sign_w0_storage)>=6*(3*256)?1:-1];
typedef char lc_packed_t_align[(6*((256*19/8)+(256/8)))%_Alignof(mld_poly)==0?1:-1];
static inline unsigned lc_matrix_native_index(unsigned i) {
  return i;
}
static inline void lc_stream_transform_order(mld_poly *p) {
  (void)p;
}

static inline uint32_t a127_public_u24(const uint8_t *p){uint32_t x;__asm__("ldrh %0,[%1]":"=r"(x):"r"(p):"memory");return (x|((uint32_t)p[2]<<16))&0x7fffffu;}
static inline int32_t a127_read24(const uint8_t *p){
    uint16_t lo;
    __asm__("ldrh %0,[%1]":"=r"(lo):"r"(p):"memory");
    return (int32_t)lo+((int32_t)(int8_t)p[2]*65536);
}
static inline void a127_write24(uint8_t *p,int32_t v){
    __asm__("strh %1,[%0]"::"r"(p),"r"(v):"memory");p[2]=(uint8_t)((uint32_t)v>>16);
}
static void lc_fused_matrix_y(uint8_t *out,const mld_poly *y,const uint8_t seed[34],unsigned first) {
  uint8_t buf[168];mld_shake128ctx state;unsigned ctr=0;
  lcbase_shake128_init(&state);do { lcbase_shake128_absorb(&state, seed, 34); lcbase_shake128_finalize(&state); } while (0);
  do {
    lcbase_shake128_squeeze(buf, (1) * 168, &state);
    for(unsigned j=0;ctr<256 && j+3<=168;j+=3) {
      uint32_t a=a127_public_u24(buf+j);
      if(a<8380417) {
        unsigned i=lc_matrix_native_index(ctr);
        uint8_t *v=out+3*i;
        int32_t x=a127_m4_mont_product(a,y->coeffs[i]);
        x+=first?0:a127_read24(v);a127_write24(v,mld_reduce32(x));ctr++;
      }
    }
  } while(ctr<256);
  lcbase_shake128_release(&state);mld_zeroize(buf,sizeof(buf));
}
static void lc_fused_matrix_v(mld_poly *out,const uint8_t *v,const uint8_t seed[34],unsigned first) {
  uint8_t buf[168];mld_shake128ctx state;unsigned ctr=0;
  lcbase_shake128_init(&state);do { lcbase_shake128_absorb(&state, seed, 34); lcbase_shake128_finalize(&state); } while (0);
  do {
    lcbase_shake128_squeeze(buf, (1) * 168, &state);
    for(unsigned j=0;ctr<256 && j+3<=168;j+=3) {
      uint32_t a=a127_public_u24(buf+j);
      if(a<8380417) {
        unsigned i=lc_matrix_native_index(ctr++);
        int32_t x=a127_m4_mont_product(a,a127_read24(v+3*i));
        out->coeffs[i]=first?x:out->coeffs[i]+x;
      }
    }
  } while(ctr<256);
  lcbase_shake128_release(&state);mld_zeroize(buf,sizeof(buf));
}
typedef a127_pending lc_pending_product;
static inline void lc_pair_add(uint8_t *w,const mld_poly *y,unsigned i,int32_t a,unsigned first)
{
  uint8_t *dest=w+3*i;
  int32_t product=a127_m4_mont_product(a,y->coeffs[i]);
  a127_write24(dest,mld_reduce32(product+(first?0:a127_read24(dest))));
}
extern unsigned a127_pair_block_plain(unsigned,const uint8_t*,uint8_t*,const int32_t*,uint8_t*,const int32_t*,uint8_t*,unsigned);
extern void a127_cached_row(const uint8_t*,uint8_t*,const int32_t*,uint8_t*,const int32_t*,unsigned);
struct y_store {uint16_t offset;uint8_t prefix;};
static const struct y_store a127_ys[] = {{0,2},{368,4},{464,4},{560,4},{656,4},{752,2},{1120,4},{1216,4},{1312,4},{1408,4}};
extern void a127_rho_begin(uint32_t *bits,const uint8_t *rho);
extern void a127_matrix_begin(uint64_t *state,const uint32_t *bits,unsigned c,unsigned r);

static inline unsigned a127_y65_margin(int32_t y){
    uint32_t u=(uint32_t)y,neg=0u-(u>>31);
    uint32_t magnitude=(u^neg)-neg;
    uint32_t d=524288u-magnitude;
    __asm__("usat %0,#10,%1":"=r"(d):"r"(d));
    return d | (neg & 1024u);
}
static void __attribute__((noinline)) a127_store65_margin(uint8_t *dst,const int32_t y[256]){
    unsigned word=0,bits=0;
    for(unsigned i=0;i<256;i++){
        word|=a127_y65_margin(y[i])<<bits;bits+=11;
        while(bits>=8){*dst++=(uint8_t)word;word>>=8;bits-=8;}
    }
}
static inline unsigned a127_bad65_margin(unsigned code,int32_t cs){
    uint32_t flip=0u-(code>>10);
    cs=mld_reduce32(cs);
    uint32_t directed=((uint32_t)cs^flip)-flip;
    return ((code & 1023u)-197u-directed)>>31;
}
static unsigned __attribute__((noinline)) a127_test65_margin(const uint8_t *src,const int32_t cs[256]){
    unsigned bad=0;
    unsigned word=0,bits=0;
    for(unsigned i=0;i<256;i++){
        while(bits<11){word|=(unsigned)*src++<<bits;bits+=8;}
        bad|=a127_bad65_margin(word&2047u,cs[i]);word>>=11;bits-=11;
    }
    return bad;
}

extern void three(void*,void*,void*);
extern void a127_extract_words(const void*,void*,unsigned);
static void a127_mask_three(void *a,void *b,void *c,const uint8_t *seed,uint16_t origin){
    uint8_t *dst[3]={a,b,c};uint64_t *state[3];
    for(unsigned k=0;k<3;k++){
        state[k]=(uint64_t*)(void*)(dst[k]+704);
        if(!k)memset(state[k],0,64);
        if(!k)pqm46_KeccakF1600_StateXORBytes(state[k],seed,0,64);
        else memcpy(state[k],state[0],64);
        uint32_t *w=(uint32_t*)(void*)state[k];unsigned nonce=origin+5*k;
        unsigned long long tail=(unsigned long long)nonce|0x1f0000ull;
        uint32_t even=0,odd=0;
        for(unsigned i=0;i<11;i++){even|=((tail>>(2*i))&1u)<<i;odd|=((tail>>(2*i+1))&1u)<<i;}
        w[16]=even;w[17]=odd;w[33]=0x80000000u;
    }
    for(unsigned j=0;j<5;j++){
        if(!j)three66(state[0],state[1],state[2]);else three(state[0],state[1],state[2]);
        for(unsigned k=0;k<3;k++)a127_extract_words(state[k],dst[k]+136*j,17);
    }
}
static void lc_pair_product(lc_pending_product *look,uint8_t *rows,mld_polymat65 *mat,const mld_yvec65 *y,mld_poly *current)
{

  _Static_assert(4*768<=3309,"signature scratch exceeded");

    _Static_assert(A127_TRIAL_CACHE_B>=4608+1024+30*112,"three-candidate storage");
    uint8_t *store=(uint8_t*)(void*)mat->cache;
    uint8_t *third_rows=store;
    mld_poly *third_mask=(mld_poly*)(void*)(store+4608);
    unsigned trial=(unsigned)y->kappa/5u;
    const unsigned phase=(trial+0u)%3u;
    if(look->pending_nonce==y->kappa){
        if(phase==2u)memcpy(rows,third_rows,4608);
        else {memcpy(rows,look->output,3072);memcpy(rows+3072,look->pending,1536);}
        look->pending_nonce=phase==1u && look->can_look_ahead ? (uint32_t)y->kappa+5u : 4294967295U;
        return;
    }
    const unsigned ahead=look->can_look_ahead ;
    const unsigned third=ahead && phase==0u && trial+2u<((65535u-5u)/5u)
                         && (unsigned)y->kappa+14u<=65535u;
  __attribute__((aligned(32))) uint8_t seed[((((32 +2) + (32 - 1)) / 32) * 32)];
  uint32_t *common=(uint32_t*)(void*)seed; a127_rho_begin(common,mat->rho);
  for(unsigned l=0;l<5;l++){
    if(ahead){
          if(third){
              a127_mask_three(current,&mat->cur,third_mask,y->rhoprime,(uint16_t)(y->kappa+l));
              if(l<2u)memcpy(store+6912+640u*l,third_mask,640);
              lc_expand_gamma(third_mask->coeffs,20,524288);
          }else a127_mask_bytes(current,&mat->cur,y->rhoprime,(uint16_t)(y->kappa+l),(uint16_t)(y->kappa+5+l));
          if(l<2u){
                memcpy(store+5632+640u*l,&mat->cur,640);

          }
          lc_expand_gamma(current->coeffs,20,524288);
          lc_expand_gamma(mat->cur.coeffs,20,524288);
          if(l<2u)a127_store65_margin(store+8192+352*l,current->coeffs);
        }
    else mld_yvec_get_poly_lazy65(current,y,l);
    lcbase_poly_ntt(current);lc_stream_transform_order(current);
    if(ahead){lcbase_poly_ntt(&mat->cur);lc_stream_transform_order(&mat->cur);
    }
    
    if(third){

        lcbase_poly_ntt(third_mask);lc_stream_transform_order(third_mask);
    }
    for(unsigned k=0;k<6;k+=4){
      unsigned n=6-k>=4?4:6-k;
      unsigned count[4]={0,0,256,256};
      if(n==4)count[2]=count[3]=0;
      unsigned round=0;
      uint8_t *tailp[4]={0,0};
      unsigned char *dst[4],*next[4],*cache[4]={0,0};
      _Static_assert(sizeof(lc_sign_w0_storage)>=6*768+1*200,"disjoint Keccak arena");
      uint64_t local[3][25];
      uint64_t (*backup)[25]=(uint64_t(*)[25])(void*)(rows+6*768);
      uint64_t *streams[4]={local[0],local[1],local[2],backup[0]};
      uint8_t block[168];
      for(unsigned side=0;side<n;++side){
        unsigned row=k+side, slot=l*6+row;
        if(slot<2u){
          tailp[side]=store+8896+112*slot;
          if(y->kappa==0)tailp[side][108]=0;
        }

        uint8_t *r0=rows+row*(3*256);
      unsigned saved=ahead && row<6;
      uint8_t *r1=saved ? (row<4?look->output+768*row:look->pending+768*(row-4)) : ((void*)0);
        dst[side]=r0;next[side]=r1;
        a127_matrix_begin(streams[side],common,l,row);
      }
      while(count[0]<256 || count[1]<256 || count[2]<256 || count[3]<256){
        if(round==4 && y->kappa){
          for(unsigned j=0;j<n;j++)if(count[j]<256 && tailp[j] && tailp[j][108]){
            memcpy(block,tailp[j],108);memset(block+108,255,60);
            
            if(third)count[j]=a127_three_block(count[j],block,dst[j],current->coeffs,next[j],mat->cur.coeffs,third_rows+768*(k+j),third_mask->coeffs,l==0);else count[j]=a127_pair_block_plain(count[j],block,dst[j],current->coeffs,next[j],mat->cur.coeffs,0,l==0);
          }
          if(count[0]==256 && count[1]==256 && count[2]==256 && count[3]==256)break;
        }
        if(round==0u){
          if(n==4 && count[0]<256 && count[1]<256 && count[2]<256 && count[3]<256)four34(streams[0],streams[1],streams[2],streams[3]);
          else for(unsigned j=0;j<n;j+=2){
              if(count[j]<256 && count[j+1]<256)two34(streams[j],streams[j+1]);
              else if(count[j]<256 || count[j+1]<256)two34(streams[j+(count[j]==256)],(void*)0);
          }
        }else if(count[0]<256 && count[1]<256 && count[2]<256 && count[3]<256){
          four(streams[0],streams[1],streams[2],streams[3]);
        } else {
          for(unsigned j=0;j<n;j+=2){
            if(count[j]<256 && count[j+1]<256)two(streams[j],streams[j+1]);
            else if(count[j]<256 || count[j+1]<256)pqm46_KeccakF1600_StatePermute(streams[j+(count[j]==256)]);
          }
        }
        for(unsigned side=0;side<n;++side){
          if(count[side]>=256)continue;
          a127_extract_words(streams[side],block,21);
          if(!y->kappa && round==4 && tailp[side] && count[side]>=220){
            unsigned good=0;
            for(unsigned j=0;j<108;j+=3)good+=(a127_public_u24(block+j)<8380417u);
            if(count[side]+good>=256){
              memcpy(tailp[side],block,108);tailp[side][108]=1;
            }
          }
          
          if(third)count[side]=a127_three_block(count[side],block,dst[side],current->coeffs,next[side],mat->cur.coeffs,third_rows+768*(k+side),third_mask->coeffs,l==0);else count[side]=a127_pair_block_plain(count[side],block,dst[side],current->coeffs,
              next[side],mat->cur.coeffs,cache[side],l==0);
        }
        round++;
      }
      mld_zeroize(local,sizeof(local));mld_zeroize(backup,200);mld_zeroize(block,sizeof(block));
    }

  }
  mat->cache_ready=1;
  if(ahead)look->pending_nonce=(uint32_t)y->kappa+5;
  mld_zeroize(seed,sizeof(seed));
}
static void lc_packed_ay(lc_pending_product *look, uint8_t *w,mld_polymat65 *mat,const mld_yvec65 *y,mld_poly *scratch
) {
  lc_pair_product(look,w,mat,y,scratch);
  return;
  __attribute__((aligned(32))) uint8_t seed[((((32 +2) + (32 - 1)) / 32) * 32)];
  memcpy(seed,mat->rho,32);
  for(unsigned l=0;l<5;l++) {
    mld_yvec_get_poly_lazy65(scratch,y,l);lcbase_poly_ntt(scratch);
    lc_stream_transform_order(scratch);
    for(unsigned k=0;k<6;k++) {
      const unsigned idx=l*6 +k;
      uint8_t *row_acc=w+k*(3*256);
      if(idx >= ((12 < 6*5) ? 12 : 6*5)) {
        seed[32]=(uint8_t)l; seed[33]=(uint8_t)k;
        lc_fused_matrix_y(row_acc,scratch,seed,l==0);
      } else {
        uint8_t *cache=mat->cache[idx];
        if(!mat->cache_ready) {
          mld_polymat_expand_entry65(&mat->cur,seed,(uint8_t)l,(uint8_t)k);
          for(unsigned j=0;j<256;j++) {
            uint32_t a=(uint32_t)mat->cur.coeffs[j];
            cache[3*j]=(uint8_t)a;cache[3*j+1]=(uint8_t)(a>>8);cache[3*j+2]=(uint8_t)(a>>16);
          }
        }
        for(unsigned j=0;j<256;j++) {
          const uint8_t *c=cache+3*j;
          uint32_t a=(uint32_t)c[0]|((uint32_t)c[1]<<8)|((uint32_t)c[2]<<16);
          int32_t z=a127_m4_mont_product(a,scratch->coeffs[j]);
          uint8_t *v=row_acc+3*j;
          lc_store_signed24(v,mld_reduce32(z+(l?lc_load_signed24(v):0)));
        }
      }
    }
  }
  mat->cache_ready=1;
  mld_zeroize(seed,sizeof(seed));
}
static void lc_pack_matrix_ntt24(uint8_t *out,mld_poly *p) {
  lc_stream_transform_order(p);
  for(unsigned j=0;j<256;j++)lc_store_signed24(out+3*j,mld_reduce32(p->coeffs[j]));
}
static void lc_packed_matrix_row(mld_poly *out,mld_polymat65 *mat,const lc_packed_vecl *v,unsigned k) {
  uint8_t seed[32 +2];
  memcpy(seed,mat->rho,32);
  for(unsigned l=0;l<5;l++) {
    seed[32]=(uint8_t)l;seed[33]=(uint8_t)k;
    lc_fused_matrix_v(out,(*v)[l],seed,l==0);
  }
  lcbase_poly_reduce(out);lc_stream_transform_order(out);mld_zeroize(seed,sizeof(seed));
}
static void lc_pack_ntt24(uint8_t *out,const mld_poly *p) {
  for(unsigned j=0;j<256;j++)lc_store_signed24(out+3*j,mld_reduce32(p->coeffs[j]));
}
extern void a127_inv_packed24(int32_t*,const uint8_t*);
extern void a127_split_19(const int32_t*,uint8_t*,uint8_t*,uint8_t*);
void __attribute__((noinline)) a127_split_19(const int32_t *a,uint8_t *low,uint8_t *high,uint8_t *nonzero){
for(unsigned group=0;group<32;group++,a+=8,low+=19,high+=4){
uint32_t x[8],h[8];
#pragma clang loop unroll(disable)
for(unsigned i=0;i<8;i++){
int32_t signed_a=a[i];uint32_t canonical=(uint32_t)(signed_a+((signed_a>>31)&8380417));
uint32_t adjusted=canonical+261887u;
int32_t hprod; __asm__("smmul %0,%1,%2":"=r"(hprod):"r"(adjusted),"r"(537395713u));
uint32_t n=(uint32_t)hprod>>16;
uint32_t wrap=n>>4;
x[i]=(canonical-n*523776u-wrap)&524287u;
h[i]=n-16u*wrap;
}
__asm__ volatile("str %1,[%0]"::"r"(low+0),"r"((x[0]|(x[1]<<19))):"memory");
__asm__ volatile("str %1,[%0]"::"r"(low+4),"r"(((x[1]>>13)|(x[2]<<6)|(x[3]<<25))):"memory");
__asm__ volatile("str %1,[%0]"::"r"(low+8),"r"(((x[3]>>7)|(x[4]<<12)|(x[5]<<31))):"memory");
__asm__ volatile("str %1,[%0]"::"r"(low+12),"r"(((x[5]>>1)|(x[6]<<18))):"memory");
__asm__ volatile("strh %1,[%0]"::"r"(low+16),"r"(((x[6]>>14)|(x[7]<<5))):"memory");
__asm__ volatile("strb %1,[%0]"::"r"(low+18),"r"((((x[6]>>14)|(x[7]<<5))>>16)):"memory");
__asm__ volatile("str %1,[%0]"::"r"(high+0),"r"((h[0]|(h[1]<<4)|(h[2]<<8)|(h[3]<<12)|(h[4]<<16)|(h[5]<<20)|(h[6]<<24)|(h[7]<<28))):"memory");
uint32_t packed=0; for(unsigned j=0;j<8;j++)packed|=((h[j]|(0u-h[j]))>>31)<<j;
nonzero[group]=(uint8_t)packed;
}
}
static void lc_sign_decompose_hash_bitmap(uint8_t *challenge,const uint8_t *mu,
    lc_sign_w0_storage *storage,mld_poly *saved_last,mld_poly *scratch) {
  uint8_t *bytes=storage->bytes,*saved=(uint8_t*)saved_last;
  uint8_t *encoded=saved+(3*256);
  mld_shake256ctx *state=(mld_shake256ctx*)(bytes+((6*((256*19/8)+(256/8)))>((6 -1)*(3*256))?(6*((256*19/8)+(256/8))):((6 -1)*(3*256))));
  memcpy(saved,bytes+(6 -1)*(3*256),(3*256));
  lcbase_shake256_init(state);lcbase_shake256_absorb(state,mu,64);
  for(unsigned k=0;k<6;k++) {
    const uint8_t *src=k==6 -1?saved:bytes+k*(3*256);
    uint8_t *row=bytes+k*((256*19/8)+(256/8)),*flags=row+(256*19/8);
    mld_poly *row_poly=scratch;
    a127_inv_packed24(row_poly->coeffs,src);
    a127_split_19(row_poly->coeffs,row,encoded,flags);
    lcbase_shake256_absorb(state,encoded,128);
  }
  lcbase_shake256_finalize(state);lcbase_shake256_squeeze(challenge,48,state);
  lcbase_shake256_release(state);mld_zeroize(state,sizeof(*state));
}
static unsigned lc_check_hint_weight_before_disclosure(const uint8_t *w0,
                                                       mld_poly *low) {
  unsigned total=0;
  for(unsigned k=0;k<6;k++) {
    const uint8_t *row=w0+k*((256*19/8)+(256/8));
    const uint8_t *flags=row+(256*19/8);
    lc_unpack_w0_row(low,row);
    for(unsigned j=0;j<256;j++) {
      unsigned high=(flags[j/8]>>(j%8))&1u;
      total+=lc_make_hint_secret(low->coeffs[j],high);
    }
  }
  return total>55;
}
static int lc_pack_sig_h_bitmap(uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))],
    const uint8_t *w0,mld_poly *low) {
  unsigned int j,k,n=0;
  uint8_t *sig_h=sig+((0 + 48) + (5 * 640));
  memset(sig_h,0,(55 + 6));
  for(k=0;k<6;k++) {
    const uint8_t *row=w0+k*((256*19/8)+(256/8));
    const uint8_t *flags=row+(256*19/8);
    (void)low;
    for(j=0;j<256;j++) {
      unsigned int retained_high=(flags[j/8]>>(j%8))&1u;
      unsigned int bit=retained_high;
      if(bit) {
        if(n==55) return (-1);
        sig_h[n]=(uint8_t)j;n++;
      }
    }
    sig_h[55 +k]=(uint8_t)n;
  }
  return 0;
}
static int mld_check_pct65 (uint8_t const pk[((0 + 32) + (6 * 320))], uint8_t const sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
 ;
static int mld_check_pct65 (uint8_t const pk[((0 + 32) + (6 * 320))], uint8_t const sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
{
  ((void)pk);
  ((void)sk);
  ((void)(context));
  return 0;
}
static void mld_sample_s1_s265(mld_polyvecl65 *s1, mld_polyveck65 *s2,
                             const uint8_t seed[64])
{
  lcbase65_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                          seed, 0, 1, 2, 3);
  lcbase65_poly_uniform_eta_4x(&s1->vec[4], &s2->vec[0], &s2->vec[1],
                          &s2->vec[2] , seed, 4, 5, 6,
                          0xFF );
  lcbase65_poly_uniform_eta_4x(&s2->vec[2], &s2->vec[3], &s2->vec[4], &s2->vec[5],
                          seed, 7, 8, 9, 10);
}
__attribute__((warn_unused_result))
static int mld_compute_pack_t0_t165 (uint8_t pk_t1[6 * 320], uint8_t t0_packed[6 * 416], const mld_polyvecl65 *s1hat, const mld_polyveck65 *s2, const uint8_t rho[32], struct lc_dsa_arena * context)
{
  unsigned int k;
  int ret;
  mld_polymat65 *mat = (mld_polymat65 *)lc_dsa_alloc(context,sizeof(mld_polymat65)*(1));
  mld_poly *t0k = (mld_poly *)lc_dsa_alloc(context,sizeof(mld_poly)*(1));
  mld_poly *t1k = (mld_poly *)lc_dsa_alloc(context,sizeof(mld_poly)*(1));
  if (mat == ((void*)0) || t0k == ((void*)0) || t1k == ((void*)0))
  {
    ret = (-2);
    goto cleanup;
  }
  lcbase65_polyvec_matrix_expand_lazy(mat, rho);
  for (k = 0; k < 6; k++)
  {
    lcbase65_polyvec_matrix_pointwise_montgomery_row_lazy(t0k, mat, s1hat, k);
    lcbase_poly_invntt_tomont(t0k);
    lcbase_poly_add(t0k, &s2->vec[k]);
    lcbase_poly_reduce(t0k);
    lcbase_poly_caddq(t0k);
    lcbase_poly_power2round(t1k, t0k, t0k);
    lcbase_polyt1_pack(pk_t1 + k * 320, t1k);
    lcbase_polyt0_pack(t0_packed + k * 416, t0k);
  }
  ret = 0;
cleanup:
  do { if (t1k != ((void*)0)) { mld_zeroize(t1k, sizeof(mld_poly) * (1)); lc_dsa_free(context,t1k,sizeof(mld_poly)*(1)); t1k = ((void*)0); } } while (0);
  do { if (t0k != ((void*)0)) { mld_zeroize(t0k, sizeof(mld_poly) * (1)); lc_dsa_free(context,t0k,sizeof(mld_poly)*(1)); t0k = ((void*)0); } } while (0);
  do { if (mat != ((void*)0)) { mld_zeroize(mat, sizeof(mld_polymat65) * (1)); lc_dsa_free(context,mat,sizeof(mld_polymat65)*(1)); mat = ((void*)0); } } while (0);
  return ret;
}
__attribute__((warn_unused_result))
int lcbase65_keypair_internal (uint8_t pk[((0 + 32) + (6 * 320))], uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], const uint8_t seed[32], struct lc_dsa_arena * context)
{return a127_dsa_keygen(&selected_dsa_route,pk,sk,seed,context);}
__attribute__((warn_unused_result))
int lcbase65_keypair (uint8_t pk[((0 + 32) + (6 * 320))], uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
{
  int ret;
  uint8_t *seed = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(32));
  if (seed == ((void*)0))
  {
    ret = (-2);
    goto cleanup;
  }
  if (lc_dsa_system_random(seed, 32) != 0)
  {
    ret = (-3);
    goto cleanup;
  }
  do { } while (0);
  ret = lcbase65_keypair_internal (pk, sk, seed, context);
cleanup:
  do { if (seed != ((void*)0)) { mld_zeroize(seed, sizeof(uint8_t) * (32)); lc_dsa_free(context,seed,sizeof(uint8_t)*(32)); seed = ((void*)0); } } while (0);
  return ret;
}
static void mld_H65(uint8_t *out, size_t outlen, const uint8_t *in1,
                  size_t in1len, const uint8_t *in2, size_t in2len,
                  const uint8_t *in3, size_t in3len)
{
  mld_shake256ctx state;
  lcbase_shake256_init(&state);
  lcbase_shake256_absorb(&state, in1, in1len);
  if (in2len != 0)
  {
    lcbase_shake256_absorb(&state, in2, in2len);
  }
  if (in3len != 0)
  {
    lcbase_shake256_absorb(&state, in3, in3len);
  }
  lcbase_shake256_finalize(&state);
  lcbase_shake256_squeeze(out, outlen, &state);
  lcbase_shake256_release(&state);
  mld_zeroize(&state, sizeof(state));
}
__attribute__((warn_unused_result))
extern unsigned a127_z20(int32_t *z,const uint8_t *in,uint8_t *out,unsigned limit);
unsigned a127_z20(int32_t *z,const uint8_t *in,uint8_t *out,unsigned limit){unsigned bad=0;for(unsigned j=0;j<256;j+=2){
uint32_t a;__asm__("ldr %0,[%1]":"=r"(a):"r"(in):"memory");uint32_t b=in[4];
int32_t zz0=mld_reduce32(z[j+0]+524288-(int32_t)((a)&1048575u));
                z[j+0]=zz0;uint32_t u0=(uint32_t)zz0,m0=0u-(u0>>31);bad|=(limit-1u-((u0^m0)-m0))>>31;
int32_t zz1=mld_reduce32(z[j+1]+524288-(int32_t)(((a>>20)|(b<<12))&1048575u));
                z[j+1]=zz1;uint32_t u1=(uint32_t)zz1,m1=0u-(u1>>31);bad|=(limit-1u-((u1^m1)-m1))>>31;
uint32_t enc0=(524288u-(uint32_t)zz0)&1048575u;
uint32_t enc1=(524288u-(uint32_t)zz1)&1048575u;
if(out){
uint32_t word=enc0|(enc1<<20);__asm__("str %1,[%0]"::"r"(out),"r"(word):"memory");out[4]=(uint8_t)(enc1>>12);
out+=5;}
in+=5;}return bad;}
extern void a127_z_mask_prefix(uint8_t*,const uint32_t*,uint16_t,unsigned);
__attribute__((noinline)) void a127_z_mask_prefix(uint8_t *dst,const uint32_t *prefix,uint16_t coord,unsigned blocks){
            uint64_t state[25];uint32_t a=coord&0x5555u,b=(coord>>1)&0x5555u;
            a=(a|(a>>1))&0x3333u;b=(b|(b>>1))&0x3333u;
            a=(a|(a>>2))&0x0f0fu;b=(b|(b>>2))&0x0f0fu;
            a=((a|(a>>4))&255u)|0x700u;b=((b|(b>>4))&255u)|0x300u;
            memcpy(state,prefix,64);memset(state+8,0,136);
            state[8]=(uint64_t)a|((uint64_t)b<<32);state[16]=(uint64_t)1<<63;
            for(unsigned i=0;i<blocks;i++){
                if(!i)two66(state,(void*)0);else pqm46_KeccakF1600_StatePermute(state);a127_extract_words(state,dst+136*i,17);
            }
            mld_zeroize(state,sizeof state);
        }
static int mld_compute_pack_z65(const mld_poly *wave_s1,const uint8_t *edge, uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))],
                              const mld_poly *cp, const mld_sk_s1hat65 *s1hat,
                              const mld_yvec65 *y, mld_poly *z, mld_poly *tmp, unsigned lc_canonical_secret, const uint8_t *retained
                              )
{
  unsigned int i;
  uint32_t prefix[16];
  /* The existing polynomial output below has a separate lifetime from this
     prefix. Each closure uses fixed addresses and only public LE16 coordinates. */
  {
      uint64_t *st=(uint64_t*)(void*)tmp;memset(st,0,200);
      pqm46_KeccakF1600_StateXORBytes(st,y->rhoprime,0,64);
      memcpy(prefix,st,sizeof prefix);mld_zeroize(st,200);
  }

  uint32_t z_invalid;
  for (i = 0; i < 5; i++)
  {
    const unsigned column=0?(i==0?5 -1:i-1):i;
    if(column==0)memcpy(z,wave_s1,sizeof(*z));else mld_sk_s1hat_get_poly_lazy65(z,s1hat,column);
    lcbase_poly_pointwise_montgomery(z, cp);
    lcbase_poly_invntt_tomont(z);
    if(!sig && column<2u){
        z_invalid=a127_test65_margin(edge+352*column,z->coeffs);
    } else {
    const uint8_t *raw_response=(const uint8_t*)tmp;
    if(retained && column<2u)raw_response=retained+640u*column;
        else a127_z_mask_prefix((uint8_t*)tmp,prefix,(uint16_t)(y->kappa+column),5);
    z_invalid=a127_z20(z->coeffs,raw_response,sig?sig+48+640*column:(uint8_t*)0,524092u);

    }
    do { } while (0);
    if (z_invalid)
    {
      mld_zeroize(prefix,sizeof prefix);return (-1);
    }
    do { } while (0);
    
  }
  mld_zeroize(prefix,sizeof prefix);return 0;
}
__attribute__((warn_unused_result))
static inline uint16_t mld_get_max_signing_attempts65(void)
{
            ;
  return ((65535U - 5) / 5);
}
__attribute__((warn_unused_result))
static int mld_attempt_signature_generation65 (lc_pending_product *look, uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *mu, const uint8_t rhoprime[64], uint16_t kappa, mld_polymat65 *mat, const mld_sk_s1hat65 *s1hat, const mld_sk_s2hat65 *s2hat, const mld_sk_t0hat65 *t0hat, unsigned lc_canonical_secret, struct lc_dsa_arena * context)
{
  unsigned int k;
  uint32_t w0_invalid, h_invalid;
  unsigned hint_total=0;
  int ret;
  typedef union
  {
    mld_yvec_scratch65 y;
    mld_poly w;
  } scratch_u;
  mld_yvec_scratch65 *scratch_yvec;
  mld_poly *scratch_w;
  uint8_t *challenge_bytes = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(48 +64*0));
  mld_yvec65 *y = (mld_yvec65 *)lc_dsa_alloc(context,sizeof(mld_yvec65)*(1));
  scratch_u *scratch = (scratch_u *)lc_dsa_alloc(context,sizeof(scratch_u)*(1));
  lc_sign_w0_storage *w0_storage = (lc_sign_w0_storage *)lc_dsa_alloc(context,sizeof(lc_sign_w0_storage)*(1));
  uint8_t *w0=w0_storage==((void*)0)?((void*)0):w0_storage->bytes;
  mld_poly *cp = &mat->cur;
  mld_poly *t=w0==((void*)0)?((void*)0):(mld_poly*)(w0+(6*((256*19/8)+(256/8))));
  if (
      challenge_bytes == ((void*)0) || y == ((void*)0) || scratch == ((void*)0) ||
      w0 == ((void*)0) || cp == ((void*)0) || t == ((void*)0)
      )
  {
    ret = (-2);
    goto cleanup;
  }
  scratch_yvec = &scratch->y;
  scratch_w = &scratch->w;
  mld_yvec_init_lazy65(y, rhoprime, kappa
  );
  /* The last legal nonce need not have a next candidate. A paired
       retry can still consume its predecessor's saved, exactly matching raw mask. */
    unsigned phase=((unsigned)kappa/5u)%3u;
        const uint8_t *retained=(look->pending_nonce==kappa && phase) ?
            ((const uint8_t*)(const void*)mat->cache+5632u+(phase-1u)*1280u) : (const uint8_t*)0;
    lc_packed_ay(look, w0,mat,y,scratch_yvec
               );

    mld_poly *wave_s1=(mld_poly*)(void*)((uint8_t*)mat->cache+4608);
    /* phase zero has finished every matrix multiplication for the wave.
       Phases one and two only load retained rows and leave this slot live. */
    if(((unsigned)kappa/5u)%3u==0u)mld_sk_s1hat_get_poly_lazy65(wave_s1,s1hat,0);
  lc_sign_decompose_hash_bitmap(challenge_bytes,mu,w0_storage,cp,scratch_w);
  do { } while (0);
  lcbase65_poly_challenge(cp, challenge_bytes);
  lcbase_poly_ntt(cp);
  const unsigned needs_output=(((unsigned)kappa/5u+0u)%3u==0u && look->pending_nonce==(uint32_t)kappa+5u);
  ret = mld_compute_pack_z65(wave_s1,(const uint8_t*)(const void*)mat->cache+8192,needs_output?((void*)0):sig, cp, s1hat, y, t, scratch_w, lc_canonical_secret,retained
                           );
  if (ret != 0)
  {
    goto cleanup;
  }
  for (k = 0; k < 6; k++)
  {
    lc_unpack_w0_row(t,(const uint8_t*)w0+k*((256*19/8)+(256/8)));
    mld_sk_s2hat_get_poly_lazy65(scratch_w, s2hat, k);
    lcbase_poly_pointwise_montgomery(scratch_w, cp);
    lcbase_poly_invntt_tomont(scratch_w);
    
    uint32_t overflow=0;
    for(unsigned jj=0;jj<256;jj++){
        int32_t v=mld_reduce32(t->coeffs[jj]-scratch_w->coeffs[jj]);
        t->coeffs[jj]=v;
        uint32_t u=(uint32_t)v,sgn=0u-(u>>31);
        overflow|=((unsigned)(((8380417 - 1) / 32) - 196)-1u-((u^sgn)-sgn))>>31;
    }
    w0_invalid=overflow;
    do { } while (0);
    if (w0_invalid)
    {
      ret = (-1);
      goto cleanup;
    }
    lc_pack_w0_row((uint8_t*)w0+k*((256*19/8)+(256/8)),t);
  }
  for (k = 0; k < 6; k++)
  {
    lc_unpack_w0_row(t,(const uint8_t*)w0+k*((256*19/8)+(256/8)));
    mld_sk_t0hat_get_poly_lazy65(scratch_w, t0hat, k);
    lcbase_poly_pointwise_montgomery(scratch_w, cp);
    lcbase_poly_invntt_tomont(scratch_w);
    uint32_t invalid_hint_norm=0;uint8_t *old_high=w0+k*640+608;
    for(unsigned group=0;group<32;group++){
        unsigned high=old_high[group],hints=0;
        for(unsigned bit=0;bit<8;bit++){
            unsigned index=8*group+bit;
            int32_t t0=mld_reduce32(scratch_w->coeffs[index]);
            uint32_t v=(uint32_t)t0,neg=0u-(v>>31);
            invalid_hint_norm|=(261888u-1u-((v^neg)-neg))>>31;
            unsigned h=lc_make_hint_secret(t->coeffs[index]+t0,(high>>bit)&1u);
            hints|=h<<bit;hint_total+=h;
        }
        old_high[group]=(uint8_t)hints;
    }
    if(invalid_hint_norm){ret=-1;goto cleanup;}


  }
  {
    unsigned hint_invalid=hint_total>55u;
    do { } while (0);
    if(hint_invalid) {
      ret=(-1);
      goto cleanup;
    }
  }
  do { } while (0);
  if(needs_output){ret=mld_compute_pack_z65(wave_s1,(const uint8_t*)(const void*)mat->cache+8192,sig,cp,s1hat,y,t,scratch_w,lc_canonical_secret,retained);
  if(ret)goto cleanup;}
  lcbase65_pack_sig_c(sig, challenge_bytes);
  ret=lc_pack_sig_h_bitmap(sig,(const uint8_t*)w0,t);
  if (ret != 0)
  {
    goto cleanup;
  }
  do { } while (0);
  ret = 0;
cleanup:
  do { if (w0_storage != ((void*)0)) { mld_zeroize(w0_storage, sizeof(lc_sign_w0_storage) * (1)); lc_dsa_free(context,w0_storage,sizeof(lc_sign_w0_storage)*(1)); w0_storage = ((void*)0); } } while (0);
  do { if (scratch != ((void*)0)) { mld_zeroize(scratch, sizeof(scratch_u) * (1)); lc_dsa_free(context,scratch,sizeof(scratch_u)*(1)); scratch = ((void*)0); } } while (0);
  do { if (y != ((void*)0)) { mld_zeroize(y, sizeof(mld_yvec65) * (1)); lc_dsa_free(context,y,sizeof(mld_yvec65)*(1)); y = ((void*)0); } } while (0);
  do { if (challenge_bytes != ((void*)0)) { mld_zeroize(challenge_bytes, sizeof(uint8_t) * (48 +64*0)); lc_dsa_free(context,challenge_bytes,sizeof(uint8_t)*(48 +64*0)); challenge_bytes = ((void*)0); } } while (0);
  return ret;
}
static void shared_route_unpack(a127_sign_state *s,const uint8_t *sk){
    uint8_t *seed=s->slot[D_SEED];
    lcbase65_unpack_sk(seed,seed+32,seed+96,s->slot[D_T0],s->slot[D_S1],s->slot[D_S2],sk);
}
static void shared_route_matrix(a127_sign_state *s){
    mld_polymat65 *mat=s->slot[D_MATRIX];
    lcbase65_polyvec_matrix_expand_lazy(mat,s->slot[D_SEED]);
    mat->cache=s->slot[D_ACACHE];
}
static int shared_route_attempt(a127_sign_state *s,uint8_t *sig,uint16_t kappa,struct lc_dsa_arena *a){
    uint8_t *seed=s->slot[D_SEED];
    return mld_attempt_signature_generation65(&s->look,sig,seed+128,seed+192,kappa,
        s->slot[D_MATRIX],s->slot[D_S1],s->slot[D_S2],s->slot[D_T0],0,a);
}
static const a127_sign_route shared_sign_route={
    6,5,3309,((65535U-5)/5),
    {256,sizeof(mld_polymat65),A127_TRIAL_CACHE_B,2*768,sizeof(mld_sk_s1hat65),sizeof(mld_sk_t0hat65),sizeof(mld_sk_s2hat65)},
    lc_dsa_alloc,lc_dsa_free,shared_route_unpack,mld_H65,shared_route_matrix,shared_route_attempt
};
__attribute__((warn_unused_result))
int lcbase65_signature_internal (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen, const uint8_t rnd[32], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], int externalmu, struct lc_dsa_arena * context)
{ return a127_sign_message(&shared_sign_route,sig,m,mlen,pre,prelen,rnd,sk,externalmu,context); }
__attribute__((warn_unused_result))
int lcbase65_signature (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
{
  size_t pre_len;
  int ret;
  uint8_t *pre = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*((2 + 255 + 11 + 64)));
  uint8_t *rnd = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(32));
  if (pre == ((void*)0) || rnd == ((void*)0))
  {
    ret = (-2);
    goto cleanup;
  }
  pre_len = lcbase65_prepare_domain_separation_prefix(pre, ((void*)0), 0, ctx, ctxlen,
                                                 0);
  if (pre_len == 0)
  {
    ret = (-9);
    goto cleanup;
  }
  if (lc_dsa_system_random(rnd, 32) != 0)
  {
    ret = (-3);
    goto cleanup;
  }
  do { } while (0);
  ret = lcbase65_signature_internal (sig, m, mlen, pre, pre_len, rnd, sk, 0, context);
cleanup:
  if (ret != 0)
  {
    mld_zeroize(sig, (((0 + 48) + (5 * 640)) + (55 + 6)));
  }
  do { if (rnd != ((void*)0)) { mld_zeroize(rnd, sizeof(uint8_t) * (32)); lc_dsa_free(context,rnd,sizeof(uint8_t)*(32)); rnd = ((void*)0); } } while (0);
  do { if (pre != ((void*)0)) { mld_zeroize(pre, sizeof(uint8_t) * ((2 + 255 + 11 + 64))); lc_dsa_free(context,pre,sizeof(uint8_t)*((2 + 255 + 11 + 64))); pre = ((void*)0); } } while (0);
  return ret;
}
__attribute__((warn_unused_result))
int lcbase65_signature_extmu (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t mu[64], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
{
  int ret;
  uint8_t *rnd = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(32));
  if (rnd == ((void*)0))
  {
    ret = (-2);
    goto cleanup;
  }
  if (lc_dsa_system_random(rnd, 32) != 0)
  {
    ret = (-3);
    goto cleanup;
  }
  do { } while (0);
  ret = lcbase65_signature_internal (sig, mu, 64, ((void*)0), 0, rnd, sk, 1, context);
cleanup:
  do { if (rnd != ((void*)0)) { mld_zeroize(rnd, sizeof(uint8_t) * (32)); lc_dsa_free(context,rnd,sizeof(uint8_t)*(32)); rnd = ((void*)0); } } while (0);
  return ret;
}
static void lc_verify_mu_segments65(uint8_t out[64],const uint8_t tr[64],
 const uint8_t *pre,size_t prelen,const uint8_t *pre1,size_t prelen1,
 const uint8_t *message,size_t message_length) {
 mld_shake256ctx state;
 lcbase_shake256_init(&state);
 lcbase_shake256_absorb(&state,tr,64);
 if(prelen)lcbase_shake256_absorb(&state,pre,prelen);
 if(prelen1)lcbase_shake256_absorb(&state,pre1,prelen1);
 if(message_length)lcbase_shake256_absorb(&state,message,message_length);
 lcbase_shake256_finalize(&state);lcbase_shake256_squeeze(out,64,&state);
 lcbase_shake256_release(&state);mld_zeroize(&state,sizeof(state));
}
__attribute__((warn_unused_result))
static int lcbase65_verify_segments (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen, const uint8_t *pre1, size_t prelen1, const uint8_t pk[((0 + 32) + (6 * 320))], int externalmu, struct lc_dsa_arena * context)
{return a127_dsa_verify(&selected_dsa_route,sig,m,mlen,pre,prelen,pre1,prelen1,pk,externalmu,context);}
__attribute__((warn_unused_result))
int lcbase65_verify_internal (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *pre, size_t prelen, const uint8_t pk[((0 + 32) + (6 * 320))], int externalmu, struct lc_dsa_arena * context)
{
  return lcbase65_verify_segments (sig, m, mlen, pre, prelen, ((void*)0), 0, pk, externalmu, context);
}
__attribute__((warn_unused_result))
int lcbase65_verify (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t pk[((0 + 32) + (6 * 320))], struct lc_dsa_arena * context)
{
  uint8_t pre[2];int ret;
  if(ctxlen>255)return (-9);
  pre[0]=0;pre[1]=(uint8_t)ctxlen;
  ret=lcbase65_verify_segments (sig, m, mlen, pre, 2, ctx, ctxlen, pk, 0, context);
  mld_zeroize(pre,sizeof(pre));
  return ret;
}
__attribute__((warn_unused_result))
int lcbase65_verify_extmu (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t mu[64], const uint8_t pk[((0 + 32) + (6 * 320))], struct lc_dsa_arena * context)
{
  return lcbase65_verify_internal (sig, mu, 64, ((void*)0), 0, pk, 1, context);
}
__attribute__((warn_unused_result))
int lcbase65_signature_pre_hash_internal (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], int hashalg, struct lc_dsa_arena * context)
{
  __attribute__((aligned(32))) uint8_t pre[(2 + 255 + 11 + 64)];
  size_t pre_len;
  int ret;
  if (hashalg == 0)
  {
    ret = (-9);
    goto cleanup;
  }
  pre_len = lcbase65_prepare_domain_separation_prefix(pre, ph, phlen, ctx, ctxlen,
                                                 hashalg);
  if (pre_len == 0)
  {
    ret = (-9);
    goto cleanup;
  }
  ret = lcbase65_signature_internal (sig, pre, pre_len, ((void*)0), 0, rnd, sk, 0, context);
cleanup:
  if (ret != 0)
  {
    mld_zeroize(sig, (((0 + 48) + (5 * 640)) + (55 + 6)));
  }
  mld_zeroize(pre, sizeof(pre));
  return ret;
}
__attribute__((warn_unused_result))
int lcbase65_verify_pre_hash_internal (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen, const uint8_t pk[((0 + 32) + (6 * 320))], int hashalg, struct lc_dsa_arena * context)
{
  __attribute__((aligned(32))) uint8_t pre[(2 + 255 + 11 + 64)];
  size_t pre_len;
  int ret;
  if (hashalg == 0)
  {
    ret = (-9);
    goto cleanup;
  }
  pre_len = lcbase65_prepare_domain_separation_prefix(pre, ph, phlen, ctx, ctxlen,
                                                 hashalg);
  if (pre_len == 0)
  {
    ret = (-9);
    goto cleanup;
  }
  ret = lcbase65_verify_internal (sig, pre, pre_len, ((void*)0), 0, pk, 0, context);
cleanup:
  mld_zeroize(pre, sizeof(pre));
  return ret;
}
__attribute__((warn_unused_result))
int lcbase65_signature_pre_hash_shake256 (uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[32], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
{
  __attribute__((aligned(32))) uint8_t ph[64];
  int ret;
  lcbase_shake256(ph, sizeof(ph), m, mlen);
  ret = lcbase65_signature_pre_hash_internal (sig, ph, sizeof(ph), ctx, ctxlen, rnd, sk, 12, context);
  mld_zeroize(ph, sizeof(ph));
  return ret;
}
__attribute__((warn_unused_result))
int lcbase65_verify_pre_hash_shake256 (const uint8_t sig[(((0 + 48) + (5 * 640)) + (55 + 6))], const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t pk[((0 + 32) + (6 * 320))], struct lc_dsa_arena * context)
{
  __attribute__((aligned(32))) uint8_t ph[64];
  int ret;
  lcbase_shake256(ph, sizeof(ph), m, mlen);
  ret = lcbase65_verify_pre_hash_internal (sig, ph, sizeof(ph), ctx, ctxlen, pk, 12, context);
  mld_zeroize(ph, sizeof(ph));
  return ret;
}
static void mld_get_hash_oid65(uint8_t oid[11], int hashalg)
{
  unsigned int i;
  static const struct
  {
    int alg;
    uint8_t oid[11];
  } oid_map[] = {
      {1,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}},
      {2,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}},
      {3,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}},
      {4,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}},
      {5,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05}},
      {6,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06}},
      {7,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07}},
      {8,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08}},
      {9,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09}},
      {10,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A}},
      {11,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B}},
      {12,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C}}};
  for (i = 0; i < sizeof(oid_map) / sizeof(oid_map[0]); i++)
  {
    if (oid_map[i].alg == hashalg)
    {
      memcpy(oid, oid_map[i].oid, 11);
      return;
    }
  }
}
static int mld_validate_hash_length65(int hashalg, size_t len)
{
  switch (hashalg)
  {
    case 1:
      return (len == 224 / 8) ? 0 : -1;
    case 2:
      return (len == 256 / 8) ? 0 : -1;
    case 3:
      return (len == 384 / 8) ? 0 : -1;
    case 4:
      return (len == 512 / 8) ? 0 : -1;
    case 5:
      return (len == 224 / 8) ? 0 : -1;
    case 6:
      return (len == 256 / 8) ? 0 : -1;
    case 7:
      return (len == 224 / 8) ? 0 : -1;
    case 8:
      return (len == 256 / 8) ? 0 : -1;
    case 9:
      return (len == 384 / 8) ? 0 : -1;
    case 10:
      return (len == 512 / 8) ? 0 : -1;
    case 11:
      return (len == 256 / 8) ? 0 : -1;
    case 12:
      return (len == 512 / 8) ? 0 : -1;
    default:
      return -1;
  }
}
size_t lcbase65_prepare_domain_separation_prefix(
    uint8_t prefix[(2 + 255 + 11 + 64)], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen, int hashalg)
{
  if (ctxlen > 255)
  {
    return 0;
  }
  if (hashalg != 0)
  {
    if (ph == ((void*)0) || mld_validate_hash_length65(hashalg, phlen) != 0)
    {
      return 0;
    }
  }
  prefix[0] = (hashalg == 0) ? 0 : 1;
  prefix[1] = (uint8_t)ctxlen;
  if (ctxlen > 0)
  {
    memcpy(prefix + 2, ctx, ctxlen);
  }
  if (hashalg == 0)
  {
    return 2 + ctxlen;
  }
  mld_get_hash_oid65(prefix + 2 + ctxlen, hashalg);
  memcpy(prefix + 2 + ctxlen + 11, ph, phlen);
  return 2 + ctxlen + 11 + phlen;
}
int lcbase65_pk_from_sk (uint8_t pk[((0 + 32) + (6 * 320))], const uint8_t sk[((((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)) + (6 * 416))], struct lc_dsa_arena * context)
{
  uint8_t check, cmp0, cmp1, chk1, chk2;
  int ret;
  uint8_t *rho = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(32));
  uint8_t *tr = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(64));
  uint8_t *tr_computed = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(64));
  uint8_t *key = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(32));
  mld_polyvecl65 *s1 = (mld_polyvecl65 *)lc_dsa_alloc(context,sizeof(mld_polyvecl65)*(1));
  mld_polyveck65 *s2 = (mld_polyveck65 *)lc_dsa_alloc(context,sizeof(mld_polyveck65)*(1));
  uint8_t *t0_packed = (uint8_t *)lc_dsa_alloc(context,sizeof(uint8_t)*(6 *416));
  if (rho == ((void*)0) || tr == ((void*)0) || tr_computed == ((void*)0) || key == ((void*)0) ||
      s1 == ((void*)0) || s2 == ((void*)0) || t0_packed == ((void*)0))
  {
    ret = (-2);
    goto cleanup;
  }
  memcpy(rho, sk + 0, 32);
  memcpy(key, sk + (0 + 32), 32);
  memcpy(tr, sk + ((0 + 32) + 32), 64);
  lcbase65_polyvecl_unpack_eta(s1, sk + (((0 + 32) + 32) + 64));
  lcbase65_polyveck_unpack_eta(s2, sk + ((((0 + 32) + 32) + 64) + (5 * 128)));
  chk1 = lcbase65_polyvecl_chknorm(s1, 4 + 1) & 0xFF;
  chk2 = lcbase65_polyveck_chknorm(s2, 4 + 1) & 0xFF;
  lcbase65_polyvecl_ntt(s1);
  memcpy(pk + 0, rho, 32);
  ret = mld_compute_pack_t0_t165 (pk + (0 + 32), t0_packed, s1, s2, rho, context);
  if (ret != 0)
  {
    goto cleanup;
  }
  cmp0 = mld_ct_memcmp(t0_packed, sk + (((((0 + 32) + 32) + 64) + (5 * 128)) + (6 * 128)),
                       6 * 416);
  lcbase_shake256(tr_computed, 64, pk, ((0 + 32) + (6 * 320)));
  cmp1 = mld_ct_memcmp((const uint8_t *)tr, (const uint8_t *)tr_computed,
                       64);
  check = mld_value_barrier_u8(cmp0 | cmp1 | chk1 | chk2);
  do { } while (0);
  ret = (check != 0) ? (-7) : 0;
cleanup:
  if (ret != 0)
  {
    mld_zeroize(pk, ((0 + 32) + (6 * 320)));
  }
  do { } while (0);
  do { if (t0_packed != ((void*)0)) { mld_zeroize(t0_packed, sizeof(uint8_t) * (6 *416)); lc_dsa_free(context,t0_packed,sizeof(uint8_t)*(6 *416)); t0_packed = ((void*)0); } } while (0);
  do { if (s2 != ((void*)0)) { mld_zeroize(s2, sizeof(mld_polyveck65) * (1)); lc_dsa_free(context,s2,sizeof(mld_polyveck65)*(1)); s2 = ((void*)0); } } while (0);
  do { if (s1 != ((void*)0)) { mld_zeroize(s1, sizeof(mld_polyvecl65) * (1)); lc_dsa_free(context,s1,sizeof(mld_polyvecl65)*(1)); s1 = ((void*)0); } } while (0);
  do { if (key != ((void*)0)) { mld_zeroize(key, sizeof(uint8_t) * (32)); lc_dsa_free(context,key,sizeof(uint8_t)*(32)); key = ((void*)0); } } while (0);
  do { if (tr_computed != ((void*)0)) { mld_zeroize(tr_computed, sizeof(uint8_t) * (64)); lc_dsa_free(context,tr_computed,sizeof(uint8_t)*(64)); tr_computed = ((void*)0); } } while (0);
  do { if (tr != ((void*)0)) { mld_zeroize(tr, sizeof(uint8_t) * (64)); lc_dsa_free(context,tr,sizeof(uint8_t)*(64)); tr = ((void*)0); } } while (0);
  do { if (rho != ((void*)0)) { mld_zeroize(rho, sizeof(uint8_t) * (32)); lc_dsa_free(context,rho,sizeof(uint8_t)*(32)); rho = ((void*)0); } } while (0);
  return ret;
}
static void keccak_init(uint64_t s[25])
{
  memset(s, 0, sizeof(uint64_t) * 25);
}
static unsigned int keccak_absorb(uint64_t s[25],
                                  unsigned int pos, unsigned int r,
                                  const uint8_t *in, size_t inlen)
{
  while (inlen >= r - pos)
  {
    lcbase_keccakf1600_xor_bytes(s, in, pos, r - pos);
    inlen -= r - pos;
    in += r - pos;
    lcbase_keccakf1600_permute(s);
    pos = 0;
  }
  lcbase_keccakf1600_xor_bytes(s, in, pos, (unsigned)inlen);
  return (unsigned)(pos + inlen);
}
static void keccak_finalize(uint64_t s[25], unsigned int pos,
                            unsigned int r, uint8_t p)
{
  uint8_t b = 0x80;
  lcbase_keccakf1600_xor_bytes(s, &p, pos, 1);
  lcbase_keccakf1600_xor_bytes(s, &b, r - 1, 1);
}
static unsigned int keccak_squeeze(uint8_t *out, size_t outlen,
                                   uint64_t s[25],
                                   unsigned int pos, unsigned int r)
{
  unsigned int i;
  size_t out_offset = 0;
  size_t bytes_to_go = outlen;
  while (bytes_to_go > 0)
  {
    if (pos == r)
    {
      lcbase_keccakf1600_permute(s);
      pos = 0;
    }
    i = bytes_to_go < r - pos ? (unsigned)bytes_to_go : r - pos;
    lcbase_keccakf1600_extract_bytes(s, out + out_offset, pos, i);
    bytes_to_go -= i;
    pos += i;
    out_offset += i;
  }
  return pos;
}
void lcbase_shake128_init(mld_shake128ctx *state)
{
  keccak_init(state->s);
  state->pos = 0;
}
void lcbase_shake128_absorb(mld_shake128ctx *state, const uint8_t *in,
                         size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, 168, in, inlen);
}
void lcbase_shake128_finalize(mld_shake128ctx *state)
{
  keccak_finalize(state->s, state->pos, 168, 0x1F);
  state->pos = 168;
}
void lcbase_shake128_squeeze(uint8_t *out, size_t outlen, mld_shake128ctx *state)
{
  state->pos = keccak_squeeze(out, outlen, state->s, state->pos, 168);
}
void lcbase_shake128_release(mld_shake128ctx *state)
{
  mld_zeroize(state, sizeof(mld_shake128ctx));
}
void lcbase_shake256_init(mld_shake256ctx *state)
{
  keccak_init(state->s);
  state->pos = 0;
}
void lcbase_shake256_absorb(mld_shake256ctx *state, const uint8_t *in,
                         size_t inlen)
{
  state->pos = keccak_absorb(state->s, state->pos, 136, in, inlen);
}
void lcbase_shake256_finalize(mld_shake256ctx *state)
{
  keccak_finalize(state->s, state->pos, 136, 0x1F);
  state->pos = 136;
}
void lcbase_shake256_squeeze(uint8_t *out, size_t outlen, mld_shake256ctx *state)
{
  state->pos = keccak_squeeze(out, outlen, state->s, state->pos, 136);
}
void lcbase_shake256_release(mld_shake256ctx *state)
{
  mld_zeroize(state, sizeof(mld_shake256ctx));
}
void lcbase_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  mld_shake256ctx state;
  lcbase_shake256_init(&state);
  lcbase_shake256_absorb(&state, in, inlen);
  lcbase_shake256_finalize(&state);
  lcbase_shake256_squeeze(out, outlen, &state);
  lcbase_shake256_release(&state);
}
static void mld_keccak_absorb_once_x4(uint64_t *s, unsigned r,
                                      const uint8_t *in0, const uint8_t *in1,
                                      const uint8_t *in2, const uint8_t *in3,
                                      size_t inlen, uint8_t p)
{
  while (inlen >= r)
  {
    lcbase_keccakf1600x4_xor_bytes(s, in0, in1, in2, in3, 0, r);
    lcbase_keccakf1600x4_permute(s);
    in0 += r;
    in1 += r;
    in2 += r;
    in3 += r;
    inlen -= r;
  }
  if (inlen > 0)
  {
    lcbase_keccakf1600x4_xor_bytes(s, in0, in1, in2, in3, 0, (unsigned)inlen);
  }
  if (inlen == r - 1)
  {
    p |= 128;
    lcbase_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, (unsigned)inlen, 1);
  }
  else
  {
    lcbase_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, (unsigned)inlen, 1);
    p = 128;
    lcbase_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, r - 1, 1);
  }
}
static void mld_keccak_squeezeblocks_x4(uint8_t *out0, uint8_t *out1,
                                        uint8_t *out2, uint8_t *out3,
                                        size_t nblocks, uint64_t *s, unsigned r)
{
  size_t current_offset = 0;
  while (nblocks > 0)
  {
    lcbase_keccakf1600x4_permute(s);
    lcbase_keccakf1600x4_extract_bytes(
        s, &out0[current_offset], &out1[current_offset], &out2[current_offset],
        &out3[current_offset], 0, r);
    current_offset += r;
    nblocks--;
  }
}
void lcbase_shake256x4_absorb_once(mld_shake256x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen)
{
  memset(state, 0, sizeof(mld_shake256x4ctx));
  mld_keccak_absorb_once_x4(state->ctx, 136, in0, in1, in2, in3,
                            inlen, 0x1F);
}
void lcbase_shake256x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mld_shake256x4ctx *state)
{
  mld_keccak_squeezeblocks_x4(out0, out1, out2, out3, nblocks, state->ctx,
                              136);
}
void lcbase_shake256x4_init(mld_shake256x4ctx *state) { (void)state; }
void lcbase_shake256x4_release(mld_shake256x4ctx *state)
{
  mld_zeroize(state, sizeof(mld_shake256x4ctx));
}
void lcbase_keccakf1600_extract_bytes(uint64_t *state, unsigned char *data,
                                   unsigned offset, unsigned length)
{pqm46_KeccakF1600_StateExtractBytes(state,data,offset,length);}
void lcbase_keccakf1600_xor_bytes(uint64_t *state, const unsigned char *data,
                               unsigned offset, unsigned length)
{pqm46_KeccakF1600_StateXORBytes(state,data,offset,length);}
static void mld_keccakf1600x4_extract_bytes_c(uint64_t *state,
                                              unsigned char *data0,
                                              unsigned char *data1,
                                              unsigned char *data2,
                                              unsigned char *data3,
                                              unsigned offset, unsigned length)
{
  lcbase_keccakf1600_extract_bytes(state + 25 * 0, data0, offset,
                                length);
  lcbase_keccakf1600_extract_bytes(state + 25 * 1, data1, offset,
                                length);
  lcbase_keccakf1600_extract_bytes(state + 25 * 2, data2, offset,
                                length);
  lcbase_keccakf1600_extract_bytes(state + 25 * 3, data3, offset,
                                length);
}
void lcbase_keccakf1600x4_extract_bytes(uint64_t *state, unsigned char *data0,
                                     unsigned char *data1, unsigned char *data2,
                                     unsigned char *data3, unsigned offset,
                                     unsigned length)
{
  mld_keccakf1600x4_extract_bytes_c(state, data0, data1, data2, data3, offset,
                                    length);
}
static void mld_keccakf1600x4_xor_bytes_c(uint64_t *state,
                                          const unsigned char *data0,
                                          const unsigned char *data1,
                                          const unsigned char *data2,
                                          const unsigned char *data3,
                                          unsigned offset, unsigned length)
{
  lcbase_keccakf1600_xor_bytes(state + 25 * 0, data0, offset,
                            length);
  lcbase_keccakf1600_xor_bytes(state + 25 * 1, data1, offset,
                            length);
  lcbase_keccakf1600_xor_bytes(state + 25 * 2, data2, offset,
                            length);
  lcbase_keccakf1600_xor_bytes(state + 25 * 3, data3, offset,
                            length);
}
void lcbase_keccakf1600x4_xor_bytes(uint64_t *state, const unsigned char *data0,
                                 const unsigned char *data1,
                                 const unsigned char *data2,
                                 const unsigned char *data3, unsigned offset,
                                 unsigned length)
{
  mld_keccakf1600x4_xor_bytes_c(state, data0, data1, data2, data3, offset,
                                length);
}
void lcbase_keccakf1600x4_permute(uint64_t *state)
{
  lcbase_keccakf1600_permute(state + 25 * 0);
  lcbase_keccakf1600_permute(state + 25 * 1);
  lcbase_keccakf1600_permute(state + 25 * 2);
  lcbase_keccakf1600_permute(state + 25 * 3);
}
static const uint64_t mld_KeccakF_RoundConstants[24] = {
    (uint64_t)0x0000000000000001ULL, (uint64_t)0x0000000000008082ULL,
    (uint64_t)0x800000000000808aULL, (uint64_t)0x8000000080008000ULL,
    (uint64_t)0x000000000000808bULL, (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008009ULL,
    (uint64_t)0x000000000000008aULL, (uint64_t)0x0000000000000088ULL,
    (uint64_t)0x0000000080008009ULL, (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL, (uint64_t)0x800000000000008bULL,
    (uint64_t)0x8000000000008089ULL, (uint64_t)0x8000000000008003ULL,
    (uint64_t)0x8000000000008002ULL, (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL, (uint64_t)0x800000008000000aULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008080ULL,
    (uint64_t)0x0000000080000001ULL, (uint64_t)0x8000000080008008ULL};
static
void mld_keccakf1600_permute_c(uint64_t *state)
{
  unsigned round;
  uint64_t Aba, Abe, Abi, Abo, Abu;
  uint64_t Aga, Age, Agi, Ago, Agu;
  uint64_t Aka, Ake, Aki, Ako, Aku;
  uint64_t Ama, Ame, Ami, Amo, Amu;
  uint64_t Asa, Ase, Asi, Aso, Asu;
  uint64_t BCa, BCe, BCi, BCo, BCu;
  uint64_t Da, De, Di, Do, Du;
  uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
  uint64_t Ega, Ege, Egi, Ego, Egu;
  uint64_t Eka, Eke, Eki, Eko, Eku;
  uint64_t Ema, Eme, Emi, Emo, Emu;
  uint64_t Esa, Ese, Esi, Eso, Esu;
  Aba = state[0];
  Abe = state[1];
  Abi = state[2];
  Abo = state[3];
  Abu = state[4];
  Aga = state[5];
  Age = state[6];
  Agi = state[7];
  Ago = state[8];
  Agu = state[9];
  Aka = state[10];
  Ake = state[11];
  Aki = state[12];
  Ako = state[13];
  Aku = state[14];
  Ama = state[15];
  Ame = state[16];
  Ami = state[17];
  Amo = state[18];
  Amu = state[19];
  Asa = state[20];
  Ase = state[21];
  Asi = state[22];
  Aso = state[23];
  Asu = state[24];
  for (round = 0; round < 24; round += 2)
  {
    BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
    Da = BCu ^ (((BCe) << (1)) ^ ((BCe) >> (64 - (1))));
    De = BCa ^ (((BCi) << (1)) ^ ((BCi) >> (64 - (1))));
    Di = BCe ^ (((BCo) << (1)) ^ ((BCo) >> (64 - (1))));
    Do = BCi ^ (((BCu) << (1)) ^ ((BCu) >> (64 - (1))));
    Du = BCo ^ (((BCa) << (1)) ^ ((BCa) >> (64 - (1))));
    Aba ^= Da;
    BCa = Aba;
    Age ^= De;
    BCe = (((Age) << (44)) ^ ((Age) >> (64 - (44))));
    Aki ^= Di;
    BCi = (((Aki) << (43)) ^ ((Aki) >> (64 - (43))));
    Amo ^= Do;
    BCo = (((Amo) << (21)) ^ ((Amo) >> (64 - (21))));
    Asu ^= Du;
    BCu = (((Asu) << (14)) ^ ((Asu) >> (64 - (14))));
    Eba = BCa ^ ((~BCe) & BCi);
    Eba ^= (uint64_t)mld_KeccakF_RoundConstants[round];
    Ebe = BCe ^ ((~BCi) & BCo);
    Ebi = BCi ^ ((~BCo) & BCu);
    Ebo = BCo ^ ((~BCu) & BCa);
    Ebu = BCu ^ ((~BCa) & BCe);
    Abo ^= Do;
    BCa = (((Abo) << (28)) ^ ((Abo) >> (64 - (28))));
    Agu ^= Du;
    BCe = (((Agu) << (20)) ^ ((Agu) >> (64 - (20))));
    Aka ^= Da;
    BCi = (((Aka) << (3)) ^ ((Aka) >> (64 - (3))));
    Ame ^= De;
    BCo = (((Ame) << (45)) ^ ((Ame) >> (64 - (45))));
    Asi ^= Di;
    BCu = (((Asi) << (61)) ^ ((Asi) >> (64 - (61))));
    Ega = BCa ^ ((~BCe) & BCi);
    Ege = BCe ^ ((~BCi) & BCo);
    Egi = BCi ^ ((~BCo) & BCu);
    Ego = BCo ^ ((~BCu) & BCa);
    Egu = BCu ^ ((~BCa) & BCe);
    Abe ^= De;
    BCa = (((Abe) << (1)) ^ ((Abe) >> (64 - (1))));
    Agi ^= Di;
    BCe = (((Agi) << (6)) ^ ((Agi) >> (64 - (6))));
    Ako ^= Do;
    BCi = (((Ako) << (25)) ^ ((Ako) >> (64 - (25))));
    Amu ^= Du;
    BCo = (((Amu) << (8)) ^ ((Amu) >> (64 - (8))));
    Asa ^= Da;
    BCu = (((Asa) << (18)) ^ ((Asa) >> (64 - (18))));
    Eka = BCa ^ ((~BCe) & BCi);
    Eke = BCe ^ ((~BCi) & BCo);
    Eki = BCi ^ ((~BCo) & BCu);
    Eko = BCo ^ ((~BCu) & BCa);
    Eku = BCu ^ ((~BCa) & BCe);
    Abu ^= Du;
    BCa = (((Abu) << (27)) ^ ((Abu) >> (64 - (27))));
    Aga ^= Da;
    BCe = (((Aga) << (36)) ^ ((Aga) >> (64 - (36))));
    Ake ^= De;
    BCi = (((Ake) << (10)) ^ ((Ake) >> (64 - (10))));
    Ami ^= Di;
    BCo = (((Ami) << (15)) ^ ((Ami) >> (64 - (15))));
    Aso ^= Do;
    BCu = (((Aso) << (56)) ^ ((Aso) >> (64 - (56))));
    Ema = BCa ^ ((~BCe) & BCi);
    Eme = BCe ^ ((~BCi) & BCo);
    Emi = BCi ^ ((~BCo) & BCu);
    Emo = BCo ^ ((~BCu) & BCa);
    Emu = BCu ^ ((~BCa) & BCe);
    Abi ^= Di;
    BCa = (((Abi) << (62)) ^ ((Abi) >> (64 - (62))));
    Ago ^= Do;
    BCe = (((Ago) << (55)) ^ ((Ago) >> (64 - (55))));
    Aku ^= Du;
    BCi = (((Aku) << (39)) ^ ((Aku) >> (64 - (39))));
    Ama ^= Da;
    BCo = (((Ama) << (41)) ^ ((Ama) >> (64 - (41))));
    Ase ^= De;
    BCu = (((Ase) << (2)) ^ ((Ase) >> (64 - (2))));
    Esa = BCa ^ ((~BCe) & BCi);
    Ese = BCe ^ ((~BCi) & BCo);
    Esi = BCi ^ ((~BCo) & BCu);
    Eso = BCo ^ ((~BCu) & BCa);
    Esu = BCu ^ ((~BCa) & BCe);
    BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
    Da = BCu ^ (((BCe) << (1)) ^ ((BCe) >> (64 - (1))));
    De = BCa ^ (((BCi) << (1)) ^ ((BCi) >> (64 - (1))));
    Di = BCe ^ (((BCo) << (1)) ^ ((BCo) >> (64 - (1))));
    Do = BCi ^ (((BCu) << (1)) ^ ((BCu) >> (64 - (1))));
    Du = BCo ^ (((BCa) << (1)) ^ ((BCa) >> (64 - (1))));
    Eba ^= Da;
    BCa = Eba;
    Ege ^= De;
    BCe = (((Ege) << (44)) ^ ((Ege) >> (64 - (44))));
    Eki ^= Di;
    BCi = (((Eki) << (43)) ^ ((Eki) >> (64 - (43))));
    Emo ^= Do;
    BCo = (((Emo) << (21)) ^ ((Emo) >> (64 - (21))));
    Esu ^= Du;
    BCu = (((Esu) << (14)) ^ ((Esu) >> (64 - (14))));
    Aba = BCa ^ ((~BCe) & BCi);
    Aba ^= (uint64_t)mld_KeccakF_RoundConstants[round + 1];
    Abe = BCe ^ ((~BCi) & BCo);
    Abi = BCi ^ ((~BCo) & BCu);
    Abo = BCo ^ ((~BCu) & BCa);
    Abu = BCu ^ ((~BCa) & BCe);
    Ebo ^= Do;
    BCa = (((Ebo) << (28)) ^ ((Ebo) >> (64 - (28))));
    Egu ^= Du;
    BCe = (((Egu) << (20)) ^ ((Egu) >> (64 - (20))));
    Eka ^= Da;
    BCi = (((Eka) << (3)) ^ ((Eka) >> (64 - (3))));
    Eme ^= De;
    BCo = (((Eme) << (45)) ^ ((Eme) >> (64 - (45))));
    Esi ^= Di;
    BCu = (((Esi) << (61)) ^ ((Esi) >> (64 - (61))));
    Aga = BCa ^ ((~BCe) & BCi);
    Age = BCe ^ ((~BCi) & BCo);
    Agi = BCi ^ ((~BCo) & BCu);
    Ago = BCo ^ ((~BCu) & BCa);
    Agu = BCu ^ ((~BCa) & BCe);
    Ebe ^= De;
    BCa = (((Ebe) << (1)) ^ ((Ebe) >> (64 - (1))));
    Egi ^= Di;
    BCe = (((Egi) << (6)) ^ ((Egi) >> (64 - (6))));
    Eko ^= Do;
    BCi = (((Eko) << (25)) ^ ((Eko) >> (64 - (25))));
    Emu ^= Du;
    BCo = (((Emu) << (8)) ^ ((Emu) >> (64 - (8))));
    Esa ^= Da;
    BCu = (((Esa) << (18)) ^ ((Esa) >> (64 - (18))));
    Aka = BCa ^ ((~BCe) & BCi);
    Ake = BCe ^ ((~BCi) & BCo);
    Aki = BCi ^ ((~BCo) & BCu);
    Ako = BCo ^ ((~BCu) & BCa);
    Aku = BCu ^ ((~BCa) & BCe);
    Ebu ^= Du;
    BCa = (((Ebu) << (27)) ^ ((Ebu) >> (64 - (27))));
    Ega ^= Da;
    BCe = (((Ega) << (36)) ^ ((Ega) >> (64 - (36))));
    Eke ^= De;
    BCi = (((Eke) << (10)) ^ ((Eke) >> (64 - (10))));
    Emi ^= Di;
    BCo = (((Emi) << (15)) ^ ((Emi) >> (64 - (15))));
    Eso ^= Do;
    BCu = (((Eso) << (56)) ^ ((Eso) >> (64 - (56))));
    Ama = BCa ^ ((~BCe) & BCi);
    Ame = BCe ^ ((~BCi) & BCo);
    Ami = BCi ^ ((~BCo) & BCu);
    Amo = BCo ^ ((~BCu) & BCa);
    Amu = BCu ^ ((~BCa) & BCe);
    Ebi ^= Di;
    BCa = (((Ebi) << (62)) ^ ((Ebi) >> (64 - (62))));
    Ego ^= Do;
    BCe = (((Ego) << (55)) ^ ((Ego) >> (64 - (55))));
    Eku ^= Du;
    BCi = (((Eku) << (39)) ^ ((Eku) >> (64 - (39))));
    Ema ^= Da;
    BCo = (((Ema) << (41)) ^ ((Ema) >> (64 - (41))));
    Ese ^= De;
    BCu = (((Ese) << (2)) ^ ((Ese) >> (64 - (2))));
    Asa = BCa ^ ((~BCe) & BCi);
    Ase = BCe ^ ((~BCi) & BCo);
    Asi = BCi ^ ((~BCo) & BCu);
    Aso = BCo ^ ((~BCu) & BCa);
    Asu = BCu ^ ((~BCa) & BCe);
  }
  state[0] = Aba;
  state[1] = Abe;
  state[2] = Abi;
  state[3] = Abo;
  state[4] = Abu;
  state[5] = Aga;
  state[6] = Age;
  state[7] = Agi;
  state[8] = Ago;
  state[9] = Agu;
  state[10] = Aka;
  state[11] = Ake;
  state[12] = Aki;
  state[13] = Ako;
  state[14] = Aku;
  state[15] = Ama;
  state[16] = Ame;
  state[17] = Ami;
  state[18] = Amo;
  state[19] = Amu;
  state[20] = Asa;
  state[21] = Ase;
  state[22] = Asi;
  state[23] = Aso;
  state[24] = Asu;
}
void lcbase_keccakf1600_permute(uint64_t *state)
{pqm46_KeccakF1600_StatePermute(state);}

extern void a127_column_rows(int32_t*,const uint8_t*,const uint8_t*,unsigned,unsigned);
extern void a127_matrix_rows(int32_t *,const uint8_t *,const uint8_t *,unsigned,unsigned,void *);
extern unsigned a127_dense_block(unsigned,const uint8_t *,int32_t *,const uint8_t *,unsigned);
static void dsa_prep_s(void *s,void *t,const uint8_t *rho,unsigned i,uint8_t *sk){
 lcbase65_poly_uniform_eta(t,rho,(uint8_t)i);lcbase65_polyeta_pack(sk,t);lcbase_poly_ntt(t);lcbase_poly_reduce(t);memcpy((uint8_t*)s+i*1024,t,sizeof(mld_poly));
}
static void dsa_init_mat(void *m,const uint8_t *rho){lcbase65_polyvec_matrix_expand_lazy(m,rho);}
static void dsa_key_row(void *row,void *mat,void *s,const uint8_t *rho,void *t,unsigned i,uint8_t *sk){a127_column_rows((int32_t*)row,((mld_polymat65*)mat)->rho,s,5,i);(void)rho;(void)t;(void)sk;}
extern void a127_power2_wire(const int32_t*,const int32_t*,uint8_t*,uint8_t*);
static void dsa_finish_key(void *w,void *t,const uint8_t *rho,unsigned n,uint8_t*s2,uint8_t*t1,uint8_t*t0){
 lcbase_poly_invntt_tomont(w);lcbase65_poly_uniform_eta(t,rho,(uint8_t)n);lcbase65_polyeta_pack(s2,t);
 a127_power2_wire(w,t,t1,t0);
}
static int dsa_z(void *t,void *z,const uint8_t *bytes,unsigned i){(void)t;
    mld_poly *out=(mld_poly*)z+i;
    unsigned lo=197u,span=1048182u,bad=0;
    for(unsigned j=0;j<256;j+=2,bytes+=5){
        uint32_t a;__asm__("ldr %0,[%1]":"=r"(a):"r"(bytes):"memory");
        unsigned last=bytes[4];
        unsigned w0=a&1048575u,d0=w0-lo;bad|=d0|(span-d0);out->coeffs[j+0]=524288-(int32_t)w0;
        unsigned w1=((a>>20)|(last<<12))&1048575u,d1=w1-lo;bad|=d1|(span-d1);out->coeffs[j+1]=524288-(int32_t)w1;
    }
    if(bad>>31)return -6;
    lcbase_poly_ntt(out);lcbase_poly_reduce(out);return 0;
}
static void dsa_verify_init(void *state,void *cp,void *mat,const uint8_t *mu,const uint8_t *pk,const uint8_t *sig){
 lcbase_shake256_init(state);lcbase_shake256_absorb(state,mu,64);lcbase65_polyvec_matrix_expand_lazy(mat,pk);lcbase65_poly_challenge(cp,sig);lcbase_poly_ntt(cp);
}
extern int a127_hint_wire(const void*,void*,const uint8_t*,unsigned,unsigned,unsigned);
extern void a127_shifted_t1(int32_t*,const uint8_t*);
extern void a127_verify_product(int32_t*,const int32_t*,const int32_t*);
static int dsa_verify_row(void *w,void *mat,void *z,void*cp,void*t,const uint8_t *sig,const uint8_t *pk,unsigned i){
 a127_column_rows((int32_t*)w,((mld_polymat65*)mat)->rho,z,5,i);
 a127_shifted_t1((int32_t*)t,pk+32+i*320);lcbase_poly_ntt(t);a127_verify_product(w,t,cp);lcbase_poly_invntt_tomont(w);
 return a127_hint_wire(w,t,sig+3248,i,6,55);
}
static void dsa_absorb_row(void *s,const uint8_t*d,size_t n){lcbase_shake256_absorb(s,d,n);}
static int dsa_verify_finish(void*s,uint8_t*out,const uint8_t*challenge,size_t n){
 lcbase_shake256_finalize(s);lcbase_shake256_squeeze(out,n,s);return mld_ct_memcmp(challenge,out,n)==0?0:-6;
}
static void dsa_hash_done(void*s){lcbase_shake256_release(s);}
static const a127_dsa_route selected_dsa_route={
 6,5,1952,4032,128,640,48,128,
 {128,34,64,5*sizeof(mld_poly),sizeof(mld_polymat65),4*sizeof(mld_poly)+1600},
 {sizeof(mld_shake256ctx),64,5*sizeof(mld_poly),sizeof(mld_poly),sizeof(mld_polymat65),4*sizeof(mld_poly)+1600},
 __builtin_offsetof(mld_polymat65,cur),
 lc_dsa_alloc,lc_dsa_free,lcbase_shake256,dsa_init_mat,dsa_prep_s,dsa_key_row,dsa_finish_key,
 dsa_z,lc_verify_mu_segments65,dsa_verify_init,dsa_verify_row,dsa_absorb_row,dsa_verify_finish,dsa_hash_done
};
