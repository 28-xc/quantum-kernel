extern void two66(void*,void*);
extern void a127_kem_four_row(void*,void*,const unsigned char*,unsigned,unsigned,unsigned,const void*,const void*);
extern void pqm33_invntt_fast(short*,const int*);
extern const int a127_montgomery_twist[256];
extern void pqm46_KeccakF1600_StateExtractBytes(const void*,unsigned char*,unsigned,unsigned);
extern void pqm46_KeccakF1600_StateXORBytes(void*,const unsigned char*,unsigned,unsigned);
extern void pqm46_KeccakF1600_StatePermute(void*);
extern void pqm20_ntt(short*);extern void pqm20_invntt(short*);
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
typedef struct lc_arena {
    uint8_t *base;
    size_t capacity, used, high_water, failed_size, allocations;
    int error;
} lc_arena;
void lc_arena_init(lc_arena *a, void *base, size_t capacity);
void *lc_arena_alloc(lc_arena *a, size_t bytes);
void lc_arena_free(lc_arena *a, void *ptr, size_t bytes);
void lc_zero(void *p, size_t bytes);
typedef enum
{
  MLK_SYS_CAP_X86_64_AVX2,
  MLK_SYS_CAP_AARCH64_NEON,
  MLK_SYS_CAP_AARCH64_SHA3,
  MLK_SYS_CAP_ARMV81M_MVE
} mlk_sys_cap;
__attribute__((warn_unused_result))
static inline int mlk_sys_check_capability(mlk_sys_cap cap)
{
  (void)cap;
  return 1;
}
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
static inline uint32_t mlk_value_barrier_u32(uint32_t b)
{
  __asm__ volatile("" : "+r"(b));
  return b;
}
static inline int32_t mlk_value_barrier_i32(int32_t b)
{
  __asm__ volatile("" : "+r"(b));
  return b;
}
static inline uint8_t mlk_value_barrier_u8(uint8_t b)
{
  __asm__ volatile("" : "+r"(b));
  return b;
}
static inline __attribute__((always_inline)) int16_t mlk_cast_uint16_to_int16(uint16_t x)
{
  return (int16_t)x;
}
static inline __attribute__((always_inline)) uint16_t mlk_cast_int32_to_uint16(int32_t x)
{
  return (uint16_t)(x & (int32_t)65535U);
}
static inline __attribute__((always_inline)) uint16_t mlk_cast_int16_to_uint16(int32_t x)
{
  return mlk_cast_int32_to_uint16(x);
}
static inline uint16_t mlk_ct_cmask_neg_i16(int16_t x)
{
  int32_t tmp = mlk_value_barrier_i32((int32_t)x);
  tmp >>= 16;
  return mlk_cast_int32_to_uint16(tmp);
}
static inline uint16_t mlk_ct_cmask_nonzero_u16(uint16_t x)
{
  int32_t tmp = mlk_value_barrier_i32(-((int32_t)x));
  tmp >>= 16;
  return mlk_cast_int32_to_uint16(tmp);
}
static inline uint8_t mlk_ct_cmask_nonzero_u8(uint8_t x)
{
  uint16_t mask = mlk_ct_cmask_nonzero_u16((uint16_t)x);
  return (uint8_t)(mask & 0xFF);
}
static inline int16_t mlk_ct_sel_int16(int16_t a, int16_t b, uint16_t cond)
{
  uint16_t au = mlk_cast_int16_to_uint16(a);
  uint16_t bu = mlk_cast_int16_to_uint16(b);
  uint16_t res = bu ^ (mlk_ct_cmask_nonzero_u16(cond) & (au ^ bu));
  return mlk_cast_uint16_to_int16(res);
}
static inline uint8_t mlk_ct_sel_uint8(uint8_t a, uint8_t b, uint8_t cond)
{
  return b ^ (mlk_ct_cmask_nonzero_u8(cond) & (a ^ b));
}
static inline uint8_t mlk_ct_memcmp(const uint8_t *a, const uint8_t *b,
                                        const size_t len)
{
  uint8_t r = 0, s = 0;
  unsigned i;
  for (i = 0; i < len; i++)
  {
    r |= a[i] ^ b[i];
    s ^= a[i] ^ b[i];
  }
  return (mlk_value_barrier_u8(mlk_ct_cmask_nonzero_u8(r) ^ s) ^ s);
}
static inline void mlk_ct_cmov_zero(uint8_t *r, const uint8_t *x,
                                        size_t len, uint8_t b)
{
  size_t i;
  for (i = 0; i < len; i++)
  {
    r[i] = mlk_ct_sel_uint8(r[i], x[i], b);
  }
}
static inline void mlk_zeroize(void *ptr, size_t len)
{
  memset(ptr, 0, len);
  __asm__ volatile("" : : "r"(ptr) : "memory");
}
typedef struct
{
  int16_t coeffs[256];
} __attribute__((aligned(32))) mlk_poly;
typedef struct
{
  int16_t coeffs[256 >> 1];
} __attribute__((aligned(32))) mlk_poly_mulcache;
static inline __attribute__((always_inline)) int16_t mlk_montgomery_reduce(int32_t a)
{
  const uint32_t QINV = 62209;
  const uint16_t a_reduced = mlk_cast_int32_to_uint16(a);
  const uint16_t a_inverted = (a_reduced * QINV) & 65535U;
  const int16_t t = mlk_cast_uint16_to_int16(a_inverted);
  int32_t r;
  do { } while (0);
  r = a - ((int32_t)t * 3329);
  r = r >> 16;
  return (int16_t)r;
}
void lc_base_mlk_poly_tomont(mlk_poly *r)
 ;
void lc_base_mlk_poly_mulcache_compute(mlk_poly_mulcache *x, const mlk_poly *a)
 ;
void lc_base_mlk_poly_reduce(mlk_poly *r)
 ;
void lc_base_mlk_poly_add(mlk_poly *r, const mlk_poly *b)
 ;
void lc_base_mlk_poly_sub(mlk_poly *r, const mlk_poly *b)
 ;
void lc_base_mlk_poly_ntt(mlk_poly *r)
 ;
void lc_base_mlk_poly_invntt_tomont(mlk_poly *r)
 ;
static inline uint8_t mlk_scalar_compress_d1(int16_t u)
{
  uint32_t d0 = (uint32_t)u * 1290168;
  return (uint8_t)((d0 + ((uint32_t)1u << 30)) >> 31);
}
static inline uint8_t mlk_scalar_compress_d4(int16_t u)
{
  uint32_t d0 = (uint32_t)u * 1290160;
  return (uint8_t)((d0 + ((uint32_t)1u << 27)) >> 28);
}
static inline int16_t mlk_scalar_decompress_d4(uint8_t u)
{
  return (int16_t)((((uint32_t)u * 3329) + 8) >> 4);
}
static inline uint8_t mlk_scalar_compress_d5(int16_t u)
{
  uint32_t d0 = (uint32_t)u * 1290176;
  return (uint8_t)((d0 + ((uint32_t)1u << 26)) >> 27);
}
static inline int16_t mlk_scalar_decompress_d5(uint8_t u)
{
  return (int16_t)((((uint32_t)u * 3329) + 16) >> 5);
}
static inline uint16_t mlk_scalar_compress_d10(int16_t u)
{
  uint64_t d0 = (uint64_t)u * 2642263040;
  d0 = (d0 + ((uint64_t)1u << 32)) >> 33;
  return (d0 & 0x3FF);
}
static inline int16_t mlk_scalar_decompress_d10(uint16_t u)
{
  return (int16_t)((((uint32_t)u * 3329) + 512) >> 10);
}
static inline uint16_t mlk_scalar_compress_d11(int16_t u)
{
  uint64_t d0 = (uint64_t)u * 5284526080;
  d0 = (d0 + ((uint64_t)1u << 32)) >> 33;
  return (d0 & 0x7FF);
}
static inline int16_t mlk_scalar_decompress_d11(uint16_t u)
{
  return (int16_t)((((uint32_t)u * 3329) + 1024) >> 11);
}
void lc_base_mlk_poly_compress_d4(uint8_t r[128],
                          const mlk_poly *a);
void lc_base_mlk_poly_compress_d10(uint8_t r[320],
                           const mlk_poly *a);
void lc_base_mlk_poly_decompress_d4(mlk_poly *r,
                            const uint8_t a[128]);
void lc_base_mlk_poly_decompress_d10(mlk_poly *r,
                             const uint8_t a[320]);
void lc_base_mlk_poly_compress_d5(uint8_t r[160],
                          const mlk_poly *a);
void lc_base_mlk_poly_compress_d11(uint8_t r[352],
                           const mlk_poly *a);
void lc_base_mlk_poly_decompress_d5(mlk_poly *r,
                            const uint8_t a[160]);
void lc_base_mlk_poly_decompress_d11(mlk_poly *r,
                             const uint8_t a[352]);
void lc_base_mlk_poly_tobytes(uint8_t r[384], const mlk_poly *a)
 ;
void lc_base_mlk_poly_frombytes(mlk_poly *r, const uint8_t a[384])
 ;
void lc_base_mlk_poly_frommsg(mlk_poly *r, const uint8_t msg[(32)])
 ;
void lc_base_mlk_poly_tomsg(uint8_t msg[(32)], const mlk_poly *r)
 ;
static void mlk_poly_compress_d4_c(
    uint8_t r[128], const mlk_poly *a)
{
  unsigned i;
  do { } while (0);
  for (i = 0; i < 256 / 8; i++)
  {
    unsigned j;
    uint8_t t[8] = {0};
    for (j = 0; j < 8; j++)
    {
      t[j] = mlk_scalar_compress_d4(a->coeffs[8 * i + j]);
    }
    r[i * 4] = (uint8_t)(t[0] | (t[1] << 4));
    r[i * 4 + 1] = (uint8_t)(t[2] | (t[3] << 4));
    r[i * 4 + 2] = (uint8_t)(t[4] | (t[5] << 4));
    r[i * 4 + 3] = (uint8_t)(t[6] | (t[7] << 4));
  }
}
void lc_base_mlk_poly_compress_d4(uint8_t r[128],
                          const mlk_poly *a)
{
  mlk_poly_compress_d4_c(r, a);
}
static void mlk_poly_compress_d10_c(
    uint8_t r[320], const mlk_poly *a)
{
  unsigned j;
  do { } while (0);
  for (j = 0; j < 256 / 4; j++)
  {
    unsigned k;
    uint16_t t[4];
    for (k = 0; k < 4; k++)
    {
      t[k] = mlk_scalar_compress_d10(a->coeffs[4 * j + k]);
    }
    r[5 * j + 0] = (uint8_t)((t[0] >> 0) & 0xFF);
    r[5 * j + 1] = (uint8_t)((t[0] >> 8) | ((t[1] << 2) & 0xFF));
    r[5 * j + 2] = (uint8_t)((t[1] >> 6) | ((t[2] << 4) & 0xFF));
    r[5 * j + 3] = (uint8_t)((t[2] >> 4) | ((t[3] << 6) & 0xFF));
    r[5 * j + 4] = (uint8_t)(t[3] >> 2);
  }
}
void lc_base_mlk_poly_compress_d10(uint8_t r[320],
                           const mlk_poly *a)
{
  mlk_poly_compress_d10_c(r, a);
}
static void mlk_poly_decompress_d4_c(
    mlk_poly *r, const uint8_t a[128])
{
  unsigned i;
  for (i = 0; i < 256 / 2; i++)
  {
    r->coeffs[2 * i + 0] = mlk_scalar_decompress_d4((a[i] >> 0) & 0xF);
    r->coeffs[2 * i + 1] = mlk_scalar_decompress_d4((a[i] >> 4) & 0xF);
  }
  do { } while (0);
}
void lc_base_mlk_poly_decompress_d4(mlk_poly *r,
                            const uint8_t a[128])
{
  mlk_poly_decompress_d4_c(r, a);
}
static void mlk_poly_decompress_d10_c(
    mlk_poly *r, const uint8_t a[320])
{
  unsigned j;
  for (j = 0; j < 256 / 4; j++)
  {
    unsigned k;
    uint16_t t[4];
    uint8_t const *base = &a[5 * j];
    t[0] = 0x3FF & ((base[0] >> 0) | ((uint16_t)base[1] << 8));
    t[1] = 0x3FF & ((base[1] >> 2) | ((uint16_t)base[2] << 6));
    t[2] = 0x3FF & ((base[2] >> 4) | ((uint16_t)base[3] << 4));
    t[3] = 0x3FF & ((base[3] >> 6) | ((uint16_t)base[4] << 2));
    for (k = 0; k < 4; k++)
    {
      r->coeffs[4 * j + k] = mlk_scalar_decompress_d10(t[k]);
    }
  }
  do { } while (0);
}
void lc_base_mlk_poly_decompress_d10(mlk_poly *r,
                             const uint8_t a[320])
{
  mlk_poly_decompress_d10_c(r, a);
}
static void mlk_poly_compress_d5_c(
    uint8_t r[160], const mlk_poly *a)
{
  unsigned i;
  do { } while (0);
  for (i = 0; i < 256 / 8; i++)
  {
    unsigned j;
    uint8_t t[8] = {0};
    for (j = 0; j < 8; j++)
    {
      t[j] = mlk_scalar_compress_d5(a->coeffs[8 * i + j]);
    }
    r[i * 5] = (uint8_t)(0xFF & ((t[0] >> 0) | (t[1] << 5)));
    r[i * 5 + 1] = (uint8_t)(0xFF & ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7)));
    r[i * 5 + 2] = (uint8_t)(0xFF & ((t[3] >> 1) | (t[4] << 4)));
    r[i * 5 + 3] = (uint8_t)(0xFF & ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6)));
    r[i * 5 + 4] = (uint8_t)(0xFF & ((t[6] >> 2) | (t[7] << 3)));
  }
}
void lc_base_mlk_poly_compress_d5(uint8_t r[160],
                          const mlk_poly *a)
{
  mlk_poly_compress_d5_c(r, a);
}
static void mlk_poly_compress_d11_c(
    uint8_t r[352], const mlk_poly *a)
{
  unsigned j;
  do { } while (0);
  for (j = 0; j < 256 / 8; j++)
  {
    unsigned k;
    uint16_t t[8];
    for (k = 0; k < 8; k++)
    {
      t[k] = mlk_scalar_compress_d11(a->coeffs[8 * j + k]);
    }
    r[11 * j + 0] = (uint8_t)((t[0] >> 0) & 0xFF);
    r[11 * j + 1] = (uint8_t)((t[0] >> 8) | ((t[1] << 3) & 0xFF));
    r[11 * j + 2] = (uint8_t)((t[1] >> 5) | ((t[2] << 6) & 0xFF));
    r[11 * j + 3] = (uint8_t)((t[2] >> 2) & 0xFF);
    r[11 * j + 4] = (uint8_t)((t[2] >> 10) | ((t[3] << 1) & 0xFF));
    r[11 * j + 5] = (uint8_t)((t[3] >> 7) | ((t[4] << 4) & 0xFF));
    r[11 * j + 6] = (uint8_t)((t[4] >> 4) | ((t[5] << 7) & 0xFF));
    r[11 * j + 7] = (uint8_t)((t[5] >> 1) & 0xFF);
    r[11 * j + 8] = (uint8_t)((t[5] >> 9) | ((t[6] << 2) & 0xFF));
    r[11 * j + 9] = (uint8_t)((t[6] >> 6) | ((t[7] << 5) & 0xFF));
    r[11 * j + 10] = (uint8_t)(t[7] >> 3);
  }
}
void lc_base_mlk_poly_compress_d11(uint8_t r[352],
                           const mlk_poly *a)
{
  mlk_poly_compress_d11_c(r, a);
}
static void mlk_poly_decompress_d5_c(
    mlk_poly *r, const uint8_t a[160])
{
  unsigned i;
  for (i = 0; i < 256 / 8; i++)
  {
    unsigned j;
    uint8_t t[8];
    const unsigned offset = i * 5;
    t[0] = 0x1F & (a[offset + 0] >> 0);
    t[1] = 0x1F & ((a[offset + 0] >> 5) | (a[offset + 1] << 3));
    t[2] = 0x1F & (a[offset + 1] >> 2);
    t[3] = 0x1F & ((a[offset + 1] >> 7) | (a[offset + 2] << 1));
    t[4] = 0x1F & ((a[offset + 2] >> 4) | (a[offset + 3] << 4));
    t[5] = 0x1F & (a[offset + 3] >> 1);
    t[6] = 0x1F & ((a[offset + 3] >> 6) | (a[offset + 4] << 2));
    t[7] = 0x1F & (a[offset + 4] >> 3);
    for (j = 0; j < 8; j++)
    {
      r->coeffs[8 * i + j] = mlk_scalar_decompress_d5(t[j]);
    }
  }
  do { } while (0);
}
void lc_base_mlk_poly_decompress_d5(mlk_poly *r,
                            const uint8_t a[160])
{
  mlk_poly_decompress_d5_c(r, a);
}
static void mlk_poly_decompress_d11_c(
    mlk_poly *r, const uint8_t a[352])
{
  unsigned j;
  for (j = 0; j < 256 / 8; j++)
  {
    unsigned k;
    uint16_t t[8];
    uint8_t const *base = &a[11 * j];
    t[0] = 0x7FF & ((base[0] >> 0) | ((uint16_t)base[1] << 8));
    t[1] = 0x7FF & ((base[1] >> 3) | ((uint16_t)base[2] << 5));
    t[2] = 0x7FF & ((base[2] >> 6) | ((uint16_t)base[3] << 2) |
                    ((uint16_t)base[4] << 10));
    t[3] = 0x7FF & ((base[4] >> 1) | ((uint16_t)base[5] << 7));
    t[4] = 0x7FF & ((base[5] >> 4) | ((uint16_t)base[6] << 4));
    t[5] = 0x7FF & ((base[6] >> 7) | ((uint16_t)base[7] << 1) |
                    ((uint16_t)base[8] << 9));
    t[6] = 0x7FF & ((base[8] >> 2) | ((uint16_t)base[9] << 6));
    t[7] = 0x7FF & ((base[9] >> 5) | ((uint16_t)base[10] << 3));
    for (k = 0; k < 8; k++)
    {
      r->coeffs[8 * j + k] = mlk_scalar_decompress_d11(t[k]);
    }
  }
  do { } while (0);
}
void lc_base_mlk_poly_decompress_d11(mlk_poly *r,
                             const uint8_t a[352])
{
  mlk_poly_decompress_d11_c(r, a);
}
static void mlk_poly_tobytes_c(uint8_t r[384],
                                            const mlk_poly *a)
{
  unsigned i;
  do { } while (0);
  for (i = 0; i < 256 / 2; i++)
  {
    const uint16_t t0 = (uint16_t)a->coeffs[2 * i];
    const uint16_t t1 = (uint16_t)a->coeffs[2 * i + 1];
    r[3 * i + 0] = (uint8_t)(t0 & 0xFF);
    r[3 * i + 1] = (uint8_t)((t0 >> 8) | ((t1 << 4) & 0xF0));
    r[3 * i + 2] = (uint8_t)(t1 >> 4);
  }
}
void lc_base_mlk_poly_tobytes(uint8_t r[384], const mlk_poly *a)
{
  mlk_poly_tobytes_c(r, a);
}
static void mlk_poly_frombytes_c(mlk_poly *r,
                                              const uint8_t a[384])
{
  unsigned i;
  for (i = 0; i < 256 / 2; i++)
  {
    const uint8_t t0 = a[3 * i + 0];
    const uint8_t t1 = a[3 * i + 1];
    const uint8_t t2 = a[3 * i + 2];
    r->coeffs[2 * i + 0] = (int16_t)(t0 | (((uint16_t)t1 << 8) & 0xFFF));
    r->coeffs[2 * i + 1] = (int16_t)((t1 >> 4) | (t2 << 4));
  }
  do { } while (0);
}
void lc_base_mlk_poly_frombytes(mlk_poly *r, const uint8_t a[384])
{
  mlk_poly_frombytes_c(r, a);
}
void lc_base_mlk_poly_frommsg(mlk_poly *r, const uint8_t msg[(32)])
{
  unsigned i;
  for (i = 0; i < 256 / 8; i++)
  {
    unsigned j;
    for (j = 0; j < 8; j++)
    {
      uint8_t mask = mlk_value_barrier_u8((uint8_t)(1u << j));
      r->coeffs[8 * i + j] = mlk_ct_sel_int16(((3329 + 1) / 2), 0, msg[i] & mask);
    }
  }
  do { } while (0);
}
void lc_base_mlk_poly_tomsg(uint8_t msg[(32)], const mlk_poly *r)
{
  unsigned i;
  do { } while (0);
  for (i = 0; i < 256 / 8; i++)
  {
    unsigned j;
    msg[i] = 0;
    for (j = 0; j < 8; j++)
    {
      uint32_t t = mlk_scalar_compress_d1(r->coeffs[8 * i + j]);
      msg[i] |= (uint8_t)(t << j);
    }
  }
}
extern int lc_base_mlk512_empty_cu_debug;
typedef struct
{
  mlk_poly vec[2];
} __attribute__((aligned(32))) mlk_polyvec512;
typedef struct
{
  mlk_polyvec512 vec[2];
} __attribute__((aligned(32))) mlk_polymat512;
typedef struct
{
  mlk_poly_mulcache vec[2];
} __attribute__((aligned(32))) mlk_polyvec_mulcache512;
static inline void lc_base_mlk512_poly_compress_du(
    uint8_t r[320], const mlk_poly *a)
{
  lc_base_mlk_poly_compress_d10(r, a);
}
static inline void lc_base_mlk512_poly_decompress_du(
    mlk_poly *r, const uint8_t a[320])
{
  lc_base_mlk_poly_decompress_d10(r, a);
}
static inline void lc_base_mlk512_poly_compress_dv(
    uint8_t r[128], const mlk_poly *a)
{
  lc_base_mlk_poly_compress_d4(r, a);
}
static inline void lc_base_mlk512_poly_decompress_dv(
    mlk_poly *r, const uint8_t a[128])
{
  lc_base_mlk_poly_decompress_d4(r, a);
}
void lc_base_mlk512_polyvec_compress_du(uint8_t r[(2 * 320)],
                             const mlk_polyvec512 *a)
 ;
void lc_base_mlk512_polyvec_decompress_du(mlk_polyvec512 *r,
                               const uint8_t a[(2 * 320)])
 ;
void lc_base_mlk512_polyvec_tobytes(uint8_t r[(2 * 384)], const mlk_polyvec512 *a)
 ;
void lc_base_mlk512_polyvec_frombytes(mlk_polyvec512 *r, const uint8_t a[(2 * 384)])
 ;
void lc_base_mlk512_polyvec_ntt(mlk_polyvec512 *r)
 ;
void lc_base_mlk512_polyvec_invntt_tomont(mlk_polyvec512 *r)
 ;
void lc_base_mlk512_polyvec_basemul_acc_montgomery_cached(
    mlk_poly *r, const mlk_polyvec512 *a, const mlk_polyvec512 *b,
    const mlk_polyvec_mulcache512 *b_cache)
 ;
void lc_base_mlk512_polyvec_mulcache_compute(mlk_polyvec_mulcache512 *x, const mlk_polyvec512 *a)
 ;
void lc_base_mlk512_polyvec_reduce(mlk_polyvec512 *r)
 ;
void lc_base_mlk512_polyvec_add(mlk_polyvec512 *r, const mlk_polyvec512 *b)
 ;
void lc_base_mlk512_polyvec_tomont(mlk_polyvec512 *r)
 ;
void lc_base_mlk512_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const uint8_t seed[32],
                               uint8_t nonce0, uint8_t nonce1, uint8_t nonce2,
                               uint8_t nonce3)
 ;
void lc_base_mlk512_poly_getnoise_eta2(mlk_poly *r, const uint8_t seed[32],
                            uint8_t nonce)
 ;
void lc_base_mlk512_poly_getnoise_eta1122_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                                  mlk_poly *r3,
                                  const uint8_t seed[32],
                                  uint8_t nonce0, uint8_t nonce1,
                                  uint8_t nonce2, uint8_t nonce3)
 ;
void lc_base_mlk512_gen_matrix(mlk_polymat512 *a, const uint8_t seed[32],
                    int transposed)
 ;
__attribute__((warn_unused_result))
int lc_base_mlk512_indcpa_keypair_derand (uint8_t pk[((2 * 384) + 32)], uint8_t sk[((2 * 384))], const uint8_t coins[32], lc_arena * context)
 ;
__attribute__((warn_unused_result))
int lc_base_mlk512_indcpa_enc (uint8_t c[((2 * 320) + 128)], const uint8_t m[(32)], const uint8_t pk[((2 * 384) + 32)], const uint8_t coins[32], lc_arena * context)
 ;
__attribute__((warn_unused_result))
int lc_base_mlk512_indcpa_dec (uint8_t m[(32)], const uint8_t c[((2 * 320) + 128)], const uint8_t sk[((2 * 384))], lc_arena * context)
 ;
void lc_base_mlk_poly_cbd2(mlk_poly *r, const uint8_t buf[2 * 256 / 4]);
void lc_base_mlk_poly_cbd3(mlk_poly *r, const uint8_t buf[3 * 256 / 4]);
void lc_base_mlk_poly_rej_uniform_x4(mlk_poly *vec0, mlk_poly *vec1, mlk_poly *vec2,
                             mlk_poly *vec3,
                             uint8_t seed[4][((((32 + 2) + (32 - 1)) / 32) * 32)])
                                                             ;
void lc_base_mlk_poly_rej_uniform(mlk_poly *entry, uint8_t seed[32 + 2])
                                                              ;
typedef struct
{
  uint64_t ctx[25];
} __attribute__((aligned(32))) mlk_shake128ctx;
void lc_base_mlk_shake128_absorb_once(mlk_shake128ctx *state, const uint8_t *input,
                              size_t inlen)
 ;
void lc_base_mlk_shake128_squeezeblocks(uint8_t *output, size_t nblocks,
                                mlk_shake128ctx *state)
 ;
void lc_base_mlk_shake128_init(mlk_shake128ctx *state);
void lc_base_mlk_shake128_release(mlk_shake128ctx *state);
void lc_base_mlk_shake256(uint8_t *output, size_t outlen, const uint8_t *input,
                  size_t inlen)
 ;
void lc_base_mlk_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen)
 ;
void lc_base_mlk_sha3_512(uint8_t *output, const uint8_t *input, size_t inlen)
 ;
void lc_base_mlk_keccakf1600_extract_bytes(uint64_t *state, unsigned char *data,
                                   unsigned offset, unsigned length)
 ;
void lc_base_mlk_keccakf1600_xor_bytes(uint64_t *state, const unsigned char *data,
                               unsigned offset, unsigned length)
 ;
void lc_base_mlk_keccakf1600x4_extract_bytes(uint64_t *state, unsigned char *data0,
                                     unsigned char *data1, unsigned char *data2,
                                     unsigned char *data3, unsigned offset,
                                     unsigned length)
 ;
void lc_base_mlk_keccakf1600x4_xor_bytes(uint64_t *state, const unsigned char *data0,
                                 const unsigned char *data1,
                                 const unsigned char *data2,
                                 const unsigned char *data3, unsigned offset,
                                 unsigned length)
 ;
void lc_base_mlk_keccakf1600x4_permute(uint64_t *state)
 ;
void lc_base_mlk_keccakf1600_permute(uint64_t *state)
 ;
typedef struct
{
  uint64_t ctx[25 *
               4];
} __attribute__((aligned(32))) mlk_shake128x4ctx;
void lc_base_mlk_shake128x4_absorb_once(mlk_shake128x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen)
 ;
void lc_base_mlk_shake128x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mlk_shake128x4ctx *state)
 ;
void lc_base_mlk_shake128x4_init(mlk_shake128x4ctx *state);
void lc_base_mlk_shake128x4_release(mlk_shake128x4ctx *state);
void lc_base_mlk_shake256x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
                    size_t outlen, const uint8_t *in0, const uint8_t *in1,
                    const uint8_t *in2, const uint8_t *in3, size_t inlen)
 ;
static void mlk_pack_pk512(uint8_t r[((2 * 384) + 32)],
                        const mlk_polyvec512 *pk,
                        const uint8_t seed[32])
{
  do { } while (0);
  lc_base_mlk512_polyvec_tobytes(r, pk);
  memcpy(r + (2 * 384), seed, 32);
}
static void mlk_unpack_pk512(mlk_polyvec512 *pk, uint8_t seed[32],
                          const uint8_t packedpk[((2 * 384) + 32)])
{
  lc_base_mlk512_polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk + (2 * 384), 32);
}
static void mlk_pack_sk512(uint8_t r[((2 * 384))],
                        const mlk_polyvec512 *sk)
{
  do { } while (0);
  lc_base_mlk512_polyvec_tobytes(r, sk);
}
static void mlk_unpack_sk512(mlk_polyvec512 *sk,
                          const uint8_t packedsk[((2 * 384))])
{
  lc_base_mlk512_polyvec_frombytes(sk, packedsk);
}
static void mlk_pack_ciphertext512(uint8_t r[((2 * 320) + 128)],
                                const mlk_polyvec512 *b, mlk_poly *v)
{
  lc_base_mlk512_polyvec_compress_du(r, b);
  lc_base_mlk512_poly_compress_dv(r + (2 * 320), v);
}
static void mlk_unpack_ciphertext512(mlk_polyvec512 *b, mlk_poly *v,
                                  const uint8_t c[((2 * 320) + 128)])
{
  lc_base_mlk512_polyvec_decompress_du(b, c);
  lc_base_mlk512_poly_decompress_dv(v, c + (2 * 320));
}
static void mlk_polymat_permute_bitrev_to_custom512(mlk_polymat512 *a)
{
  (void)a;
}
void lc_base_mlk512_gen_matrix(mlk_polymat512 *a, const uint8_t seed[32],
                    int transposed)
{
  unsigned i, j;
  __attribute__((aligned(32))) uint8_t seed_ext[4][((((32 + 2) + (32 - 1)) / 32) * 32)];
  for (j = 0; j < 4; j++)
  {
    memcpy(seed_ext[j], seed, 32);
  }
  for (i = 0; i < (2 * 2 / 4) * 4; i += 4)
  {
    for (j = 0; j < 4; j++)
    {
      uint8_t x, y;
      x = (uint8_t)((i + j) / 2);
      y = (uint8_t)((i + j) % 2);
      if (transposed)
      {
        seed_ext[j][32 + 0] = x;
        seed_ext[j][32 + 1] = y;
      }
      else
      {
        seed_ext[j][32 + 0] = y;
        seed_ext[j][32 + 1] = x;
      }
    }
    lc_base_mlk_poly_rej_uniform_x4(&a->vec[i / 2].vec[i % 2],
                            &a->vec[(i + 1) / 2].vec[(i + 1) % 2],
                            &a->vec[(i + 2) / 2].vec[(i + 2) % 2],
                            &a->vec[(i + 3) / 2].vec[(i + 3) % 2],
                            seed_ext);
  }
  for (; i < 2 * 2; i++)
  {
    uint8_t x, y;
    x = (uint8_t)(i / 2);
    y = (uint8_t)(i % 2);
    if (transposed)
    {
      seed_ext[0][32 + 0] = x;
      seed_ext[0][32 + 1] = y;
    }
    else
    {
      seed_ext[0][32 + 0] = y;
      seed_ext[0][32 + 1] = x;
    }
    lc_base_mlk_poly_rej_uniform(&a->vec[i / 2].vec[i % 2], seed_ext[0]);
  }
  do { } while (0);
  mlk_polymat_permute_bitrev_to_custom512(a);
  mlk_zeroize(seed_ext, sizeof(seed_ext));
}
static void mlk_matvec_mul512(mlk_polyvec512 *out, const mlk_polymat512 *a,
                           const mlk_polyvec512 *v, const mlk_polyvec_mulcache512 *vc)
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk512_polyvec_basemul_acc_montgomery_cached(&out->vec[i], &a->vec[i], v, vc);
  }
}
static void mlk_keypair_getnoise_eta1512(mlk_polyvec512 *pv, mlk_polyvec512 *e,
                                      const uint8_t seed[32])
{
  lc_base_mlk512_poly_getnoise_eta1_4x(&pv->vec[0], &pv->vec[1],
                            &e->vec[0], &e->vec[1],
                            seed, 0, 1, 2, 3);
}
static void mlk_enc_getnoise_eta1_eta2512(mlk_polyvec512 *sp, mlk_polyvec512 *ep,
                                       mlk_poly *epp,
                                       const uint8_t coins[32])
{
  lc_base_mlk512_poly_getnoise_eta1122_4x(&sp->vec[0], &sp->vec[1], &ep->vec[0],
                               &ep->vec[1], coins, 0, 1, 2, 3);
  lc_base_mlk512_poly_getnoise_eta2(epp, coins, 4);
}
extern void a127_noise_inplace(int16_t*,const uint8_t*,unsigned,unsigned);

extern void a127_extract_words(const void*,void*,unsigned);
extern void two(void*,void*);
static inline uint32_t noise_even(uint32_t x){
    x&=0x55555555u;x=(x|(x>>1))&0x33333333u;x=(x|(x>>2))&0x0f0f0f0fu;
    x=(x|(x>>4))&0x00ff00ffu;return (x|(x>>8))&0xffffu;
}
static void a127_bind_noise(uint64_t *state,const uint8_t *seed,unsigned nonce){
      uint32_t *planes=(uint32_t*)(void*)state;
    memset(planes+10,0,32);
    for(unsigned j=0;j<4;j++){
        uint32_t a,b;__asm__("ldr %0,[%2]\n ldr %1,[%2,#4]":"=&r"(a),"=&r"(b):"r"(seed+8*j):"memory");
        planes[2*j]=noise_even(a)|(noise_even(b)<<16);
        planes[2*j+1]=noise_even(a>>1)|(noise_even(b>>1)<<16);
    }
    planes[8]=noise_even(nonce|0x1f00u);planes[9]=noise_even((nonce|0x1f00u)>>1);
    planes[33]=0x80000000u;
 }
static void a127_finish_noise(int16_t *out,unsigned eta){uint8_t *raw=(uint8_t*)(void*)out;
    const unsigned samples=eta==2?8u:4u;
    for(unsigned top=256;top>0;top-=samples){
        unsigned group=top-samples,t,mask;
        if(eta==2){__asm__("ldr %0,[%1]":"=r"(t):"r"(raw+group/2):"memory");mask=0x55555555u;}
        else{const uint8_t *v=raw+3*group/4;
            __asm__("ldrh %0,[%1]":"=r"(t):"r"(v):"memory");t|=(unsigned)v[2]<<16;mask=0x249249u;}
        unsigned sums=(t&mask)+((t>>1)&mask);
        if(eta==3)sums+=(t>>2)&mask;
if(eta==2){{
                unsigned a,b,hi;__asm__("ubfx %0,%3,#0,#2\n ubfx %1,%3,#2,#2\n ubfx %2,%3,#4,#2\n pkhbt %0,%0,%2,lsl #16\n ubfx %2,%3,#6,#2\n pkhbt %1,%1,%2,lsl #16\n ssub16 %0,%0,%1\n str %0,[%4,#0]" : "=&r"(a),"=&r"(b),"=&r"(hi):"r"(sums),"r"(out+group):"memory","cc");
            }
{
                unsigned a,b,hi;__asm__("ubfx %0,%3,#8,#2\n ubfx %1,%3,#10,#2\n ubfx %2,%3,#12,#2\n pkhbt %0,%0,%2,lsl #16\n ubfx %2,%3,#14,#2\n pkhbt %1,%1,%2,lsl #16\n ssub16 %0,%0,%1\n str %0,[%4,#4]" : "=&r"(a),"=&r"(b),"=&r"(hi):"r"(sums),"r"(out+group):"memory","cc");
            }
{
                unsigned a,b,hi;__asm__("ubfx %0,%3,#16,#2\n ubfx %1,%3,#18,#2\n ubfx %2,%3,#20,#2\n pkhbt %0,%0,%2,lsl #16\n ubfx %2,%3,#22,#2\n pkhbt %1,%1,%2,lsl #16\n ssub16 %0,%0,%1\n str %0,[%4,#8]" : "=&r"(a),"=&r"(b),"=&r"(hi):"r"(sums),"r"(out+group):"memory","cc");
            }
{
                unsigned a,b,hi;__asm__("ubfx %0,%3,#24,#2\n ubfx %1,%3,#26,#2\n ubfx %2,%3,#28,#2\n pkhbt %0,%0,%2,lsl #16\n ubfx %2,%3,#30,#2\n pkhbt %1,%1,%2,lsl #16\n ssub16 %0,%0,%1\n str %0,[%4,#12]" : "=&r"(a),"=&r"(b),"=&r"(hi):"r"(sums),"r"(out+group):"memory","cc");
            }}else{{
                unsigned a,b,hi;__asm__("ubfx %0,%3,#0,#3\n ubfx %1,%3,#3,#3\n ubfx %2,%3,#6,#3\n pkhbt %0,%0,%2,lsl #16\n ubfx %2,%3,#9,#3\n pkhbt %1,%1,%2,lsl #16\n ssub16 %0,%0,%1\n str %0,[%4,#0]" : "=&r"(a),"=&r"(b),"=&r"(hi):"r"(sums),"r"(out+group):"memory","cc");
            }
{
                unsigned a,b,hi;__asm__("ubfx %0,%3,#12,#3\n ubfx %1,%3,#15,#3\n ubfx %2,%3,#18,#3\n pkhbt %0,%0,%2,lsl #16\n ubfx %2,%3,#21,#3\n pkhbt %1,%1,%2,lsl #16\n ssub16 %0,%0,%1\n str %0,[%4,#4]" : "=&r"(a),"=&r"(b),"=&r"(hi):"r"(sums),"r"(out+group):"memory","cc");
            }}
    }
    __asm__ volatile(""::"r"(out):"memory");
 }
void a127_noise_inplace(int16_t *out,const uint8_t *seed,unsigned nonce,unsigned eta){
    uint8_t *raw=(uint8_t*)(void*)out;uint64_t *state=(uint64_t*)(void*)(raw+256);
    a127_bind_noise(state,seed,nonce);two66(state,(void*)0);a127_extract_words(state,raw,17);
    if(eta==3){two(state,(void*)0);a127_extract_words(state,raw+136,7);}
    a127_finish_noise(out,eta);
}
static void a127_kem_pair_samples(int16_t *out,const unsigned char *seed,unsigned first,unsigned rank,unsigned eta){
    for(unsigned base=0;base<rank;base+=2){
        int16_t *p=out+256*base;
        if(base+1==rank){a127_noise_inplace(p,seed,first+base,eta);continue;}
        uint8_t *a=(uint8_t*)(void*)p,*b=a+512;
        uint64_t *s=(uint64_t*)(void*)(a+256),*t=(uint64_t*)(void*)(b+256);
        a127_bind_noise(s,seed,first+base);a127_bind_noise(t,seed,first+base+1);
        two66(s,t);a127_extract_words(s,a,17);a127_extract_words(t,b,17);
        if(eta==3){two(s,t);a127_extract_words(s,a+136,7);a127_extract_words(t,b+136,7);}
        a127_finish_noise(p,eta);a127_finish_noise(p+256,eta);
    }
}

static void lc_kem_noise512(mlk_poly *p,const uint8_t seed[32],uint8_t nonce,unsigned eta) {
    a127_noise_inplace(p->coeffs,seed,nonce,eta);
}
static inline uint32_t arm3329_load_pair(const int16_t *p) {
    uint32_t pair; __asm__("ldr %0,[%1]" : "=r"(pair) : "r"(p) : "memory");
    return pair;
}
static inline int32_t arm3329_mac_even(int32_t a,uint32_t x,uint32_t y,int16_t cached) {
    uint32_t v;int32_t out;
    __asm__("pkhbt %0,%1,%2,lsl #16":"=r"(v):"r"(y),"r"((uint32_t)(uint16_t)cached));
    __asm__("smlad %0,%1,%2,%3":"=r"(out):"r"(x),"r"(v),"r"(a));return out;
}
static inline int32_t arm3329_mac_odd(int32_t a,uint32_t x,uint32_t y) {
    int32_t out;__asm__("smladx %0,%1,%2,%3":"=r"(out):"r"(x),"r"(y),"r"(a));return out;
}
static inline uint32_t arm3329_decode_pair(const uint8_t *p){
    uint32_t x=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16);
    return (x&0xfffu)|((x>>12)<<16);
}
static void arm3329_dot(mlk_poly *out,const mlk_polyvec512 *a,const uint8_t *packed,
                        const mlk_polyvec512 *b,const mlk_polyvec_mulcache512 *cache){
    for(unsigned i=0;i<128u;i++){
        int32_t e=0,o=0;
#pragma clang loop unroll(full)
        for(unsigned j=0;j<2;j++){
            uint32_t x=packed?arm3329_decode_pair(packed+384u*j+3u*i):arm3329_load_pair(a->vec[j].coeffs+2*i);
            uint32_t y=arm3329_load_pair(b->vec[j].coeffs+2*i);
            e=arm3329_mac_even(e,x,y,cache->vec[j].coeffs[i]);o=arm3329_mac_odd(o,x,y);
        }
        out->coeffs[2*i]=mlk_montgomery_reduce(e);out->coeffs[2*i+1]=mlk_montgomery_reduce(o);
    }
}
static void arm3329_matrix_row(mlk_poly *out,void *workspace,const uint8_t rho[32],
                       unsigned row,unsigned transpose,const mlk_polyvec512 *b,const mlk_polyvec_mulcache512 *cache){
    int32_t *acc=workspace;
    uint8_t seed[34];memcpy(seed,rho,32);
    for(unsigned j=0;j<2;j++){
        seed[32]=(uint8_t)(transpose?row:j);seed[33]=(uint8_t)(transpose?j:row);
        lc_base_mlk_poly_rej_uniform(out,seed);
        for(unsigned i=0;i<128u;i++){
            uint32_t x=arm3329_load_pair(out->coeffs+2*i),y=arm3329_load_pair(b->vec[j].coeffs+2*i);
            int32_t e=j?acc[2*i]:0,o=j?acc[2*i+1]:0;
            acc[2*i]=arm3329_mac_even(e,x,y,cache->vec[j].coeffs[i]);acc[2*i+1]=arm3329_mac_odd(o,x,y);
        }
    }
    for(unsigned i=0;i<256u;i++)out->coeffs[i]=mlk_montgomery_reduce(acc[i]);
    mlk_zeroize(seed,sizeof(seed));
}
static void lc_kem_tile512(mlk_poly *tile,const uint8_t seed[32],unsigned first,unsigned rows,int transpose
) {
    __attribute__((aligned(32))) uint8_t ext[4][((((34) + (32 - 1)) / 32) * 32)];
    unsigned n=rows*2,i,j;
    for(j=0;j<4;j++)memcpy(ext[j],seed,32);
    for(i=0;i<n;i+=1) {
        for(j=0;j<1;j++) {
            unsigned idx=i+j;
            if(idx>=n)idx=n-1;
            unsigned row=first+idx/2,col=idx%2;
            ext[j][32]=(uint8_t)(transpose?row:col);
            ext[j][33]=(uint8_t)(transpose?col:row);
        }
        lc_base_mlk_poly_rej_uniform(tile+i,ext[0]);
    }
    mlk_zeroize(ext,sizeof ext);
}

typedef struct cpa_dispatch {
 unsigned char rank, eta, du, combined;
 void (*noise)(void*,const unsigned char*,unsigned char,unsigned);
 void (*ntt_vec)(void*); void (*cache)(void*,const void*);
 void (*row)(void*,void*,const unsigned char*,unsigned,int,const void*,const void*);
 void (*dot)(void*,void*,const unsigned char*,const void*,const void*);
 void (*du_pack)(unsigned char*,const void*); void (*dv_pack)(unsigned char*,const void*);
 void (*unpack_ct)(void*,void*,const unsigned char*);
} cpa_dispatch;
extern int cpa_key(const cpa_dispatch*,unsigned char*,unsigned char*,const unsigned char*,lc_arena*);
extern int cpa_enc(const cpa_dispatch*,unsigned char*,const unsigned char*,const unsigned char*,const unsigned char*,lc_arena*);
extern int cpa_dec(const cpa_dispatch*,unsigned char*,const unsigned char*,const unsigned char*,lc_arena*);

static void bind_noise(void *v,const uint8_t *seed,uint8_t n,unsigned eta){lc_kem_noise512(v,seed,n,eta);}
static void bind_ntt(void *v){lc_base_mlk512_polyvec_ntt(v);}
static void bind_cache(void *c,const void *v){lc_base_mlk512_polyvec_mulcache_compute(c,v);}
static void bind_row(void *out,void *tile,const uint8_t *seed,unsigned i,int transpose,const void *s,const void *cache){a127_kem_four_row(out,tile,seed,2,i,transpose,s,cache);}
static void bind_dot(void *out,void *tile,const uint8_t *packed,const void *s,const void *cache){(void)tile;arm3329_dot(out,0,packed,s,cache);}
static void bind_du(uint8_t *dest,const void *p){lc_base_mlk512_poly_compress_du(dest,p);}
static void bind_dv(uint8_t *dest,const void *p){lc_base_mlk512_poly_compress_dv(dest,p);}
static void bind_unpack(void *v,void *w,const uint8_t *ct){mlk_unpack_ciphertext512(v,w,ct);}
static const cpa_dispatch cpa_cell={2,3,10,1,bind_noise,bind_ntt,bind_cache,bind_row,bind_dot,bind_du,bind_dv,bind_unpack};
_Static_assert(sizeof(mlk_poly)==512 && sizeof(mlk_polyvec512)==1024 && sizeof(mlk_polyvec_mulcache512)==512,"KEM allocation ABI");

typedef struct{lc_arena *arena;void *v[6];unsigned sizes[6];unsigned count,failed;} cpa_frame;
static void *cpa_take(cpa_frame *f,unsigned n){
 void *v=lc_arena_alloc(f->arena,n);
 f->v[f->count]=v;f->sizes[f->count++]=n;if(!v)f->failed=1;return v;
}
static void cpa_drop(cpa_frame *f){
 while(f->count){unsigned i=--f->count;if(f->v[i]){mlk_zeroize(f->v[i],f->sizes[i]);lc_arena_free(f->arena,f->v[i],f->sizes[i]);}}
}
static void cpa_seedvec(const cpa_dispatch *d,mlk_poly *s,void *cache,const uint8_t *coins){
 a127_kem_pair_samples((int16_t*)(void*)s,coins,0,d->rank,d->eta);
 d->ntt_vec(s);d->cache(cache,s);
}
int cpa_key(const cpa_dispatch *d,uint8_t *pk,uint8_t *sk,const uint8_t *coins,lc_arena *arena){
 unsigned k=d->rank; cpa_frame f={.arena=arena};uint8_t *seed=cpa_take(&f,64);
 void *tile=cpa_take(&f,d->combined?1024:512*k);mlk_poly *s=cpa_take(&f,512*k);
 void *cache=cpa_take(&f,256*k);mlk_poly *row=cpa_take(&f,512),*e=cpa_take(&f,512);
 if(!f.failed){
  uint8_t dom[33];memcpy(dom,coins,32);dom[32]=(uint8_t)k;lc_base_mlk_sha3_512(seed,dom,33);mlk_zeroize(dom,sizeof dom);
  cpa_seedvec(d,s,cache,seed+32);
  for(unsigned i=0;i<k;i++){
   d->noise(e,seed+32,(uint8_t)(k+i),d->eta);lc_base_mlk_poly_ntt(e);
   d->row(row,tile,seed,i,0,s,cache);lc_base_mlk_poly_tomont(row);lc_base_mlk_poly_add(row,e);lc_base_mlk_poly_reduce(row);lc_base_mlk_poly_tobytes(pk+i*384,row);
  }
  for(unsigned i=0;i<k;i++){lc_base_mlk_poly_reduce(s+i);lc_base_mlk_poly_tobytes(sk+i*384,s+i);}
  memcpy(pk+k*384,seed,32);
 }
 cpa_drop(&f);return f.failed?-2:0;
}
int cpa_enc(const cpa_dispatch *d,uint8_t *ct,const uint8_t *msg,const uint8_t *pk,const uint8_t *coins,lc_arena *arena){
 unsigned k=d->rank,stride=32u*d->du;cpa_frame f={.arena=arena};
 void *tile=cpa_take(&f,d->combined?1024:512*k);mlk_poly *s=cpa_take(&f,512*k);
 void *cache=cpa_take(&f,256*k);mlk_poly *row=cpa_take(&f,512),*e=cpa_take(&f,512);
 if(!f.failed){
  cpa_seedvec(d,s,cache,coins);
  for(unsigned i=0;i<k;i++){
   d->row(row,tile,pk+384*k,i,1,s,cache);lc_base_mlk_poly_invntt_tomont(row);d->noise(e,coins,(uint8_t)(k+i),2);
   lc_base_mlk_poly_add(row,e);lc_base_mlk_poly_reduce(row);d->du_pack(ct+i*stride,row);
  }
  d->dot(row,tile,pk,s,cache);lc_base_mlk_poly_invntt_tomont(row);
  d->noise(e,coins,(uint8_t)(2*k),2);lc_base_mlk_poly_add(row,e);lc_base_mlk_poly_frommsg(e,msg);lc_base_mlk_poly_add(row,e);lc_base_mlk_poly_reduce(row);d->dv_pack(ct+k*stride,row);
 }
 cpa_drop(&f);return f.failed?-2:0;
}
int cpa_dec(const cpa_dispatch *d,uint8_t *msg,const uint8_t *ct,const uint8_t *sk,lc_arena *arena){
 unsigned k=d->rank;cpa_frame f={.arena=arena};mlk_poly *b=cpa_take(&f,512*k);
 void *skpv=d->combined?0:cpa_take(&f,512*k);
 mlk_poly *v=cpa_take(&f,512),*sb=cpa_take(&f,512);void *cache=cpa_take(&f,256*k);
 if(!f.failed){
  d->unpack_ct(b,v,ct);d->ntt_vec(b);d->cache(cache,b);d->dot(sb,skpv,sk,b,cache);
  lc_base_mlk_poly_invntt_tomont(sb);lc_base_mlk_poly_sub(v,sb);lc_base_mlk_poly_reduce(v);lc_base_mlk_poly_tomsg(msg,v);
 }
 cpa_drop(&f);return f.failed?-2:0;
}
int lc_base_mlk512_indcpa_keypair_derand (uint8_t pk[((2 * 384) + 32)], uint8_t sk[((2 * 384))], const uint8_t coins[32], lc_arena * context) {return cpa_key(&cpa_cell,pk,sk,coins,context);}
int lc_base_mlk512_indcpa_enc (uint8_t c[((2 * 320) + 128)], const uint8_t m[32], const uint8_t pk[((2 * 384) + 32)], const uint8_t coins[32], lc_arena * context) {return cpa_enc(&cpa_cell,c,m,pk,coins,context);}
int lc_base_mlk512_indcpa_dec (uint8_t m[(32)], const uint8_t c[((2 * 320) + 128)], const uint8_t sk[((2 * 384))], lc_arena * context)
{return cpa_dec(&cpa_cell,m,c,sk,context);}
__attribute__((warn_unused_result))
int lc_base_mlk512_check_pk (const uint8_t pk[(((2 * 384) + 32))], lc_arena * context)
 ;
__attribute__((warn_unused_result))
int lc_base_mlk512_check_sk (const uint8_t sk[(((2 * 384)) + ((2 * 384) + 32) + 2 * 32)], lc_arena * context)
 ;
__attribute__((warn_unused_result))
int lc_base_mlk512_keypair_derand (uint8_t pk[(((2 * 384) + 32))], uint8_t sk[(((2 * 384)) + ((2 * 384) + 32) + 2 * 32)], const uint8_t coins[2 * 32], lc_arena * context)
 ;
__attribute__((warn_unused_result))
int lc_base_mlk512_enc_derand (uint8_t ct[(((2 * 320) + 128))], uint8_t ss[32], const uint8_t pk[(((2 * 384) + 32))], const uint8_t coins[32], lc_arena * context)
 ;
__attribute__((warn_unused_result))
int lc_base_mlk512_dec (uint8_t ss[32], const uint8_t ct[(((2 * 320) + 128))], const uint8_t sk[(((2 * 384)) + ((2 * 384) + 32) + 2 * 32)], lc_arena * context)
 ;
__attribute__((warn_unused_result))
extern int k24_check_pk(const unsigned char*,unsigned);
/* Fixed public length. One bit in each 16-bit half indicates a decoded value >=3329. */
__attribute__((noinline)) int k24_check_pk(const uint8_t *pk,unsigned n){
 unsigned bad=0;
 while(n){
   unsigned v=pk[0]|((unsigned)pk[1]<<8)|((unsigned)pk[2]<<16);
   unsigned pair=(v&4095u)|((v>>12)<<16);
   bad|=(pair+0x02ff02ffu)&0x10001000u;pk+=3;n-=3;
 }
 return -(int)(((bad|(bad>>16))>>12)*4u&4u);
}
int lc_base_mlk512_check_pk (const uint8_t pk[(((2 * 384) + 32))], lc_arena * context)
{(void)context;return k24_check_pk(pk,768);}

struct a127_fo {
 unsigned pk_bytes, sk_bytes, ct_bytes, cpa_sk_bytes;
 int (*cpa_key)(unsigned char*,unsigned char*,const unsigned char*,lc_arena*);
 int (*cpa_enc)(unsigned char*,const unsigned char*,const unsigned char*,const unsigned char*,lc_arena*);
 int (*cpa_dec)(unsigned char*,const unsigned char*,const unsigned char*,lc_arena*);
 int (*check_pk)(const unsigned char*,lc_arena*);
 int (*pct)(const unsigned char*,const unsigned char*,lc_arena*);
 void (*h)(unsigned char*,const unsigned char*,size_t);
 void (*g)(unsigned char*,const unsigned char*,size_t);
 void (*j)(unsigned char*,size_t,const unsigned char*,size_t);
};

static const struct a127_fo fo_512_combined;
__attribute__((noinline)) int a127_fo_check_sk(const struct a127_fo *route, const uint8_t *sk,lc_arena *context);
__attribute__((noinline)) int a127_fo_keypair_derand(const struct a127_fo *route, uint8_t *pk,uint8_t *sk,const uint8_t *coins,lc_arena *context);
__attribute__((noinline)) int a127_fo_enc_derand(const struct a127_fo *route, uint8_t *ct,uint8_t *ss,const uint8_t *pk,const uint8_t *coins,lc_arena *context);
__attribute__((noinline)) int a127_fo_dec(const struct a127_fo *route, uint8_t *ss,const uint8_t *ct,const uint8_t *sk,lc_arena *context);
__attribute__((warn_unused_result))
int lc_base_mlk512_check_sk (const uint8_t sk[(((2 * 384)) + ((2 * 384) + 32) + 2 * 32)], lc_arena * context)
{return a127_fo_check_sk(&fo_512_combined,sk,context);}
__attribute__((warn_unused_result))
static int mlk_check_pct512 (uint8_t const pk[(((2 * 384) + 32))], uint8_t const sk[(((2 * 384)) + ((2 * 384) + 32) + 2 * 32)], lc_arena * context)
 ;
__attribute__((warn_unused_result))
static int mlk_check_pct512 (uint8_t const pk[(((2 * 384) + 32))], uint8_t const sk[(((2 * 384)) + ((2 * 384) + 32) + 2 * 32)], lc_arena * context)
{
  ((void)pk);
  ((void)sk);
  ((void)(context));
  return 0;
}
__attribute__((warn_unused_result))
int lc_base_mlk512_keypair_derand (uint8_t pk[(((2 * 384) + 32))], uint8_t sk[(((2 * 384)) + ((2 * 384) + 32) + 2 * 32)], const uint8_t coins[2 * 32], lc_arena * context)
{return a127_fo_keypair_derand(&fo_512_combined,pk,sk,coins,context);}
int lc_base_mlk512_enc_derand (uint8_t ct[(((2 * 320) + 128))], uint8_t ss[32], const uint8_t pk[(((2 * 384) + 32))], const uint8_t coins[32], lc_arena * context)
{return a127_fo_enc_derand(&fo_512_combined,ct,ss,pk,coins,context);}
int lc_base_mlk512_dec (uint8_t ss[32], const uint8_t ct[(((2 * 320) + 128))], const uint8_t sk[(((2 * 384)) + ((2 * 384) + 32) + 2 * 32)], lc_arena * context)
{return a127_fo_dec(&fo_512_combined,ss,ct,sk,context);}
int lc_poly_ntt(uint32_t q, uint32_t a[256]);
int lc_poly_intt(uint32_t q, uint32_t a[256]);
int lc_poly_basemul(uint32_t q, uint32_t c[256],const uint32_t a[256],const uint32_t b[256]);
int lc_poly_mul(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]);
int lc_poly_add(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]);
int lc_poly_sub(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]);
static inline int16_t mlk_fqmul(int16_t a, int16_t b)
{
  int16_t res;
  do { } while (0);
  res = mlk_montgomery_reduce((int32_t)a * (int32_t)b);
  do { } while (0);
  return res;
}
static inline int16_t mlk_barrett_reduce(int16_t a)
{
  const int32_t magic = 20159;
  const int32_t t = (magic * a + ((int32_t)1 << 25)) >> 26;
  int16_t res = (int16_t)(a - t * 3329);
  do { } while (0);
  return res;
}
static void mlk_poly_tomont_c(mlk_poly *r)
{
  unsigned i;
  const int16_t f = 1353;
  for (i = 0; i < 256; i++)
  {
    r->coeffs[i] = mlk_fqmul(r->coeffs[i], f);
  }
  do { } while (0);
}
void lc_base_mlk_poly_tomont(mlk_poly *r)
{
  mlk_poly_tomont_c(r);
}
static inline int16_t mlk_scalar_signed_to_unsigned_q(int16_t c)
{
  do { } while (0);
  c = mlk_ct_sel_int16((int16_t)(c + 3329), c, mlk_ct_cmask_neg_i16(c));
  do { } while (0);
  return c;
}
static void mlk_poly_reduce_c(mlk_poly *r)
{
  unsigned i;
  for (i = 0; i < 256; i++)
  {
    int16_t t = mlk_barrett_reduce(r->coeffs[i]);
    r->coeffs[i] = mlk_scalar_signed_to_unsigned_q(t);
  }
  do { } while (0);
}
void lc_base_mlk_poly_reduce(mlk_poly *r)
{
            for(unsigned i=0;i<256;i+=2){
                unsigned packed;
                __asm__("ldr %0,[%1]":"=r"(packed):"r"(r->coeffs+i):"memory");
                int lo,hi;
                __asm__("smlabb %0,%1,%2,%3":"=r"(lo):"r"(packed),"r"(20159),"r"(8192));
                __asm__("smlatb %0,%1,%2,%3":"=r"(hi):"r"(packed),"r"(20159),"r"(8192));
                unsigned q0=(unsigned)(lo>>26)*3329u,q1=(unsigned)(hi>>26)*3329u;
                unsigned sub=(q0&65535u)|(q1<<16),out;
                __asm__("usub16 %0,%1,%2":"=r"(out):"r"(packed),"r"(sub):"cc");
                __asm__("str %0,[%1]"::"r"(out),"r"(r->coeffs+i):"memory");
            }
        }
void lc_base_mlk_poly_add(mlk_poly *r, const mlk_poly *b)
{
  unsigned i;
  for (i = 0; i < 256; i++)
  {
    r->coeffs[i] = (int16_t)(r->coeffs[i] + b->coeffs[i]);
  }
}
void lc_base_mlk_poly_sub(mlk_poly *r, const mlk_poly *b)
{
  unsigned i;
  for (i = 0; i < 256; i++)
  {
    r->coeffs[i] = (int16_t)(r->coeffs[i] - b->coeffs[i]);
  }
}
extern const int16_t a127_mlkem_roots[128];
static void mlk_poly_mulcache_compute_c(mlk_poly_mulcache *x,
                                                     const mlk_poly *a)
{
  unsigned i;
  for (i = 0; i < 256 / 4; i++)
  {
    x->coeffs[2 * i + 0] = mlk_fqmul(a->coeffs[4 * i + 1], a127_mlkem_roots[64 + i]);
    x->coeffs[2 * i + 1] =
        mlk_fqmul(a->coeffs[4 * i + 3], (int16_t)(-a127_mlkem_roots[64 + i]));
  }
  do { } while (0);
}
void lc_base_mlk_poly_mulcache_compute(mlk_poly_mulcache *x, const mlk_poly *a)
{
  mlk_poly_mulcache_compute_c(x, a);
}
static void mlk_ntt_butterfly_block(int16_t r[256], int16_t zeta,
                                    unsigned start, unsigned len,
                                    unsigned bound)
{
  unsigned j;
  ((void)bound);
  for (j = start; j < start + len; j++)
  {
    int16_t t;
    t = mlk_fqmul(r[j + len], zeta);
    r[j + len] = (int16_t)(r[j] - t);
    r[j] = (int16_t)(r[j] + t);
  }
}
static void mlk_ntt_layer(int16_t r[256], unsigned layer)
{
  unsigned start, k, len;
  k = 1u << (layer - 1);
  len = (unsigned)256 >> layer;
  for (start = 0; start < 256; start += 2 * len)
  {
    int16_t zeta = a127_mlkem_roots[k++];
    mlk_ntt_butterfly_block(r, zeta, start, len, layer * 3329);
  }
}
static void mlk_poly_ntt_c(mlk_poly *p)
{
  unsigned layer;
  int16_t *r;
  do { } while (0);
  r = p->coeffs;
  for (layer = 1; layer <= 7; layer++)
  {
    mlk_ntt_layer(r, layer);
  }
  do { } while (0);
}
void lc_base_mlk_poly_ntt(mlk_poly *r)
{pqm20_ntt(r->coeffs);}
static void mlk_invntt_layer(int16_t *r, unsigned layer)
{
  unsigned start, k, len;
  len = (unsigned)256 >> layer;
  k = (1u << layer) - 1;
  for (start = 0; start < 256; start += 2 * len)
  {
    unsigned j;
    int16_t zeta = a127_mlkem_roots[k--];
    for (j = start; j < start + len; j++)
    {
      int16_t t = r[j];
      r[j] = mlk_barrett_reduce((int16_t)(t + r[j + len]));
      r[j + len] = (int16_t)(r[j + len] - t);
      r[j + len] = mlk_fqmul(r[j + len], zeta);
    }
  }
}
static void mlk_poly_invntt_tomont_c(mlk_poly *p)
{
  unsigned j, layer;
  const int16_t f = 1441;
  int16_t *r = p->coeffs;
  for (j = 0; j < 256; j++)
  {
    r[j] = mlk_fqmul(r[j], f);
  }
  for (layer = 7; layer > 0; layer--)
  {
    mlk_invntt_layer(r, layer);
  }
  do { } while (0);
}
void lc_base_mlk_poly_invntt_tomont(mlk_poly *r)
{
       for(unsigned i=0;i<256;i+=2){
          unsigned in,x;int lo,hi;
          __asm__("ldr %0,[%1]":"=r"(in):"r"(r->coeffs+i):"memory");
          __asm__("smlabb %0,%1,%2,%3":"=r"(lo):"r"(in),"r"(20159),"r"(33554432));
          __asm__("smlatb %0,%1,%2,%3":"=r"(hi):"r"(in),"r"(20159),"r"(33554432));
          unsigned n0=(unsigned)(lo>>26)*3329u,n1=(unsigned)(hi>>26)*3329u;
          __asm__("usub16 %0,%1,%2":"=r"(x):"r"(in),"r"((n0&65535u)|(n1<<16)):"cc");
          __asm__("str %0,[%1]"::"r"(x),"r"(r->coeffs+i):"memory");
       }
       pqm33_invntt_fast(r->coeffs,a127_montgomery_twist);
    }
void lc_base_mlk512_polyvec_compress_du(uint8_t r[(2 * 320)],
                             const mlk_polyvec512 *a)
{
  unsigned i;
  do { } while (0);
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk512_poly_compress_du(r + i * 320, &a->vec[i]);
  }
}
void lc_base_mlk512_polyvec_decompress_du(mlk_polyvec512 *r,
                               const uint8_t a[(2 * 320)])
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk512_poly_decompress_du(&r->vec[i], a + i * 320);
  }
  do { } while (0);
}
void lc_base_mlk512_polyvec_tobytes(uint8_t r[(2 * 384)], const mlk_polyvec512 *a)
{
  unsigned i;
  do { } while (0);
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk_poly_tobytes(&r[i * 384], &a->vec[i]);
  }
}
void lc_base_mlk512_polyvec_frombytes(mlk_polyvec512 *r, const uint8_t a[(2 * 384)])
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk_poly_frombytes(&r->vec[i], a + i * 384);
  }
  do { } while (0);
}
void lc_base_mlk512_polyvec_ntt(mlk_polyvec512 *r)
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk_poly_ntt(&r->vec[i]);
  }
  do { } while (0);
}
void lc_base_mlk512_polyvec_invntt_tomont(mlk_polyvec512 *r)
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk_poly_invntt_tomont(&r->vec[i]);
  }
  do { } while (0);
}
static void mlk_polyvec_basemul_acc_montgomery_cached_c512(
    mlk_poly *r, const mlk_polyvec512 *a, const mlk_polyvec512 *b,
    const mlk_polyvec_mulcache512 *b_cache)
{
  unsigned i;
  do { } while (0);
  for (i = 0; i < 256 / 2; i++)
  {
    unsigned k;
    int32_t t[2] = {0};
    for (k = 0; k < 2; k++)
    {
      t[0] += (int32_t)a->vec[k].coeffs[2 * i + 1] * b_cache->vec[k].coeffs[i];
      t[0] += (int32_t)a->vec[k].coeffs[2 * i] * b->vec[k].coeffs[2 * i];
      t[1] += (int32_t)a->vec[k].coeffs[2 * i] * b->vec[k].coeffs[2 * i + 1];
      t[1] += (int32_t)a->vec[k].coeffs[2 * i + 1] * b->vec[k].coeffs[2 * i];
    }
    r->coeffs[2 * i + 0] = mlk_montgomery_reduce(t[0]);
    r->coeffs[2 * i + 1] = mlk_montgomery_reduce(t[1]);
  }
}
void lc_base_mlk512_polyvec_basemul_acc_montgomery_cached(
    mlk_poly *r, const mlk_polyvec512 *a, const mlk_polyvec512 *b,
    const mlk_polyvec_mulcache512 *b_cache)
{arm3329_dot(r,a,0,b,b_cache);}
void lc_base_mlk512_polyvec_mulcache_compute(mlk_polyvec_mulcache512 *x, const mlk_polyvec512 *a)
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk_poly_mulcache_compute(&x->vec[i], &a->vec[i]);
  }
}
void lc_base_mlk512_polyvec_reduce(mlk_polyvec512 *r)
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk_poly_reduce(&r->vec[i]);
  }
  do { } while (0);
}
void lc_base_mlk512_polyvec_add(mlk_polyvec512 *r, const mlk_polyvec512 *b)
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk_poly_add(&r->vec[i], &b->vec[i]);
  }
}
void lc_base_mlk512_polyvec_tomont(mlk_polyvec512 *r)
{
  unsigned i;
  for (i = 0; i < 2; i++)
  {
    lc_base_mlk_poly_tomont(&r->vec[i]);
  }
  do { } while (0);
}
static inline void mlk_poly_cbd_eta1512(
    mlk_poly *r, const uint8_t buf[3 * 256 / 4])
{
  lc_base_mlk_poly_cbd3(r, buf);
}
void lc_base_mlk512_poly_getnoise_eta1_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                               mlk_poly *r3, const uint8_t seed[32],
                               uint8_t nonce0, uint8_t nonce1, uint8_t nonce2,
                               uint8_t nonce3)
{
  __attribute__((aligned(32))) uint8_t buf[4][((((3 * 256 / 4) + (32 - 1)) / 32) * 32)];
  __attribute__((aligned(32))) uint8_t extkey[4][((((32 + 1) + (32 - 1)) / 32) * 32)];
  memcpy(extkey[0], seed, 32);
  memcpy(extkey[1], seed, 32);
  memcpy(extkey[2], seed, 32);
  memcpy(extkey[3], seed, 32);
  extkey[0][32] = nonce0;
  extkey[1][32] = nonce1;
  extkey[2][32] = nonce2;
  extkey[3][32] = nonce3;
  lc_base_mlk_shake256(buf[0], (3) * 256 / 4, extkey[0], 32 + 1);
  lc_base_mlk_shake256(buf[1], (3) * 256 / 4, extkey[1], 32 + 1);
  lc_base_mlk_shake256(buf[2], (3) * 256 / 4, extkey[2], 32 + 1);
  if (r3 != ((void*)0))
  {
    lc_base_mlk_shake256(buf[3], (3) * 256 / 4, extkey[3], 32 + 1);
  }
  mlk_poly_cbd_eta1512(r0, buf[0]);
  mlk_poly_cbd_eta1512(r1, buf[1]);
  mlk_poly_cbd_eta1512(r2, buf[2]);
  if (r3 != ((void*)0))
  {
    mlk_poly_cbd_eta1512(r3, buf[3]);
    do { } while (0);
  }
  do { } while (0);
  do { } while (0);
  do { } while (0);
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
}
static inline void mlk_poly_cbd_eta2512(
    mlk_poly *r, const uint8_t buf[2 * 256 / 4])
{
  lc_base_mlk_poly_cbd2(r, buf);
}
void lc_base_mlk512_poly_getnoise_eta2(mlk_poly *r, const uint8_t seed[32],
                            uint8_t nonce)
{
  __attribute__((aligned(32))) uint8_t buf[2 * 256 / 4];
  __attribute__((aligned(32))) uint8_t extkey[32 + 1];
  memcpy(extkey, seed, 32);
  extkey[32] = nonce;
  lc_base_mlk_shake256(buf, (2) * 256 / 4, extkey, 32 + 1);
  mlk_poly_cbd_eta2512(r, buf);
  do { } while (0);
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
}
void lc_base_mlk512_poly_getnoise_eta1122_4x(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
                                  mlk_poly *r3,
                                  const uint8_t seed[32],
                                  uint8_t nonce0, uint8_t nonce1,
                                  uint8_t nonce2, uint8_t nonce3)
{
  __attribute__((aligned(32))) uint8_t buf[4][((((3 * 256 / 4) + (32 - 1)) / 32) * 32)];
  __attribute__((aligned(32))) uint8_t extkey[4][((((32 + 1) + (32 - 1)) / 32) * 32)];
  memcpy(extkey[0], seed, 32);
  memcpy(extkey[1], seed, 32);
  memcpy(extkey[2], seed, 32);
  memcpy(extkey[3], seed, 32);
  extkey[0][32] = nonce0;
  extkey[1][32] = nonce1;
  extkey[2][32] = nonce2;
  extkey[3][32] = nonce3;
  lc_base_mlk_shake256(buf[0], (3) * 256 / 4, extkey[0], 32 + 1);
  lc_base_mlk_shake256(buf[1], (3) * 256 / 4, extkey[1], 32 + 1);
  lc_base_mlk_shake256(buf[2], (2) * 256 / 4, extkey[2], 32 + 1);
  lc_base_mlk_shake256(buf[3], (2) * 256 / 4, extkey[3], 32 + 1);
  mlk_poly_cbd_eta1512(r0, buf[0]);
  mlk_poly_cbd_eta1512(r1, buf[1]);
  mlk_poly_cbd_eta2512(r2, buf[2]);
  mlk_poly_cbd_eta2512(r3, buf[3]);
  do { } while (0);
  do { } while (0);
  do { } while (0);
  do { } while (0);
  mlk_zeroize(buf, sizeof(buf));
  mlk_zeroize(extkey, sizeof(extkey));
}
static unsigned mlk_rej_uniform_c(int16_t *r, unsigned target,
                                               unsigned offset,
                                               const uint8_t *buf,
                                               unsigned buflen)
{
  unsigned ctr, pos;
  int16_t val0, val1;
  do { } while (0);
  ctr = offset;
  pos = 0;
  while (ctr < target && pos + 3 <= buflen)
  {
    val0 = (int16_t)(((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) &
                     0xFFF);
    val1 = (int16_t)(((buf[pos + 1] >> 4) | (buf[pos + 2] << 4)) & 0xFFF);
    pos += 3;
    if (val0 < 3329)
    {
      r[ctr++] = val0;
    }
    if (ctr < target && val1 < 3329)
    {
      r[ctr++] = val1;
    }
  }
  do { } while (0);
  return ctr;
}
static unsigned mlk_rej_uniform(int16_t *r, unsigned target, unsigned offset,
                                const uint8_t *buf, unsigned buflen)
{
  return mlk_rej_uniform_c(r, target, offset, buf, buflen);
}
void lc_base_mlk_poly_rej_uniform_x4(mlk_poly *vec0, mlk_poly *vec1, mlk_poly *vec2,
                             mlk_poly *vec3,
                             uint8_t seed[4][((((32 + 2) + (32 - 1)) / 32) * 32)])
{
  __attribute__((aligned(32))) uint8_t
      buf[4][((((((12 * 256 / 8 * ((uint32_t)1 << 12) / 3329 + 168) / 168) * 168) + (32 - 1)) / 32) * 32)];
  unsigned ctr[4];
  mlk_shake128x4ctx statex;
  unsigned buflen;
  lc_base_mlk_shake128x4_init((&statex));
  lc_base_mlk_shake128x4_absorb_once((&statex), (seed)[0], (seed)[1], (seed)[2], (seed)[3], (32 + 2));
  lc_base_mlk_shake128x4_squeezeblocks((buf)[0], (buf)[1], (buf)[2], (buf)[3], (((12 * 256 / 8 * ((uint32_t)1 << 12) / 3329 + 168) / 168)), (&statex));
  buflen = ((12 * 256 / 8 * ((uint32_t)1 << 12) / 3329 + 168) / 168) * 168;
  ctr[0] = mlk_rej_uniform(vec0->coeffs, 256, 0, buf[0], buflen);
  ctr[1] = mlk_rej_uniform(vec1->coeffs, 256, 0, buf[1], buflen);
  ctr[2] = mlk_rej_uniform(vec2->coeffs, 256, 0, buf[2], buflen);
  ctr[3] = mlk_rej_uniform(vec3->coeffs, 256, 0, buf[3], buflen);
  buflen = 168;
  while (ctr[0] < 256 || ctr[1] < 256 || ctr[2] < 256 ||
         ctr[3] < 256)
  {
    lc_base_mlk_shake128x4_squeezeblocks((buf)[0], (buf)[1], (buf)[2], (buf)[3], (1), (&statex));
    ctr[0] = mlk_rej_uniform(vec0->coeffs, 256, ctr[0], buf[0], buflen);
    ctr[1] = mlk_rej_uniform(vec1->coeffs, 256, ctr[1], buf[1], buflen);
    ctr[2] = mlk_rej_uniform(vec2->coeffs, 256, ctr[2], buf[2], buflen);
    ctr[3] = mlk_rej_uniform(vec3->coeffs, 256, ctr[3], buf[3], buflen);
  }
  lc_base_mlk_shake128x4_release((&statex));
  mlk_zeroize(buf, sizeof(buf));
}
void lc_base_mlk_poly_rej_uniform(mlk_poly *entry, uint8_t seed[32 + 2])
{
  mlk_shake128ctx state;
  __attribute__((aligned(32))) uint8_t buf[((12 * 256 / 8 * ((uint32_t)1 << 12) / 3329 + 168) / 168) * 168];
  unsigned ctr, buflen;
  lc_base_mlk_shake128_init((&state));
  lc_base_mlk_shake128_absorb_once((&state), (seed), (32 + 2));
  lc_base_mlk_shake128_squeezeblocks((buf), (((12 * 256 / 8 * ((uint32_t)1 << 12) / 3329 + 168) / 168)), (&state));
  buflen = ((12 * 256 / 8 * ((uint32_t)1 << 12) / 3329 + 168) / 168) * 168;
  ctr = mlk_rej_uniform(entry->coeffs, 256, 0, buf, buflen);
  buflen = 168;
  while (ctr < 256)
  {
    lc_base_mlk_shake128_squeezeblocks((buf), (1), (&state));
    ctr = mlk_rej_uniform(entry->coeffs, 256, ctr, buf, buflen);
  }
  lc_base_mlk_shake128_release((&state));
  mlk_zeroize(buf, sizeof(buf));
}
static uint32_t mlk_load32_littleendian(const uint8_t x[4])
{
  uint32_t r;
  r = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  r |= (uint32_t)x[3] << 24;
  return r;
}
void lc_base_mlk_poly_cbd2(mlk_poly *r, const uint8_t buf[2 * 256 / 4])
{
  unsigned i;
  for (i = 0; i < 256 / 8; i++)
  {
    unsigned j;
    uint32_t t = mlk_load32_littleendian(buf + 4 * i);
    uint32_t d = t & 0x55555555;
    d += (t >> 1) & 0x55555555;
    for (j = 0; j < 8; j++)
    {
      const int16_t a = (int16_t)((d >> (4 * j + 0)) & 0x3);
      const int16_t b = (int16_t)((d >> (4 * j + 2)) & 0x3);
      r->coeffs[8 * i + j] = (int16_t)(a - b);
    }
  }
}
static uint32_t mlk_load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}
void lc_base_mlk_poly_cbd3(mlk_poly *r, const uint8_t buf[3 * 256 / 4])
{
  unsigned i;
  for (i = 0; i < 256 / 4; i++)
  {
    unsigned j;
    const uint32_t t = mlk_load24_littleendian(buf + 3 * i);
    uint32_t d = t & 0x00249249;
    d += (t >> 1) & 0x00249249;
    d += (t >> 2) & 0x00249249;
    for (j = 0; j < 4; j++)
    {
      const int16_t a = (int16_t)((d >> (6 * j + 0)) & 0x7);
      const int16_t b = (int16_t)((d >> (6 * j + 3)) & 0x7);
      r->coeffs[4 * i + j] = (int16_t)(a - b);
    }
  }
}
extern int lc_base_mlk512_empty_cu_verify;
static void mlk_keccak_absorb_once(uint64_t *s, unsigned r, const uint8_t *m,
                                   size_t mlen, uint8_t p)
{
  size_t i;
  for (i = 0; i < 25; ++i)
  {
    s[i] = 0;
  }
  while (mlen >= r)
  {
    lc_base_mlk_keccakf1600_xor_bytes(s, m, 0, r);
    lc_base_mlk_keccakf1600_permute(s);
    mlen -= r;
    m += r;
  }
  if (mlen > 0)
  {
    lc_base_mlk_keccakf1600_xor_bytes(s, m, 0, (unsigned int)mlen);
  }
  if (mlen == r - 1)
  {
    p |= 128;
    lc_base_mlk_keccakf1600_xor_bytes(s, &p, (unsigned int)mlen, 1);
  }
  else
  {
    lc_base_mlk_keccakf1600_xor_bytes(s, &p, (unsigned int)mlen, 1);
    p = 128;
    lc_base_mlk_keccakf1600_xor_bytes(s, &p, r - 1, 1);
  }
}
static void mlk_keccak_squeezeblocks(uint8_t *h, size_t nblocks, uint64_t *s,
                                     unsigned r)
{
  while (nblocks > 0)
  {
    lc_base_mlk_keccakf1600_permute(s);
    lc_base_mlk_keccakf1600_extract_bytes(s, h, 0, r);
    h += r;
    nblocks--;
  }
}
static void mlk_keccak_squeeze_once(uint8_t *h, size_t outlen, uint64_t *s,
                                    unsigned r)
{
  size_t len;
  while (outlen > 0)
  {
    lc_base_mlk_keccakf1600_permute(s);
    if (outlen < r)
    {
      len = outlen;
    }
    else
    {
      len = r;
    }
    lc_base_mlk_keccakf1600_extract_bytes(s, h, 0, (unsigned int)len);
    h += len;
    outlen -= len;
  }
}
void lc_base_mlk_shake128_absorb_once(mlk_shake128ctx *state, const uint8_t *input,
                              size_t inlen)
{
  mlk_keccak_absorb_once(state->ctx, 168, input, inlen, 0x1F);
}
void lc_base_mlk_shake128_squeezeblocks(uint8_t *output, size_t nblocks,
                                mlk_shake128ctx *state)
{
  mlk_keccak_squeezeblocks(output, nblocks, state->ctx, 168);
}
void lc_base_mlk_shake128_init(mlk_shake128ctx *state) { (void)state; }
void lc_base_mlk_shake128_release(mlk_shake128ctx *state)
{
  mlk_zeroize(state, sizeof(mlk_shake128ctx));
}
typedef mlk_shake128ctx mlk_shake256ctx;
void lc_base_mlk_shake256(uint8_t *output, size_t outlen, const uint8_t *input,
                  size_t inlen)
{
  mlk_shake256ctx state;
  mlk_keccak_absorb_once(state.ctx, 136, input, inlen, 0x1F);
  mlk_keccak_squeeze_once(output, outlen, state.ctx, 136);
  mlk_zeroize(&state, sizeof(state));
}
void lc_base_mlk_sha3_256(uint8_t *output, const uint8_t *input, size_t inlen)
{
  uint64_t ctx[25];
  mlk_keccak_absorb_once(ctx, 136, input, inlen, 0x06);
  mlk_keccak_squeeze_once(output, 32, ctx, 136);
  mlk_zeroize(ctx, sizeof(ctx));
}
void lc_base_mlk_sha3_512(uint8_t *output, const uint8_t *input, size_t inlen)
{
  uint64_t ctx[25];
  mlk_keccak_absorb_once(ctx, 72, input, inlen, 0x06);
  mlk_keccak_squeeze_once(output, 64, ctx, 72);
  mlk_zeroize(ctx, sizeof(ctx));
}
typedef mlk_shake128x4ctx mlk_shake256x4_ctx;
static void mlk_keccak_absorb_once_x4(uint64_t *s, unsigned r,
                                      const uint8_t *in0, const uint8_t *in1,
                                      const uint8_t *in2, const uint8_t *in3,
                                      size_t inlen, uint8_t p)
{
  while (inlen >= r)
  {
    lc_base_mlk_keccakf1600x4_xor_bytes(s, in0, in1, in2, in3, 0, r);
    lc_base_mlk_keccakf1600x4_permute(s);
    in0 += r;
    in1 += r;
    in2 += r;
    in3 += r;
    inlen -= r;
  }
  if (inlen > 0)
  {
    lc_base_mlk_keccakf1600x4_xor_bytes(s, in0, in1, in2, in3, 0, (unsigned int)inlen);
  }
  if (inlen == r - 1)
  {
    p |= 128;
    lc_base_mlk_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, (unsigned int)inlen, 1);
  }
  else
  {
    lc_base_mlk_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, (unsigned int)inlen, 1);
    p = 128;
    lc_base_mlk_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, r - 1, 1);
  }
}
static void mlk_keccak_squeezeblocks_x4(uint8_t *out0, uint8_t *out1,
                                        uint8_t *out2, uint8_t *out3,
                                        size_t nblocks, uint64_t *s, unsigned r)
{
  size_t current_offset = 0;
  while (nblocks > 0)
  {
    lc_base_mlk_keccakf1600x4_permute(s);
    lc_base_mlk_keccakf1600x4_extract_bytes(
        s, &out0[current_offset], &out1[current_offset], &out2[current_offset],
        &out3[current_offset], 0, r);
    current_offset += r;
    nblocks--;
  }
}
void lc_base_mlk_shake128x4_absorb_once(mlk_shake128x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen)
{
  memset(state, 0, sizeof(mlk_shake128x4ctx));
  mlk_keccak_absorb_once_x4(state->ctx, 168, in0, in1, in2, in3,
                            inlen, 0x1F);
}
void lc_base_mlk_shake128x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mlk_shake128x4ctx *state)
{
  mlk_keccak_squeezeblocks_x4(out0, out1, out2, out3, nblocks, state->ctx,
                              168);
}
void lc_base_mlk_shake128x4_init(mlk_shake128x4ctx *state) { (void)state; }
void lc_base_mlk_shake128x4_release(mlk_shake128x4ctx *state)
{
  mlk_zeroize(state, sizeof(mlk_shake128x4ctx));
}
static void mlk_shake256x4_absorb_once(mlk_shake256x4_ctx *state,
                                       const uint8_t *in0, const uint8_t *in1,
                                       const uint8_t *in2, const uint8_t *in3,
                                       size_t inlen)
{
  memset(state, 0, sizeof(mlk_shake128x4ctx));
  mlk_keccak_absorb_once_x4(state->ctx, 136, in0, in1, in2, in3,
                            inlen, 0x1F);
}
static void mlk_shake256x4_squeezeblocks(uint8_t *out0, uint8_t *out1,
                                         uint8_t *out2, uint8_t *out3,
                                         size_t nblocks,
                                         mlk_shake256x4_ctx *state)
{
  mlk_keccak_squeezeblocks_x4(out0, out1, out2, out3, nblocks, state->ctx,
                              136);
}
void lc_base_mlk_shake256x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
                    size_t outlen, const uint8_t *in0, const uint8_t *in1,
                    const uint8_t *in2, const uint8_t *in3, size_t inlen)
{
  mlk_shake256x4_ctx statex;
  size_t nblocks = outlen / 136;
  uint8_t tmp0[136];
  uint8_t tmp1[136];
  uint8_t tmp2[136];
  uint8_t tmp3[136];
  mlk_shake256x4_absorb_once(&statex, in0, in1, in2, in3, inlen);
  mlk_shake256x4_squeezeblocks(out0, out1, out2, out3, nblocks, &statex);
  out0 += nblocks * 136;
  out1 += nblocks * 136;
  out2 += nblocks * 136;
  out3 += nblocks * 136;
  outlen -= nblocks * 136;
  if (outlen)
  {
    mlk_shake256x4_squeezeblocks(tmp0, tmp1, tmp2, tmp3, 1, &statex);
    memcpy(out0, tmp0, outlen);
    memcpy(out1, tmp1, outlen);
    memcpy(out2, tmp2, outlen);
    memcpy(out3, tmp3, outlen);
  }
  mlk_zeroize(&statex, sizeof(statex));
  mlk_zeroize(tmp0, sizeof(tmp0));
  mlk_zeroize(tmp1, sizeof(tmp1));
  mlk_zeroize(tmp2, sizeof(tmp2));
  mlk_zeroize(tmp3, sizeof(tmp3));
}
void lc_base_mlk_keccakf1600_extract_bytes(uint64_t *state, unsigned char *data,
                                   unsigned offset, unsigned length)
{pqm46_KeccakF1600_StateExtractBytes(state,data,offset,length);}
void lc_base_mlk_keccakf1600_xor_bytes(uint64_t *state, const unsigned char *data,
                               unsigned offset, unsigned length)
{pqm46_KeccakF1600_StateXORBytes(state,data,offset,length);}
static void mlk_keccakf1600x4_extract_bytes_c(uint64_t *state,
                                              unsigned char *data0,
                                              unsigned char *data1,
                                              unsigned char *data2,
                                              unsigned char *data3,
                                              unsigned offset, unsigned length)
{
  lc_base_mlk_keccakf1600_extract_bytes(state + 25 * 0, data0, offset,
                                length);
  lc_base_mlk_keccakf1600_extract_bytes(state + 25 * 1, data1, offset,
                                length);
  lc_base_mlk_keccakf1600_extract_bytes(state + 25 * 2, data2, offset,
                                length);
  lc_base_mlk_keccakf1600_extract_bytes(state + 25 * 3, data3, offset,
                                length);
}
void lc_base_mlk_keccakf1600x4_extract_bytes(uint64_t *state, unsigned char *data0,
                                     unsigned char *data1, unsigned char *data2,
                                     unsigned char *data3, unsigned offset,
                                     unsigned length)
{
  mlk_keccakf1600x4_extract_bytes_c(state, data0, data1, data2, data3, offset,
                                    length);
}
static void mlk_keccakf1600x4_xor_bytes_c(uint64_t *state,
                                          const unsigned char *data0,
                                          const unsigned char *data1,
                                          const unsigned char *data2,
                                          const unsigned char *data3,
                                          unsigned offset, unsigned length)
{
  lc_base_mlk_keccakf1600_xor_bytes(state + 25 * 0, data0, offset,
                            length);
  lc_base_mlk_keccakf1600_xor_bytes(state + 25 * 1, data1, offset,
                            length);
  lc_base_mlk_keccakf1600_xor_bytes(state + 25 * 2, data2, offset,
                            length);
  lc_base_mlk_keccakf1600_xor_bytes(state + 25 * 3, data3, offset,
                            length);
}
void lc_base_mlk_keccakf1600x4_xor_bytes(uint64_t *state, const unsigned char *data0,
                                 const unsigned char *data1,
                                 const unsigned char *data2,
                                 const unsigned char *data3, unsigned offset,
                                 unsigned length)
{
  mlk_keccakf1600x4_xor_bytes_c(state, data0, data1, data2, data3, offset,
                                length);
}
void lc_base_mlk_keccakf1600x4_permute(uint64_t *state)
{
  lc_base_mlk_keccakf1600_permute(state + 25 * 0);
  lc_base_mlk_keccakf1600_permute(state + 25 * 1);
  lc_base_mlk_keccakf1600_permute(state + 25 * 2);
  lc_base_mlk_keccakf1600_permute(state + 25 * 3);
}
static const uint64_t mlk_KeccakF_RoundConstants[24] = {
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
__attribute__((optimize("O3")))
void mlk_keccakf1600_permute_c(uint64_t *state)
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
    Eba ^= (uint64_t)mlk_KeccakF_RoundConstants[round];
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
    Aba ^= (uint64_t)mlk_KeccakF_RoundConstants[round + 1];
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
void lc_base_mlk_keccakf1600_permute(uint64_t *state)
{pqm46_KeccakF1600_StatePermute(state);}
int lc_mlk_call(int level, int op, unsigned char *out1, unsigned char *out2,
    const unsigned char *in1, const unsigned char *in2, lc_arena *arena) {
    switch(level) { case 512: switch(op) { case 0: return lc_base_mlk512_keypair_derand(out1,out2,in1,arena); case 1: return lc_base_mlk512_enc_derand(out1,out2,in1,in2,arena); case 2: return lc_base_mlk512_dec(out1,in1,in2,arena); case 3: return lc_base_mlk512_check_pk(in1,arena); case 4: return lc_base_mlk512_check_sk(in1,arena); } break; }
    return -99;
}

__attribute__((noinline)) int a127_fo_check_sk(const struct a127_fo *route, const uint8_t *sk,lc_arena *context)
{
  int ret = 0;
  uint8_t *test = (uint8_t *)lc_arena_alloc(context,sizeof(uint8_t)*(32));
  if (test == ((void*)0))
  {
    ret = (-2);
    goto cleanup;
  }
  do { } while (0);
  do { } while (0);
  route->h(test, sk + route->cpa_sk_bytes, route->pk_bytes);
  ret = mlk_ct_memcmp(sk + route->sk_bytes - 2 * 32,
                      test, 32)
            ? (-5)
            : 0;
cleanup:
  do { if (test != ((void*)0)) { mlk_zeroize(test, sizeof(uint8_t) * (32)); lc_arena_free(context,test,sizeof(uint8_t)*(32)); test = ((void*)0); } } while (0);
  return ret;
}
__attribute__((noinline)) int a127_fo_keypair_derand(const struct a127_fo *route, uint8_t *pk,uint8_t *sk,const uint8_t *coins,lc_arena *context)
{
  int ret;
  ret = route->cpa_key (pk, sk, coins, context);
  if (ret != 0)
  {
    goto cleanup;
  }
  memcpy(sk + route->cpa_sk_bytes, pk, route->pk_bytes);
  route->h(sk + route->sk_bytes - 2 * 32, pk, route->pk_bytes);
  memcpy(sk + route->sk_bytes - 32,
             coins + 32, 32);
  do { } while (0);
  ret = route->pct (pk, sk, context);
  if (ret != 0)
  {
    goto cleanup;
  }
cleanup:
  if (ret != 0)
  {
    mlk_zeroize(pk, route->pk_bytes);
    mlk_zeroize(sk, route->sk_bytes);
  }
  return ret;
}
__attribute__((noinline)) int a127_fo_enc_derand(const struct a127_fo *route, uint8_t *ct,uint8_t *ss,const uint8_t *pk,const uint8_t *coins,lc_arena *context)
{
  int ret = 0;
  uint8_t *buf = (uint8_t *)lc_arena_alloc(context,sizeof(uint8_t)*(2 * 32));
  uint8_t *kr = (uint8_t *)lc_arena_alloc(context,sizeof(uint8_t)*(2 * 32));
  if (buf == ((void*)0) || kr == ((void*)0))
  {
    ret = (-2);
    goto cleanup;
  }
  ret = route->check_pk (pk, context);
  if (ret != 0)
  {
    goto cleanup;
  }
  memcpy(buf, coins, 32);
  route->h(buf + 32, pk, route->pk_bytes);
  route->g(kr, buf, 2 * 32);
  ret = route->cpa_enc (ct, buf, pk, kr + 32, context);
  if (ret != 0)
  {
    goto cleanup;
  }
  memcpy(ss, kr, 32);
cleanup:
  do { if (kr != ((void*)0)) { mlk_zeroize(kr, sizeof(uint8_t) * (2 * 32)); lc_arena_free(context,kr,sizeof(uint8_t)*(2 * 32)); kr = ((void*)0); } } while (0);
  do { if (buf != ((void*)0)) { mlk_zeroize(buf, sizeof(uint8_t) * (2 * 32)); lc_arena_free(context,buf,sizeof(uint8_t)*(2 * 32)); buf = ((void*)0); } } while (0);
  return ret;
}
__attribute__((noinline)) int a127_fo_dec(const struct a127_fo *route, uint8_t *ss,const uint8_t *ct,const uint8_t *sk,lc_arena *context)
{
  int ret = 0;
  uint8_t fail;
  const uint8_t *pk = sk + route->cpa_sk_bytes;
  uint8_t *buf = (uint8_t *)lc_arena_alloc(context,sizeof(uint8_t)*(2 * 32));
  uint8_t *kr = (uint8_t *)lc_arena_alloc(context,sizeof(uint8_t)*(2 * 32));
  uint8_t *tmp = (uint8_t *)lc_arena_alloc(context,sizeof(uint8_t)*(32 + route->ct_bytes));
  if (buf == ((void*)0) || kr == ((void*)0) || tmp == ((void*)0)
  )
  {
    ret = (-2);
    goto cleanup;
  }
  ret = a127_fo_check_sk(route, sk, context);
  if (ret != 0)
  {
    goto cleanup;
  }
  ret = route->cpa_dec (buf, ct, sk, context);
  if (ret != 0)
  {
    goto cleanup;
  }
  memcpy(buf + 32,
             sk + route->sk_bytes - 2 * 32,
             32);
  route->g(kr, buf, 2 * 32);
  ret = route->cpa_enc (tmp, buf, pk, kr + 32, context);
  if (ret != 0)
  {
    goto cleanup;
  }
  fail = mlk_ct_memcmp(ct, tmp, route->ct_bytes);
  memcpy(tmp, sk + route->sk_bytes - 32,
             32);
  memcpy(tmp + 32, ct, route->ct_bytes);
  route->j(ss, 32, tmp, 32 + route->ct_bytes);
  mlk_ct_cmov_zero(ss, kr, 32, fail);
cleanup:
  do { if (tmp != ((void*)0)) { mlk_zeroize(tmp, sizeof(uint8_t) * (32 + route->ct_bytes)); lc_arena_free(context,tmp,sizeof(uint8_t)*(32 + route->ct_bytes)); tmp = ((void*)0); } } while (0);
  do { if (kr != ((void*)0)) { mlk_zeroize(kr, sizeof(uint8_t) * (2 * 32)); lc_arena_free(context,kr,sizeof(uint8_t)*(2 * 32)); kr = ((void*)0); } } while (0);
  do { if (buf != ((void*)0)) { mlk_zeroize(buf, sizeof(uint8_t) * (2 * 32)); lc_arena_free(context,buf,sizeof(uint8_t)*(2 * 32)); buf = ((void*)0); } } while (0);
  return ret;
}

static const struct a127_fo fo_512_combined={800,1632,768,768,lc_base_mlk512_indcpa_keypair_derand,lc_base_mlk512_indcpa_enc,lc_base_mlk512_indcpa_dec,lc_base_mlk512_check_pk,mlk_check_pct512,lc_base_mlk_sha3_256,lc_base_mlk_sha3_512,lc_base_mlk_shake256};
