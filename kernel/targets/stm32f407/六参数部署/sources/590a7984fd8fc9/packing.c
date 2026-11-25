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

typedef struct {
  int32_t coeffs[256];
} poly;
void pqcrystals_dilithium_poly_reduce(poly *a);
void pqcrystals_dilithium_poly_caddq(poly *a);
void pqcrystals_dilithium_poly_freeze(poly *a);
void pqcrystals_dilithium_poly_add(poly *c, const poly *a, const poly *b);
void pqcrystals_dilithium_poly_sub(poly *c, const poly *a, const poly *b);
void pqcrystals_dilithium_poly_shiftl(poly *a);
void pqcrystals_dilithium_poly_ntt(poly *a);
void pqcrystals_dilithium_poly_invntt_tomont(poly *a);
void pqcrystals_dilithium_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);
void pqcrystals_dilithium_poly_pointwise_acc_montgomery(poly *c, const poly *a, const poly *b);
void pqcrystals_dilithium_poly_power2round(poly *a1, poly *a0, const poly *a);
void pqcrystals_dilithium_poly_decompose(poly *a1, poly *a0, const poly *a);
unsigned int pqcrystals_dilithium_poly_make_hint(poly *h, const poly *a0, const poly *a1);
void pqcrystals_dilithium_poly_use_hint(poly *b, const poly *a, const poly *h);
int pqcrystals_dilithium_poly_chknorm(const poly *a, int32_t B);
void pqcrystals_dilithium_poly_uniform(poly *a,
                  const uint8_t seed[32],
                  uint16_t nonce);
void pqcrystals_dilithium_poly_uniform_eta(poly *a,
                      const uint8_t seed[64],
                      uint16_t nonce);
void pqcrystals_dilithium_poly_uniform_gamma1(poly *a,
                         const uint8_t seed[64],
                         uint16_t nonce);
void pqcrystals_dilithium_poly_challenge(poly *c, const uint8_t seed[64]);
void pqcrystals_dilithium_polyeta_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt1_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt1_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyt0_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt0_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyz_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyz_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyw1_pack(uint8_t *r, const poly *a);
typedef struct {
  poly vec[7];
} polyvecl;
void pqcrystals_dilithium_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[64], uint16_t nonce);
void pqcrystals_dilithium_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[64], uint16_t nonce);
void pqcrystals_dilithium_polyvecl_reduce(polyvecl *v);
void pqcrystals_dilithium_polyvecl_freeze(polyvecl *v);
void pqcrystals_dilithium_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
void pqcrystals_dilithium_polyvecl_ntt(polyvecl *v);
void pqcrystals_dilithium_polyvecl_invntt_tomont(polyvecl *v);
void pqcrystals_dilithium_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
void pqcrystals_dilithium_polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v);
int pqcrystals_dilithium_polyvecl_chknorm(const polyvecl *v, int32_t B);
typedef struct {
  poly vec[8];
} polyveck;
void pqcrystals_dilithium_polyveck_uniform_eta(polyveck *v, const uint8_t seed[64], uint16_t nonce);
void pqcrystals_dilithium_polyveck_reduce(polyveck *v);
void pqcrystals_dilithium_polyveck_caddq(polyveck *v);
void pqcrystals_dilithium_polyveck_freeze(polyveck *v);
void pqcrystals_dilithium_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void pqcrystals_dilithium_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void pqcrystals_dilithium_polyveck_shiftl(polyveck *v);
void pqcrystals_dilithium_polyveck_ntt(polyveck *v);
void pqcrystals_dilithium_polyveck_invntt_tomont(polyveck *v);
void pqcrystals_dilithium_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);
int pqcrystals_dilithium_polyveck_chknorm(const polyveck *v, int32_t B);
void pqcrystals_dilithium_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void pqcrystals_dilithium_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int pqcrystals_dilithium_polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);
void pqcrystals_dilithium_polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);
void pqcrystals_dilithium_polyveck_pack_w1(uint8_t r[8*128], const polyveck *w1);
void pqcrystals_dilithium_polyvec_matrix_expand(polyvecl mat[8], const uint8_t rho[32]);
void pqcrystals_dilithium_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[8], const polyvecl *v);
typedef struct {
    int16_t coeffs[256];
} smallpoly;
typedef smallpoly smallhalfpoly;
void poly_small_ntt_copy(smallpoly*, poly*);
void polyvecl_small_ntt(smallpoly v[7]);
void polyveck_small_ntt(smallpoly v[8]);
void polyvecl_small_basemul_invntt(polyvecl *r, const smallpoly *a, const smallpoly b[7]);
void poly_small_basemul_invntt(poly *r, const smallpoly *a, const smallpoly *b);
void small_polyeta_unpack(smallpoly *r, const uint8_t *a);
void pqcrystals_dilithium_pack_pk(uint8_t pk[(32 + 8*320)], const uint8_t rho[32], const polyveck *t1);
void pqcrystals_dilithium_pack_sk(uint8_t sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
             const uint8_t rho[32],
             const uint8_t tr[64],
             const uint8_t key[32],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);
void pqcrystals_dilithium_pack_sig(uint8_t sig[(64 + 7*640 + (75 + 8))], const uint8_t c[64], const polyvecl *z, const polyveck *h);
void pqcrystals_dilithium_unpack_pk(uint8_t rho[32], polyveck *t1, const uint8_t pk[(32 + 8*320)]);
void pqcrystals_dilithium_unpack_pk_t1(poly *t1, size_t idx, const unsigned char pk[(32 + 8*320)]);
void pqcrystals_dilithium_unpack_sk(uint8_t rho[32],
               uint8_t tr[64],
               uint8_t key[32],
               polyveck *t0,
               smallpoly s1[7],
               smallpoly s2[8],
               const uint8_t sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)]);
int pqcrystals_dilithium_unpack_sig(uint8_t c[64], polyvecl *z, polyveck *h, const uint8_t sig[(64 + 7*640 + (75 + 8))]);
int pqcrystals_dilithium_unpack_sig_z(polyvecl *z, const unsigned char sig[(64 + 7*640 + (75 + 8))]);
int pqcrystals_dilithium_unpack_sig_h(poly *h, size_t idx, const unsigned char sig[(64 + 7*640 + (75 + 8))]);
int pqcrystals_dilithium_unpack_sig_c(uint8_t c[64], const unsigned char sig[(64 + 7*640 + (75 + 8))]);
void pqcrystals_dilithium_pack_sig_c(uint8_t sig[(64 + 7*640 + (75 + 8))], const uint8_t c[64]);
void pqcrystals_dilithium_pack_sig_z(uint8_t sig[(64 + 7*640 + (75 + 8))], const polyvecl *z);
void pqcrystals_dilithium_pack_sig_h(unsigned char sig[(64 + 7*640 + (75 + 8))],
                const poly *h_elem,
                const unsigned int idx,
                unsigned int *hints_written);
void pqcrystals_dilithium_pack_sig_h_zero(unsigned char sig[(64 + 7*640 + (75 + 8))],
                unsigned int *hints_written);
void pqcrystals_dilithium_pack_pk(uint8_t pk[(32 + 8*320)],
             const uint8_t rho[32],
             const polyveck *t1)
{
  unsigned int i;
  for(i = 0; i < 32; ++i)
    pk[i] = rho[i];
  pk += 32;
  for(i = 0; i < 8; ++i)
    pqcrystals_dilithium_polyt1_pack(pk + i*320, &t1->vec[i]);
}
void pqcrystals_dilithium_unpack_pk(uint8_t rho[32],
               polyveck *t1,
               const uint8_t pk[(32 + 8*320)])
{
  unsigned int i;
  for(i = 0; i < 32; ++i)
    rho[i] = pk[i];
  pk += 32;
  for(i = 0; i < 8; ++i)
    pqcrystals_dilithium_polyt1_unpack(&t1->vec[i], pk + i*320);
}
void pqcrystals_dilithium_unpack_pk_t1(poly *t1, size_t idx, const unsigned char pk[(32 + 8*320)]) {
    pk += 32;
    pqcrystals_dilithium_polyt1_unpack(t1, pk + idx * 320);
}
void pqcrystals_dilithium_pack_sk(uint8_t sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
             const uint8_t rho[32],
             const uint8_t tr[64],
             const uint8_t key[32],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2)
{
  unsigned int i;
  for(i = 0; i < 32; ++i)
    sk[i] = rho[i];
  sk += 32;
  for(i = 0; i < 32; ++i)
    sk[i] = key[i];
  sk += 32;
  for(i = 0; i < 64; ++i)
    sk[i] = tr[i];
  sk += 64;
  for(i = 0; i < 7; ++i)
    pqcrystals_dilithium_polyeta_pack(sk + i*96, &s1->vec[i]);
  sk += 7*96;
  for(i = 0; i < 8; ++i)
    pqcrystals_dilithium_polyeta_pack(sk + i*96, &s2->vec[i]);
  sk += 8*96;
  for(i = 0; i < 8; ++i)
    pqcrystals_dilithium_polyt0_pack(sk + i*416, &t0->vec[i]);
}
void pqcrystals_dilithium_unpack_sk(uint8_t rho[32],
               uint8_t tr[64],
               uint8_t key[32],
               polyveck *t0,
               smallpoly s1[7],
               smallpoly s2[8],
               const uint8_t sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)])
{
  unsigned int i;
  for(i = 0; i < 32; ++i)
    rho[i] = sk[i];
  sk += 32;
  for(i = 0; i < 32; ++i)
    key[i] = sk[i];
  sk += 32;
  for(i = 0; i < 64; ++i)
    tr[i] = sk[i];
  sk += 64;
  for(i=0; i < 7; ++i)
    small_polyeta_unpack(&s1[i], sk + i*96);
  sk += 7*96;
  for(i=0; i < 8; ++i)
    small_polyeta_unpack(&s2[i], sk + i*96);
  sk += 8*96;
  for(i=0; i < 8; ++i)
    pqcrystals_dilithium_polyt0_unpack(&t0->vec[i], sk + i*416);
}
void pqcrystals_dilithium_pack_sig(uint8_t sig[(64 + 7*640 + (75 + 8))],
              const uint8_t c[64],
              const polyvecl *z,
              const polyveck *h)
{
  unsigned int i, j, k;
  for(i=0; i < 64; ++i)
    sig[i] = c[i];
  sig += 64;
  for(i = 0; i < 7; ++i)
    pqcrystals_dilithium_polyz_pack(sig + i*640, &z->vec[i]);
  sig += 7*640;
  for(i = 0; i < 75 + 8; ++i)
    sig[i] = 0;
  k = 0;
  for(i = 0; i < 8; ++i) {
    for(j = 0; j < 256; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;
    sig[75 + i] = k;
  }
}
void pqcrystals_dilithium_pack_sig_c(uint8_t sig[(64 + 7*640 + (75 + 8))],
              const uint8_t c[64])
{
  unsigned int i;
  for(i=0; i < 64; ++i)
    sig[i] = c[i];
  sig += 64;
}
void pqcrystals_dilithium_pack_sig_z(uint8_t sig[(64 + 7*640 + (75 + 8))],
              const polyvecl *z)
{
  unsigned int i;
  sig += 64;
  for(i = 0; i < 7; ++i)
    pqcrystals_dilithium_polyz_pack(sig + i*640, &z->vec[i]);
}
void pqcrystals_dilithium_pack_sig_h(unsigned char sig[(64 + 7*640 + (75 + 8))],
                const poly *h_elem,
                const unsigned int idx,
                unsigned int *hints_written)
{
  sig += 64;
  sig += 7*640;
  for (unsigned int j = 0; j < 256; j++) {
      if (h_elem->coeffs[j] != 0) {
          sig[*hints_written] = (uint8_t)j;
          (*hints_written)++;
      }
  }
  sig[75 + idx] = (uint8_t)*hints_written;
}
void pqcrystals_dilithium_pack_sig_h_zero(unsigned char sig[(64 + 7*640 + (75 + 8))],
                unsigned int *hints_written) {
    sig += 64;
    sig += 7 * 640;
    while (*hints_written < 75) {
        sig[*hints_written] = 0;
        (*hints_written)++;
    }
}
int pqcrystals_dilithium_unpack_sig(uint8_t c[64],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[(64 + 7*640 + (75 + 8))])
{
  unsigned int i, j, k;
  for(i = 0; i < 64; ++i)
    c[i] = sig[i];
  sig += 64;
  for(i = 0; i < 7; ++i)
    pqcrystals_dilithium_polyz_unpack(&z->vec[i], sig + i*640);
  sig += 7*640;
  k = 0;
  for(i = 0; i < 8; ++i) {
    for(j = 0; j < 256; ++j)
      h->vec[i].coeffs[j] = 0;
    if(sig[75 + i] < k || sig[75 + i] > 75)
      return 1;
    for(j = k; j < sig[75 + i]; ++j) {
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }
    k = sig[75 + i];
  }
  for(j = k; j < 75; ++j)
    if(sig[j])
      return 1;
  return 0;
}
int pqcrystals_dilithium_unpack_sig_c(uint8_t c[64], const unsigned char sig[(64 + 7*640 + (75 + 8))]) {
  for(size_t i = 0; i < 64; ++i)
    c[i] = sig[i];
  sig += 64;
  return 0;
}
int pqcrystals_dilithium_unpack_sig_z(polyvecl *z, const unsigned char sig[(64 + 7*640 + (75 + 8))]) {
    sig += 64;
    for (size_t i = 0; i < 7; ++i) {
        pqcrystals_dilithium_polyz_unpack(&z->vec[i], sig + i * 640);
    }
    return 0;
}
int pqcrystals_dilithium_unpack_sig_h(poly *h, size_t idx, const unsigned char sig[(64 + 7*640 + (75 + 8))]) {
    sig += 64;
    sig += 7 * 640;
    size_t k = 0;
    for (size_t i = 0; i < 8; ++i) {
        for (size_t j = 0; j < 256; ++j) {
            if (i == idx) {
                h->coeffs[j] = 0;
            }
        }
        if (sig[75 + i] < k || sig[75 + i] > 75) {
            return 1;
        }
        for (size_t j = k; j < sig[75 + i]; ++j) {
            if (j > k && sig[j] <= sig[j - 1]) {
                return 1;
            }
            if (i == idx) {
                h->coeffs[sig[j]] = 1;
            }
        }
        k = sig[75 + i];
    }
    for (size_t j = k; j < 75; ++j) {
        if (sig[j]) {
            return 1;
        }
    }
    return 0;
}
