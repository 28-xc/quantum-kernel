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

void poly_challenge_compress(uint8_t c[68], const poly *cp);
void poly_challenge_decompress(poly *cp, const uint8_t c[68]);
void poly_schoolbook(poly *c, const uint8_t ccomp[68], const uint8_t *t0);
void poly_schoolbook_t1(poly *c, const uint8_t ccomp[68], const uint8_t *t1);
void polyw_pack(uint8_t buf[3*256], poly *w);
void polyw_unpack(poly *w, const uint8_t buf[3*256]);
void polyw_add(uint8_t buf[3*256], poly *p);
void polyw_sub(poly* c, uint8_t buf[3*256], poly *a);
void poly_highbits(poly *a1, const poly *a);
void poly_lowbits(poly *a0, const poly *a);
void unpack_sk_s1(smallpoly *a, const uint8_t *sk, size_t idx);
void unpack_sk_s2(smallpoly *a, const uint8_t *sk, size_t idx);
void poly_uniform_pointwise_montgomery_polywadd_stack(uint8_t wcomp[3*256], poly *b, const uint8_t seed[32], uint16_t nonce, shake128incctx *state);
void poly_uniform_gamma1_stack(poly *a, const uint8_t seed[64], uint16_t nonce, shake256incctx *state);
void poly_uniform_gamma1_add_stack(poly *a, poly *b, const uint8_t seed[64], uint16_t nonce, shake256incctx *state);
void poly_challenge_stack(poly *c, const uint8_t seed[64]);
size_t poly_make_hint_stack(poly *a, poly *t, uint8_t w[768]);
int unpack_sig_h_indices(uint8_t h_i[75], unsigned int * number_of_hints, unsigned int idx, const unsigned char sig[(64 + 7*640 + (75 + 8))]);
void poly_use_hint_stack(poly *b, const poly *a, uint8_t h_i[75], unsigned int number_of_hints);
void pack_pk_rho(unsigned char pk[(32 + 8*320)],
                 const unsigned char rho[32]);
void pack_pk_t1(unsigned char pk[(32 + 8*320)],
             const poly *t1,
             const unsigned int idx);
void pack_sk_s1(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *s1_elem,
                const unsigned int idx);
void pack_sk_s2(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *s2_elem,
                const unsigned int idx);
void pack_sk_t0(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *t0_elem,
                const unsigned int idx);
void pack_sk_rho(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                 const unsigned char rho[32]);
void pack_sk_key(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                 const unsigned char key[32]);
void pack_sk_tr(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const unsigned char tr[64]);

typedef shake128incctx stream128_state;
typedef shake256incctx stream256_state;
void pqcrystals_dilithium_dilithium_shake128_stream_init(stream128_state *state,
                                    const uint8_t seed[32],
                                    uint16_t nonce);
void pqcrystals_dilithium_dilithium_shake256_stream_init(stream256_state *state,
                                    const uint8_t seed[64],
                                    uint16_t nonce);
void pqcrystals_dilithium_asm_reduce32(int32_t a[256]);
void pqcrystals_dilithium_small_asm_reduce32_central(int32_t a[256]);
void pqcrystals_dilithium_asm_caddq(int32_t a[256]);
void pqcrystals_dilithium_asm_freeze(int32_t a[256]);
unsigned int pqcrystals_dilithium_asm_rej_uniform(int32_t *a,
                         unsigned int len,
                         const unsigned char *buf,
                         unsigned int buflen);
static inline int32_t pqcrystals_dilithium_montgomery_reduce(int64_t a) {
  int32_t t;
  t = (int64_t)(int32_t)a*58728449;
  t = (a - (int64_t)t*8380417) >> 32;
  return t;
}
static int32_t reduce32(int32_t a) {
  int32_t t;
  t = (a + (1 << 22)) >> 23;
  t = a - t*8380417;
  return t;
}
static int32_t caddq(int32_t a) {
  a += (a >> 31) & 8380417;
  return a;
}
static int32_t freeze(int32_t a) {
  a = reduce32(a);
  a = caddq(a);
  return a;
}
int32_t pqcrystals_dilithium_power2round(int32_t *a0, int32_t a);
int32_t pqcrystals_dilithium_decompose(int32_t *a0, int32_t a);
unsigned int pqcrystals_dilithium_make_hint(int32_t a0, int32_t a1);
int32_t pqcrystals_dilithium_use_hint(int32_t a, unsigned int hint);

void poly_challenge_compress(uint8_t c[68], const poly *cp){
  unsigned int i, pos;
  uint64_t signs;
  uint64_t mask;
  for(i=0;i<68;i++) c[i] = 0;
  signs = 0;
  mask = 1;
  pos = 0;
  for(i = 0; i < 256; ++i){
    if(cp->coeffs[i] != 0){
      c[pos++] = i;
      if(cp->coeffs[i] == -1){
        signs |= mask;
      }
      mask <<= 1;
    }
  }
  for (i = 0; i < 8; ++i) {
    c[60+i] = (unsigned char) (signs >> 8 * i);
  }
}
void poly_challenge_decompress(poly *cp, const uint8_t c[68]){
  unsigned int i;
  unsigned pos;
  uint64_t signs = 0;
  for(i = 0; i < 256; i++) cp->coeffs[i] = 0;
  for(i = 0; i < 8; i++) {
    signs |= ((uint64_t)c[60+i]) << (8*i);
  }
  for(i = 0; i < 60; i++){
    pos = c[i];
    if(signs & 1){
      cp->coeffs[pos] = -1;
    } else {
      cp->coeffs[pos] = 1;
    }
    signs >>= 1;
  }
}
static inline int32_t polyt0_unpack_idx(const uint8_t *t0, unsigned idx){
    int32_t coeff;
    t0 += 13*(idx >> 3);
    if(idx % 8 == 0){
        coeff = t0[0];
        coeff |= (uint32_t)t0[1] << 8;
    } else if(idx % 8 == 1){
        coeff = t0[1] >> 5;
        coeff |= (uint32_t)t0[2] << 3;
        coeff |= (uint32_t)t0[3] << 11;
    } else if(idx % 8 == 2){
        coeff = t0[3] >> 2;
        coeff |= (uint32_t)t0[4] << 6;
    } else if(idx % 8 == 3){
        coeff = t0[4] >> 7;
        coeff |= (uint32_t)t0[5] << 1;
        coeff |= (uint32_t)t0[6] << 9;
    } else if(idx % 8 == 4){
        coeff = t0[6] >> 4;
        coeff |= (uint32_t)t0[7] << 4;
        coeff |= (uint32_t)t0[8] << 12;
    } else if(idx % 8 == 5){
        coeff = t0[8] >> 1;
        coeff |= (uint32_t)t0[9] << 7;
    } else if(idx % 8 == 6){
        coeff = t0[9] >> 6;
        coeff |= (uint32_t)t0[10] << 2;
        coeff |= (uint32_t)t0[11] << 10;
    } else if(idx % 8 == 7){
        coeff = t0[11] >> 3;
        coeff |= (uint32_t)t0[12] << 5;
    }
    coeff &= 0x1FFF;
    return (1 << (13 -1)) - coeff;
}
static inline int32_t polyt1_unpack_idx(const uint8_t *t1, unsigned idx){
    int32_t coeff;
    t1 += 5*(idx >> 2);
    if(idx % 4 == 0){
        coeff = (t1[0] >> 0);
        coeff |= ((uint32_t)t1[1] << 8);
    } else if(idx % 4 == 1){
        coeff = (t1[1] >> 2);
        coeff |= ((uint32_t)t1[2] << 6);
    } else if(idx % 4 == 2){
        coeff = (t1[2] >> 4);
        coeff |= ((uint32_t)t1[3] << 4);
    } else if(idx % 4 == 3){
        coeff = (t1[3] >> 6);
        coeff |= ((uint32_t)t1[4] << 2);
    }
    coeff &= 0x3FF;
    return coeff;
}
void poly_schoolbook(poly *c, const uint8_t ccomp[68], const uint8_t *t0){
  unsigned i,j,idx;
  uint64_t signs = 0;
  for(i = 0; i < 256; i++) c->coeffs[i] = 0;
  for(i = 0; i < 8; i++) {
    signs |= ((uint64_t)ccomp[60+i]) << (8*i);
  }
  for(idx = 0; idx < 60; idx++){
    i = ccomp[idx];
    if(!(signs & 1)){
        for(j = 0; i+j < 256; j++){
            c->coeffs[i+j] += polyt0_unpack_idx(t0, j);
        }
        for(j = 256 -i; j<256; j++){
            c->coeffs[i+j-256] -= polyt0_unpack_idx(t0, j);
        }
    } else {
        for(j = 0; i+j < 256; j++){
            c->coeffs[i+j] -= polyt0_unpack_idx(t0, j);
        }
        for(j = 256 -i; j<256; j++){
            c->coeffs[i+j-256] += polyt0_unpack_idx(t0, j);
        }
    }
    signs >>= 1;
  }
}
void poly_schoolbook_t1(poly *c, const uint8_t ccomp[68], const uint8_t *t1){
  unsigned i,j,idx;
  uint64_t signs = 0;
  for(i = 0; i < 256; i++) c->coeffs[i] = 0;
  for(i = 0; i < 8; i++) {
    signs |= ((uint64_t)ccomp[60+i]) << (8*i);
  }
  for(idx = 0; idx < 60; idx++){
    i = ccomp[idx];
    if(!(signs & 1)){
        for(j = 0; i+j < 256; j++){
            c->coeffs[i+j] += (polyt1_unpack_idx(t1, j) << 13);
        }
        for(j = 256 -i; j<256; j++){
            c->coeffs[i+j-256] -= (polyt1_unpack_idx(t1, j) << 13);
        }
    } else {
        for(j = 0; i+j < 256; j++){
            c->coeffs[i+j] -= (polyt1_unpack_idx(t1, j) << 13);
        }
        for(j = 256 -i; j<256; j++){
            c->coeffs[i+j-256] += (polyt1_unpack_idx(t1, j) << 13);
        }
    }
    signs >>= 1;
  }
}
void polyw_pack(uint8_t buf[3*256], poly *w){
  pqcrystals_dilithium_poly_reduce(w);
  pqcrystals_dilithium_poly_caddq(w);
  unsigned int i;
  for(i = 0; i < 256; i++){
    buf[i*3 + 0] = w->coeffs[i];
    buf[i*3 + 1] = w->coeffs[i] >> 8;
    buf[i*3 + 2] = w->coeffs[i] >> 16;
  }
}
void polyw_unpack(poly *w, const uint8_t buf[3*256]) {
  unsigned int i;
  for(i = 0; i < 256; i++){
    w->coeffs[i] = buf[i*3 + 0];
    w->coeffs[i] |= (int32_t)buf[i*3 + 1] << 8;
    w->coeffs[i] |= (int32_t)buf[i*3 + 2] << 16;
  }
}
static void polyw_add_idx(uint8_t buf[3*256], int32_t a, size_t i){
  int32_t coeff;
  coeff = buf[i*3 + 0];
  coeff |= (int32_t)buf[i*3 + 1] << 8;
  coeff |= (int32_t)buf[i*3 + 2] << 16;
  coeff += a;
  coeff = freeze(coeff);
  buf[i*3 + 0] = coeff;
  buf[i*3 + 1] = coeff >> 8;
  buf[i*3 + 2] = coeff >> 16;
}
void polyw_add(uint8_t buf[3*256], poly *p){
  unsigned int i;
  for(i = 0; i < 256; i++){
    polyw_add_idx(buf, p->coeffs[i], i);
  }
}
void polyw_sub(poly* c, uint8_t buf[3*256], poly *a){
  int32_t coeff;
  for(size_t i=0;i<256;i++){
    coeff = buf[i*3 + 0];
    coeff |= (int32_t)buf[i*3 + 1] << 8;
    coeff |= (int32_t)buf[i*3 + 2] << 16;
    c->coeffs[i] = coeff - a->coeffs[i];
  }
}
static int32_t highbits(int32_t a){
  int32_t a1;
  a1 = (a + 127) >> 7;
  a1 = (a1*1025 + (1 << 21)) >> 22;
  a1 &= 15;
  return a1;
}
void poly_highbits(poly *a1, const poly *a) {
  unsigned int i;
  for(i = 0; i < 256; ++i)
    a1->coeffs[i] = highbits(a->coeffs[i]);
}
static int32_t lowbits(int32_t a){
  int32_t a1;
  int32_t a0;
  a1 = (a + 127) >> 7;
  a1 = (a1*1025 + (1 << 21)) >> 22;
  a1 &= 15;
  a0 = a - a1*2*((8380417 -1)/32);
  a0 -= (((8380417 -1)/2 - a0) >> 31) & 8380417;
  return a0;
}
void poly_lowbits(poly *a0, const poly *a){
  unsigned int i;
  for(i = 0; i < 256; ++i)
    a0->coeffs[i] = lowbits(a->coeffs[i]);
}
void unpack_sk_s1(smallpoly *a, const uint8_t *sk, size_t idx) {
  small_polyeta_unpack(a, sk + 2*32 + 64 + idx*96);
}
void unpack_sk_s2(smallpoly *a, const uint8_t *sk, size_t idx) {
  small_polyeta_unpack(a, sk + 2*32 + 64 + 7*96 + idx*96);
}
void poly_uniform_pointwise_montgomery_polywadd_stack(uint8_t wcomp[3*256], poly *b, const uint8_t seed[32], uint16_t nonce, shake128incctx *state){
  int32_t t;
  uint8_t buf[3*3];
  {
    size_t ctr = 0;
    pqcrystals_dilithium_dilithium_shake128_stream_init(state, seed, nonce);
    do {
      shake128_inc_squeeze(buf, sizeof buf, state);
      for(size_t pos=0; pos < sizeof buf && ctr < 256; pos += 3){
        t = buf[pos];
        t |= (uint32_t)buf[pos+1] << 8;
        t |= (uint32_t)buf[pos+2] << 16;
        t &= 0x7FFFFF;
        if(t < 8380417) {
          t = pqcrystals_dilithium_montgomery_reduce((int64_t)t * b->coeffs[ctr]);
          polyw_add_idx(wcomp, t, ctr);
          ctr++;
        }
      }
    } while(ctr < 256);
  }
}
static void polyz_unpack_inplace(int32_t *r){
  uint8_t *a = (uint8_t *)r;
  unsigned int i,j;
  for(j = 0; j < 1; ++j) {
    i = 1 -1-j;
    int32_t tmp0, tmp1;
    tmp0 = a[5*i+2] >> 4;
    tmp0 |= (uint32_t)a[5*i+3] << 4;
    tmp0 |= (uint32_t)a[5*i+4] << 12;
    tmp0 &= 0xFFFFF;
    tmp1 = a[5*i+0];
    tmp1 |= (uint32_t)a[5*i+1] << 8;
    tmp1 |= (uint32_t)a[5*i+2] << 16;
    tmp1 &= 0xFFFFF;
    r[2*i+0] = (1 << 19) - tmp1;
    r[2*i+1] = (1 << 19) - tmp0;
  }
}
void poly_uniform_gamma1_stack(poly *a, const uint8_t seed[64], uint16_t nonce, shake256incctx *state){
  int32_t buf[(1*2)];
  pqcrystals_dilithium_dilithium_shake256_stream_init(state, seed, nonce);
  for(size_t i = 0; i < 256/(1*2); i++){
    shake256_inc_squeeze((uint8_t *)buf, (1*5), state);
    polyz_unpack_inplace(buf);
    for(size_t j = 0; j < (1*2); j++){
      a->coeffs[i*(1*2) + j] = buf[j];
    }
  }
}
void poly_uniform_gamma1_add_stack(poly *a, poly *b, const uint8_t seed[64], uint16_t nonce, shake256incctx *state){
  int32_t buf[(1*2)];
  pqcrystals_dilithium_dilithium_shake256_stream_init(state, seed, nonce);
  for(size_t i = 0; i < 256/(1*2); i++){
    shake256_inc_squeeze((uint8_t *)buf, (1*5), state);
    polyz_unpack_inplace(buf);
    for(size_t j = 0; j < (1*2); j++){
      a->coeffs[i*(1*2) + j] = buf[j] + b->coeffs[i*(1*2) + j];
    }
  }
}
static inline int32_t make_hint_stack(int32_t z, int32_t r){
  int32_t r1, v1;
  r1 = highbits(r);
  v1 = highbits(r+z);
  if(r1 != v1) return 1;
  return 0;
}
size_t poly_make_hint_stack(poly *a, poly *t, uint8_t w[768]){
  int32_t coeff;
  size_t hints_n = 0;
  for(size_t i=0;i<256;i++){
    coeff = w[i*3 + 0];
    coeff |= (int32_t)w[i*3 + 1] << 8;
    coeff |= (int32_t)w[i*3 + 2] << 16;
    coeff = coeff + t->coeffs[i];
    a->coeffs[i] = make_hint_stack(-t->coeffs[i], coeff);
    if(a->coeffs[i] == 1){
      hints_n++;
    }
  }
  return hints_n;
}
int unpack_sig_h_indices(uint8_t h_i[75], unsigned int * number_of_hints, unsigned int idx, const unsigned char sig[(64 + 7*640 + (75 + 8))]) {
    sig += 7 * 640;
    sig += 64;
    unsigned int k = 0;
    unsigned int hidx = 0;
    if (idx > 0)
    {
        k = sig[75 + (idx - 1)];
    }
    if (sig[75 + idx] < k || sig[75 + idx] > 75) {
        return 1;
    }
    for (unsigned int j = k; j < sig[75 + idx]; ++j) {
        if (j > k && sig[j] <= sig[j - 1]) {
            return 1;
        }
        h_i[hidx++] = sig[j];
    }
    *number_of_hints = hidx;
    k = sig[75 + (8 - 1)];
    for (unsigned int j = k; j < 75; ++j) {
        if (sig[j]) {
            return 1;
        }
    }
    return 0;
}
void poly_use_hint_stack(poly *b, const poly *a, uint8_t h_i[75], unsigned int number_of_hints) {
  unsigned int i;
  unsigned int in_list;
  for(i = 0; i < 256; ++i)
  {
    in_list = 0;
    for (size_t hidx = 0; hidx < number_of_hints; hidx++)
    {
      if (i == h_i[hidx])
      {
        in_list = 1;
        break;
      }
    }
    if (in_list)
    {
      b->coeffs[i] = pqcrystals_dilithium_use_hint(a->coeffs[i], 1);
    }
    else
    {
      b->coeffs[i] = pqcrystals_dilithium_use_hint(a->coeffs[i], 0);
    }
  }
}
void pack_pk_rho(unsigned char pk[(32 + 8*320)],
                 const unsigned char rho[32]) {
    for (unsigned int i = 0; i < 32; ++i) {
        pk[i] = rho[i];
    }
}
void pack_pk_t1(unsigned char pk[(32 + 8*320)],
             const poly *t1,
             const unsigned int idx) {
    pk += 32;
    pqcrystals_dilithium_polyt1_pack(pk + idx * 320, t1);
}
void pack_sk_s1(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *s1_elem,
                const unsigned int idx) {
    sk += 2 * 32 + 64;
    pqcrystals_dilithium_polyeta_pack(sk + idx * 96, s1_elem);
}
void pack_sk_s2(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *s2_elem,
                const unsigned int idx) {
    sk += 2 * 32 + 64 + 7 * 96;
    pqcrystals_dilithium_polyeta_pack(sk + idx * 96, s2_elem);
}
void pack_sk_t0(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *t0_elem,
                const unsigned int idx) {
    sk += 2 * 32 + 64 + 7 * 96 + 8 * 96;
    pqcrystals_dilithium_polyt0_pack(sk + idx * 416, t0_elem);
}
void pack_sk_rho(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                 const unsigned char rho[32]) {
  for (unsigned int i = 0; i < 32; ++i) {
    sk[i] = rho[i];
  }
}
void pack_sk_key(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                 const unsigned char key[32]) {
    sk += 32;
    for (unsigned int i = 0; i < 32; ++i) {
      sk[i] = key[i];
    }
}
void pack_sk_tr(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const unsigned char tr[64]) {
    sk += 2*32;
    for (unsigned int i = 0; i < 64; ++i) {
        sk[i] = tr[i];
    }
}
void poly_challenge_stack(poly *c, const uint8_t seed[64]) {
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t buf[8];
  shake256incctx state;
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, seed, 64);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(buf, 8, &state);
  signs = 0;
  for(i = 0; i < 8; ++i)
  {
    signs |= (uint64_t)buf[i] << 8*i;
  }
  pos = 8;
  for(i = 0; i < 256; ++i)
    c->coeffs[i] = 0;
  for(i = 256 -60; i < 256; ++i) {
    do {
      if(pos >= 8) {
        shake256_inc_squeeze(buf, 8, &state);
        pos = 0;
      }
      b = buf[pos++];
    } while(b > i);
    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1 - 2*(signs & 1);
    signs >>= 1;
  }
}
