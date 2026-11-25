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
void pqcrystals_dilithium_asm_reduce32(int32_t a[256]);
void pqcrystals_dilithium_small_asm_reduce32_central(int32_t a[256]);
void pqcrystals_dilithium_asm_caddq(int32_t a[256]);
void pqcrystals_dilithium_asm_freeze(int32_t a[256]);
unsigned int pqcrystals_dilithium_asm_rej_uniform(int32_t *a,
                         unsigned int len,
                         const unsigned char *buf,
                         unsigned int buflen);
void pqcrystals_dilithium_ntt(int32_t a[256]);
void pqcrystals_dilithium_invntt_tomont(int32_t a[256]);
void pqcrystals_dilithium_asm_pointwise_montgomery(int32_t c[256], const int32_t a[256], const int32_t b[256]);
void pqcrystals_dilithium_asm_pointwise_acc_montgomery(int32_t c[256], const int32_t a[256], const int32_t b[256]);
int32_t pqcrystals_dilithium_power2round(int32_t *a0, int32_t a);
int32_t pqcrystals_dilithium_decompose(int32_t *a0, int32_t a);
unsigned int pqcrystals_dilithium_make_hint(int32_t a0, int32_t a1);
int32_t pqcrystals_dilithium_use_hint(int32_t a, unsigned int hint);
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
typedef shake128incctx stream128_state;
typedef shake256incctx stream256_state;
void pqcrystals_dilithium_dilithium_shake128_stream_init(stream128_state *state,
                                    const uint8_t seed[32],
                                    uint16_t nonce);
void pqcrystals_dilithium_dilithium_shake256_stream_init(stream256_state *state,
                                    const uint8_t seed[64],
                                    uint16_t nonce);

void pqcrystals_dilithium_poly_reduce(poly *a) {
  pqcrystals_dilithium_asm_reduce32(a->coeffs);
}
void pqcrystals_dilithium_poly_caddq(poly *a) {
  pqcrystals_dilithium_asm_caddq(a->coeffs);
}
void pqcrystals_dilithium_poly_add(poly *c, const poly *a, const poly *b) {
  unsigned int i;
                ;
  for(i = 0; i < 256; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
                    ;
}
void pqcrystals_dilithium_poly_sub(poly *c, const poly *a, const poly *b) {
  unsigned int i;
                ;
  for(i = 0; i < 256; ++i)
    c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
                    ;
}
void pqcrystals_dilithium_poly_shiftl(poly *a) {
  unsigned int i;
                ;
  for(i = 0; i < 256; ++i)
    a->coeffs[i] <<= 13;
                    ;
}
void pqcrystals_dilithium_poly_ntt(poly *a) {
                ;
  pqcrystals_dilithium_ntt(a->coeffs);
                    ;
}
void pqcrystals_dilithium_poly_invntt_tomont(poly *a) {
                ;
  pqcrystals_dilithium_invntt_tomont(a->coeffs);
                    ;
}
void pqcrystals_dilithium_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
                ;
  pqcrystals_dilithium_asm_pointwise_montgomery(c->coeffs, a->coeffs, b->coeffs);
                    ;
}
void pqcrystals_dilithium_poly_pointwise_acc_montgomery(poly *c, const poly *a, const poly *b) {
                ;
  pqcrystals_dilithium_asm_pointwise_acc_montgomery(c->coeffs, a->coeffs, b->coeffs);
                    ;
}
void pqcrystals_dilithium_poly_power2round(poly *a1, poly *a0, const poly *a) {
  unsigned int i;
                ;
  for(i = 0; i < 256; ++i)
    a1->coeffs[i] = pqcrystals_dilithium_power2round(&a0->coeffs[i], a->coeffs[i]);
                      ;
}
void pqcrystals_dilithium_poly_decompose(poly *a1, poly *a0, const poly *a) {
  unsigned int i;
                ;
  for(i = 0; i < 256; ++i)
    a1->coeffs[i] = pqcrystals_dilithium_decompose(&a0->coeffs[i], a->coeffs[i]);
                      ;
}
unsigned int pqcrystals_dilithium_poly_make_hint(poly *h, const poly *a0, const poly *a1) {
  unsigned int i, s = 0;
                ;
  for(i = 0; i < 256; ++i) {
    h->coeffs[i] = pqcrystals_dilithium_make_hint(a0->coeffs[i], a1->coeffs[i]);
    s += h->coeffs[i];
  }
                      ;
  return s;
}
void pqcrystals_dilithium_poly_use_hint(poly *b, const poly *a, const poly *h) {
  unsigned int i;
                ;
  for(i = 0; i < 256; ++i)
    b->coeffs[i] = pqcrystals_dilithium_use_hint(a->coeffs[i], h->coeffs[i]);
                      ;
}
int pqcrystals_dilithium_poly_chknorm(const poly *a, int32_t B) {
  unsigned int i;
  int32_t t;
                ;
  if(B > (8380417 -1)/8)
    return 1;
  for(i = 0; i < 256; ++i) {
    t = a->coeffs[i] >> 31;
    t = a->coeffs[i] - (t & 2*a->coeffs[i]);
    if(t >= B) {
                           ;
      return 1;
    }
  }
                       ;
  return 0;
}
void pqcrystals_dilithium_poly_uniform(poly *a,
                  const uint8_t seed[32],
                  uint16_t nonce)
{
  unsigned int i, ctr, off;
  unsigned int buflen = ((768 + 168 - 1)/168)*168;
  uint8_t buf[((768 + 168 - 1)/168)*168 + 2];
  stream128_state state;
  pqcrystals_dilithium_dilithium_shake128_stream_init(&state, seed, nonce);
  shake128_inc_squeeze(buf, ((768 + 168 - 1)/168)*168, &state);
  ctr = pqcrystals_dilithium_asm_rej_uniform(a->coeffs, 256, buf, buflen);
  while(ctr < 256) {
    off = buflen % 3;
    for(i = 0; i < off; ++i)
      buf[i] = buf[buflen - off + i];
    shake128_inc_squeeze(buf + off, 1*168, &state);
    buflen = 168 + off;
    ctr += pqcrystals_dilithium_asm_rej_uniform(a->coeffs + ctr, 256 - ctr, buf, buflen);
  }
}
static unsigned int rej_eta(int32_t *a,
                            unsigned int len,
                            const uint8_t *buf,
                            unsigned int buflen)
{
  unsigned int ctr, pos;
  uint32_t t0, t1;
                ;
  ctr = pos = 0;
  while(ctr < len && pos < buflen) {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;
    if(t0 < 15) {
      t0 = t0 - (205*t0 >> 10)*5;
      a[ctr++] = 2 - t0;
    }
    if(t1 < 15 && ctr < len) {
      t1 = t1 - (205*t1 >> 10)*5;
      a[ctr++] = 2 - t1;
    }
  }
                       ;
  return ctr;
}
void pqcrystals_dilithium_poly_uniform_eta(poly *a,
        const uint8_t seed[64],
        uint16_t nonce) {
  unsigned int ctr;
  unsigned int buflen = ((136 + 136 - 1)/136) * 136;
  uint8_t buf[((136 + 136 - 1)/136) * 136];
  stream256_state state;
  pqcrystals_dilithium_dilithium_shake256_stream_init(&state, seed, nonce);
  shake256_inc_squeeze(buf, ((136 + 136 - 1)/136)*136, &state);
  ctr = rej_eta(a->coeffs, 256, buf, buflen);
  while(ctr < 256) {
    shake256_inc_squeeze(buf, 1*136, &state);
    ctr += rej_eta(a->coeffs + ctr, 256 - ctr, buf, 136);
  }
}
void pqcrystals_dilithium_poly_uniform_gamma1(poly *a,
                         const uint8_t seed[64],
                         uint16_t nonce)
{
  uint8_t buf[((640 + 136 - 1)/136)*136];
  stream256_state state;
  pqcrystals_dilithium_dilithium_shake256_stream_init(&state, seed, nonce);
  shake256_inc_squeeze(buf, ((640 + 136 - 1)/136)*136, &state);
  pqcrystals_dilithium_polyz_unpack(a, buf);
}
void pqcrystals_dilithium_poly_challenge(poly *c, const uint8_t seed[64]) {
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t buf[136];
  shake256incctx state;
  shake256_inc_init(&state);
  shake256_inc_absorb(&state, seed, 64);
  shake256_inc_finalize(&state);
  shake256_inc_squeeze(buf, 1*136, &state);
  signs = 0;
  for(i = 0; i < 8; ++i)
    signs |= (uint64_t)buf[i] << 8*i;
  pos = 8;
  for(i = 0; i < 256; ++i)
    c->coeffs[i] = 0;
  for(i = 256 -60; i < 256; ++i) {
    do {
      if(pos >= 136) {
        shake256_inc_squeeze(buf, 1*136, &state);
        pos = 0;
      }
      b = buf[pos++];
    } while(b > i);
    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1 - 2*(signs & 1);
    signs >>= 1;
  }
}
void pqcrystals_dilithium_polyeta_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint8_t t[8];
                ;
  for(i = 0; i < 256/8; ++i) {
    t[0] = 2 - a->coeffs[8*i+0];
    t[1] = 2 - a->coeffs[8*i+1];
    t[2] = 2 - a->coeffs[8*i+2];
    t[3] = 2 - a->coeffs[8*i+3];
    t[4] = 2 - a->coeffs[8*i+4];
    t[5] = 2 - a->coeffs[8*i+5];
    t[6] = 2 - a->coeffs[8*i+6];
    t[7] = 2 - a->coeffs[8*i+7];
    r[3*i+0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[3*i+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[3*i+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }
                     ;
}
void pqcrystals_dilithium_polyt1_pack(uint8_t *r, const poly *a) {
  unsigned int i;
                ;
  for(i = 0; i < 256/4; ++i) {
    r[5*i+0] = (a->coeffs[4*i+0] >> 0);
    r[5*i+1] = (a->coeffs[4*i+0] >> 8) | (a->coeffs[4*i+1] << 2);
    r[5*i+2] = (a->coeffs[4*i+1] >> 6) | (a->coeffs[4*i+2] << 4);
    r[5*i+3] = (a->coeffs[4*i+2] >> 4) | (a->coeffs[4*i+3] << 6);
    r[5*i+4] = (a->coeffs[4*i+3] >> 2);
  }
                     ;
}
void pqcrystals_dilithium_polyt1_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
                ;
  for(i = 0; i < 256/4; ++i) {
    r->coeffs[4*i+0] = ((a[5*i+0] >> 0) | ((uint32_t)a[5*i+1] << 8)) & 0x3FF;
    r->coeffs[4*i+1] = ((a[5*i+1] >> 2) | ((uint32_t)a[5*i+2] << 6)) & 0x3FF;
    r->coeffs[4*i+2] = ((a[5*i+2] >> 4) | ((uint32_t)a[5*i+3] << 4)) & 0x3FF;
    r->coeffs[4*i+3] = ((a[5*i+3] >> 6) | ((uint32_t)a[5*i+4] << 2)) & 0x3FF;
  }
                     ;
}
void pqcrystals_dilithium_polyt0_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint32_t t[8];
                ;
  for(i = 0; i < 256/8; ++i) {
    t[0] = (1 << (13 -1)) - a->coeffs[8*i+0];
    t[1] = (1 << (13 -1)) - a->coeffs[8*i+1];
    t[2] = (1 << (13 -1)) - a->coeffs[8*i+2];
    t[3] = (1 << (13 -1)) - a->coeffs[8*i+3];
    t[4] = (1 << (13 -1)) - a->coeffs[8*i+4];
    t[5] = (1 << (13 -1)) - a->coeffs[8*i+5];
    t[6] = (1 << (13 -1)) - a->coeffs[8*i+6];
    t[7] = (1 << (13 -1)) - a->coeffs[8*i+7];
    r[13*i+ 0] = t[0];
    r[13*i+ 1] = t[0] >> 8;
    r[13*i+ 1] |= t[1] << 5;
    r[13*i+ 2] = t[1] >> 3;
    r[13*i+ 3] = t[1] >> 11;
    r[13*i+ 3] |= t[2] << 2;
    r[13*i+ 4] = t[2] >> 6;
    r[13*i+ 4] |= t[3] << 7;
    r[13*i+ 5] = t[3] >> 1;
    r[13*i+ 6] = t[3] >> 9;
    r[13*i+ 6] |= t[4] << 4;
    r[13*i+ 7] = t[4] >> 4;
    r[13*i+ 8] = t[4] >> 12;
    r[13*i+ 8] |= t[5] << 1;
    r[13*i+ 9] = t[5] >> 7;
    r[13*i+ 9] |= t[6] << 6;
    r[13*i+10] = t[6] >> 2;
    r[13*i+11] = t[6] >> 10;
    r[13*i+11] |= t[7] << 3;
    r[13*i+12] = t[7] >> 5;
  }
                     ;
}
void pqcrystals_dilithium_polyt0_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
                ;
  for(i = 0; i < 256/8; ++i) {
    r->coeffs[8*i+0] = a[13*i+0];
    r->coeffs[8*i+0] |= (uint32_t)a[13*i+1] << 8;
    r->coeffs[8*i+0] &= 0x1FFF;
    r->coeffs[8*i+1] = a[13*i+1] >> 5;
    r->coeffs[8*i+1] |= (uint32_t)a[13*i+2] << 3;
    r->coeffs[8*i+1] |= (uint32_t)a[13*i+3] << 11;
    r->coeffs[8*i+1] &= 0x1FFF;
    r->coeffs[8*i+2] = a[13*i+3] >> 2;
    r->coeffs[8*i+2] |= (uint32_t)a[13*i+4] << 6;
    r->coeffs[8*i+2] &= 0x1FFF;
    r->coeffs[8*i+3] = a[13*i+4] >> 7;
    r->coeffs[8*i+3] |= (uint32_t)a[13*i+5] << 1;
    r->coeffs[8*i+3] |= (uint32_t)a[13*i+6] << 9;
    r->coeffs[8*i+3] &= 0x1FFF;
    r->coeffs[8*i+4] = a[13*i+6] >> 4;
    r->coeffs[8*i+4] |= (uint32_t)a[13*i+7] << 4;
    r->coeffs[8*i+4] |= (uint32_t)a[13*i+8] << 12;
    r->coeffs[8*i+4] &= 0x1FFF;
    r->coeffs[8*i+5] = a[13*i+8] >> 1;
    r->coeffs[8*i+5] |= (uint32_t)a[13*i+9] << 7;
    r->coeffs[8*i+5] &= 0x1FFF;
    r->coeffs[8*i+6] = a[13*i+9] >> 6;
    r->coeffs[8*i+6] |= (uint32_t)a[13*i+10] << 2;
    r->coeffs[8*i+6] |= (uint32_t)a[13*i+11] << 10;
    r->coeffs[8*i+6] &= 0x1FFF;
    r->coeffs[8*i+7] = a[13*i+11] >> 3;
    r->coeffs[8*i+7] |= (uint32_t)a[13*i+12] << 5;
    r->coeffs[8*i+7] &= 0x1FFF;
    r->coeffs[8*i+0] = (1 << (13 -1)) - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = (1 << (13 -1)) - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = (1 << (13 -1)) - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = (1 << (13 -1)) - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = (1 << (13 -1)) - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = (1 << (13 -1)) - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = (1 << (13 -1)) - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = (1 << (13 -1)) - r->coeffs[8*i+7];
  }
                     ;
}
void pqcrystals_dilithium_polyz_pack(uint8_t *r, const poly *a) {
  unsigned int i;
  uint32_t t[4];
                ;
  for(i = 0; i < 256/2; ++i) {
    t[0] = (1 << 19) - a->coeffs[2*i+0];
    t[1] = (1 << 19) - a->coeffs[2*i+1];
    r[5*i+0] = t[0];
    r[5*i+1] = t[0] >> 8;
    r[5*i+2] = t[0] >> 16;
    r[5*i+2] |= t[1] << 4;
    r[5*i+3] = t[1] >> 4;
    r[5*i+4] = t[1] >> 12;
  }
                     ;
}
void pqcrystals_dilithium_polyz_unpack(poly *r, const uint8_t *a) {
  unsigned int i;
                ;
  for(i = 0; i < 256/2; ++i) {
    r->coeffs[2*i+0] = a[5*i+0];
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+1] << 8;
    r->coeffs[2*i+0] |= (uint32_t)a[5*i+2] << 16;
    r->coeffs[2*i+0] &= 0xFFFFF;
    r->coeffs[2*i+1] = a[5*i+2] >> 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+3] << 4;
    r->coeffs[2*i+1] |= (uint32_t)a[5*i+4] << 12;
    r->coeffs[2*i+0] &= 0xFFFFF;
    r->coeffs[2*i+0] = (1 << 19) - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = (1 << 19) - r->coeffs[2*i+1];
  }
                     ;
}
void pqcrystals_dilithium_polyw1_pack(uint8_t *r, const poly *a) {
  unsigned int i;
                ;
  for(i = 0; i < 256/2; ++i)
    r[i] = a->coeffs[2*i+0] | (a->coeffs[2*i+1] << 4);
                     ;
}
