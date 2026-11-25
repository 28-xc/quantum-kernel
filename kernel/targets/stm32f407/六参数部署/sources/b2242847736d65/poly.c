
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
    int16_t coeffs[256];
} poly;
void poly_compress(unsigned char *r, const poly *a);
void poly_decompress(poly *r, const unsigned char *a);
void poly_packcompress(unsigned char *r, poly *a, int i);
void poly_unpackdecompress(poly *r, const unsigned char *a, int i);
int cmp_poly_compress(const unsigned char *r, poly *a);
int cmp_poly_packcompress(const unsigned char *r, poly *a, int i);
void poly_tobytes(unsigned char *r, poly *a);
void poly_frombytes(poly *r, const unsigned char *a);
void poly_frombytes_mul_16_32(int32_t *r_tmp, const poly *b, const unsigned char *a);
void poly_frombytes_mul_32_32(int32_t *r_tmp, const poly *b, const unsigned char *a);
void poly_frombytes_mul_32_16(poly *r, const poly* b, const unsigned char *a, const int32_t *r_tmp);
void poly_frommsg(poly *r, const unsigned char msg[32]);
void poly_tomsg(unsigned char msg[32], poly *a);
void poly_noise_eta1(poly *r, const unsigned char *seed, unsigned char nonce, int add);
void poly_noise_eta2(poly *r, const unsigned char *seed, unsigned char nonce, int add);
void poly_ntt(poly *r);
void poly_invntt(poly *r);
void poly_basemul_opt_16_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime);
void poly_basemul_acc_opt_32_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime);
void poly_basemul_acc_opt_32_16(poly *r, const poly *a, const poly *b, const poly *a_prime, const int32_t * r_tmp);
void poly_fromplantt(poly *r);
void poly_reduce(poly *r);
void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);
void poly_zeroize(poly *p);

void cbd_eta1(poly *r, const unsigned char *buf, int add);
void cbd_eta2(poly *r, const unsigned char *buf, int add);
extern const int32_t zetas[64];
void ntt(int16_t *poly);
void invntt(int16_t *poly);

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

typedef shake128ctx xof_state;
void kyber_shake128_absorb(xof_state *s,
        const uint8_t seed[32],
        uint8_t x,
        uint8_t y);
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[32], uint8_t nonce);
void kyber_shake256_rkprf(uint8_t out[32], const uint8_t key[32], const uint8_t input[((2 * 320) + 128)]);
void poly_compress(unsigned char *r, const poly *a)
{
  unsigned int i,j;
  int16_t u;
  uint32_t d0;
  uint8_t t[8];
  for(i=0;i<256/8;i++) {
    for(j=0;j<8;j++) {
      u = a->coeffs[8*i+j];
      u += (u >> 15) & 3329;
      d0 = u << 4;
      d0 += 1665;
      d0 *= 80635;
      d0 >>= 28;
      t[j] = d0 & 0xf;
    }
    r[0] = t[0] | (t[1] << 4);
    r[1] = t[2] | (t[3] << 4);
    r[2] = t[4] | (t[5] << 4);
    r[3] = t[6] | (t[7] << 4);
    r += 4;
  }
}
void poly_decompress(poly *r, const unsigned char *a)
{
  int i;
  for(i=0;i<256;i+=8)
  {
    r->coeffs[i+0] = (((a[0] & 15) * 3329) + 8) >> 4;
    r->coeffs[i+1] = (((a[0] >> 4) * 3329) + 8) >> 4;
    r->coeffs[i+2] = (((a[1] & 15) * 3329) + 8) >> 4;
    r->coeffs[i+3] = (((a[1] >> 4) * 3329) + 8) >> 4;
    r->coeffs[i+4] = (((a[2] & 15) * 3329) + 8) >> 4;
    r->coeffs[i+5] = (((a[2] >> 4) * 3329) + 8) >> 4;
    r->coeffs[i+6] = (((a[3] & 15) * 3329) + 8) >> 4;
    r->coeffs[i+7] = (((a[3] >> 4) * 3329) + 8) >> 4;
    a += 4;
  }
}
void poly_packcompress(unsigned char *r, poly *a, int i) {
    int j, k;
    uint64_t d0;
    uint16_t t[4];
    for (j = 0; j < 256 / 4; j++) {
        for(k=0;k<4;k++) {
            t[k] = a->coeffs[4*j+k];
            t[k] += ((int16_t)t[k] >> 15) & 3329;
            d0 = t[k];
            d0 <<= 10;
            d0 += 1665;
            d0 *= 1290167;
            d0 >>= 32;
            t[k] = d0 & 0x3ff;
        }
        r[320*i+5*j+0] = t[0] & 0xff;
        r[320*i+5*j+1] = (t[0] >> 8) | ((t[1] & 0x3f) << 2);
        r[320*i+5*j+2] = ((t[1] >> 6) | ((t[2] & 0x0f) << 4)) & 0xff;
        r[320*i+5*j+3] = ((t[2] >> 4) | ((t[3] & 0x03) << 6)) & 0xff;
        r[320*i+5*j+4] = (t[3] >> 2) & 0xff;
    }
}
void poly_unpackdecompress(poly *r, const unsigned char *a, int i) {
  int j;
    for(j=0;j<256/4;j++)
    {
      r->coeffs[4*j+0] = (((a[320*i+5*j+ 0] | (((uint32_t)a[320*i+5*j+ 1] & 0x03) << 8)) * 3329) + 512) >> 10;
      r->coeffs[4*j+1] = ((((a[320*i+5*j+ 1] >> 2) | (((uint32_t)a[320*i+5*j+ 2] & 0x0f) << 6)) * 3329) + 512) >> 10;
      r->coeffs[4*j+2] = ((((a[320*i+5*j+ 2] >> 4) | (((uint32_t)a[320*i+5*j+ 3] & 0x3f) << 4)) * 3329) + 512) >> 10;
      r->coeffs[4*j+3] = ((((a[320*i+5*j+ 3] >> 6) | (((uint32_t)a[320*i+5*j+ 4] & 0xff) << 2)) * 3329) + 512) >> 10;
    }
}
int cmp_poly_compress(const unsigned char *r, poly *a) {
    unsigned char rc = 0;
    int16_t u;
    uint32_t d0;
    uint8_t t[8];
    int i, j, k = 0;
  for(i=0;i<256/8;i++) {
    for(j=0;j<8;j++) {
      u = a->coeffs[8*i+j];
      u += (u >> 15) & 3329;
      d0 = u << 4;
      d0 += 1665;
      d0 *= 80635;
      d0 >>= 28;
      t[j] = d0 & 0xf;
    }
        rc |= r[k] ^ (t[0] | (t[1] << 4));
        rc |= r[k + 1] ^ (t[2] | (t[3] << 4));
        rc |= r[k + 2] ^ (t[4] | (t[5] << 4));
        rc |= r[k + 3] ^ (t[6] | (t[7] << 4));
        k += 4;
    }
    return rc;
}
int cmp_poly_packcompress(const unsigned char *r, poly *a, int i) {
    unsigned char rc = 0;
    int j, k;
    uint64_t d0;
    uint16_t t[4];
        for (j = 0; j < 256 / 4; j++) {
        for(k=0;k<4;k++) {
            t[k] = a->coeffs[4*j+k];
            t[k] += ((int16_t)t[k] >> 15) & 3329;
            d0 = t[k];
            d0 <<= 10;
            d0 += 1665;
            d0 *= 1290167;
            d0 >>= 32;
            t[k] = d0 & 0x3ff;
        }
            rc |= r[320*i+5*j+0] ^ (t[0] & 0xff);
            rc |= r[320*i+5*j+1] ^ ((t[0] >> 8) | ((t[1] & 0x3f) << 2));
            rc |= r[320*i+5*j+2] ^ (((t[1] >> 6) | ((t[2] & 0x0f) << 4)) & 0xff);
            rc |= r[320*i+5*j+3] ^ (((t[2] >> 4) | ((t[3] & 0x03) << 6)) & 0xff);
            rc |= r[320*i+5*j+4] ^ ((t[3] >> 2) & 0xff);
        }
    return rc;
}
void poly_tobytes(unsigned char *r, poly *a) {
    int i;
    uint16_t t0, t1;
    poly_reduce(a);
    poly_reduce(a);
    for (i = 0; i < 256 / 2; i++) {
        t0 = a->coeffs[2 * i];
        t1 = a->coeffs[2 * i + 1];
        r[3 * i] = t0 & 0xff;
        r[3 * i + 1] = (t0 >> 8) | ((t1 & 0xf) << 4);
        r[3 * i + 2] = (t1 >> 4) & 0xff;
    }
}
void poly_frombytes(poly *r, const unsigned char *a) {
    int i;
    for (i = 0; i < 256 / 2; i++) {
        r->coeffs[2 * i] = a[3 * i] | ((uint16_t)a[3 * i + 1] & 0x0f) << 8;
        r->coeffs[2 * i + 1] = a[3 * i + 1] >> 4 | ((uint16_t)a[3 * i + 2] & 0xff) << 4;
    }
}
extern void frombytes_mul_asm_16_32(int32_t *r_tmp, const int16_t *b, const unsigned char *c, const int32_t zetas[64]);
void poly_frombytes_mul_16_32(int32_t *r_tmp, const poly *b, const unsigned char *a) {
    frombytes_mul_asm_16_32(r_tmp, b->coeffs, a, zetas);
}
extern void frombytes_mul_asm_acc_32_32(int32_t *r_tmp, const int16_t *b, const unsigned char *c, const int32_t zetas[64]);
void poly_frombytes_mul_32_32(int32_t *r_tmp, const poly *b, const unsigned char *a) {
    frombytes_mul_asm_acc_32_32(r_tmp, b->coeffs, a, zetas);
}
extern void frombytes_mul_asm_acc_32_16(int16_t *r, const int16_t *b, const unsigned char *c, const int32_t zetas[64], const int32_t *r_tmp);
void poly_frombytes_mul_32_16(poly *r, const poly* b, const unsigned char *a, const int32_t *r_tmp) {
    frombytes_mul_asm_acc_32_16(r->coeffs, b->coeffs, a, zetas, r_tmp);
}
void poly_noise_eta1(poly *r, const unsigned char *seed, unsigned char nonce, int add) {
    unsigned char buf[3 * 256 / 4];
    kyber_shake256_prf(buf, 3 * 256 / 4, seed, nonce);
    cbd_eta1(r, buf, add);
}
void poly_noise_eta2(poly *r, const unsigned char *seed, unsigned char nonce, int add) {
    unsigned char buf[2 * 256 / 4];
    kyber_shake256_prf(buf, 2 * 256 / 4, seed, nonce);
    cbd_eta2(r, buf, add);
}
extern void basemul_asm_opt_16_32(int32_t *, const int16_t *, const int16_t *, const int16_t *);
void poly_basemul_opt_16_32(int32_t *r_tmp, const poly *a, const poly *b, const poly *a_prime) {
    basemul_asm_opt_16_32(r_tmp, a->coeffs, b->coeffs, a_prime->coeffs);
}
extern void basemul_asm_acc_opt_32_32(int32_t *, const int16_t *, const int16_t *, const int16_t *);
void poly_basemul_acc_opt_32_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime) {
    basemul_asm_acc_opt_32_32(r, a->coeffs, b->coeffs, a_prime->coeffs);
}
extern void basemul_asm_acc_opt_32_16(int16_t *, const int16_t *, const int16_t *, const int16_t *, const int32_t *);
void poly_basemul_acc_opt_32_16(poly *r, const poly *a, const poly *b, const poly *a_prime, const int32_t * r_tmp) {
    basemul_asm_acc_opt_32_16(r->coeffs, a->coeffs, b->coeffs, a_prime->coeffs, r_tmp);
}
void poly_ntt(poly *r) {
    ntt(r->coeffs);
}
void poly_invntt(poly *r) {
    invntt(r->coeffs);
}
extern void asm_fromplant(int16_t *r);
void poly_fromplant(poly *r) {
  asm_fromplant(r->coeffs);
}
extern void asm_barrett_reduce(int16_t *r);
void poly_reduce(poly *r) {
  asm_barrett_reduce(r->coeffs);
}
extern void pointwise_add(int16_t *, const int16_t *, const int16_t *);
void poly_add(poly *r, const poly *a, const poly *b) {
    pointwise_add(r->coeffs,a->coeffs,b->coeffs);
}
extern void pointwise_sub(int16_t *, const int16_t *, const int16_t *);
void poly_sub(poly *r, const poly *a, const poly *b) {
    pointwise_sub(r->coeffs,a->coeffs,b->coeffs);
}
void cmov_int16(int16_t *r, int16_t v, uint16_t b);
void poly_frommsg(poly *r, const uint8_t msg[32])
{
  unsigned int i,j;
  for(i=0;i<256/8;i++) {
    for(j=0;j<8;j++) {
      r->coeffs[8*i+j] = 0;
      cmov_int16(r->coeffs+8*i+j, ((3329 +1)/2), (msg[i] >> j)&1);
    }
  }
}
void poly_tomsg(unsigned char msg[32], poly *a) {
    uint32_t t;
    int i, j;
    for (i = 0; i < 32; i++) {
        msg[i] = 0;
        for (j = 0; j < 8; j++) {
            t = a->coeffs[8*i+j];
            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;
            msg[i] |= t << j;
        }
    }
}
void poly_zeroize(poly *p) {
  int i;
  for(i = 0; i < 256; i++)
   p->coeffs[i] = 0;
}
