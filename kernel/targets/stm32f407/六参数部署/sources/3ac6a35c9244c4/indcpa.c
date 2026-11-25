void indcpa_keypair_derand(unsigned char *pk,
                    unsigned char *sk,
                    const unsigned char *coins);
void indcpa_enc(unsigned char *c,
                const unsigned char *m,
                const unsigned char *pk,
                const unsigned char *coins);
unsigned char indcpa_enc_cmp(const unsigned char *ct,
                             const unsigned char *m,
                             const unsigned char *pk,
                             const unsigned char *coins);
void indcpa_dec(unsigned char *m,
                const unsigned char *c,
                const unsigned char *sk);
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

extern const int32_t zetas[64];
void ntt(int16_t *poly);
void invntt(int16_t *poly);
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
typedef struct {
    poly vec[2];
} polyvec;
void polyvec_compress(unsigned char *r, const polyvec *a);
void polyvec_decompress(polyvec *r, const unsigned char *a);
void polyvec_tobytes(unsigned char *r, polyvec *a);
void polyvec_frombytes(polyvec *r, const unsigned char *a);
void polyvec_ntt(polyvec *r);
void polyvec_invntt(polyvec *r);
void polyvec_reduce(polyvec *r);
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);
typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;

int randombytes(uint8_t*,size_t);
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
extern void matacc_asm_cache_16_32(int32_t *r_tmp, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], const int32_t zetas[64], xof_state *state, int16_t *aprimeptr);
static inline void _matacc_asm_cache_16_32(int32_t *r_tmp, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], const int32_t _zetas[64], xof_state *state, int16_t *aprimeptr)
{
  asm volatile("" : : : "s16", "s17", "s18", "s19", "s20", "s21", "s26", "s27", "s28", "s29");
  matacc_asm_cache_16_32(r_tmp, b, c, buf, _zetas, state, aprimeptr);
}
extern void matacc_asm_cache_32_32(int32_t *r_tmp, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], const int32_t zetas[64], xof_state *state, int16_t *aprimeptr);
static inline void _matacc_asm_cache_32_32(int32_t *r_tmp, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], const int32_t _zetas[64], xof_state *state, int16_t *aprimeptr)
{
  asm volatile("" : : : "s16", "s17", "s18", "s19", "s20", "s21", "s26", "s27", "s28", "s29");
  matacc_asm_cache_32_32(r_tmp, b, c, buf, _zetas, state, aprimeptr);
}
extern void matacc_asm_cache_32_16(int16_t *r, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], const int32_t zetas[64], xof_state *state, int16_t *aprimeptr, const int32_t *r_tmp);
static inline void _matacc_asm_cache_32_16(int16_t *r, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], const int32_t _zetas[64], xof_state *state, int16_t *aprimeptr, const int32_t *r_tmp)
{
  asm volatile("" : : : "s16", "s17", "s18", "s19", "s20", "s21", "s26", "s27", "s28", "s29");
  matacc_asm_cache_32_16(r, b, c, buf, _zetas, state, aprimeptr, r_tmp);
}
extern void matacc_asm_opt_16_32(int32_t *r_tmp, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], xof_state *state, const int16_t *aprimeptr);
static inline void _matacc_asm_opt_16_32(int32_t *r_tmp, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], xof_state *state, const int16_t *aprimeptr)
{
  asm volatile("" : : : "s16", "s17", "s18", "s19", "s20", "s21", "s26", "s27", "s28", "s29");
  matacc_asm_opt_16_32(r_tmp, b, c, buf, state, aprimeptr);
}
extern void matacc_asm_opt_32_32(int32_t *r_tmp, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], xof_state *state, const int16_t *aprimeptr);
static inline void _matacc_asm_opt_32_32(int32_t *r_tmp, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], xof_state *state, const int16_t *aprimeptr)
{
  asm volatile("" : : : "s16", "s17", "s18", "s19", "s20", "s21", "s26", "s27", "s28", "s29");
  matacc_asm_opt_32_32(r_tmp, b, c, buf, state, aprimeptr);
}
extern void matacc_asm_opt_32_16(int16_t *r, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], xof_state *state, const int16_t *aprimeptr, const int32_t *r_tmp);
static inline void _matacc_asm_opt_32_16(int16_t *r, const int16_t *b, int16_t c[4], unsigned char buf[168 +2], xof_state *state, const int16_t *aprimeptr, const int32_t *r_tmp)
{
  asm volatile("" : : : "s16", "s17", "s18", "s19", "s20", "s21", "s26", "s27", "s28", "s29");
  matacc_asm_opt_32_16(r, b, c, buf, state, aprimeptr, r_tmp);
}
void matacc_opt32(poly* r, const polyvec *b, const polyvec *b_prime, unsigned char i, const unsigned char *seed, int transposed);
void matacc_cache32(poly* r, const polyvec *b, polyvec *b_prime, unsigned char i, const unsigned char *seed, int transposed);

void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
void indcpa_keypair_derand(unsigned char *pk,
                    unsigned char *sk,
                    const unsigned char *coins){
    polyvec skpv, skpv_prime;
    poly pkp;
    unsigned char buf[2 * 32];
    unsigned char *publicseed = buf;
    unsigned char *noiseseed = buf + 32;
    int i;
    unsigned char nonce = 0;
    memcpy(buf, coins, 32);
    buf[32] = 2;
    sha3_512(buf, buf, 32 + 1);
    for (i = 0; i < 2; i++)
        poly_noise_eta1(skpv.vec + i, noiseseed, nonce++, 0);
    polyvec_ntt(&skpv);
    matacc_cache32(&pkp, &skpv, &skpv_prime, 0, publicseed, 0);
    poly_invntt(&pkp);
    poly_noise_eta1(&pkp, noiseseed, nonce++, 1);
    poly_ntt(&pkp);
    poly_tobytes(pk, &pkp);
    for (i = 1; i < 2; i++) {
        matacc_opt32(&pkp, &skpv, &skpv_prime, i, publicseed, 0);
        poly_invntt(&pkp);
        poly_noise_eta1(&pkp, noiseseed, nonce++, 1);
        poly_ntt(&pkp);
        poly_tobytes(pk+i*384, &pkp);
    }
    polyvec_tobytes(sk, &skpv);
    memcpy(pk + (2 * 384), publicseed, 32);
}
void indcpa_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins) {
    polyvec sp, sp_prime;
    poly bp;
    poly *pkp = &bp;
    poly *k = &bp;
    poly *v = &sp.vec[0];
    const unsigned char *seed = pk+(2 * 384);
    int i;
    unsigned char nonce = 0;
    for (i = 0; i < 2; i++)
        poly_noise_eta1(sp.vec + i, coins, nonce++, 0);
    polyvec_ntt(&sp);
    matacc_cache32(&bp, &sp, &sp_prime, 0, seed, 1);
    poly_invntt(&bp);
    poly_noise_eta2(&bp, coins, nonce++, 1);
    poly_reduce(&bp);
    poly_packcompress(c, &bp, 0);
    for (i = 1; i < 2; i++) {
        matacc_opt32(&bp, &sp, &sp_prime, i, seed, 1);
        poly_invntt(&bp);
        poly_noise_eta2(&bp, coins, nonce++, 1);
        poly_reduce(&bp);
        poly_packcompress(c, &bp, i);
    }
    poly_frombytes(pkp, pk);
    int32_t v_tmp[256];
    poly_basemul_opt_16_32(v_tmp, &sp.vec[0], pkp, &sp_prime.vec[0]);
    for (i = 1; i < 2 - 1; i++) {
        poly_frombytes(pkp, pk + i*384);
        poly_basemul_acc_opt_32_32(v_tmp, &sp.vec[i], pkp, &sp_prime.vec[i]);
    }
    poly_frombytes(pkp, pk + i*384);
    poly_basemul_acc_opt_32_16(v, &sp.vec[i], pkp, &sp_prime.vec[i], v_tmp);
    poly_invntt(v);
    poly_noise_eta2(v, coins, nonce++, 1);
    poly_frommsg(k, m);
    poly_add(v, v, k);
    poly_reduce(v);
    poly_compress(c + (2 * 320), v);
}
unsigned char indcpa_enc_cmp(const unsigned char *c,
                             const unsigned char *m,
                             const unsigned char *pk,
                             const unsigned char *coins) {
    uint64_t rc = 0;
    polyvec sp, sp_prime;
    poly bp;
    poly *pkp = &bp;
    poly *k = &bp;
    poly *v = &sp.vec[0];
    const unsigned char *seed = pk+(2 * 384);
    int i;
    unsigned char nonce = 0;
    for (i = 0; i < 2; i++)
        poly_noise_eta1(sp.vec + i, coins, nonce++, 0);
    polyvec_ntt(&sp);
    matacc_cache32(&bp, &sp, &sp_prime, 0, seed, 1);
    poly_invntt(&bp);
    poly_noise_eta2(&bp, coins, nonce++, 1);
    poly_reduce(&bp);
    rc |= cmp_poly_packcompress(c, &bp, 0);
    for (i = 1; i < 2; i++) {
        matacc_opt32(&bp, &sp, &sp_prime, i, seed, 1);
        poly_invntt(&bp);
        poly_noise_eta2(&bp, coins, nonce++, 1);
        poly_reduce(&bp);
        rc |= cmp_poly_packcompress(c, &bp, i);
    }
    poly_frombytes(pkp, pk);
    int32_t v_tmp[256];
    poly_basemul_opt_16_32(v_tmp, &sp.vec[0], pkp, &sp_prime.vec[0]);
    for (i = 1; i < 2 - 1; i++) {
        poly_frombytes(pkp, pk + i*384);
        poly_basemul_acc_opt_32_32(v_tmp, &sp.vec[i], pkp, &sp_prime.vec[i]);
    }
    poly_frombytes(pkp, pk + i*384);
    poly_basemul_acc_opt_32_16(v, &sp.vec[i], pkp, &sp_prime.vec[i], v_tmp);
    poly_invntt(v);
    poly_noise_eta2(v, coins, nonce++, 1);
    poly_frommsg(k, m);
    poly_add(v, v, k);
    poly_reduce(v);
    rc |= cmp_poly_compress(c + (2 * 320), v);
    rc = ~rc + 1;
    rc >>= 63;
    return (unsigned char)rc;
}
void __attribute__ ((noinline)) indcpa_dec(unsigned char *m,
                                           const unsigned char *c,
                                           const unsigned char *sk) {
    poly mp, bp;
    poly *v = &bp;
    int32_t r_tmp[256];
    int i;
    poly_unpackdecompress(&mp, c, 0);
    poly_ntt(&mp);
    poly_frombytes_mul_16_32(r_tmp, &mp, sk);
    for(i = 1; i < 2 - 1; i++) {
        poly_unpackdecompress(&bp, c, i);
        poly_ntt(&bp);
        poly_frombytes_mul_32_32(r_tmp, &bp, sk + i*384);
    }
    poly_unpackdecompress(&bp, c, i);
    poly_ntt(&bp);
    poly_frombytes_mul_32_16(&mp, &bp, sk + i*384, r_tmp);
    poly_invntt(&mp);
    poly_decompress(v, c+(2 * 320));
    poly_sub(&mp, v, &mp);
    poly_reduce(&mp);
    poly_tomsg(m, &mp);
}
