int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
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
void kyber_shake256_rkprf(uint8_t out[32], const uint8_t key[32], const uint8_t input[((4 * 352) + 160)]);

unsigned char verify(const unsigned char *a, const unsigned char *b, size_t len);
void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);

void *malloc(size_t);
void free(void *);
void abort(void) __attribute__((noreturn));
void exit(int) __attribute__((noreturn));
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
static int crypto_kem_keypair_derand(uint8_t *pk,
        uint8_t *sk,
        const uint8_t *coins) {
    indcpa_keypair_derand(pk, sk, coins);
    memcpy(sk + ((4 * 384)), pk, (((4 * 384) + 32)));
    sha3_256(sk + (((4 * 384)) + ((4 * 384) + 32) + 2*32) - 2 * 32, pk, (((4 * 384) + 32)));
    memcpy(sk + (((4 * 384)) + ((4 * 384) + 32) + 2*32) - 32, coins + 32, 32);
    return 0;
}
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    uint8_t coins[2 * 32];
    randombytes(coins, 2 * 32);
    crypto_kem_keypair_derand(pk, sk, coins);
    return 0;
}
static int crypto_kem_enc_derand(uint8_t *ct,
        uint8_t *ss,
        const uint8_t *pk,
        const uint8_t *coins) {
    uint8_t buf[2 * 32];
    uint8_t kr[2 * 32];
    memcpy(buf, coins, 32);
    sha3_256(buf + 32, pk, (((4 * 384) + 32)));
    sha3_512(kr, buf, 2 * 32);
    indcpa_enc(ct, buf, pk, kr + 32);
    memcpy(ss, kr, 32);
    return 0;
}
int crypto_kem_enc(uint8_t *ct,
        uint8_t *ss,
        const uint8_t *pk) {
    uint8_t coins[32];
    randombytes(coins, 32);
    crypto_kem_enc_derand(ct, ss, pk, coins);
    return 0;
}
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    int fail;
    uint8_t buf[2 * 32];
    uint8_t kr[2 * 32];
    const uint8_t *pk = sk + ((4 * 384));
    indcpa_dec(buf, ct, sk);
    memcpy(buf + 32, sk + (((4 * 384)) + ((4 * 384) + 32) + 2*32) - 2 * 32, 32);
    sha3_512(kr, buf, 2 * 32);
    fail = indcpa_enc_cmp(ct, buf, pk, kr + 32);
    kyber_shake256_rkprf(ss, sk + (((4 * 384)) + ((4 * 384) + 32) + 2*32) - 32, ct);
    cmov(ss, kr, 32, (uint8_t) (1 - fail));
    return 0;
}
