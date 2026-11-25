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
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

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
void KeccakF1600_StateExtractBytes(uint64_t *state, unsigned char *data, unsigned int offset, unsigned int length);
void KeccakF1600_StateXORBytes(uint64_t *state, const unsigned char *data, unsigned int offset, unsigned int length);
void KeccakF1600_StatePermute(uint64_t * state);
static void keccak_absorb(uint64_t *s,
    uint32_t r,
    const uint8_t *m, size_t mlen,
    uint8_t p)
{
  while (mlen >= r)
  {
    KeccakF1600_StateXORBytes(s, m, 0, r);
    KeccakF1600_StatePermute(s);
    mlen -= r;
    m += r;
  }
  if(mlen > 0){
    KeccakF1600_StateXORBytes(s, m, 0, mlen);
  }
  if(mlen == r-1){
    p |= 128;
    KeccakF1600_StateXORBytes(s, &p, mlen, 1);
  } else {
    KeccakF1600_StateXORBytes(s, &p, mlen, 1);
    p = 128;
    KeccakF1600_StateXORBytes(s, &p, r-1, 1);
  }
}
static void keccak_squeezeblocks(uint8_t *h, size_t nblocks,
    uint64_t *s,
    uint32_t r)
{
  while(nblocks > 0)
  {
    KeccakF1600_StatePermute(s);
    KeccakF1600_StateExtractBytes(s, h, 0, r);
    h += r;
    nblocks--;
  }
}
static void keccak_inc_init(uint64_t *s_inc) {
    size_t i;
    for (i = 0; i < 25; ++i) {
        s_inc[i] = 0;
    }
    s_inc[25] = 0;
}
static void keccak_inc_absorb(uint64_t *s_inc, uint32_t r, const uint8_t *m,
                              size_t mlen) {
    while (mlen + s_inc[25] >= r) {
        KeccakF1600_StateXORBytes(s_inc, m, s_inc[25], r-s_inc[25]);
        mlen -= (size_t)(r - s_inc[25]);
        m += r - s_inc[25];
        s_inc[25] = 0;
        KeccakF1600_StatePermute(s_inc);
    }
    KeccakF1600_StateXORBytes(s_inc, m, s_inc[25], mlen);
    s_inc[25] += mlen;
}
static void keccak_inc_finalize(uint64_t *s_inc, uint32_t r, uint8_t p) {
    if(s_inc[25] == r-1){
      p |= 128;
      KeccakF1600_StateXORBytes(s_inc, &p, s_inc[25], 1);
    } else {
      KeccakF1600_StateXORBytes(s_inc, &p, s_inc[25], 1);
      p = 128;
      KeccakF1600_StateXORBytes(s_inc, &p, r-1, 1);
    }
    s_inc[25] = 0;
}
static void keccak_inc_squeeze(uint8_t *h, size_t outlen,
                               uint64_t *s_inc, uint32_t r) {
    size_t len;
    if(outlen < s_inc[25])
    {
        len = outlen;
    }
    else
    {
        len = s_inc[25];
    }
    KeccakF1600_StateExtractBytes(s_inc, h, r-s_inc[25], len);
    h += len;
    outlen -= len;
    s_inc[25] -= len;
    while (outlen > 0) {
        KeccakF1600_StatePermute(s_inc);
        if(outlen < r)
        {
            len = outlen;
        }
        else
        {
            len = r;
        }
        KeccakF1600_StateExtractBytes(s_inc, h, 0, len);
        h += len;
        outlen -= len;
        s_inc[25] = r - len;
    }
}
void shake128_inc_init(shake128incctx *state) {
    keccak_inc_init(state->ctx);
}
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, 168, input, inlen);
}
void shake128_inc_finalize(shake128incctx *state) {
    keccak_inc_finalize(state->ctx, 168, 0x1F);
}
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state) {
    keccak_inc_squeeze(output, outlen, state->ctx, 168);
}
void shake128_inc_ctx_clone(shake128incctx* dest, const shake128incctx *src) {
    memcpy(dest, src, sizeof(shake128incctx));
}
void shake128_inc_ctx_release(shake128incctx *state) {
    (void) state;
}
void shake256_inc_init(shake256incctx *state) {
    keccak_inc_init(state->ctx);
}
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, 136, input, inlen);
}
void shake256_inc_finalize(shake256incctx *state) {
    keccak_inc_finalize(state->ctx, 136, 0x1F);
}
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state) {
    keccak_inc_squeeze(output, outlen, state->ctx, 136);
}
void shake256_inc_ctx_clone(shake256incctx* dest, const shake256incctx *src) {
    memcpy(dest, src, sizeof(shake256incctx));
}
void shake256_inc_ctx_release(shake256incctx *state) {
    (void) state;
}
void cshake128_simple_absorb(shake128ctx *state, uint16_t cstm, const uint8_t *in, size_t inlen)
{
  uint8_t sep[8];
  size_t i;
  for (i = 0; i < 25; i++)
    state->ctx[i] = 0;
  sep[0] = 0x01;
  sep[1] = 0xa8;
  sep[2] = 0x01;
  sep[3] = 0x00;
  sep[4] = 0x01;
  sep[5] = 16;
  sep[6] = cstm & 0xff;
  sep[7] = cstm >> 8;
  KeccakF1600_StateXORBytes(state->ctx, sep, 0, 8);
  KeccakF1600_StatePermute(state->ctx);
  keccak_absorb(state->ctx, 168, in, inlen, 0x04);
}
void cshake128_simple_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state)
{
  keccak_squeezeblocks(output, nblocks, state->ctx, 168);
}
void cshake128_simple(uint8_t *output, size_t outlen, uint16_t cstm, const uint8_t *in, size_t inlen)
{
  shake128incctx state;
  uint8_t sep[8];
  keccak_inc_init(state.ctx);
  sep[0] = 0x01;
  sep[1] = 0xa8;
  sep[2] = 0x01;
  sep[3] = 0x00;
  sep[4] = 0x01;
  sep[5] = 16;
  sep[6] = cstm & 0xff;
  sep[7] = cstm >> 8;
  KeccakF1600_StateXORBytes(state.ctx, sep, 0, 8);
  KeccakF1600_StatePermute(state.ctx);
  keccak_inc_absorb(state.ctx, 168, in, inlen);
  keccak_inc_finalize(state.ctx, 168, 0x04);
  keccak_inc_squeeze(output, outlen, state.ctx, 168);
}
void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen)
{
  int i;
  for (i = 0; i < 25; i++)
    state->ctx[i] = 0;
  keccak_absorb(state->ctx, 168, input, inlen, 0x1F);
}
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state)
{
  keccak_squeezeblocks(output, nblocks, state->ctx, 168);
}
void shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inlen)
{
  shake128incctx state;
  keccak_inc_init(state.ctx);
  keccak_inc_absorb(state.ctx, 168, input, inlen);
  keccak_inc_finalize(state.ctx, 168, 0x1F);
  keccak_inc_squeeze(output, outlen, state.ctx, 168);
}
void shake128_ctx_release(shake128ctx *state) {
    (void) state;
}
void shake128_ctx_clone(shake128ctx *dest, const shake128ctx *src) {
    memcpy(dest, src, sizeof(shake128ctx));
}
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen)
{
  int i;
  for (i = 0; i < 25; i++)
    state->ctx[i] = 0;
  keccak_absorb(state->ctx, 136, input, inlen, 0x1F);
}
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state)
{
  keccak_squeezeblocks(output, nblocks, state->ctx, 136);
}
void shake256(uint8_t *output, size_t outlen,
    const uint8_t *input, size_t inlen)
{
  shake256incctx state;
  keccak_inc_init(state.ctx);
  keccak_inc_absorb(state.ctx, 136, input, inlen);
  keccak_inc_finalize(state.ctx, 136, 0x1F);
  keccak_inc_squeeze(output, outlen, state.ctx, 136);
}
void shake256_ctx_release(shake256ctx *state) {
    (void) state;
}
void shake256_ctx_clone(shake256ctx *dest, const shake256ctx *src) {
    memcpy(dest, src, sizeof(shake256ctx));
}
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen)
{
  sha3_256incctx state;
  keccak_inc_init(state.ctx);
  keccak_inc_absorb(state.ctx, 136, input, inlen);
  keccak_inc_finalize(state.ctx, 136, 0x06);
  keccak_inc_squeeze(output, 32, state.ctx, 136);
}
void sha3_256_inc_init(sha3_256incctx *state) {
    keccak_inc_init(state->ctx);
}
void sha3_256_inc_absorb(sha3_256incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, 136, input, inlen);
}
void sha3_256_inc_finalize(uint8_t *output, sha3_256incctx *state) {
    uint8_t t[136];
    keccak_inc_finalize(state->ctx, 136, 0x06);
    keccak_squeezeblocks(t, 1, state->ctx, 136);
    for (size_t i = 0; i < 32; i++) {
        output[i] = t[i];
    }
}
void sha3_256_inc_ctx_clone(sha3_256incctx *dest, const sha3_256incctx *src) {
    memcpy(dest, src, sizeof(sha3_256incctx));
}
void sha3_256_inc_ctx_release(sha3_256incctx *state) {
    (void) state;
}
void sha3_384_inc_init(sha3_384incctx *state) {
    keccak_inc_init(state->ctx);
}
void sha3_384_inc_absorb(sha3_384incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, 104, input, inlen);
}
void sha3_384_inc_finalize(uint8_t *output, sha3_384incctx *state) {
    uint8_t t[104];
    keccak_inc_finalize(state->ctx, 104, 0x06);
    keccak_squeezeblocks(t, 1, state->ctx, 104);
    for (size_t i = 0; i < 48; i++) {
        output[i] = t[i];
    }
}
void sha3_384_inc_ctx_clone(sha3_384incctx *dest, const sha3_384incctx *src) {
    memcpy(dest, src, sizeof(sha3_384incctx));
}
void sha3_384_inc_ctx_release(sha3_384incctx *state) {
    (void) state;
}
void sha3_384(uint8_t *output, const uint8_t *input, size_t inlen) {
  sha3_384incctx state;
  keccak_inc_init(state.ctx);
  keccak_inc_absorb(state.ctx, 104, input, inlen);
  keccak_inc_finalize(state.ctx, 104, 0x06);
  keccak_inc_squeeze(output, 48, state.ctx, 104);
}
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen)
{
  sha3_512incctx state;
  keccak_inc_init(state.ctx);
  keccak_inc_absorb(state.ctx, 72, input, inlen);
  keccak_inc_finalize(state.ctx, 72, 0x06);
  keccak_inc_squeeze(output, 64, state.ctx, 72);
}
void sha3_512_inc_init(sha3_512incctx *state) {
    keccak_inc_init(state->ctx);
}
void sha3_512_inc_absorb(sha3_512incctx *state, const uint8_t *input, size_t inlen) {
    keccak_inc_absorb(state->ctx, 72, input, inlen);
}
void sha3_512_inc_finalize(uint8_t *output, sha3_512incctx *state) {
    uint8_t t[72];
    keccak_inc_finalize(state->ctx, 72, 0x06);
    keccak_squeezeblocks(t, 1, state->ctx, 72);
    for (size_t i = 0; i < 64; i++) {
        output[i] = t[i];
    }
}
void sha3_512_inc_ctx_clone(sha3_512incctx *dest, const sha3_512incctx *src) {
    memcpy(dest, src, sizeof(sha3_512incctx));
}
void sha3_512_inc_ctx_release(sha3_512incctx *state) {
    (void) state;
}
void cshake256_simple_absorb(shake256ctx *state, uint16_t cstm, const uint8_t *in, size_t inlen)
{
  uint8_t sep[8];
  size_t i;
  for (i = 0; i < 25; i++)
    state->ctx[i] = 0;
  sep[0] = 0x01;
  sep[1] = 0x88;
  sep[2] = 0x01;
  sep[3] = 0x00;
  sep[4] = 0x01;
  sep[5] = 16;
  sep[6] = cstm & 0xff;
  sep[7] = cstm >> 8;
  KeccakF1600_StateXORBytes(state->ctx, sep, 0, 8);
  KeccakF1600_StatePermute(state->ctx);
  keccak_absorb(state->ctx, 136, in, inlen, 0x04);
}
void cshake256_simple_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state)
{
  keccak_squeezeblocks(output, nblocks, state->ctx, 136);
}
void cshake256_simple(uint8_t *output, size_t outlen, uint16_t cstm, const uint8_t *in, size_t inlen)
{
  shake256incctx state;
  uint8_t sep[8];
  keccak_inc_init(state.ctx);
  sep[0] = 0x01;
  sep[1] = 0x88;
  sep[2] = 0x01;
  sep[3] = 0x00;
  sep[4] = 0x01;
  sep[5] = 16;
  sep[6] = cstm & 0xff;
  sep[7] = cstm >> 8;
  KeccakF1600_StateXORBytes(state.ctx, sep, 0, 8);
  KeccakF1600_StatePermute(state.ctx);
  keccak_inc_absorb(state.ctx, 136, in, inlen);
  keccak_inc_finalize(state.ctx, 136, 0x04);
  keccak_inc_squeeze(output, outlen, state.ctx, 136);
}
