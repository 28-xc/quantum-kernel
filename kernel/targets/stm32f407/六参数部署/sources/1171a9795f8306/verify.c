typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;

unsigned char verify(const unsigned char *a, const unsigned char *b, size_t len);
void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b);

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
void *malloc(size_t);
void free(void *);
void abort(void) __attribute__((noreturn));
void exit(int) __attribute__((noreturn));
unsigned char verify(const unsigned char *a, const unsigned char *b, size_t len) {
    uint64_t r;
    size_t i;
    r = 0;
    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }
    r = (~r + 1);
    r >>= 63;
    return (unsigned char)r;
}
void cmov(unsigned char *r, const unsigned char *x, size_t len, unsigned char b) {
    size_t i;
    b = -b;
    for (i = 0; i < len; i++) {
        r[i] ^= b & (x[i] ^ r[i]);
    }
}
