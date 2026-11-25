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
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

void lc_zero(void *p, size_t bytes) {
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (bytes--) *q++ = 0;
}
void lc_arena_init(lc_arena *a, void *base, size_t capacity) {
    a->base = base; a->capacity = capacity; a->used = 0;
    a->high_water = 0; a->failed_size = 0; a->allocations = 0; a->error = 0;
}
void *lc_arena_alloc(lc_arena *a, size_t bytes) {
    uintptr_t addr;
    size_t padding, start, end;
    if (!a || !a->base || a->used > a->capacity) return ((void*)0);
    addr = (uintptr_t)a->base + a->used;
    padding = (32u - ((addr + sizeof(size_t)) & 31u)) & 31u;
    if (padding + sizeof(size_t) > a->capacity - a->used) goto fail;
    start = a->used + padding + sizeof(size_t);
    if (bytes > a->capacity - start) goto fail;
    end = start + bytes;
    memcpy(a->base + start - sizeof(size_t), &a->used, sizeof(size_t));
    a->used = end;
    if (end > a->high_water) a->high_water = end;
    a->allocations++;
    return a->base + start;
fail:
    a->failed_size = bytes;
    return ((void*)0);
}
void lc_arena_free(lc_arena *a, void *ptr, size_t bytes) {
    size_t previous, offset;
    if (!ptr) return;
    if (!a || !a->base || (uintptr_t)ptr < (uintptr_t)a->base) return;
    offset = (size_t)((uint8_t *)ptr - a->base);
    if (offset < sizeof(size_t) || offset > a->used || bytes != a->used - offset) {
        a->error = 1; return;
    }
    memcpy(&previous, a->base + offset - sizeof(size_t), sizeof(size_t));
    if (previous > offset - sizeof(size_t)) { a->error = 1; return; }
    lc_zero(a->base + previous, offset - previous);
    a->used = previous;
}
