#include "lc_arena.h"
#include <string.h>

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
    if (!a || !a->base || a->used > a->capacity) return NULL;
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
    return NULL;
}
#if defined(__aarch64__) && defined(LC_DSA_RUNTIME_CACHE) && LC_DSA_RUNTIME_CACHE
__attribute__((noipa))
#endif
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
    /* The primitive must erase the object before release. This allocator
     * erases only its own alignment/header area, avoiding double erasure. */
    lc_zero(a->base + previous, offset - previous);
    a->used = previous;
}
