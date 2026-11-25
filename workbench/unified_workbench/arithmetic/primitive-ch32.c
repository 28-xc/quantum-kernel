#include "primitive-dispatch.h"

extern primitive_input work;
typedef struct { uint32_t magic,cookie,status,lo,hi; } primitive_receipt;
extern volatile primitive_receipt receipt;

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *out = dst;
    const uint8_t *in = src;
    while (n--) *out++ = *in++;
    return dst;
}
void *memset(void *dst, int value, size_t n) {
    uint8_t *out = dst;
    while (n--) *out++ = (uint8_t)value;
    return dst;
}

static uint64_t stamp(void) {
    volatile uint32_t *t = (volatile uint32_t *)0xe000f008u;
    uint32_t high, low, check;
    do { high=t[1]; low=t[0]; check=t[1]; } while (high != check);
    return ((uint64_t)high<<32)|low;
}

__attribute__((used,noinline)) void evaluate(void) {
    receipt.magic=0;
    receipt.cookie=work.cookie;
    uint64_t start=stamp();
    receipt.status=(uint32_t)run_primitive(&work);
    uint64_t elapsed=stamp()-start;
    receipt.lo=(uint32_t)elapsed;
    receipt.hi=(uint32_t)(elapsed>>32);
    __asm__ volatile("fence rw,rw" ::: "memory");
    receipt.magic=0x504f4c59u;
}
__asm__(".section .text.qual_entry,\"ax\"\n.global qual_entry\nqual_entry:\n.option push\n.option norelax\n"
        "la sp,__qual_stack_top\ncall evaluate\n1:j 1b\n.option pop\n.previous\n");
