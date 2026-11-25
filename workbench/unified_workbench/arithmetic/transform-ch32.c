/* The builder omits the original assembly entry. Capture uses the same
 * timer and receipt layout as the formal ring diagnostic. */
#include "formal_ring_driver.h"
#include "lc_poly.h"

static void forward_kem(void) { kem_ntt(target); }
static void forward_dsa(void) { dsa_ntt(target); }
static void inverse_kem(void) { kem_intt(target); }
static void inverse_dsa(void) { dsa_intt(target); }
static void add_kem(void) { lc_poly_add(3329, (uint32_t *)target, (uint32_t *)work_a, (uint32_t *)work_b); }
static void add_dsa(void) { lc_poly_add(8380417, (uint32_t *)target, (uint32_t *)work_a, (uint32_t *)work_b); }
static void subtract_kem(void) { lc_poly_sub(3329, (uint32_t *)target, (uint32_t *)work_a, (uint32_t *)work_b); }
static void subtract_dsa(void) { lc_poly_sub(8380417, (uint32_t *)target, (uint32_t *)work_a, (uint32_t *)work_b); }
static void reduce_kem(void) { kem_reduce(target); }
static void reduce_dsa(void) { dsa_reduce(target); }
static void (*const operations[])(void) = {forward_kem, forward_dsa, inverse_kem, inverse_dsa,
    add_kem, add_dsa, subtract_kem, subtract_dsa, reduce_kem, reduce_dsa};

__attribute__((noinline,used)) static void run_transform(void) {
    unsigned op = request[1];
    result.magic = 0;
    if (op < 2 || op > 11) return;
    int pair = op >= 6 && op < 10;
    unsigned n = (pair || (op & 1)) ? 1024 : 512;
    result.cookie = request[0];
    result.operation = op;
    result.control = *(volatile uint32_t *)0xe000f000u;
    result.timer = 0xe000f008u;
    result.repeats = RUNS;
    result.bytes = n;
    result.reserved = 0;
    for (unsigned rep = 0; rep < RUNS; ++rep) {
        if (pair) {
            for (unsigned i = 0; i < n; ++i) {
                work_a[i] = source_a[i];
                work_b[i] = source_b[i];
            }
        } else for (unsigned i = 0; i < n; ++i) target[i] = source_a[i];
        if (rep & 1) capture(&result.empty[rep], empty_ring);
        capture(&result.call[rep], operations[op - 2]);
        if (!(rep & 1)) capture(&result.empty[rep], empty_ring);
        for (unsigned i = 0; i < n; ++i) snapshots[1024 * rep + i] = target[i];
    }
    __asm__ volatile("fence rw,rw" ::: "memory");
    result.magic = 0x52494e47u;
}
__asm__(".section .text.qual_entry,\"ax\"\n.global qual_entry\nqual_entry:\n.option push\n.option norelax\n"
        "la gp,__production_gp\nla sp,__qual_stack_top\ncall run_transform\n1:j 1b\n.option pop\n.previous\n");
