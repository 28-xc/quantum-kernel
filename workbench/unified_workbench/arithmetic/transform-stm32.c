#define experiment ring_experiment
#include "formal_ring_driver.h"
#undef experiment
#include "lc_poly.h"

static void forward_kem(void) { kem_ntt(s.ka); }
static void forward_dsa(void) { dsa_ntt(s.a); }
static void inverse_kem(void) { kem_intt(s.ka); }
static void inverse_dsa(void) { dsa_intt(s.a); }
static void add_kem(void) { lc_poly_add(3329, (uint32_t *)s.out, (uint32_t *)s.a, (uint32_t *)s.b); }
static void add_dsa(void) { lc_poly_add(8380417, (uint32_t *)s.out, (uint32_t *)s.a, (uint32_t *)s.b); }
static void subtract_kem(void) { lc_poly_sub(3329, (uint32_t *)s.out, (uint32_t *)s.a, (uint32_t *)s.b); }
static void subtract_dsa(void) { lc_poly_sub(8380417, (uint32_t *)s.out, (uint32_t *)s.a, (uint32_t *)s.b); }
static void reduce_kem(void) { kem_reduce(s.ka); }
static void reduce_dsa(void) { dsa_reduce(s.a); }

void experiment(const m4_request *q, m4_response *r) {
  unsigned op = q->w[8];
  if (q->w[2] != 21 || op < 2) {
    ring_experiment(q, r);
    return;
  }
  valid = 0;
  if (op > 11 || q->w[9] != 0) return;
  const runner operations[] = {forward_kem, forward_dsa, inverse_kem, inverse_dsa,
                              add_kem, add_dsa, subtract_kem, subtract_dsa, reduce_kem, reduce_dsa};
  int pair = op >= 6 && op < 10;
  active_op = op;
  active_index = 0;
  initialize_guards();
  input_check = m4_checksum(s.original, sizeof(s.original));
  chosen = operations[op - 2];
  for (unsigned rep = 0; rep < 9; ++rep) {
    if (pair || (op & 1)) memcpy(s.a, s.original[0], sizeof(s.a));
    else for (unsigned i = 0; i < 256; ++i) s.ka[i] = (int16_t)s.original[0][i];
    if (pair) memcpy(s.b, s.original[1], sizeof(s.b));
    empty_starts[rep] = cycle_stamp();
    no_op();
    empty_ends[rep] = cycle_stamp();
    starts[rep] = cycle_stamp();
    chosen();
    ends[rep] = cycle_stamp();
    if (pair) memcpy(s.outputs[rep], s.out, sizeof(s.out));
    else for (unsigned i = 0; i < 256; ++i)
        s.outputs[rep][i] = (op & 1) ? s.a[i] : s.ka[i];
    checks[rep] = m4_checksum(s.outputs[rep], sizeof(s.outputs[rep]));
  }
  valid = guards_ok() && input_check == m4_checksum(s.original, sizeof(s.original));
  r->w[23] = valid;
  r->w[41] = active_op;
  r->w[42] = active_index;
  r->w[43] = input_check;
}
