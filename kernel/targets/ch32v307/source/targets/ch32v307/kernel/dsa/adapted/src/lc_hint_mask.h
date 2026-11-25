/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#ifndef LC_HINT_MASK_H
#define LC_HINT_MASK_H
#include "ct.h"
/* |low| < 2*GAMMA2 follows from the preceding two norm checks. The mask
 * barriers are inherited from the upstream constant-time arithmetic layer.
 * Unlike mld_make_hint, this form is valid before all later rows accept. */
static MLD_INLINE unsigned lc_make_hint_secret(int32_t low,uint32_t high_nonzero) {
  uint32_t above=mld_ct_cmask_neg_i32(MLDSA_GAMMA2-low);
  uint32_t below=mld_ct_cmask_neg_i32(low+MLDSA_GAMMA2);
  uint32_t equal=~mld_ct_cmask_nonzero_u32((uint32_t)(low+MLDSA_GAMMA2));
  uint32_t nonzero=mld_ct_cmask_nonzero_u32(high_nonzero);
  return (above|below|(equal&nonzero))&1u;
}
#ifndef LC_DSA_FUSED_HINT_NEON
#define LC_DSA_FUSED_HINT_NEON 0
#endif
#if LC_DSA_FUSED_HINT_NEON
#if !defined(__aarch64__)
#error "NEON hint predicates require AArch64"
#endif
#include <arm_neon.h>
/* The preceding complete-polynomial norm checks bound each sum. Preserve
 * the -gamma2 boundary and the old high-part-nonzero predicate exactly.
 * The bitmap remains secret until all later acceptance checks succeed. */
static void lc_hint_fused_neon(uint8_t flags[32],const int32_t low[256],
                               const int32_t ct0[256],int32_t gamma2) {
  const int32x4_t g=vdupq_n_s32(gamma2),ng=vdupq_n_s32(-gamma2);
  const uint32x4_t weights={1,2,4,8};
  for(unsigned group=0;group<32;group++) {
    int32x4_t a=vaddq_s32(vld1q_s32(low+8*group),vld1q_s32(ct0+8*group));
    int32x4_t b=vaddq_s32(vld1q_s32(low+8*group+4),vld1q_s32(ct0+8*group+4));
    uint32x4_t oa=vorrq_u32(vcgtq_s32(a,g),vcltq_s32(a,ng));
    uint32x4_t ob=vorrq_u32(vcgtq_s32(b,g),vcltq_s32(b,ng));
    unsigned outside=vaddvq_u32(vandq_u32(oa,weights))|
                     (vaddvq_u32(vandq_u32(ob,weights))<<4);
    unsigned boundary=vaddvq_u32(vandq_u32(vceqq_s32(a,ng),weights))|
                      (vaddvq_u32(vandq_u32(vceqq_s32(b,ng),weights))<<4);
    flags[group]=(uint8_t)(outside|(boundary&flags[group]));
  }
}
#endif
#endif
