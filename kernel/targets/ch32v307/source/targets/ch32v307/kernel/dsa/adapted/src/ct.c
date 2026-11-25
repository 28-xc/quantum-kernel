/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#include "ct.h"

#if !defined(MLD_USE_ASM_VALUE_BARRIER) && \
    !defined(MLD_CONFIG_MULTILEVEL_NO_SHARED)
/*
 * Masking value used in constant-time functions from
 * ct.h to block the compiler's range analysis and
 * thereby reduce the risk of compiler-introduced branches.
 */
volatile uint64_t mld_ct_opt_blocker_u64 = 0;

#else /* !MLD_USE_ASM_VALUE_BARRIER && !MLD_CONFIG_MULTILEVEL_NO_SHARED */

MLD_EMPTY_CU(ct)

#endif /* !(!MLD_USE_ASM_VALUE_BARRIER && !MLD_CONFIG_MULTILEVEL_NO_SHARED) */

#if LC_DSA_SHARED_SENSITIVE_FREE && !defined(MLD_CONFIG_MULTILEVEL_NO_SHARED)
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
/* Same object extent, zeroize primitive and LIFO release as MLD_FREE.
 * Keep one entity: all arguments describe public allocation metadata. */
#else
/* Exactly the former MLD_FREE extent, zeroization and LIFO order. */
#endif
__attribute__((noipa,visibility("hidden")))
void lc_dsa_sensitive_free(struct lc_dsa_arena *a,void *ptr,size_t bytes)
{
  if (ptr != NULL) {
    mld_zeroize(ptr,bytes);
    lc_dsa_free(a,ptr,bytes);
  }
}
#endif
