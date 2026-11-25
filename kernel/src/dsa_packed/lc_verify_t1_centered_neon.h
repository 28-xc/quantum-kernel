/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LC_VERIFY_T1_CENTERED_NEON_H
#define LC_VERIFY_T1_CENTERED_NEON_H
#include <stdint.h>
/* Public verification data. owner uses offsets0..60 and64..575; the original
 * 768-byte allocation remains its sole owner. All pointers are disjoint.
 * c has tau nonzero coefficients in{-1,+1}; tau<=60. */
void lc_verify_t1_neon_prepare(uint8_t owner[768],const int32_t c[256],unsigned tau);
/* w is the coefficient-domain INTT(Az), |w[j]|<8380417. tmp initially holds
 * unsigned10-bit t1, then becomes -x[256]||x[256] with x=t1-512.
 * w returns canonical (w-8192*c*t1) mod8380417. */
void lc_verify_t1_neon_subtract(int32_t w[256],int32_t tmp[256],
                              const uint8_t owner[768],unsigned tau);
#endif
