/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#ifndef LC_HINT_WEIGHT_H
#define LC_HINT_WEIGHT_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* A fixed traversal of 256 hint bits per row. Both addresses and operation
 * counts depend only on the public row count and stride. No lookup table
 * or position-dependent store is used before the weight decision. */
static unsigned lc_hint_weight_exceeds(const uint8_t *flags, size_t rows,
                                      size_t stride, unsigned omega) {
  uint32_t weight = 0;
  for (size_t k = 0; k < rows; k++) {
    const uint8_t *p = flags + k * stride;
    for (size_t j = 0; j < 32; j += 4) {
      uint32_t x;
      /* Population count is independent of byte order; memcpy also covers
       * deliberately unaligned rows without pointer aliasing assumptions. */
      memcpy(&x, p + j, sizeof(x));
      x -= (x >> 1) & UINT32_C(0x55555555);
      x = (x & UINT32_C(0x33333333)) +
          ((x >> 2) & UINT32_C(0x33333333));
      x = (x + (x >> 4)) & UINT32_C(0x0f0f0f0f);
      weight += (x * UINT32_C(0x01010101)) >> 24;
    }
  }
  return weight > omega;
}
#endif
