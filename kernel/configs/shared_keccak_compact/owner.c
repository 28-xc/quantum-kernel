/* The permutation body is included unchanged from mlkem-native.
 * Copyright (c) The mlkem-native project authors.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * Give the existing portable body its shared linkage name directly. This
 * removes the forwarding function used by the previous sharing adapter.
 * The original arithmetic and its 24 round constants remain unchanged.
 */
#include "shared.h"
#include "../../third_party/mlkem-native/mlkem/src/fips202/keccakf1600.h"
#undef MLK_STATIC_TESTABLE
#define MLK_STATIC_TESTABLE
#define mlk_keccakf1600_permute_c lc_shared_keccakf1600
#include "../../third_party/mlkem-native/mlkem/src/fips202/keccakf1600.c"
