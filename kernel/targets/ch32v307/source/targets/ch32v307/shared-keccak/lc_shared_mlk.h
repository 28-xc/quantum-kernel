#ifndef LC_SHARED_COMPACT_MLK_BACKEND_H
#define LC_SHARED_COMPACT_MLK_BACKEND_H
#define MLK_USE_NATIVE_FIPS202_X1
#ifndef __ASSEMBLER__
#include "shared.h"
#include "src/fips202/native/api.h"
static MLK_INLINE int mlk_keccak_f1600_x1_native(uint64_t *state) {
  lc_shared_keccakf1600(state);
  return MLK_NATIVE_FUNC_SUCCESS;
}
#endif
#endif
