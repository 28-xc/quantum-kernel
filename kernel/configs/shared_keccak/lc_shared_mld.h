/* mldsa-native's documented FIPS202 backend interface, portable C provider. */
#ifndef LC_SHARED_MLD_BACKEND_H
#define LC_SHARED_MLD_BACKEND_H
#define MLD_USE_NATIVE_FIPS202_X1
#ifndef __ASSEMBLER__
#include "shared.h"
#include "src/fips202/native/api.h"
static MLD_INLINE int mld_keccak_f1600_x1_native(uint64_t *state) {
  lc_shared_keccakf1600(state);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif
#endif
