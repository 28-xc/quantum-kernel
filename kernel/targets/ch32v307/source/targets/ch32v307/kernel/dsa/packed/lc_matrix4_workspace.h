/* Copyright (c) The mldsa-native project authors.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Explicit call-owned storage for the unchanged four-lane uniform sampler.
 * The four outputs and workspace are pairwise non-overlapping. The seed
 * argument is the explicit workspace->seeds subview and is erased on return.
 * Arena storage and outputs have their declared 32-byte type alignment.
 * These are implementation contracts, not a claim of an executed proof. */
#ifndef LC_MATRIX4_WORKSPACE_H
#define LC_MATRIX4_WORKSPACE_H
#if LC_DSA_MATRIX4_ARENA
#if !LC_DSA_NATIVE_MATRIX_ROWS || defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
#error "Explicit matrix workspace requires the four-lane native row schedule"
#endif
#ifndef MLD_POLY_UNIFORM_NBLOCKS
#define MLD_POLY_UNIFORM_NBLOCKS ((768+MLD_STREAM128_BLOCKBYTES-1)/MLD_STREAM128_BLOCKBYTES)
#endif
typedef struct {
  MLD_ALIGN uint8_t buf[4][MLD_ALIGN_UP(MLD_POLY_UNIFORM_NBLOCKS*MLD_STREAM128_BLOCKBYTES)];
  mld_xof128_x4_ctx state;
  MLD_ALIGN uint8_t seeds[4][MLD_ALIGN_UP(34)];
} lc_matrix4_workspace;
_Static_assert(sizeof(lc_matrix4_workspace)==4512,"update adapter accounting if sampler workspace changes");
#define lc_poly_uniform4_arena MLD_NAMESPACE(poly_uniform4_arena)
MLD_INTERNAL_API void lc_poly_uniform4_arena(mld_poly *r0,mld_poly *r1,mld_poly *r2,mld_poly *r3,
    uint8_t seed[4][MLD_ALIGN_UP(34)],lc_matrix4_workspace *workspace)
__contract__(
  requires(memory_no_alias(r0,sizeof(*r0)))
  requires(memory_no_alias(r1,sizeof(*r1)))
  requires(memory_no_alias(r2,sizeof(*r2)))
  requires(memory_no_alias(r3,sizeof(*r3)))
  requires(memory_no_alias(workspace,sizeof(*workspace)))
  requires(seed == workspace->seeds)
  assigns(memory_slice(r0,sizeof(*r0)),memory_slice(r1,sizeof(*r1)),
          memory_slice(r2,sizeof(*r2)),memory_slice(r3,sizeof(*r3)),
          memory_slice(workspace,sizeof(*workspace)))
  ensures(array_bound(r0->coeffs,0,MLDSA_N,0,MLDSA_Q))
  ensures(array_bound(r1->coeffs,0,MLDSA_N,0,MLDSA_Q))
  ensures(array_bound(r2->coeffs,0,MLDSA_N,0,MLDSA_Q))
  ensures(array_bound(r3->coeffs,0,MLDSA_N,0,MLDSA_Q))
  ensures(forall(i,0,sizeof(*workspace),((const uint8_t*)workspace)[i]==0))
);
#define LC_MATRIX4_PARAM ,lc_matrix4_workspace *matrix_workspace
#define LC_MATRIX4_PASS ,matrix_workspace
#define LC_MATRIX4_SAMPLE(A,B,C,D,S,W) lc_poly_uniform4_arena(A,B,C,D,S,W)
#else
#define LC_MATRIX4_PARAM
#define LC_MATRIX4_PASS
#define LC_MATRIX4_SAMPLE(A,B,C,D,S,W) mld_poly_uniform_4x(A,B,C,D,S)
#endif
#endif
