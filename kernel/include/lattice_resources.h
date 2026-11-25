#ifndef LATTICE_RESOURCES_H
#define LATTICE_RESOURCES_H
#include "latticecore.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Operation 0: keypair. Operation 1: encaps/sign. Operation 2: decaps/verify.
 * Sizes describe this exact build. Workspace excludes stack, I/O and globals.
 * `minimum` is the smallest supported plan's sufficient bound; fixed-operation
 * bounds may be conservative. It is not a measured total-RAM claim. */
enum { LC_RESOURCE_FIXED=0, LC_RESOURCE_FULL_MATRIX=1,
       LC_RESOURCE_FIVE_ROWS=2 };
/* Same numeric status as the existing parameter-pruned API. */
enum { LC_RESOURCE_E_UNSUPPORTED=-8 };
typedef struct {
  size_t minimum_workspace_bytes, preferred_workspace_bytes;
  size_t alignment, public_context_bytes, caller_plan_bytes;
  unsigned adaptive, exact_workspace_bound;
} lc_resource_requirements;
typedef struct {
  size_t workspace_bytes, alignment_padding, usable_workspace_bytes;
  size_t required_workspace_bytes, matrix_cache_bytes, saved_input_bytes;
  unsigned mode, cached_rows, cached_polynomials;
} lc_resource_plan;
/* Query succeeds independently of whether the caller has enough storage.
 * A standard parameter/operation removed from this build returns -8; unknown
 * parameters or operation numbers return LC_E_ARGUMENT. Failure clears output. */
__attribute__((externally_visible)) int lc_resource_query(int parameter,int operation,
    lc_resource_requirements *requirements);
/* The plan is determined only by public operation, parameter, address and size.
 * A successful plan uses the same selector as the complete signing operation.
 * No state is retained and no library is loaded or switched by this function. */
__attribute__((externally_visible)) int lc_resource_make_plan(int parameter,int operation,
    const void *workspace,size_t bytes,lc_resource_plan *plan);
/* Add independently established reservations, with checked size arithmetic.
 * stack_bytes must cover the new binary's full call chain. `other_bytes` covers
 * writable globals/TLS/outside heap and retained caller plan, if any. I/O objects
 * are added separately when computing complete application RAM. */
__attribute__((externally_visible)) int lc_resource_algorithm_bytes(size_t workspace_bytes,
    size_t stack_bytes,size_t other_bytes,size_t *total_bytes);
#ifdef __cplusplus
}
#endif
#endif
