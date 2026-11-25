#ifndef LC_DSA_CONFIG_H
#define LC_DSA_CONFIG_H
#define MLD_CONFIG_NAMESPACE_PREFIX lcbase
#define MLD_CONFIG_MULTILEVEL_BUILD
#define MLD_CONFIG_CONTEXT_PARAMETER
#define MLD_CONFIG_CONTEXT_PARAMETER_TYPE struct lc_dsa_arena *
#define MLD_CONFIG_CUSTOM_ALLOC_FREE
#define MLD_CONFIG_CUSTOM_RANDOMBYTES
#ifndef __ASSEMBLER__
#include "lc_dsa_arena.h"
#define MLD_CUSTOM_ALLOC(v,T,N,context) T *v = (T *)lc_dsa_alloc(context,sizeof(T)*(N))
#define MLD_CUSTOM_FREE(v,T,N,context) lc_dsa_free(context,v,sizeof(T)*(N))
#define mld_randombytes lc_dsa_system_random
#endif
#ifndef LC_DSA_KEYGEN_ETA4
#define LC_DSA_KEYGEN_ETA4 0
#endif
#ifndef LC_DSA_FUSED_KEYGEN_PACK
#define LC_DSA_FUSED_KEYGEN_PACK 0
#endif
#ifndef LC_DSA_VERIFY_HASH_BATCH
#define LC_DSA_VERIFY_HASH_BATCH 0
#endif
/* Portable current-attempt mask reuse. This does not change ExpandMask:
 * exact sampled bytes occupy the final z slices until each z is produced.
 * The caller destroys every borrowed slice immediately on rejection. */
#ifndef LC_DSA_PORTABLE_SIG_Y
#define LC_DSA_PORTABLE_SIG_Y 0
#endif
#if LC_DSA_PORTABLE_SIG_Y != 0 && LC_DSA_PORTABLE_SIG_Y != 1
#error "portable mask retention must be boolean"
#endif
#if LC_DSA_PORTABLE_SIG_Y
#if !defined(MLD_CONFIG_REDUCE_RAM) || defined(__AVX2__) || defined(__aarch64__)
#error "portable mask retention requires scalar reduced-memory signing"
#endif
#if (LC_DSA_A_CACHE_POLYS != 0 && LC_DSA_A_CACHE_POLYS != 56) || (LC_DSA_A_CACHE_POLYS && (LC_DSA_A_CACHE_BITS != 24 || !LC_DSA_A_CACHE_SIGN_ONLY)) || LC_DSA_INPLACE_SAMPLE != 2 || LC_DSA_STREAM_RECOMPUTE || LC_DSA_STREAM_CACHE24 || LC_DSA_RAW_Y_ALL_CACHE || LC_DSA_RAW_Y4_CACHE || LC_DSA_FIRST_GAMMA_CACHE || LC_DSA_BORROW_SIG_Y || LC_DSA_NATURAL_SIG_Y || LC_DSA_CACHED_DOT_TILE
#error "portable mask retention requires the explicit uncached or cache56 scalar schedules"
#endif
#endif
/* Partial-row signing owns either only the overwritten high y columns or
 * every y column. The function-like count is shared by parameter TUs and the
 * all-parameter workspace query, so allocation/free/query use one rule. */
#ifndef LC_DSA_PARTIAL_DENSE_ROWS
#define LC_DSA_PARTIAL_DENSE_ROWS 0
#endif
#ifndef LC_DSA_PARTIAL_DENSE_SEPARATE_Y
#define LC_DSA_PARTIAL_DENSE_SEPARATE_Y 0
#endif
#if LC_DSA_PARTIAL_DENSE_SEPARATE_Y != 0 && LC_DSA_PARTIAL_DENSE_SEPARATE_Y != 1
#error "partial dense separate Y must be zero or one"
#endif
#if LC_DSA_PARTIAL_DENSE_ROWS < 0 || LC_DSA_PARTIAL_DENSE_ROWS > 6
#error "partial dense rows must be zero or in one through six"
#endif
#if LC_DSA_PARTIAL_DENSE_SEPARATE_Y && !LC_DSA_PARTIAL_DENSE_ROWS
#error "separate Y requires the partial dense product"
#endif
#define LC_DSA_PARTIAL_DENSE_SAVED_COUNT(l) \
  (LC_DSA_PARTIAL_DENSE_SEPARATE_Y ? (l) : ((l)-LC_DSA_PARTIAL_DENSE_ROWS))
/* Explicit recipe features; disabled configurations retain the original paths. */
#ifndef LC_DSA_BORROW_SIG_Y
#define LC_DSA_BORROW_SIG_Y 0
#endif
#if LC_DSA_BORROW_SIG_Y != 0 && LC_DSA_BORROW_SIG_Y != 1
#error "LC_DSA_BORROW_SIG_Y must be zero or one"
#endif
#ifndef LC_DSA_NATURAL_SIG_Y
#define LC_DSA_NATURAL_SIG_Y 0
#endif
#if LC_DSA_NATURAL_SIG_Y != 0 && LC_DSA_NATURAL_SIG_Y != 1
#error "LC_DSA_NATURAL_SIG_Y must be zero or one"
#endif
#ifndef LC_DSA_CHECKED_SPARSE
#define LC_DSA_CHECKED_SPARSE 0
#endif
#if LC_DSA_CHECKED_SPARSE != 0 && LC_DSA_CHECKED_SPARSE != 1
#error "LC_DSA_CHECKED_SPARSE must be zero or one"
#endif
#ifndef LC_DSA_DEFER_CHALLENGE_NTT
#define LC_DSA_DEFER_CHALLENGE_NTT 0
#endif
#if LC_DSA_DEFER_CHALLENGE_NTT != 0 && LC_DSA_DEFER_CHALLENGE_NTT != 1
#error "LC_DSA_DEFER_CHALLENGE_NTT must be zero or one"
#endif
#ifndef LC_DSA_PARAMETER_A32
#define LC_DSA_PARAMETER_A32 0
#endif
#if LC_DSA_PARAMETER_A32 != 0 && LC_DSA_PARAMETER_A32 != 1
#error "LC_DSA_PARAMETER_A32 must be zero or one"
#endif
#ifndef LC_DSA_EARLY_LOW_44
#define LC_DSA_EARLY_LOW_44 0
#endif
#if LC_DSA_EARLY_LOW_44 != 0 && LC_DSA_EARLY_LOW_44 != 1
#error "LC_DSA_EARLY_LOW_44 must be zero or one"
#endif
#ifndef LC_DSA_T0_NTT_CACHE44
#define LC_DSA_T0_NTT_CACHE44 0
#endif
#if LC_DSA_T0_NTT_CACHE44 != 0 && LC_DSA_T0_NTT_CACHE44 != 1
#error "LC_DSA_T0_NTT_CACHE44 must be zero or one"
#endif
#if LC_DSA_T0_NTT_CACHE44
#error "The t0 cache is not part of the supported configurations"
#endif
/* Compact87 batch producer: retain exactly seven current
 * attempt masks in the already borrowed output. No future nonce is produced. */
#ifndef LC_DSA_COMPACT_BATCH87
#define LC_DSA_COMPACT_BATCH87 0
#endif
#if LC_DSA_COMPACT_BATCH87 != 0 && LC_DSA_COMPACT_BATCH87 != 1
#error "compact batch87 must be boolean"
#endif
#if LC_DSA_COMPACT_BATCH87 && MLD_CONFIG_PARAMETER_SET == 87
#if !defined(__AVX2__) || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE) || LC_DSA_STREAM_CACHE24 || LC_DSA_STREAM_RECOMPUTE || !LC_DSA_BORROW_SIG_Y || !LC_DSA_NATURAL_SIG_Y || LC_DSA_MASK_PIPELINE
#error "compact batch87 requires the existing uncached AVX2 natural mask owner"
#endif
#undef LC_DSA_NATURAL_SIG_Y
#define LC_DSA_NATURAL_SIG_Y 0
#undef LC_DSA_RAW_Y_ALL_CACHE
#define LC_DSA_RAW_Y_ALL_CACHE 1
#endif
/* Compact ARM keeps only current-attempt masks in the exact output region.
 * Parameter65 retains its existing mixed-head schedule, with no raw prefix. */
#ifndef LC_DSA_ARM_COMPACT_BATCH87
#define LC_DSA_ARM_COMPACT_BATCH87 0
#endif
#if LC_DSA_ARM_COMPACT_BATCH87 != 0 && LC_DSA_ARM_COMPACT_BATCH87 != 1
#error "ARM compact mask retention must be zero or one"
#endif
#if LC_DSA_ARM_COMPACT_BATCH87
#if !defined(__aarch64__) || !defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE || !defined(MLD_CONFIG_REDUCE_RAM)
#error "Compact mask retention requires the reduced-memory ARM implementation"
#endif
#if LC_DSA_BORROW_SIG_Y || LC_DSA_FULL_Y_BATCH || LC_DSA_A_CACHE_POLYS || LC_DSA_RAW_Y_PREFIX65 || LC_DSA_RAW_Y_PREFIX87
#error "Compact ARM mask schedule has exclusive current-output ownership"
#endif
#undef LC_DSA_BORROW_SIG_Y
#define LC_DSA_BORROW_SIG_Y 1
#undef LC_DSA_FULL_Y_BATCH
#define LC_DSA_FULL_Y_BATCH 1
#undef LC_DSA_RAW_Y_PREFIX87
#define LC_DSA_RAW_Y_PREFIX87 7
#endif
/* These predicates remain parameter-local in multilevel translation units. */
#define LC_DSA_NATURAL_SIG_Y_ACTIVE (LC_DSA_NATURAL_SIG_Y && MLD_CONFIG_PARAMETER_SET != 44)
#define LC_DSA_BORROW_SIG_Y_ACTIVE (LC_DSA_BORROW_SIG_Y && (!LC_DSA_NATURAL_SIG_Y || MLD_CONFIG_PARAMETER_SET != 44))
#if LC_DSA_NATURAL_SIG_Y
#if !LC_DSA_BORROW_SIG_Y || !LC_DSA_FIRST_GAMMA_CACHE || LC_DSA_RAW_Y_ALL_CACHE || LC_DSA_STREAM_CACHE24 || LC_DSA_STREAM_RECOMPUTE || !LC_DSA_RAW_Y4_CACHE || !defined(__AVX2__) || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE)
#error "Natural mask retention requires the compact AVX2 sampling schedule"
#endif
#endif
#if LC_DSA_BORROW_SIG_Y
#if !defined(MLD_CONFIG_REDUCE_RAM)
#error "Signature-backed masks require reduced-memory signing"
#endif
#if !(defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE) && !LC_DSA_RAW_Y_ALL_CACHE && !LC_DSA_NATURAL_SIG_Y
#error "AVX2 signature-backed masks require full raw retention or natural retention"
#endif
#endif
#if LC_DSA_DEFER_CHALLENGE_NTT
#if !defined(__AVX2__) || !LC_DSA_SPARSE_PRODUCT || !LC_DSA_SPARSE_SEPARATE_CP || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE)
#error "Deferred challenge NTT requires the AVX2 separate-challenge sparse path"
#endif
#endif
#if LC_DSA_PARAMETER_A32
#if !defined(__AVX2__) || LC_DSA_A_CACHE_BITS != 24 || !LC_DSA_A_PLANES24 || !LC_DSA_A_CACHE_SIGN_ONLY || LC_DSA_A_CACHE_POLYS < 56 || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE)
#error "Parameter-selected matrix words require the complete AVX2 split-plane sign cache"
#endif
#endif
#if LC_DSA_EARLY_LOW_44 && (LC_DSA_EARLY_LOW_ROWS < 4 || LC_DSA_STREAM_RECOMPUTE || !LC_DSA_PACK_W0)
#error "Early44 low checks require all four packed low rows"
#endif
#ifndef LC_DSA_PUBLIC_A_SESSION
#define LC_DSA_PUBLIC_A_SESSION 0
#endif
#if LC_DSA_PUBLIC_A_SESSION != 0 && LC_DSA_PUBLIC_A_SESSION != 1
#error "public A session must be zero or one"
#endif
#if LC_DSA_PUBLIC_A_SESSION && LC_DSA_PARTIAL_DENSE_ROWS
#error "row-major partial cache and column-major public session are mutually exclusive"
#endif
#if LC_DSA_PUBLIC_A_SESSION && LC_DSA_A_CACHE_BATCH4
#error "public session forbids call-owned batch prefill of the retained cache"
#endif
#if LC_DSA_PUBLIC_A_SESSION
#if !defined(MLD_CONFIG_REDUCE_RAM) || !LC_DSA_A_CACHE_SIGN_ONLY || LC_DSA_A_CACHE_POLYS < 56 || !LC_DSA_CACHED_DOT_TILE || !LC_DSA_STREAM_CACHE24 || !LC_DSA_A_PLANES24
#error "Public-A session prototype requires the complete speed matrix configuration"
#endif
#endif
#include "mldsa_native_config.h"
#endif
