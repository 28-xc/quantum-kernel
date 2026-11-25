#ifndef LC_HOSTED_MLK_CONFIG_H
#define LC_HOSTED_MLK_CONFIG_H
#define MLK_CONFIG_NAMESPACE_PREFIX lc_base_mlk
#define MLK_CONFIG_MULTILEVEL_BUILD
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_CONTEXT_PARAMETER
#define MLK_CONFIG_CONTEXT_PARAMETER_TYPE lc_arena *
#if !defined(__ASSEMBLER__)
#include "lc_arena.h"
#endif
#if defined(LC_NATIVE)
#define MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
#define MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLK_CONFIG_ARITH_BACKEND_FILE "native/meta.h"
#define MLK_CONFIG_FIPS202_BACKEND_FILE "fips202/native/auto.h"
#endif
#if defined(MLK_BUILD_INTERNAL)
#define MLK_CONFIG_CUSTOM_ALLOC_FREE
/* Assembly accesses the same constant objects as C; do not make them static.
 * The shared-library export map keeps implementation entities private. */
#if !defined(__ASSEMBLER__)
#define MLK_CUSTOM_ALLOC(v,T,N,context) T *v = (T *)lc_arena_alloc(context,sizeof(T)*(N))
#define MLK_CUSTOM_FREE(v,T,N,context) lc_arena_free(context,v,sizeof(T)*(N))
#endif
#endif
#endif
