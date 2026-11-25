#ifndef LC_DSA_CONFIG_H
#define LC_DSA_CONFIG_H
#if LC_DSA_PUBLIC_A_SESSION != 0 && LC_DSA_PUBLIC_A_SESSION != 1
#error Native public A session must be zero or one
#endif
#if LC_NATIVE_MATRIX_CACHE < 0 || LC_NATIVE_MATRIX_CACHE > 56 || \
    LC_NATIVE_S1_CACHE < 0 || LC_NATIVE_S1_CACHE > 7 || \
    LC_NATIVE_S2_CACHE < 0 || LC_NATIVE_S2_CACHE > 8 || \
    LC_NATIVE_T0_CACHE < 0 || LC_NATIVE_T0_CACHE > 8
#error Native cache prefix outside the supported standard-parameter maxima
#endif
#if LC_NATIVE_A_SESSION_POLYS && !LC_DSA_PUBLIC_A_SESSION
#error Native persistent A prefix requires the public session API
#endif
#if LC_DSA_PUBLIC_A_SESSION
#if !defined(MLD_CONFIG_REDUCE_RAM)
#error Native public A session requires the lazy native backend
#endif
#if !defined(LC_NATIVE_A_SESSION_POLYS) || LC_NATIVE_A_SESSION_POLYS < 1 || LC_NATIVE_A_SESSION_POLYS > 56
#error Native public A session prefix must be in 1..56
#endif
#if defined(LC_NATIVE_MATRIX_CACHE) && LC_NATIVE_MATRIX_CACHE > 0
#error Session A and call-owned A must not both allocate a prefix
#endif
#if defined(MLD_CONFIG_KEYGEN_PCT)
#error Session prototype does not include nested key-generation PCT bounds
#endif
#endif
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
#include "mldsa_native_config.h"
#endif
