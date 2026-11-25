/* SPDX-License-Identifier: Apache-2.0
 * Component validation of the included production in-place A*y helper.
 * NTT/order adapters inject an existing frequency-domain vector; this file
 * does not test an NTT, SHAKE, a complete signature, or side-channel security.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifndef TEST_PARAMETER
#error "Select TEST_PARAMETER=44,65,87"
#endif
#if TEST_PARAMETER == 44
#define MLDSA_K 4
#define MLDSA_L 4
#elif TEST_PARAMETER == 65
#define MLDSA_K 6
#define MLDSA_L 5
#elif TEST_PARAMETER == 87
#define MLDSA_K 8
#define MLDSA_L 7
#else
#error "Unsupported ML-DSA parameter"
#endif
#define MLDSA_N 256
#define MLDSA_Q 8380417
#define MLDSA_SEEDBYTES 32
#define SHAKE128_RATE 168
#define LC_DSA_DENSE_SIGN_ROWS 1
#define LC_DSA_CACHED_DOT_TILE 1
#define LC_DSA_INPLACE_AY 1
#define LC_DSA_A_PLANES24 1
#define LC_DSA_A_CACHE_BITS 24
#define LC_DSA_A_CACHE_COUNT (MLDSA_K*MLDSA_L)
#define LC_DSA_STREAM_CACHE24 1
#define LC_DSA_MATRIX_STREAM_VECTOR 1
#define LC_DSA_NATIVE_SIGN_ORDER 0
#define LC_SIGN_AY_ROW_BYTES 1056
#define GUARD 64
#define Y_BOUND 94279698
#define RANDOM_CASES 512
#define mld_memcpy memcpy
#define mld_memset memset
typedef struct { _Alignas(32) int32_t coeffs[MLDSA_N]; } mld_poly;
typedef struct {
  uint8_t (*cache)[768];
  unsigned cache_ready;
  uint8_t rho[32];
  struct { uint64_t state[100]; } stream4;
} mld_polymat;
typedef struct { const mld_poly *input; } mld_yvec;

static void mld_yvec_get_poly(mld_poly *dst,const mld_yvec *v,unsigned l) {
  memcpy(dst,v->input+l,sizeof(*dst));
}
static void mld_poly_ntt(mld_poly *p) { (void)p; }
static void lc_stream_transform_order(mld_poly *p) { (void)p; }

#include "lc_a_planes24.h"
#if defined(__AVX2__)
#include "lc_stream4_vector.h"
#include "lc_inplace_ay.h"
#define TEST_BACKEND "AVX2"
static void invoke(uint8_t *w,mld_polymat *mat,const mld_yvec *y) {
  lc_inplace_ay(w,mat,y);
}
static void encode8(uint8_t *a,unsigned i,const uint32_t *x) {
  lc_a_planes_store8(a,i,_mm256_loadu_si256((const __m256i *)(const void *)x));
}
static void decode8(uint32_t *x,const uint8_t *a,unsigned i) {
  _mm256_storeu_si256((__m256i *)(void *)x,lc_a_planes_load(a,i));
}
#elif defined(__aarch64__)
#include "lc_stream_neon.h"
/* cache_ready=1 is a precondition of this injected-domain component test.
 * Fail closed if production unexpectedly calls its matrix-generation path. */
static void unreachable_fill(void) {
  fputs("Unexpected matrix generation in injected-domain test\n",stderr);
  abort();
}
static void mld_keccakf1600x4_permute(uint64_t *state) {
  (void)state;unreachable_fill();
}
static void lc_stream_cache_store8(mld_polymat *m,unsigned at,unsigned i,
                                   uint32x4_t a,uint32x4_t b) {
  (void)m;(void)at;(void)i;(void)a;(void)b;unreachable_fill();
}
static void lc_stream_cache_store1(mld_polymat *m,unsigned at,unsigned i,uint32_t a) {
  (void)m;(void)at;(void)i;(void)a;unreachable_fill();
}
#include "lc_speed32_neon.h"
#define TEST_BACKEND "AArch64-NEON"
static void invoke(uint8_t *w,mld_polymat *mat,const mld_yvec *y) {
  lc_arm_speed32_ay(w,mat,y,NULL);
}
static void encode8(uint8_t *a,unsigned i,const uint32_t *x) {
  lc_a_planes_store8_neon(a,i,vld1q_u32(x),vld1q_u32(x+4));
}
static void decode8(uint32_t *x,const uint8_t *a,unsigned i) {
  uint32x4_t a0,a1;lc_a_planes_load_neon(a,i,&a0,&a1);
  vst1q_u32(x,a0);vst1q_u32(x+4,a1);
}
#else
#error "This component test requires real AVX2 or AArch64 NEON execution"
#endif

static _Alignas(32) uint8_t output_region[GUARD+MLDSA_K*LC_SIGN_AY_ROW_BYTES+GUARD];
static _Alignas(32) uint8_t matrix_region[GUARD+MLDSA_K*MLDSA_L*768+GUARD];
static uint8_t matrix_copy[sizeof(matrix_region)];
static mld_poly inputs[MLDSA_L],input_copy[MLDSA_L];
static uint32_t original_a[MLDSA_L][MLDSA_K][MLDSA_N];
static uint64_t rng=UINT64_C(0xc937a6054e21b8df);
static uint64_t cases_checked,coefficients_checked,plane_coefficients_checked,guard_bytes_checked;
static uint64_t result_digest=UINT64_C(1469598103934665603);
static unsigned family_counts[4];
static uint32_t rinv;
static uint64_t next_u64(void) {
  rng ^= rng<<13;rng ^= rng>>7;rng ^= rng<<17;return rng;
}
static uint32_t power_mod(uint32_t a,uint32_t n) {
  uint64_t r=1,b=a;
  while(n) {if(n&1u)r=r*b%MLDSA_Q;b=b*b%MLDSA_Q;n>>=1;}
  return (uint32_t)r;
}
static int32_t center(int64_t x) {
  x%=MLDSA_Q;if(x<0)x+=MLDSA_Q;
  if(x>MLDSA_Q/2)x-=MLDSA_Q;
  return (int32_t)x;
}
static int fail(const char *kind,unsigned k,unsigned i,int64_t actual,int64_t expected) {
  fprintf(stderr,"FAIL parameter=%d case=%" PRIu64 " kind=%s row=%u index=%u actual=%" PRId64 " expected=%" PRId64 "\n",
          TEST_PARAMETER,cases_checked,kind,k,i,actual,expected);
  return 0;
}
static uint8_t gap_value(unsigned k) {return (uint8_t)(0x38u+7u*k);}
static int check_guards(void) {
  for(unsigned i=0;i<GUARD;i++) {
    guard_bytes_checked+=4;
    if(output_region[i]!=0xa5 || output_region[sizeof(output_region)-GUARD+i]!=0x5a)
      return fail("outer-output-guard",0,i,0,1);
    if(matrix_region[i]!=0x69 || matrix_region[sizeof(matrix_region)-GUARD+i]!=0x96)
      return fail("outer-matrix-guard",0,i,0,1);
  }
  for(unsigned k=0;k<MLDSA_K;k++)for(unsigned i=1024;i<LC_SIGN_AY_ROW_BYTES;i++) {
    guard_bytes_checked++;
    if(output_region[GUARD+k*LC_SIGN_AY_ROW_BYTES+i]!=gap_value(k))
      return fail("row-gap",k,i,output_region[GUARD+k*LC_SIGN_AY_ROW_BYTES+i],gap_value(k));
  }
  return 1;
}
static int check_case(unsigned family) {
  mld_polymat mat={0};
  mld_yvec y={inputs};
  uint8_t *w=output_region+GUARD;
  mat.cache=(uint8_t (*)[768])(void *)(matrix_region+GUARD);
  mat.cache_ready=1;
  memset(output_region,0xcc,sizeof(output_region));
  memset(output_region,0xa5,GUARD);
  memset(output_region+sizeof(output_region)-GUARD,0x5a,GUARD);
  memset(matrix_region,0x69,GUARD);
  memset(matrix_region+sizeof(matrix_region)-GUARD,0x96,GUARD);
  for(unsigned k=0;k<MLDSA_K;k++)
    memset(w+k*LC_SIGN_AY_ROW_BYTES+1024,gap_value(k),LC_SIGN_AY_ROW_BYTES-1024);
  for(unsigned l=0;l<MLDSA_L;l++)for(unsigned k=0;k<MLDSA_K;k++) {
    uint8_t *dst=mat.cache[l*MLDSA_K+k];
    if(cases_checked&1u)for(unsigned i=0;i<MLDSA_N;i++)
      lc_a_planes_store1(dst,i,original_a[l][k][i]);
    else for(unsigned i=0;i<MLDSA_N;i+=8)encode8(dst,i,original_a[l][k]+i);
    for(unsigned i=0;i<MLDSA_N;i+=8) {
      uint32_t recovered[8];decode8(recovered,dst,i);
      for(unsigned j=0;j<8;j++) {
        plane_coefficients_checked++;
        if(recovered[j]!=original_a[l][k][i+j])
          return fail("plane-roundtrip",k,i+j,recovered[j],original_a[l][k][i+j]);
      }
    }
  }
  if(!check_guards())return 0;
  memcpy(matrix_copy,matrix_region,sizeof(matrix_copy));
  memcpy(input_copy,inputs,sizeof(inputs));
  invoke(w,&mat,&y);
  if(memcmp(matrix_copy,matrix_region,sizeof(matrix_copy)))
    return fail("matrix-immutability",0,0,0,1);
  if(memcmp(input_copy,inputs,sizeof(inputs)))
    return fail("input-immutability",0,0,0,1);
  if(!check_guards())return 0;
  for(unsigned k=0;k<MLDSA_K;k++)for(unsigned i=0;i<MLDSA_N;i++) {
    int64_t sum=0;
    for(unsigned l=0;l<MLDSA_L;l++)
      sum+=(int64_t)original_a[l][k][i]*input_copy[l].coeffs[i];
    /* Independent integer reference, without Montgomery or SIMD helper reuse.
     * Reduce before multiplying rinv, keeping every intermediate inside int64. */
    const int32_t expected=center((sum%MLDSA_Q)*(int64_t)rinv);
    int32_t raw;
    memcpy(&raw,w+k*LC_SIGN_AY_ROW_BYTES+4*i,sizeof(raw));
    if(raw<=-6283009 || raw>=6283009)return fail("output-range",k,i,raw,6283008);
    const int32_t actual=center(raw);
    if(actual!=expected)return fail("domain-product",k,i,actual,expected);
    result_digest^=(uint32_t)actual;result_digest*=UINT64_C(1099511628211);
    coefficients_checked++;
  }
  cases_checked++;family_counts[family]++;
  return 1;
}
static const uint32_t a_edges[]={0,1,2,255,256,65535,65536,65537,4194304,MLDSA_Q-2,MLDSA_Q-1};
static const int32_t y_edges[]={0,1,-1,MLDSA_Q-1,-(MLDSA_Q-1),Y_BOUND-1,-(Y_BOUND-1),Y_BOUND,-Y_BOUND,131072,-524288};
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
int main(void) {
#if defined(__AVX2__) && defined(__GNUC__)
  __builtin_cpu_init();
  if(!__builtin_cpu_supports("avx2")) {fputs("AVX2 unavailable\n",stderr);return 77;}
#endif
  const uint32_t rmod=(uint32_t)((UINT64_C(1)<<32)%MLDSA_Q);
  rinv=power_mod(rmod,MLDSA_Q-2);
  if((uint64_t)rinv*rmod%MLDSA_Q!=1)return 2;
  for(unsigned a=0;a<COUNT(a_edges);a++)for(unsigned y=0;y<COUNT(y_edges);y++) {
    for(unsigned l=0;l<MLDSA_L;l++)for(unsigned i=0;i<MLDSA_N;i++) {
      inputs[l].coeffs[i]=y_edges[y];
      for(unsigned k=0;k<MLDSA_K;k++)original_a[l][k][i]=a_edges[a];
    }
    if(!check_case(0))return 1;
  }
  for(unsigned t=0;t<32;t++) {
    for(unsigned l=0;l<MLDSA_L;l++)for(unsigned i=0;i<MLDSA_N;i++) {
      inputs[l].coeffs[i]=y_edges[(i+3*l+t)%COUNT(y_edges)];
      if((i+l+t)&1u)inputs[l].coeffs[i]=-inputs[l].coeffs[i];
      for(unsigned k=0;k<MLDSA_K;k++)original_a[l][k][i]=a_edges[(i+5*k+7*l+t)%COUNT(a_edges)];
    }
    if(!check_case(1))return 1;
  }
  for(unsigned active=0;active<MLDSA_L;active++)for(unsigned t=0;t<8;t++) {
    for(unsigned l=0;l<MLDSA_L;l++)for(unsigned i=0;i<MLDSA_N;i++) {
      inputs[l].coeffs[i]=(l==active && (i+t)%8==0)?((i&8)?-(Y_BOUND-1):(Y_BOUND-1)):0;
      for(unsigned k=0;k<MLDSA_K;k++)original_a[l][k][i]=(uint32_t)((next_u64()+k+i)%MLDSA_Q);
    }
    if(!check_case(2))return 1;
  }
  for(unsigned t=0;t<RANDOM_CASES;t++) {
    for(unsigned l=0;l<MLDSA_L;l++)for(unsigned i=0;i<MLDSA_N;i++) {
      inputs[l].coeffs[i]=(int32_t)(next_u64()%(2u*Y_BOUND-1u))-(Y_BOUND-1);
      for(unsigned k=0;k<MLDSA_K;k++)original_a[l][k][i]=(uint32_t)(next_u64()%MLDSA_Q);
    }
    if(!check_case(3))return 1;
  }
  printf("{\"status\":\"PASS\",\"parameter\":%d,\"backend\":\"%s\","
         "\"cases\":%" PRIu64 ",\"coefficients_checked\":%" PRIu64 ","
         "\"plane_coefficients_checked\":%" PRIu64 ",\"guard_bytes_checked\":%" PRIu64 ","
         "\"families\":{\"endpoint_cross_product\":%u,\"alternating_pattern\":%u,\"sparse_column\":%u,\"fixed_seed_random\":%u},"
         "\"maximum_contract_input_abs\":%d,\"additional_boundary_abs\":%d,"
         "\"row_stride\":%d,\"matrix_polynomial_bytes\":768,\"outer_guard_bytes\":%d,"
         "\"R_inverse_mod_q\":%u,\"result_digest_fnv64\":\"%016" PRIx64 "\"}\n",
         TEST_PARAMETER,TEST_BACKEND,cases_checked,coefficients_checked,plane_coefficients_checked,guard_bytes_checked,
         family_counts[0],family_counts[1],family_counts[2],family_counts[3],
         Y_BOUND-1,Y_BOUND,LC_SIGN_AY_ROW_BYTES,GUARD,rinv,result_digest);
  return 0;
}

