/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [DilithiumMemory]
 *   Dilithium for Memory Constrained Devices
 *   Bos, Renes, Sprenkels
 *   https://eprint.iacr.org/2022/323
 *
 * - [FIPS140_3_IG]
 *   Implementation Guidance for FIPS 140-3 and the Cryptographic Module
 *   Validation Program
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements
 *
 * - [FIPS204]
 *   FIPS 204 Module-Lattice-Based Digital Signature Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/204/final
 *
 * - [FIPS204_UPDATES]
 *   FIPS 204 Potential Updates (Errata)
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx
 *
 * - [Round3_Spec]
 *   CRYSTALS-Dilithium Algorithm Specifications and Supporting Documentation
 *   (Version 3.1)
 *   Bai, Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Seiler, Stehl茅
 *   https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
 */

#include "sign.h"
#ifndef LC_DSA_SPARSE_VERIFY_ENCODE
#define LC_DSA_SPARSE_VERIFY_ENCODE 0
#endif
#if LC_DSA_SPARSE_VERIFY_ENCODE
/* FIPS 204 public verification data only. */
#ifndef LC_VERIFY_ENCODE_HINTS_SCALAR_H
#define LC_VERIFY_ENCODE_HINTS_SCALAR_H
#include <stdint.h>
static inline unsigned lc_verify_high32(int32_t a,unsigned gamma2) {
 uint32_t h=((uint32_t)a+127u)>>7;
 if(gamma2==261888u)return ((h*1025u+(1u<<21))>>22)&15u;
 h=(h*11275u+(1u<<23))>>24;
 return h>43u?0u:h;
}
/* out has 128/192 bytes disjoint from canonical a[256]; hints has omega+k.
 * Only public signature counts/positions and public reconstructed values
 * select branches or memory addresses. No secret key is input. */
static inline int lc_verify_encode_hints_scalar(uint8_t *out,const int32_t *a,
 const uint8_t *hints,unsigned row,unsigned k,unsigned omega,unsigned gamma2) {
 unsigned first=row?hints[omega+row-1]:0,last=hints[omega+row];
 if(last<first||last>omega)return -1;
 for(unsigned t=first+1;t<last;t++)if(hints[t]<=hints[t-1])return -1;
 if(row==k-1)for(unsigned t=last;t<omega;t++)if(hints[t])return -1;
 if(gamma2==261888u) {
  for(unsigned j=0;j<256;j+=2)out[j/2]=(uint8_t)(lc_verify_high32(a[j],gamma2)|(lc_verify_high32(a[j+1],gamma2)<<4));
  for(unsigned t=first;t<last;t++) {
   unsigned j=hints[t],shift=4*(j&1u),high=(out[j/2]>>shift)&15u;
   int32_t low=a[j]-(int32_t)high*523776;
   if(low>4190208)low-=8380417;
   unsigned adjusted=(high+1u-2u*(low<=0))&15u;
   out[j/2]=(uint8_t)((out[j/2]&~(15u<<shift))|(adjusted<<shift));
  }
 } else {
  for(unsigned j=0;j<256;j+=4) {
   uint32_t packed=lc_verify_high32(a[j],gamma2)|(lc_verify_high32(a[j+1],gamma2)<<6)|(lc_verify_high32(a[j+2],gamma2)<<12)|(lc_verify_high32(a[j+3],gamma2)<<18);
   out[3*j/4]=(uint8_t)packed;out[3*j/4+1]=(uint8_t)(packed>>8);out[3*j/4+2]=(uint8_t)(packed>>16);
  }
  for(unsigned t=first;t<last;t++) {
   unsigned j=hints[t],bit=6*j,byte=bit>>3,shift=bit&7u,high=out[byte]>>shift;
   if(shift>2)high|=(unsigned)out[byte+1]<<(8-shift);
   high&=63u;
   int32_t low=a[j]-(int32_t)high*190464;
   if(low>4190208)low-=8380417;
   int32_t adjusted=(int32_t)high+1-2*(low<=0);
   if(adjusted<0)adjusted+=44;
   if(adjusted>43)adjusted-=44;
   out[byte]=(uint8_t)((out[byte]&~(63u<<shift))|((unsigned)adjusted<<shift));
   if(shift>2)out[byte+1]=(uint8_t)((out[byte+1]&~(63u>>(8-shift)))|((unsigned)adjusted>>(8-shift)));
  }
 }
 return 0;
}
#endif

#endif
/* Direct row consumption changes only where an existing dense polynomial is
 * evaluated. It preserves arithmetic, row checks and all owner lifetimes. */
#ifndef LC_DSA_DIRECT_DENSE_ROWS
#define LC_DSA_DIRECT_DENSE_ROWS 0
#endif
#if LC_DSA_DIRECT_DENSE_ROWS != 0 && LC_DSA_DIRECT_DENSE_ROWS != 1
#error "direct dense rows must be disabled or enabled"
#endif
#if LC_DSA_DIRECT_DENSE_ROWS && (!LC_DSA_DENSE_SIGN_ROWS || !LC_DSA_PACKED_ACCUM || !LC_DSA_PACK_W0 || LC_DSA_STREAM_RECOMPUTE)
#error "direct row consumption requires dense packed one-pass signing rows"
#endif
#if LC_DSA_CHECKED_SPARSE
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if !defined(__aarch64__) || !LC_DSA_SPARSE_NEON
#error "Checked sparse products require the AArch64 NEON eta path"
#endif
#else
#if !defined(__AVX2__) || !LC_DSA_SPARSE_PRODUCT
#error "Checked sparse products require the AVX2 eta path"
#endif
#endif
#include "lc_dsa_keycheck.h"
#endif
#if LC_DSA_BORROW_SIG_Y_ACTIVE
/* The caller owns a complete signature allocation before the call starts.
 * During each attempt its z slice temporarily holds the standard ExpandMask
 * encodings. A*y reads every row before response generation; each z row is
 * decoded completely before its same-size encoding overwrites that row.
 * A rejected attempt clears the whole borrowed slice before it returns to
 * the retry loop. Successful return replaces every borrowed row with z;
 * all failing outer returns additionally clear the complete output.
 * No borrowed address is passed to the arena allocator or its release path. */
_Static_assert(MLDSA_SIG_Z_BYTES == MLDSA_L*MLDSA_POLYZ_PACKEDBYTES,
               "response allocation must fit the complete masking encoding");
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#ifndef LC_DSA_LAST_Y_CACHE
#define LC_DSA_LAST_Y_CACHE 0
#endif
#ifndef LC_DSA_LAST_Z_FIRST
#define LC_DSA_LAST_Z_FIRST 0
#endif
#ifndef LC_DSA_LAST_Y_ONLY87
#define LC_DSA_LAST_Y_ONLY87 0
#endif
#if LC_DSA_LAST_Y_ONLY87 && MLD_CONFIG_PARAMETER_SET != 87
#undef LC_DSA_LAST_Y_CACHE
#define LC_DSA_LAST_Y_CACHE 0
#undef LC_DSA_LAST_Z_FIRST
#define LC_DSA_LAST_Z_FIRST 0
#endif
#if LC_DSA_LAST_Y_CACHE && (!LC_DSA_LAST_Z_FIRST || !LC_DSA_PACKED_ACCUM || LC_DSA_STREAM_RECOMPUTE)
#error "Retained masking transform requires packed one-pass accumulation and last-z-first schedule"
#endif
#endif

#include "cbmc.h"
#include "ct.h"
#include "debug.h"
#include "packing.h"
#include "poly.h"
#include "poly_kl.h"
#include "polyvec.h"
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_DECOMPOSE_VECTOR && defined(__AVX2__)
#include "lc_decompose_vector.h"
#endif
#endif
#include "randombytes.h"
#include "symmetric.h"
#include "lc_matrix4_workspace.h"

#ifndef LC_DSA_PARTIAL_DENSE_ROWS
#define LC_DSA_PARTIAL_DENSE_ROWS 0
#endif
#define LC_DSA_PARTIAL_DENSE_ACTIVE (LC_DSA_PARTIAL_DENSE_ROWS && MLDSA_K == 8)
#if LC_DSA_PARTIAL_DENSE_ACTIVE
#if LC_DSA_PARTIAL_DENSE_ROWS < 1 || LC_DSA_PARTIAL_DENSE_ROWS >= MLDSA_L || LC_DSA_A_CACHE_COUNT != LC_DSA_PARTIAL_DENSE_ROWS*MLDSA_L || !LC_DSA_INPLACE_AY || !LC_DSA_A_PLANES24
#error "Partial dense rows require exact whole cached rows and split-plane in-place product"
#endif
#if defined(__aarch64__)
#if !defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE || !LC_DSA_STREAM_NEON || !LC_DSA_STREAM_DIRECT_STATE
#error "partial dense AArch64 sampling requires stream NEON and direct state bytes"
#endif
#if !defined(MLD_SYS_LITTLE_ENDIAN) || defined(MLD_USE_NATIVE_NTT_CUSTOM_ORDER)
#error "partial dense AArch64 sampling requires canonical little-endian lanes and NTT order"
#endif
#elif !defined(__AVX2__) || !LC_DSA_MATRIX_INTERLEAVED
#error "partial dense x86 sampling requires AVX2 interleaved Keccak"
#endif
#endif

/* In-place rows are safe only when the complete product is handled by the
 * native tile routine, which loads every source lane before the first store. */
#if LC_DSA_INPLACE_AY
#if !LC_DSA_DENSE_SIGN_ROWS || !LC_DSA_CACHED_DOT_TILE || !LC_DSA_STREAM_CACHE24 || (LC_DSA_A_CACHE_COUNT < MLDSA_K*MLDSA_L && !LC_DSA_PARTIAL_DENSE_ACTIVE) || (LC_DSA_A_CACHE_BITS != 32 && !LC_DSA_A_PLANES24)
#error "in-place product requires dense rows and a complete native matrix cache"
#endif
#if defined(__aarch64__)
#if !LC_DSA_ARM_SPEED32
#error "in-place AArch64 product requires the native wide-dot implementation"
#endif
#elif !defined(__AVX2__)
#error "in-place product requires AVX2 or AArch64 NEON"
#endif
#endif

#include "rounding.h"
#include "reduce.h"
#include "lc_inplace_sampling.h"
#include "lc_hint_mask.h"
#include "lc_hint_weight.h"
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_DECOMPOSE_NEON) && LC_DSA_DECOMPOSE_NEON
#include "lc_decompose_neon.h"
#endif
#else
#endif
#if !LC_DSA_PACK_W0 || !LC_DSA_ALIAS_SIGN_CP || !defined(MLD_CONFIG_REDUCE_RAM)
#error "bitmap signing requires packed low-RAM and mat->cur aliasing"
#endif
#ifndef LC_DSA_W0_CODEC
#define LC_DSA_W0_CODEC 0
#endif
#ifndef LC_DSA_RETAIN_FULL_HIGH
#define LC_DSA_RETAIN_FULL_HIGH 0
#endif
#ifndef LC_DSA_EARLY_HINT_FLAGS
#define LC_DSA_EARLY_HINT_FLAGS 0
#endif
#if defined(_WIN32) && defined(__AVX2__) &&     defined(MLD_CONFIG_USE_NATIVE_BACKEND_ARITH) &&     LC_DSA_EARLY_HINT_FLAGS &&     (MLD_CONFIG_PARAMETER_SET == 65 || MLD_CONFIG_PARAMETER_SET == 87)
#define LC_DSA_FUSED_HINT_BITMAP 1
#include "lc_hint_fused_avx2.h"
#else
#define LC_DSA_FUSED_HINT_BITMAP 0
#endif

#ifndef LC_DSA_SIGNED24_NATIVE
#define LC_DSA_SIGNED24_NATIVE 0
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#ifndef LC_DSA_SPARSE_PRODUCT
#define LC_DSA_SPARSE_PRODUCT 0
#endif
#ifndef LC_DSA_SPARSE_SEPARATE_CP
#define LC_DSA_SPARSE_SEPARATE_CP 0
#endif
#ifndef LC_DSA_DEFER_CHALLENGE_NTT
#define LC_DSA_DEFER_CHALLENGE_NTT 0
#endif
#if LC_DSA_DEFER_CHALLENGE_NTT && (!LC_DSA_SPARSE_PRODUCT || !LC_DSA_SPARSE_SEPARATE_CP || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE))
#error "Deferred challenge requires x86 separate cp and sparse eta products"
#endif
#if LC_DSA_SPARSE_PRODUCT
#if !LC_DSA_SIGNED24_NATIVE || !LC_DSA_MATRIX_STREAM_DIRECT4 || LC_DSA_STREAM_RECOMPUTE
#error "Sparse challenge reuse requires the native one-pass packed schedule"
#endif
#include "lc_sparse8_blocks.h"
#endif
#endif
#ifndef LC_DSA_PACK_VERIFY_CP
#define LC_DSA_PACK_VERIFY_CP 0
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#ifndef LC_DSA_EARLY_LOW_ROWS
#define LC_DSA_EARLY_LOW_ROWS 0
#endif
#ifndef LC_DSA_SPARSE_NEON
#define LC_DSA_SPARSE_NEON 0
#endif
#if LC_DSA_SPARSE_NEON
#if !defined(__aarch64__) || !LC_DSA_PACKED_ACCUM || LC_DSA_STREAM_RECOMPUTE
#error "Sparse NEON requires the AArch64 one-pass packed schedule"
#endif
#include "lc_sparse8_neon.h"
#endif
#if LC_DSA_EARLY_LOW_ROWS && (!LC_DSA_SPARSE_NEON || LC_DSA_STREAM_RECOMPUTE || !LC_DSA_PACK_W0)
#error "Early low rows require sparse one-pass packed low rows"
#endif
#ifndef LC_DSA_SPARSE_T0_NEON
#define LC_DSA_SPARSE_T0_NEON 0
#endif
#if LC_DSA_SPARSE_T0_NEON
#if !LC_DSA_SPARSE_NEON
#error "Sparse t0 requires all eta products to use the coefficient domain"
#endif
#include "lc_sparse_t0_neon.h"
#endif
#if LC_DSA_PACK_VERIFY_CP && (!LC_DSA_PACKED_ACCUM || !LC_DSA_SIGNED24_NATIVE)
#error "packed challenge requires the signed24 consumer"
#endif
#ifndef LC_DSA_VERIFY_T1_CENTERED_NEON
#define LC_DSA_VERIFY_T1_CENTERED_NEON 0
#endif
#if LC_DSA_VERIFY_T1_CENTERED_NEON
#if !defined(__aarch64__) || !LC_DSA_PACK_VERIFY_CP || !LC_DSA_ALIAS_VERIFY_TMP
#error "Centered t1 uses the AArch64 packed challenge and post-matrix temporary"
#endif
#include "lc_verify_t1_centered_neon.h"
#endif
#else
#if LC_DSA_PACK_VERIFY_CP && (!LC_DSA_PACKED_ACCUM || !LC_DSA_SIGNED24_NATIVE)
#error "packed challenge requires the signed24 consumer"
#endif
#endif
#if LC_DSA_SIGNED24_NATIVE
#include "signed24_pointwise.h"
static void lc_signed24_product(mld_poly *out,const uint8_t *packed,const mld_poly *rhs,int add) {
  int avx2=0;
#if defined(__AVX2__) && defined(MLD_CONFIG_USE_NATIVE_BACKEND_ARITH)
  avx2=mld_sys_check_capability(MLD_SYS_CAP_X86_64_AVX2);
#endif
  lc_signed24_pointwise_acc(out->coeffs,packed,rhs->coeffs,add,avx2);
}
#endif
#if LC_DSA_EARLY_HINT_FLAGS && (LC_DSA_RETAIN_FULL_HIGH || LC_DSA_STREAM_RECOMPUTE)
#error "early hint flags require the one-pass bitmap layout"
#endif
#if LC_DSA_RETAIN_FULL_HIGH != 0 && LC_DSA_RETAIN_FULL_HIGH != 1
#error "retained HighBits mode must be 0 or 1"
#endif
#if LC_DSA_W0_CODEC < 0 || LC_DSA_W0_CODEC > 2
#error "unsupported low-part representation"
#endif
#ifndef LC_DSA_W0_POLYZ20
#define LC_DSA_W0_POLYZ20 0
#endif
#if LC_DSA_PACK_W0
/* Deferred hints retain the norm-adjusted value bounded by 2*gamma2 and use
 * 19/20 bits. Early fixed-time hint flags consume that value immediately;
 * their stored initial LowBits require only 18/19 bits.
 * Rows are compressed forwards into their own allocation. The tail polynomial
 * is reused only after every original 32-bit row has been consumed. */
#if LC_DSA_EARLY_HINT_FLAGS
#if MLD_CONFIG_PARAMETER_SET == 44
#define LC_W0_BITS 18
#else
#define LC_W0_BITS 19
#endif
#elif MLD_CONFIG_PARAMETER_SET == 44
#define LC_W0_BITS 19
#elif LC_DSA_W0_CODEC == 2
#define LC_W0_BITS 24
#else
#define LC_W0_BITS 20
#endif
#if LC_DSA_W0_POLYZ20 && MLDSA_K > 4 && (!defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE)
#if !LC_DSA_EARLY_HINT_FLAGS || LC_DSA_STREAM_RECOMPUTE || !defined(__AVX2__)
#error "Twenty-bit LowBits requires the AVX2 one-pass early-hint layout"
#endif
#undef LC_W0_BITS
#define LC_W0_BITS 20
#endif
#ifndef LC_DSA_INPLACE_AY
#define LC_DSA_INPLACE_AY 0
#endif
#ifndef LC_DSA_DENSE_SIGN_ROWS
#define LC_DSA_DENSE_SIGN_ROWS 0
#endif
#if LC_DSA_DENSE_SIGN_ROWS
#if !LC_DSA_CACHED_DOT_TILE || (LC_DSA_A_CACHE_BITS != 32 && !LC_DSA_A_PLANES24) || (!defined(__AVX2__) && !defined(__aarch64__))
#error "Dense rows require the complete native 32-bit matrix dot path"
#endif
#undef LC_W0_BITS
#define LC_W0_BITS 32
#endif
#define LC_W0_ROW_BYTES (MLDSA_N*LC_W0_BITS/8)
#if LC_DSA_DENSE_SIGN_ROWS
static void lc_pack_w0_row(uint8_t *out,const mld_poly *p) { mld_memcpy(out,p->coeffs,1024); }
static void lc_unpack_w0_row(mld_poly *p,const uint8_t *in) { mld_memcpy(p->coeffs,in,1024); }
#elif LC_DSA_W0_CODEC == 0
static void lc_pack_w0_row(uint8_t *out,const mld_poly *p) {
  uint32_t acc=0;
  unsigned int i,live=0,pos=0;
  for(i=0;i<MLDSA_N;i++) {
    uint32_t u=(uint32_t)p->coeffs[i]&((1u<<LC_W0_BITS)-1u);
    acc|=u<<live;live+=LC_W0_BITS;
    while(live>=8) {out[pos++]=(uint8_t)acc;acc>>=8;live-=8;}
  }
}
static void lc_unpack_w0_row(mld_poly *p,const uint8_t *in) {
  uint32_t acc=0;
  unsigned int i,live=0,pos=0;
  for(i=0;i<MLDSA_N;i++) {
    while(live<LC_W0_BITS) {acc|=(uint32_t)in[pos++]<<live;live+=8;}
    uint32_t u=acc&((1u<<LC_W0_BITS)-1u);
    p->coeffs[i]=(int32_t)(u&((1u<<(LC_W0_BITS-1))-1u))-(int32_t)(u&(1u<<(LC_W0_BITS-1)));
    acc>>=LC_W0_BITS;live-=LC_W0_BITS;
  }
}

#else
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#include "lc_w0_fixed.h"
#else
#if LC_DSA_W0_POLYZ20 && MLDSA_K > 4
#include "lc_w0_polyz20.h"
#elif LC_DSA_W0_VECTOR && defined(__AVX2__)
#include "lc_w0_vector.h"
#else
#include "lc_w0_fixed.h"
#endif
#endif
#endif

/* HighBits is needed in full only while building the challenge byte string.
 * The later MakeHint expression depends on HighBits solely through != 0. */
#if LC_DSA_RETAIN_FULL_HIGH
#define LC_W1_FLAG_BYTES 0
#else
#define LC_W1_FLAG_BYTES (MLDSA_N/8)
#endif
#define LC_W0_FLAG_STRIDE (LC_W0_ROW_BYTES+LC_W1_FLAG_BYTES)
#if LC_DSA_DIRECT_DENSE_ROWS
_Static_assert(LC_W0_ROW_BYTES == sizeof(mld_poly),
               "the dense coefficient region must be exactly one polynomial");
_Static_assert(LC_W0_FLAG_STRIDE % _Alignof(mld_poly) == 0,
               "each dense row must retain native polynomial alignment");
#endif
#if LC_DSA_PACKED_ACCUM
#define LC_PACKED_ROW_BYTES (3*MLDSA_N)
#if LC_DSA_DENSE_SIGN_ROWS
#define LC_SIGN_AY_ROW_BYTES LC_W0_FLAG_STRIDE
#else
#define LC_SIGN_AY_ROW_BYTES LC_PACKED_ROW_BYTES
#endif
#define LC_SIGN_T_OFFSET (MLDSA_K*LC_W0_FLAG_STRIDE)
#define LC_SIGN_LAST_NTT_OFFSET ((MLDSA_K-1)*LC_SIGN_AY_ROW_BYTES)
#define LC_SIGN_HASH_OFFSET (LC_SIGN_T_OFFSET>LC_SIGN_LAST_NTT_OFFSET?LC_SIGN_T_OFFSET:LC_SIGN_LAST_NTT_OFFSET)
#if LC_DSA_STREAM_RECOMPUTE
typedef struct { MLD_ALIGN uint8_t bytes[sizeof(mld_poly)+256]; } lc_sign_w0_storage;
_Static_assert(sizeof(mld_shake256ctx)<=256,"stream hash state must fit tail");
_Static_assert(sizeof(mld_poly)%_Alignof(mld_shake256ctx)==0,"stream hash tail alignment");
_Static_assert(_Alignof(lc_sign_w0_storage)>=_Alignof(mld_shake256ctx),"stream storage alignment");
#else
typedef struct { MLD_ALIGN uint8_t bytes[LC_SIGN_T_OFFSET+sizeof(mld_poly)]; } lc_sign_w0_storage;
_Static_assert(LC_SIGN_HASH_OFFSET+sizeof(mld_shake256ctx)<=sizeof(lc_sign_w0_storage),"stream hash must fit beyond compact rows and last NTT row");
_Static_assert(LC_SIGN_HASH_OFFSET%_Alignof(mld_shake256ctx)==0,"stream hash offset alignment");
_Static_assert(_Alignof(lc_sign_w0_storage)>=_Alignof(mld_shake256ctx),"stream hash storage alignment");
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_LAST_Y_CACHE
#define LC_LAST_Y_OFFSET (LC_SIGN_T_OFFSET+sizeof(mld_poly)-LC_PACKED_ROW_BYTES)
_Static_assert(LC_LAST_Y_OFFSET>=LC_SIGN_LAST_NTT_OFFSET,"cached y overwrites only saved last row");
_Static_assert(LC_LAST_Y_OFFSET>=LC_SIGN_T_OFFSET,"cached y follows all low rows");
_Static_assert(LC_LAST_Y_OFFSET+LC_PACKED_ROW_BYTES==sizeof(lc_sign_w0_storage),"cache fits existing tail");
_Static_assert(sizeof(mld_poly)-LC_PACKED_ROW_BYTES>=MLDSA_TAU+1,"challenge staging precedes cache");
#endif
#endif
#if LC_DSA_KEYVERIFY_DENSE && defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#define LC_DSA_VECTOR_ROW_BYTES 1024
#else
#define LC_DSA_VECTOR_ROW_BYTES LC_PACKED_ROW_BYTES
#endif
typedef uint8_t lc_packed_vecl[MLDSA_L][LC_DSA_VECTOR_ROW_BYTES];
typedef char lc_packed_w_fit[LC_DSA_STREAM_RECOMPUTE || sizeof(lc_sign_w0_storage)>=MLDSA_K*LC_PACKED_ROW_BYTES?1:-1];
typedef char lc_packed_t_align[LC_SIGN_T_OFFSET%_Alignof(mld_poly)==0?1:-1];
#ifndef LC_DSA_FUSED_PACKED_MATRIX
#define LC_DSA_FUSED_PACKED_MATRIX 0
#endif
/* AVX2 custom order is an 8-by-8 transpose inside each 64 coefficients.
 * Addresses depend only on the public ExpandA rejection cursor. */
static MLD_INLINE unsigned lc_matrix_native_index(unsigned i) {
#if LC_DSA_MATRIX_STREAM_VECTOR
  return i;
#elif defined(MLD_ARITH_BACKEND_X86_64_DEFAULT)
  if(mld_sys_check_capability(MLD_SYS_CAP_X86_64_AVX2))
    return (i&192u)|((i&7u)<<3)|((i&56u)>>3);
#elif defined(MLD_USE_NATIVE_NTT_CUSTOM_ORDER)
#error "Define the transform-order mapping for this native backend"
#endif
  return i;
}
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_MATRIX_STREAM_VECTOR && defined(__AVX2__) && defined(MLD_ARITH_BACKEND_X86_64_DEFAULT)
#include "lc_permute_i32.h"
#endif
#endif
static MLD_INLINE void lc_stream_transform_order(mld_poly *p) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_MATRIX_STREAM_VECTOR && defined(MLD_ARITH_BACKEND_X86_64_DEFAULT)
  mld_poly_permute_bitrev_to_custom(p->coeffs);
#else
  (void)p;
#endif
#else
#if LC_DSA_MATRIX_STREAM_VECTOR && defined(__AVX2__) && defined(MLD_ARITH_BACKEND_X86_64_DEFAULT)
  lc_flat_permute_i32(p);
#else
  (void)p;
#endif
#endif
}
#if LC_DSA_FUSED_PACKED_MATRIX
/* ExpandA uses public rho and public indices. The rejection cursor depends
 * solely on those public bytes. SHAKE rate blocks are consumed in order. */
static void lc_fused_matrix_y(uint8_t *out,const mld_poly *y,const uint8_t seed[34],unsigned first) {
  uint8_t buf[SHAKE128_RATE];mld_xof128_ctx state;unsigned ctr=0;
  mld_xof128_init(&state);mld_xof128_absorb_once(&state,seed,34);
  do {
    mld_xof128_squeezeblocks(buf,1,&state);
    for(unsigned j=0;ctr<MLDSA_N && j+3<=SHAKE128_RATE;j+=3) {
      uint32_t a=((uint32_t)buf[j]|((uint32_t)buf[j+1]<<8)|((uint32_t)buf[j+2]<<16))&0x7fffffu;
      if(a<MLDSA_Q) {
        unsigned i=lc_matrix_native_index(ctr);
        uint8_t *v=out+3*i;
        int32_t x=mld_montgomery_reduce((int64_t)a*y->coeffs[i]);
        x+=first?0:lc_load_signed24(v);lc_store_signed24(v,mld_reduce32(x));ctr++;
      }
    }
  } while(ctr<MLDSA_N);
  mld_xof128_release(&state);mld_zeroize(buf,sizeof(buf));
}
static void lc_fused_matrix_v(mld_poly *out,const uint8_t *v,const uint8_t seed[34],unsigned first) {
  uint8_t buf[SHAKE128_RATE];mld_xof128_ctx state;unsigned ctr=0;
  mld_xof128_init(&state);mld_xof128_absorb_once(&state,seed,34);
  do {
    mld_xof128_squeezeblocks(buf,1,&state);
    for(unsigned j=0;ctr<MLDSA_N && j+3<=SHAKE128_RATE;j+=3) {
      uint32_t a=((uint32_t)buf[j]|((uint32_t)buf[j+1]<<8)|((uint32_t)buf[j+2]<<16))&0x7fffffu;
      if(a<MLDSA_Q) {
        unsigned i=lc_matrix_native_index(ctr++);
        int32_t x=mld_montgomery_reduce((int64_t)a*lc_load_signed24(v+3*i));
        out->coeffs[i]=first?x:out->coeffs[i]+x;
      }
    }
  } while(ctr<MLDSA_N);
  mld_xof128_release(&state);mld_zeroize(buf,sizeof(buf));
}
#endif
#if LC_DSA_A_PLANES24
#include "lc_a_planes24.h"
#endif
#if LC_DSA_MATRIX_STREAM_DIRECT4
#include "lc_matrix_stream4.h"
#if LC_DSA_FLAT_MATRIX_NEON && defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#include "lc_flat_matrix_neon.h"
#endif
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_CODEC24_NEON) && LC_DSA_CODEC24_NEON
#include "lc_codec24_neon.h"
#endif
#if defined(LC_DSA_CROSSCOL6) && LC_DSA_CROSSCOL6 && MLDSA_K == 6
#include "lc_crosscol6.h"
#endif
#if LC_DSA_Y_CACHE_COUNT > 0
#include "lc_raw_y4.h"
#endif

#else
#if LC_DSA_FLAT_VERIFY
#include "lc_flat_verify.h"
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
#include "lc_verify_hash3.h"
#endif
#endif
#if LC_DSA_CROSSCOL6 == 2 && MLDSA_K == 6 && (!LC_DSA_STREAM_CACHE24 || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE))
#include "lc_crosscol6_avx2.h"
#if LC_DSA_HYBRID_NEXTY
#include "lc_nexty5.h"
#endif
#endif
#if (LC_DSA_RAW_Y4_CACHE && MLDSA_K == 4) || LC_DSA_RAW_Y_ALL_CACHE
#include "lc_raw_y4.h"
#endif
#if LC_DSA_PAIR_COLUMN && MLDSA_K == 4 && !LC_DSA_STREAM_CACHE24
#include "lc_pair_column.h"
#endif
#endif
/* Keep one y transform per column. Every column is reduced into signed 24-bit
 * residues; |reduce32(x)|<6283009 fits the signed representation exactly. */
#ifndef LC_DSA_CACHED_DOT_TILE
#define LC_DSA_CACHED_DOT_TILE 0
#endif
#if LC_DSA_CACHED_DOT_TILE && LC_DSA_STREAM_CACHE24 && defined(__AVX2__) && !LC_DSA_MATRIX_INTERLEAVED
#error "Cached vector dot requires interleaved AVX2 matrix sampling"
#endif
#if LC_DSA_CACHED_DOT_TILE && LC_DSA_STREAM_CACHE24 && defined(__AVX2__) && LC_DSA_A_CACHE_COUNT >= MLDSA_K*MLDSA_L
/* Complete the public matrix once, before consuming the independent y vector.
 * Four consecutive column-major entries can span a column boundary. */
static __attribute__((optimize("O3"))) void lc_fill_full_cache(mld_polymat *mat) {
  for(unsigned base=0;base<MLDSA_K*MLDSA_L;base+=4) {
    unsigned lanes=MLDSA_K*MLDSA_L-base<4?MLDSA_K*MLDSA_L-base:4;
    unsigned ctr[4]={0,0,0,0};
    mld_memset(&mat->stream4,0,sizeof(mat->stream4));
    for(unsigned lane=0;lane<4;lane++) {
      unsigned index=base+(lane<lanes?lane:0);
      for(unsigned word=0;word<4;word++) {
        uint64_t x;mld_memcpy(&x,mat->rho+8*word,8);
        mat->stream4.state[4*word+lane]=x;
      }
      mat->stream4.state[16+lane]=(uint64_t)(index/MLDSA_K)
         |((uint64_t)(index%MLDSA_K)<<8)|((uint64_t)0x1f<<16);
      mat->stream4.state[56+lane]=(uint64_t)0x80<<56;
    }
    for(;;) {
      unsigned pending=0;
      lc_matrix_x4_permute(mat,4);
      for(unsigned lane=0;lane<lanes;lane++) {
        if(ctr[lane]==MLDSA_N)continue;
        lc_matrix_x4_extract(mat,lane,4);
        for(unsigned j=0;ctr[lane]<MLDSA_N && j+3<=SHAKE128_RATE;) {
          const uint8_t *b=mat->stream4.rate+j;
          if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N) {
            __m256i a=_mm256_and_si256(lc_s4_load24(b),_mm256_set1_epi32(0x7fffff));
            if(!_mm256_movemask_epi8(_mm256_cmpgt_epi32(a,_mm256_set1_epi32(8380416)))) {
#if LC_DSA_A_PLANES24
              lc_a_planes_store8(mat->cache[base+lane],ctr[lane],a);
#elif LC_DSA_A_CACHE_BITS == 32
              _mm256_storeu_si256((__m256i*)(void*)(mat->cache[base+lane]+4*ctr[lane]),a);
#else
              lc_s4_store24(mat->cache[base+lane]+3*ctr[lane],a);
#endif
              ctr[lane]+=8;j+=24;continue;
            }
          }
          uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
          j+=3;
          if(a<MLDSA_Q) {
#if LC_DSA_A_PLANES24
            lc_a_planes_store1(mat->cache[base+lane],ctr[lane]++,a);
#elif LC_DSA_A_CACHE_BITS == 32
            mld_memcpy(mat->cache[base+lane]+4*ctr[lane]++,&a,sizeof(a));
#else
            uint8_t *out=mat->cache[base+lane]+3*ctr[lane]++;
            out[0]=(uint8_t)a;out[1]=(uint8_t)(a>>8);out[2]=(uint8_t)(a>>16);
#endif
          }
        }
        if(ctr[lane]<MLDSA_N)pending=1;
      }
      if(!pending)break;
    }
  }
  mat->cache_ready=1;
}
#endif
#if LC_DSA_JOINT_A_MASK65 && MLDSA_K == 6
static __attribute__((optimize("O3"))) void lc_fill_joint_matrix_mask65(mld_yvec *y,mld_polymat *mat,uint8_t *encoded) {
  for(unsigned base=0;base<MLDSA_K*MLDSA_L;base+=4) {
    unsigned lanes=MLDSA_K*MLDSA_L-base<4?MLDSA_K*MLDSA_L-base:4;
    unsigned ctr[4]={0,0,0,0};
    mld_memset(&mat->stream4,0,sizeof(mat->stream4));
    for(unsigned lane=0;lane<4;lane++) {
      if(base+2==MLDSA_K*MLDSA_L && lane>=2) {
        for(unsigned word=0;word<8;word++) {
          uint64_t x;mld_memcpy(&x,y->rhoprime+8*word,8);
          mat->stream4.state[4*lc_matrix_word_to_slot[word]+lane]=x;
        }
        uint16_t nonce=(uint16_t)(y->kappa+lane-2);
        mat->stream4.state[4*lc_matrix_word_to_slot[8]+lane]=(uint64_t)nonce|((uint64_t)0x1f<<16);
        mat->stream4.state[4*lc_matrix_word_to_slot[16]+lane]=(uint64_t)0x80<<56;
        continue;
      }
      unsigned index=base+(lane<lanes?lane:0);
      for(unsigned word=0;word<4;word++) {
        uint64_t x;mld_memcpy(&x,mat->rho+8*word,8);
        mat->stream4.state[4*word+lane]=x;
      }
      mat->stream4.state[16+lane]=(uint64_t)(index/MLDSA_K)
         |((uint64_t)(index%MLDSA_K)<<8)|((uint64_t)0x1f<<16);
      mat->stream4.state[56+lane]=(uint64_t)0x80<<56;
    }
    unsigned gamma_pos=0;
    for(;;) {
      unsigned pending=0;
      lc_matrix_x4_permute(mat,4);
      if(base+2==MLDSA_K*MLDSA_L && gamma_pos<MLDSA_POLYZ_PACKEDBYTES) {
        unsigned bytes=MLDSA_POLYZ_PACKEDBYTES-gamma_pos;
        if(bytes>SHAKE256_RATE)bytes=SHAKE256_RATE;
        for(unsigned lane=2;lane<4;lane++)
          for(unsigned word=0;word<bytes/8;word++)
            mld_memcpy(encoded+(lane-2)*MLDSA_POLYZ_PACKEDBYTES+gamma_pos+8*word,
                       mat->stream4.state+4*lc_matrix_word_to_slot[word]+lane,8);
        gamma_pos+=bytes;
      }
      for(unsigned lane=0;lane<lanes;lane++) {
        if(ctr[lane]==MLDSA_N)continue;
        lc_matrix_x4_extract(mat,lane,4);
        for(unsigned j=0;ctr[lane]<MLDSA_N && j+3<=SHAKE128_RATE;) {
          const uint8_t *b=mat->stream4.rate+j;
          if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N) {
            __m256i a=_mm256_and_si256(lc_s4_load24(b),_mm256_set1_epi32(0x7fffff));
            if(!_mm256_movemask_epi8(_mm256_cmpgt_epi32(a,_mm256_set1_epi32(8380416)))) {
#if LC_DSA_A_PLANES24
              lc_a_planes_store8(mat->cache[base+lane],ctr[lane],a);
#elif LC_DSA_A_CACHE_BITS == 32
              _mm256_storeu_si256((__m256i*)(void*)(mat->cache[base+lane]+4*ctr[lane]),a);
#else
              lc_s4_store24(mat->cache[base+lane]+3*ctr[lane],a);
#endif
              ctr[lane]+=8;j+=24;continue;
            }
          }
          uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
          j+=3;
          if(a<MLDSA_Q) {
#if LC_DSA_A_PLANES24
            lc_a_planes_store1(mat->cache[base+lane],ctr[lane]++,a);
#elif LC_DSA_A_CACHE_BITS == 32
            mld_memcpy(mat->cache[base+lane]+4*ctr[lane]++,&a,sizeof(a));
#else
            uint8_t *out=mat->cache[base+lane]+3*ctr[lane]++;
            out[0]=(uint8_t)a;out[1]=(uint8_t)(a>>8);out[2]=(uint8_t)(a>>16);
#endif
          }
        }
        if(ctr[lane]<MLDSA_N)pending=1;
      }
      if(!pending)break;
    }
  }
  mat->cache_ready=1;
}

#endif

#if LC_DSA_ARM_SPEED32 && !LC_DSA_PARTIAL_DENSE_ACTIVE
#include "lc_speed32_neon.h"
#endif
#if LC_DSA_INPLACE_AY && defined(__AVX2__) && !LC_DSA_PARTIAL_DENSE_ACTIVE
#include "lc_inplace_ay.h"
#endif
#if LC_DSA_PARTIAL_DENSE_ACTIVE
#include "lc_partial_dense.h"
#endif
static void lc_packed_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,mld_poly *scratch
#if LC_DSA_CACHED_DOT_TILE
    ,mld_poly *tile
#endif
) {
#if LC_DSA_PARTIAL_DENSE_ACTIVE
  lc_partial_dense_ay(w,mat,y,tile);return;
#elif LC_DSA_ARM_SPEED32
  lc_arm_speed32_ay(w,mat,y,tile);return;
#endif
#if LC_DSA_CACHED_DOT_TILE && LC_DSA_STREAM_CACHE24 && defined(__AVX2__) && LC_DSA_A_CACHE_COUNT >= MLDSA_K*MLDSA_L
  if(!mat->cache_ready)lc_fill_full_cache(mat);
  if(mat->cache_ready) {
#if LC_DSA_INPLACE_AY
    lc_inplace_ay(w,mat,y);return;
#endif
    for(unsigned l=0;l<MLDSA_L;l++) {
      mld_yvec_get_poly(&tile[l],y,l);
      mld_poly_ntt(&tile[l]);
      lc_stream_transform_order(&tile[l]);
    }
    for(unsigned k=0;k<MLDSA_K;k++) {
      for(unsigned i=0;i<MLDSA_N;i+=8) {
        __m256i even=_mm256_setzero_si256(),odd=_mm256_setzero_si256();
        for(unsigned l=0;l<MLDSA_L;l++) {
#if LC_DSA_A_PLANES24
          __m256i av=lc_a_planes_load(mat->cache[l*MLDSA_K+k],i);
#elif LC_DSA_A_CACHE_BITS == 32
          __m256i av=_mm256_loadu_si256((const __m256i*)(const void*)(mat->cache[l*MLDSA_K+k]+4*i));
#else
          __m256i av=lc_s4_load24(mat->cache[l*MLDSA_K+k]+3*i);
#endif
          __m256i yv=_mm256_loadu_si256((const __m256i*)(const void*)(tile[l].coeffs+i));
          even=_mm256_add_epi64(even,_mm256_mul_epi32(av,yv));
          odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(yv,32)));
        }
        const __m256i qi=_mm256_set1_epi32(58728449),q=_mm256_set1_epi32(8380417);
        __m256i te=_mm256_mul_epi32(even,qi),to=_mm256_mul_epi32(odd,qi);
        __m256i re=_mm256_sub_epi64(even,_mm256_mul_epi32(te,q));
        __m256i ro=_mm256_sub_epi64(odd,_mm256_mul_epi32(to,q));
        __m256i sum=_mm256_blend_epi32(_mm256_srli_epi64(re,32),ro,0xaa);
#if LC_DSA_DENSE_SIGN_ROWS
        _mm256_store_si256((__m256i*)(void*)(w+k*LC_SIGN_AY_ROW_BYTES+4*i),lc_s4_reduce(sum));
#else
        lc_s4_store24(w+k*LC_PACKED_ROW_BYTES+3*i,lc_s4_reduce(sum));
#endif
      }
    }
    return;
  }
#elif LC_DSA_CACHED_DOT_TILE
  (void)tile;
#endif
  uint8_t seed[MLDSA_SEEDBYTES+2];
  mld_memcpy(seed,mat->rho,MLDSA_SEEDBYTES);
  for(unsigned l=0;l<MLDSA_L;l++) {
    mld_yvec_get_poly(scratch,y,l);mld_poly_ntt(scratch);
    lc_stream_transform_order(scratch);
#if LC_DSA_MATRIX_STREAM_DIRECT4
    for(unsigned k=0;k<MLDSA_K;k+=4) {
      unsigned lanes=MLDSA_K-k<4?MLDSA_K-k:4;
      lc_matrix_y_x4(w+k*LC_PACKED_ROW_BYTES,mat,scratch,l,k,lanes,l==0);
    }
#else
    for(unsigned k=0;k<MLDSA_K;k++) {
#if LC_DSA_FUSED_PACKED_MATRIX
      seed[32]=(uint8_t)l;seed[33]=(uint8_t)k;
      lc_fused_matrix_y(w+k*LC_PACKED_ROW_BYTES,scratch,seed,l==0);
#else
      MLD_ADD_PARAM_SET(mld_polymat_expand_entry)(&mat->cur,seed,(uint8_t)l,(uint8_t)k);
      mld_poly_pointwise_montgomery(&mat->cur,scratch);
      for(unsigned j=0;j<MLDSA_N;j++) {
        uint8_t *v=w+k*LC_PACKED_ROW_BYTES+3*j;
        int32_t x=mat->cur.coeffs[j]+(l==0?0:lc_load_signed24(v));
        lc_store_signed24(v,mld_reduce32(x));
      }
#endif
    }
#endif
  }
  mld_zeroize(seed,sizeof(seed));
}
static void lc_pack_matrix_ntt24(uint8_t *out,mld_poly *p) {
#if !LC_DSA_NATIVE_MATRIX_ROWS
  lc_stream_transform_order(p);
#endif
#if LC_DSA_KEYVERIFY_DENSE && defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  mld_memcpy(out,p->coeffs,1024);
#else
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_CODEC24_NEON) && LC_DSA_CODEC24_NEON
  lc_codec24_pack_neon(out,p->coeffs);
#else
  for(unsigned j=0;j<MLDSA_N;j++)lc_store_signed24(out+3*j,mld_reduce32(p->coeffs[j]));
#endif
#else
  #if LC_DSA_SIGNED24_CODEC_VECTOR && defined(__AVX2__)
  lc_s4_pack_row(out,p->coeffs);
#else
  for(unsigned j=0;j<MLDSA_N;j++)lc_store_signed24(out+3*j,mld_reduce32(p->coeffs[j]));
#endif
#endif
#endif
}
#if LC_DSA_NATIVE_MATRIX_ROWS
#define LC_DSA_VERIFY_HASH_BATCH_ARM (LC_DSA_VERIFY_HASH_BATCH && MLDSA_K < 8)
#define LC_DSA_VERIFY_MATRIX_POLYS (LC_DSA_VERIFY_HASH_BATCH_ARM?MLDSA_K*MLDSA_L:2*MLDSA_L)
#if !LC_DSA_KEYVERIFY_DENSE
#error "Native dense products require 32-bit input vectors"
#endif
static void lc_expand_native_matrix(mld_poly *a,mld_poly *spare,const uint8_t rho[32] LC_MATRIX4_PARAM) {
  #if LC_DSA_MATRIX4_ARENA
  uint8_t (*seeds)[MLD_ALIGN_UP(34)]=matrix_workspace->seeds;
#else
  MLD_ALIGN uint8_t seeds[4][MLD_ALIGN_UP(34)];
#endif
  for(unsigned flat=0;flat<MLDSA_K*MLDSA_L;flat+=4) {
    mld_poly *lane[4];
    for(unsigned j=0;j<4;j++) {
      unsigned at=flat+j;
      mld_memcpy(seeds[j],rho,32);seeds[j][32]=(uint8_t)(at%MLDSA_L);seeds[j][33]=(uint8_t)(at/MLDSA_L);
      lane[j]=at<MLDSA_K*MLDSA_L?&a[at]:&spare[j];
    }
    LC_MATRIX4_SAMPLE(lane[0],lane[1],lane[2],lane[3],seeds,matrix_workspace);
    for(unsigned j=0;j<4 && flat+j<MLDSA_K*MLDSA_L;j++)mld_poly_permute_bitrev_to_custom_optional(lane[j]);
  }
  mld_zeroize(seeds,4*MLD_ALIGN_UP(34));
}
#if LC_DSA_VERIFY_HASH_BATCH_ARM
#include "lc_verify_hash_state.h"
extern const uint8_t lcbase_rej_uniform_table[256];
extern uint64_t lcbase_rej_uniform_aarch64_asm(int32_t *,const uint8_t *,unsigned,const uint8_t *);
static void lc_expand_matrix_hash_batch(mld_poly *a,mld_poly *spare,mld_polymat *mat,
    mld_shake256ctx *saved,uint8_t mu[64],const uint8_t *pk,
    const uint8_t *pre,size_t prelen,const uint8_t *pre1,size_t prelen1,
    const uint8_t *msg,size_t mlen LC_MATRIX4_PARAM) {
  lc_verify_hash3_state hash;
  #if LC_DSA_MATRIX4_ARENA
  uint8_t (*seeds)[MLD_ALIGN_UP(34)]=matrix_workspace->seeds;
#else
  MLD_ALIGN uint8_t seeds[4][MLD_ALIGN_UP(34)];
#endif
  uint8_t *bytes=(uint8_t*)(void*)spare;
  lc_vh_start(&hash,saved,mu,pk,pre,prelen,pre1,prelen1,msg,mlen);
  for(unsigned flat=0;flat<MLDSA_K*MLDSA_L;) {
    if(hash.done) {
      mld_poly *lane[4];
      for(unsigned j=0;j<4;j++){
        unsigned at=flat+j;mld_memcpy(seeds[j],pk,32);
        seeds[j][32]=(uint8_t)(at%MLDSA_L);seeds[j][33]=(uint8_t)(at/MLDSA_L);
        lane[j]=at<MLDSA_K*MLDSA_L?&a[at]:&spare[j];
      }
      LC_MATRIX4_SAMPLE(lane[0],lane[1],lane[2],lane[3],seeds,matrix_workspace);
      for(unsigned j=0;j<4 && flat+j<MLDSA_K*MLDSA_L;j++)mld_poly_permute_bitrev_to_custom_optional(lane[j]);
      flat+=4;continue;
    }
    const unsigned lanes=MLDSA_K*MLDSA_L-flat<3?MLDSA_K*MLDSA_L-flat:3;
    unsigned ctr[3]={0,0,0};
    mld_memset(&mat->stream4,0,sizeof(mat->stream4));
    mld_memcpy(mat->stream4.state+75,saved->s,25*8);
    for(unsigned j=0;j<3;j++) {
      unsigned at=flat+(j<lanes?j:0);uint64_t *st=mat->stream4.state+25*j;
      mld_memcpy(st,pk,32);st[4]=(at%MLDSA_L)|((uint64_t)(at/MLDSA_L)<<8)|((uint64_t)0x1f<<16);st[20]=(uint64_t)0x80<<56;
    }
    for(unsigned round=0;round<5;round++) {
      if(!hash.done){lc_vh_block(&hash,mat->stream4.rate);for(unsigned j=0;j<17;j++){uint64_t x;mld_memcpy(&x,mat->stream4.rate+8*j,8);mat->stream4.state[75+j]^=x;}}
      mld_keccakf1600x4_permute(mat->stream4.state);
      for(unsigned j=0;j<lanes;j++)mld_memcpy(bytes+840*j+168*round,mat->stream4.state+25*j,168);
      if(!hash.done)lc_vh_after(&hash,mat->stream4.state,1);
    }
    for(unsigned j=0;j<lanes;j++)ctr[j]=(unsigned)lcbase_rej_uniform_aarch64_asm(a[flat+j].coeffs,bytes+840*j,840,lcbase_rej_uniform_table);
    for(;;) {
      unsigned pending=0;for(unsigned j=0;j<lanes;j++)pending|=ctr[j]<256;
      if(!pending)break;
      if(!hash.done){lc_vh_block(&hash,mat->stream4.rate);for(unsigned j=0;j<17;j++){uint64_t x;mld_memcpy(&x,mat->stream4.rate+8*j,8);mat->stream4.state[75+j]^=x;}}
      mld_keccakf1600x4_permute(mat->stream4.state);
      for(unsigned j=0;j<lanes;j++) {
        const uint8_t *rate=(const uint8_t*)(const void*)(mat->stream4.state+25*j);
        for(unsigned pos=0;pos<168 && ctr[j]<256;pos+=3){uint32_t x=((uint32_t)rate[pos]|((uint32_t)rate[pos+1]<<8)|((uint32_t)rate[pos+2]<<16))&0x7fffff;if(x<8380417)a[flat+j].coeffs[ctr[j]++]=(int32_t)x;}
      }
      if(!hash.done)lc_vh_after(&hash,mat->stream4.state,1);
    }
    if(!hash.done)mld_memcpy(saved->s,mat->stream4.state+75,25*8);
    for(unsigned j=0;j<lanes;j++)mld_poly_permute_bitrev_to_custom_optional(&a[flat+j]);
    flat+=lanes;
  }
  if(!hash.done)lc_vh_finish(&hash,saved,mat);
  mld_zeroize(saved,sizeof(*saved));mld_zeroize(&mat->stream4,sizeof(mat->stream4));
  mld_zeroize(&hash,sizeof(hash));mld_zeroize(seeds,4*MLD_ALIGN_UP(34));
}
#endif
static void lc_native_matrix_row(mld_poly *out,mld_poly *a,const lc_packed_vecl *v,unsigned row,const uint8_t rho[32],unsigned resident LC_MATRIX4_PARAM) {
  if(!resident) {
  #if LC_DSA_MATRIX4_ARENA
  uint8_t (*seeds)[MLD_ALIGN_UP(34)]=matrix_workspace->seeds;
#else
  MLD_ALIGN uint8_t seeds[4][MLD_ALIGN_UP(34)];
#endif
  for(unsigned flat=((row*MLDSA_L+3)/4)*4;flat<(row+1)*MLDSA_L;flat+=4) {
    mld_poly *lane[4];
    for(unsigned j=0;j<4;j++) {
      unsigned at=flat+j;
      mld_memcpy(seeds[j],rho,32);seeds[j][32]=(uint8_t)(at%MLDSA_L);seeds[j][33]=(uint8_t)(at/MLDSA_L);
      lane[j]=&a[at%(2*MLDSA_L)];
    }
    LC_MATRIX4_SAMPLE(lane[0],lane[1],lane[2],lane[3],seeds,matrix_workspace);
    for(unsigned j=0;j<4;j++)mld_poly_permute_bitrev_to_custom_optional(lane[j]);
  }
  mld_zeroize(seeds,4*MLD_ALIGN_UP(34));
  row%=2;
  }
  mld_polyvecl_pointwise_acc_montgomery(out,(const mld_polyvecl *)(const void *)&a[row*MLDSA_L],(const mld_polyvecl *)(const void *)v);
}
#endif
static void lc_packed_matrix_row(mld_poly *out,mld_polymat *mat,const lc_packed_vecl *v,unsigned k) {
  uint8_t seed[MLDSA_SEEDBYTES+2];
  mld_memcpy(seed,mat->rho,MLDSA_SEEDBYTES);
#if LC_DSA_KEYVERIFY_DENSE && defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  mld_memset(out,0,sizeof(*out));
  for(unsigned l=0;l<MLDSA_L;l+=4) {
    unsigned lanes=MLDSA_L-l<4?MLDSA_L-l:4;
    lc_arm_flat_matrix4(out->coeffs,out->coeffs,mat,(const uint8_t *)v,k*MLDSA_L+l,MLDSA_L,lanes);
  }
#elif LC_DSA_MATRIX_STREAM_DIRECT4
  mld_memset(out,0,sizeof(*out));
  for(unsigned l=0;l<MLDSA_L;l+=4) {
    unsigned lanes=MLDSA_L-l<4?MLDSA_L-l:4;
    lc_matrix_v_x4(out,mat,v,l,k,lanes);
  }
#else
  for(unsigned l=0;l<MLDSA_L;l++) {
#if LC_DSA_FUSED_PACKED_MATRIX
    seed[32]=(uint8_t)l;seed[33]=(uint8_t)k;
    lc_fused_matrix_v(out,(*v)[l],seed,l==0);
#else
    MLD_ADD_PARAM_SET(mld_polymat_expand_entry)(&mat->cur,seed,(uint8_t)l,(uint8_t)k);
    for(unsigned j=0;j<MLDSA_N;j++) {
      int32_t x=mld_montgomery_reduce((int64_t)mat->cur.coeffs[j]*lc_load_signed24((*v)[l]+3*j));
      out->coeffs[j]=l==0?x:out->coeffs[j]+x;
    }
#endif
  }
#endif
  mld_poly_reduce(out);lc_stream_transform_order(out);mld_zeroize(seed,sizeof(seed));
}
static void lc_pack_ntt24(uint8_t *out,const mld_poly *p) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_CODEC24_NEON) && LC_DSA_CODEC24_NEON
  lc_codec24_pack_neon(out,p->coeffs);
#else
  for(unsigned j=0;j<MLDSA_N;j++)lc_store_signed24(out+3*j,mld_reduce32(p->coeffs[j]));
#endif
#else
  #if LC_DSA_SIGNED24_CODEC_VECTOR && defined(__AVX2__)
  lc_s4_pack_row(out,p->coeffs);
#else
  for(unsigned j=0;j<MLDSA_N;j++)lc_store_signed24(out+3*j,mld_reduce32(p->coeffs[j]));
#endif
#endif
}
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_LAST_Y_CACHE
/* The saved transform is in matrix order. The native permutation is an
 * involution; invNTT_tomont returns R*y. Montgomery reduction followed by
 * reduce32 selects the original y in [-gamma1+1,gamma1]. */
static __attribute__((noinline)) void lc_restore_last_y(mld_poly *out,const uint8_t *packed) {
#if LC_DSA_SIGNED24_CODEC_VECTOR && defined(__AVX2__)
  lc_s4_unpack_row(out->coeffs,packed);
#else
  for(unsigned j=0;j<MLDSA_N;j++)out->coeffs[j]=lc_load_signed24(packed+3*j);
#endif
  lc_stream_transform_order(out);
  mld_poly_invntt_tomont(out);
  for(unsigned j=0;j<MLDSA_N;j++)
    out->coeffs[j]=mld_reduce32(mld_montgomery_reduce((int64_t)out->coeffs[j]));
}
#endif
#endif
#if LC_DSA_STREAM_RECOMPUTE
/* Each dense row is consumed before the next. A second ExpandA pass restores
 * the exact low row after the challenge, retaining only the hint predicates.
 * Every address in matrix generation is a function of public loop indices. */
static void lc_fused_matrix_dense(mld_poly *out,const mld_poly *v,const uint8_t seed[34],unsigned first) {
  uint8_t buf[SHAKE128_RATE];mld_xof128_ctx state;unsigned ctr=0;
  mld_xof128_init(&state);mld_xof128_absorb_once(&state,seed,34);
  do {
    mld_xof128_squeezeblocks(buf,1,&state);
    for(unsigned j=0;ctr<MLDSA_N && j+3<=SHAKE128_RATE;j+=3) {
      uint32_t a=((uint32_t)buf[j]|((uint32_t)buf[j+1]<<8)|((uint32_t)buf[j+2]<<16))&0x7fffffu;
      if(a<MLDSA_Q) {
        int32_t x=mld_montgomery_reduce((int64_t)a*v->coeffs[ctr]);
        out->coeffs[ctr]=first?x:out->coeffs[ctr]+x;ctr++;
      }
    }
  } while(ctr<MLDSA_N);
  mld_xof128_release(&state);mld_zeroize(buf,sizeof(buf));
}
static void lc_stream_y_row(mld_poly *out,const mld_polymat *mat,const mld_yvec *y,mld_poly *scratch,unsigned row) {
  uint8_t seed[34];mld_memcpy(seed,mat->rho,32);seed[33]=(uint8_t)row;
  for(unsigned l=0;l<MLDSA_L;l++) {
    mld_yvec_get_poly(scratch,y,l);mld_poly_ntt(scratch);seed[32]=(uint8_t)l;
    lc_fused_matrix_dense(out,scratch,seed,l==0);
  }
  mld_poly_reduce(out);mld_poly_invntt_tomont(out);mld_poly_caddq(out);mld_zeroize(seed,sizeof(seed));
}
static void lc_stream_s1_row(mld_poly *out,const mld_polymat *mat,const uint8_t *rhoprime,mld_poly *scratch,unsigned row,uint8_t *sk) {
  uint8_t seed[34];mld_memcpy(seed,mat->rho,32);seed[33]=(uint8_t)row;
  for(unsigned l=0;l<MLDSA_L;l++) {
    mld_poly_uniform_eta(scratch,rhoprime,(uint8_t)l);
    if(row==0)mld_polyeta_pack(sk+MLDSA_SK_S1_OFFSET+l*MLDSA_POLYETA_PACKEDBYTES,scratch);
    mld_poly_ntt(scratch);seed[32]=(uint8_t)l;
    lc_fused_matrix_dense(out,scratch,seed,l==0);
  }
  mld_poly_reduce(out);mld_zeroize(seed,sizeof(seed));
}
static void lc_stream_z_row(mld_poly *out,const mld_polymat *mat,const uint8_t *sig,mld_poly *scratch,unsigned row) {
  uint8_t seed[34];mld_memcpy(seed,mat->rho,32);seed[33]=(uint8_t)row;
  for(unsigned l=0;l<MLDSA_L;l++) {
    mld_polyz_unpack(scratch,sig+MLDSA_SIG_Z_OFFSET+l*MLDSA_POLYZ_PACKEDBYTES);
    mld_poly_ntt(scratch);seed[32]=(uint8_t)l;
    lc_fused_matrix_dense(out,scratch,seed,l==0);
  }
  mld_poly_reduce(out);mld_zeroize(seed,sizeof(seed));
}
static void lc_stream_hash(uint8_t *challenge,const uint8_t *mu,lc_sign_w0_storage *store,const mld_polymat *mat,const mld_yvec *y,mld_poly *scratch) {
  mld_poly *w=(mld_poly*)store->bytes;
  mld_shake256ctx *state=(mld_shake256ctx*)(store->bytes+sizeof(mld_poly));
  mld_shake256_init(state);mld_shake256_absorb(state,mu,MLDSA_CRHBYTES);
  for(unsigned k=0;k<MLDSA_K;k++) {
    lc_stream_y_row(w,mat,y,scratch,k);mld_poly_decompose(scratch,w);
    mld_polyw1_pack((uint8_t*)w,scratch);
    mld_shake256_absorb(state,(uint8_t*)w,MLDSA_POLYW1_PACKEDBYTES);
  }
  mld_shake256_finalize(state);mld_shake256_squeeze(challenge,MLDSA_CTILDEBYTES,state);
  mld_shake256_release(state);mld_zeroize(state,sizeof(*state));
}
static int lc_pack_hint_flags(uint8_t *sig,const uint8_t *flags) {
  unsigned n=0;uint8_t *h=sig+MLDSA_SIG_H_OFFSET;
  mld_memset(h,0,MLDSA_POLYVECH_PACKEDBYTES);
  for(unsigned k=0;k<MLDSA_K;k++) {
    for(unsigned j=0;j<MLDSA_N;j++)if((flags[32*k+j/8]>>(j%8))&1u) {
      if(n==MLDSA_OMEGA)return MLD_ERR_FAIL;h[n++]=(uint8_t)j;
    }
    h[MLDSA_OMEGA+k]=(uint8_t)n;
  }
  return 0;
}
#endif
#if !LC_DSA_STREAM_RECOMPUTE
static void lc_sign_decompose_hash_bitmap(uint8_t *challenge,const uint8_t *mu,
    lc_sign_w0_storage *storage,mld_poly *saved_last,mld_poly *scratch) {
  uint8_t *bytes=storage->bytes,*saved=(uint8_t*)saved_last;
#if LC_DSA_DIRECT_DENSE_ROWS
  (void)scratch;
#endif
  #if LC_DSA_DENSE_SIGN_ROWS
  uint8_t *encoded=saved;
#else
  uint8_t *encoded=saved+LC_PACKED_ROW_BYTES;
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  mld_shake256ctx *state=(mld_shake256ctx*)(bytes+LC_SIGN_HASH_OFFSET);
#else
#if LC_DSA_LAST_Y_CACHE
  mld_shake256ctx local_hash;
  mld_shake256ctx *state=&local_hash;
#else
  mld_shake256ctx *state=(mld_shake256ctx*)(bytes+LC_SIGN_HASH_OFFSET);
#endif
#endif
#if !LC_DSA_DENSE_SIGN_ROWS
  mld_memcpy(saved,bytes+(MLDSA_K-1)*LC_PACKED_ROW_BYTES,LC_PACKED_ROW_BYTES);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_LAST_Y_CACHE
  lc_pack_ntt24(bytes+LC_LAST_Y_OFFSET,scratch);
#endif
#endif
  mld_shake256_init(state);mld_shake256_absorb(state,mu,MLDSA_CRHBYTES);
  for(unsigned k=0;k<MLDSA_K;k++) {
#if !LC_DSA_DIRECT_DENSE_ROWS
#if LC_DSA_DENSE_SIGN_ROWS
    const uint8_t *src=bytes+k*LC_SIGN_AY_ROW_BYTES;
#else
    const uint8_t *src=k==MLDSA_K-1?saved:bytes+k*LC_PACKED_ROW_BYTES;
#endif
#endif
    uint8_t *row=bytes+k*LC_W0_FLAG_STRIDE,*flags=row+LC_W0_ROW_BYTES;
#if LC_DSA_DIRECT_DENSE_ROWS
    /* Every AY row is complete before this loop. Native transforms touch
     * exactly its 1024 coefficient bytes; the adjacent bitmap stays separate. */
    mld_poly *row_poly=(mld_poly *)(void *)row;
#else
    mld_poly *row_poly=scratch;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_DENSE_SIGN_ROWS
    mld_memcpy(scratch->coeffs,src,1024);
#elif defined(LC_DSA_CODEC24_NEON) && LC_DSA_CODEC24_NEON
    lc_codec24_unpack_neon(scratch->coeffs,src);
#else
    for(unsigned j=0;j<MLDSA_N;j++)scratch->coeffs[j]=lc_load_signed24(src+3*j);
#endif
#else
#if LC_DSA_DENSE_SIGN_ROWS
    mld_memcpy(scratch->coeffs,src,1024);
#elif LC_DSA_SIGNED24_CODEC_VECTOR && defined(__AVX2__)
    lc_s4_unpack_row(scratch->coeffs,src);
#else
    for(unsigned j=0;j<MLDSA_N;j++)scratch->coeffs[j]=lc_load_signed24(src+3*j);
#endif
#endif
#endif
    lc_stream_transform_order(row_poly);
    mld_poly_invntt_tomont(row_poly);mld_poly_caddq(row_poly);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_DECOMPOSE_NEON) && LC_DSA_DECOMPOSE_NEON
    lc_decompose_encode_neon(row_poly->coeffs,encoded,flags,MLDSA_GAMMA2);
#else
    mld_memset(encoded,0,MLDSA_POLYW1_PACKEDBYTES);mld_memset(flags,0,LC_W1_FLAG_BYTES);
    for(unsigned j=0;j<MLDSA_N;j++) {
      int32_t high; mld_decompose(&row_poly->coeffs[j],&high,row_poly->coeffs[j]);
      unsigned h=(unsigned)high;
      const unsigned bits=MLDSA_K==4?6:4,bit=j*bits,pos=bit/8,shift=bit%8;
      encoded[pos]|=(uint8_t)(h<<shift);
      if(shift+bits>8) encoded[pos+1]|=(uint8_t)(h>>(8-shift));
      flags[j/8]|=(uint8_t)((uint32_t)(h!=0)<<(j%8));
    }
#endif
#else
#if LC_DSA_DECOMPOSE_VECTOR && defined(__AVX2__)
    lc_decompose_encode_vector(row_poly->coeffs,encoded,flags,MLDSA_GAMMA2);
#else
    mld_memset(encoded,0,MLDSA_POLYW1_PACKEDBYTES);mld_memset(flags,0,LC_W1_FLAG_BYTES);
    for(unsigned j=0;j<MLDSA_N;j++) {
      int32_t high; mld_decompose(&row_poly->coeffs[j],&high,row_poly->coeffs[j]);
      unsigned h=(unsigned)high;
      const unsigned bits=MLDSA_K==4?6:4,bit=j*bits,pos=bit/8,shift=bit%8;
      encoded[pos]|=(uint8_t)(h<<shift);
      if(shift+bits>8) encoded[pos+1]|=(uint8_t)(h>>(8-shift));
      flags[j/8]|=(uint8_t)((uint32_t)(h!=0)<<(j%8));
    }
#endif
#endif
#if !LC_DSA_DIRECT_DENSE_ROWS
    lc_pack_w0_row(row,row_poly);
#endif
    mld_shake256_absorb(state,encoded,MLDSA_POLYW1_PACKEDBYTES);
  }
  mld_shake256_finalize(state);mld_shake256_squeeze(challenge,MLDSA_CTILDEBYTES,state);
  mld_shake256_release(state);mld_zeroize(state,sizeof(*state));
}
#endif /* !LC_DSA_STREAM_RECOMPUTE */
#else
typedef struct {
 union {
  mld_polyveck full;
  struct {
    uint8_t consumed_prefix[(MLDSA_K-1)*sizeof(mld_poly)];
    mld_shake256ctx hash;
  } oracle_phase;
 };
#if LC_DSA_RETAIN_FULL_HIGH
  /* Counterfactual: retain the complete standard w1 encoding after each
   * streamed hash update, instead of retaining only its nonzero predicate. */
  uint8_t high_encoded[MLDSA_K][MLDSA_POLYW1_PACKEDBYTES];
#endif
} lc_sign_w0_storage;
typedef char lc_bitmap_storage_size_check[
  sizeof(lc_sign_w0_storage)==sizeof(mld_polyveck)+
  LC_DSA_RETAIN_FULL_HIGH*MLDSA_K*MLDSA_POLYW1_PACKEDBYTES ? 1 : -1];
typedef char lc_bitmap_row_gap_check[
  LC_W0_FLAG_STRIDE+MLDSA_POLYW1_PACKEDBYTES<=sizeof(mld_poly) ? 1 : -1];
typedef char lc_bitmap_tail_gap_check[
  MLDSA_K*LC_W0_FLAG_STRIDE+MLDSA_POLYW1_PACKEDBYTES
    <=(MLDSA_K-1)*sizeof(mld_poly) ? 1 : -1];
typedef char lc_bitmap_hash_fit_check[
  sizeof(mld_shake256ctx)<=sizeof(mld_poly) ? 1 : -1];

#ifndef LC_DSA_LAST_ROW_HASH
#define LC_DSA_LAST_ROW_HASH 0
#endif
#if LC_DSA_LAST_ROW_HASH && MLDSA_K > 4 && LC_DSA_PACK_W0 && !LC_DSA_RETAIN_FULL_HIGH
_Static_assert(LC_W0_FLAG_STRIDE+MLDSA_POLYW1_PACKEDBYTES+
               sizeof(mld_shake256ctx)<=sizeof(mld_poly),
               "Last row must contain its compact values and hash state");
_Static_assert((LC_W0_FLAG_STRIDE+MLDSA_POLYW1_PACKEDBYTES)%
               _Alignof(mld_shake256ctx)==0,"Last-row hash alignment");
static __attribute__((noinline,noclone)) void lc_sign_decompose_hash_bitmap_runtime(uint8_t *challenge,const uint8_t *mu,
    void *storage,mld_poly *saved_last,mld_poly *high,unsigned rows,unsigned challenge_bytes) {
  uint8_t *bytes=(uint8_t*)storage;
  mld_poly *dense=(mld_poly*)storage;
  uint8_t *last=(uint8_t*)&dense[rows-1];
  uint8_t *last_high=last+LC_W0_FLAG_STRIDE;
  mld_shake256ctx *state=(mld_shake256ctx*)(void*)
      (last_high+MLDSA_POLYW1_PACKEDBYTES);
  (void)saved_last;
  /* First consume the final dense row in its own allocation. Its compact
   * LowBits, bitmap and full encoded HighBits occupy 800 bytes for 65/87.
   * The trailing 224 bytes hold the incremental hash until the transcript
   * has consumed that final HighBits string in the original row order. */
  for(unsigned pass=0;pass<rows;pass++) {
    const unsigned k=pass==0?rows-1:pass-1;
    mld_poly *low=&dense[k];
    uint8_t *row=pass==0?last:bytes+k*LC_W0_FLAG_STRIDE;
    uint8_t *flags=row+LC_W0_ROW_BYTES;
    uint8_t *encoded=row+LC_W0_FLAG_STRIDE;
    mld_poly_decompose(high,low);
    lc_pack_w0_row(row,low);
    mld_memset(flags,0,LC_W1_FLAG_BYTES);
    for(unsigned j=0;j<MLDSA_N;j++)
      flags[j/8]|=(uint8_t)((uint32_t)(high->coeffs[j]!=0)<<(j%8));
    mld_polyw1_pack(encoded,high);
    if(pass==0) {
      mld_shake256_init(state);
      mld_shake256_absorb(state,mu,MLDSA_CRHBYTES);
    } else mld_shake256_absorb(state,encoded,MLDSA_POLYW1_PACKEDBYTES);
  }
  mld_shake256_absorb(state,last_high,MLDSA_POLYW1_PACKEDBYTES);
  mld_shake256_finalize(state);
  mld_shake256_squeeze(challenge,challenge_bytes,state);
  /* release wipes the complete context and retains the zeroization barrier. */
  mld_shake256_release(state);
  /* Only now is every dense row dead. Move the final compact row below its
   * original location; its source and destination are disjoint. */
  mld_memcpy(bytes+(rows-1)*LC_W0_FLAG_STRIDE,last,LC_W0_FLAG_STRIDE);
}
/* The 65/87 arithmetic and codecs are identical. These two public shape
 * parameters allow the linker to share the complete transition rather than
 * duplicating it inside the parameter-specific signing implementations. */
#define lc_sign_decompose_hash_bitmap(C,M,S,L,H) \
  lc_sign_decompose_hash_bitmap_runtime((C),(M),(S),(L),(H),MLDSA_K,MLDSA_CTILDEBYTES)

#else
static void lc_sign_decompose_hash_bitmap(uint8_t *challenge,const uint8_t *mu,
    lc_sign_w0_storage *storage,mld_poly *saved_last,mld_poly *high) {
  unsigned int k;
#if !LC_DSA_RETAIN_FULL_HIGH
  unsigned int j;
#endif
  uint8_t *bytes=(uint8_t*)storage;
  mld_polyveck *w0=&storage->full;
  mld_shake256ctx *state=&storage->oracle_phase.hash;
  /* mat->cur is dead after the entire A*y product. Save the final original
   * row BEFORE initializing the hash in its old location. No other row is
   * overwritten before its coefficients have all been consumed. */
  mld_memcpy(saved_last,&w0->vec[MLDSA_K-1],sizeof(mld_poly));
  mld_shake256_init(state);
  mld_shake256_absorb(state,mu,MLDSA_CRHBYTES);
  for(k=0;k<MLDSA_K;k++) {
    mld_poly *low=k==MLDSA_K-1 ? saved_last : &w0->vec[k];
    uint8_t *row=bytes+k*LC_W0_FLAG_STRIDE;
#if !LC_DSA_RETAIN_FULL_HIGH
    uint8_t *flags=row+LC_W0_ROW_BYTES;
#endif
    uint8_t *encoded=row+LC_W0_FLAG_STRIDE;
    mld_poly_decompose(high,low);
    lc_pack_w0_row(row,low);
#if !LC_DSA_RETAIN_FULL_HIGH
    mld_memset(flags,0,LC_W1_FLAG_BYTES);
    for(j=0;j<MLDSA_N;j++) {
      /* Fixed index/address and fixed loop bounds; no secret-dependent
       * branch is introduced before the original norm declassification. */
      flags[j/8]|=(uint8_t)((uint32_t)(high->coeffs[j]!=0)<<(j%8));
    }
#endif
    /* The gap following this completed compact row lies before the next
     * unread source row and before the live tail state (compile-time checks
     * above). Absorb immediately; the next compact row may overwrite it. */
    mld_polyw1_pack(encoded,high);
#if LC_DSA_RETAIN_FULL_HIGH
    mld_memcpy(storage->high_encoded[k],encoded,MLDSA_POLYW1_PACKEDBYTES);
#endif
    mld_shake256_absorb(state,encoded,MLDSA_POLYW1_PACKEDBYTES);
  }
  mld_shake256_finalize(state);
  mld_shake256_squeeze(challenge,MLDSA_CTILDEBYTES,state);
  /* release wipes the complete context and retains the zeroization barrier. */
  mld_shake256_release(state);
  /* saved_last now becomes cp; the old tail now becomes t. No return or
   * rejection path exists between init and release of the borrowed state. */
}
#endif

#endif /* LC_DSA_PACKED_ACCUM */

/* Evaluate the final weight condition while every hint remains secret.
 * This is called after all norm checks and before hint declassification. */
static unsigned lc_check_hint_weight_before_disclosure(const uint8_t *w0,
                                                       mld_poly *low) {
#if LC_DSA_STREAM_RECOMPUTE
  (void)low;
  return lc_hint_weight_exceeds(w0+sizeof(mld_poly),MLDSA_K,32,MLDSA_OMEGA);
#elif LC_DSA_EARLY_HINT_FLAGS
  (void)low;
  return lc_hint_weight_exceeds(w0+LC_W0_ROW_BYTES,MLDSA_K,
                               LC_W0_FLAG_STRIDE,MLDSA_OMEGA);
#else
  unsigned total=0;
  for(unsigned k=0;k<MLDSA_K;k++) {
    const uint8_t *row=w0+k*LC_W0_FLAG_STRIDE;
#if LC_DSA_RETAIN_FULL_HIGH
    const uint8_t *flags=((const lc_sign_w0_storage*)w0)->high_encoded[k];
#else
    const uint8_t *flags=row+LC_W0_ROW_BYTES;
#endif
    lc_unpack_w0_row(low,row);
    for(unsigned j=0;j<MLDSA_N;j++) {
#if LC_DSA_RETAIN_FULL_HIGH
#if MLD_CONFIG_PARAMETER_SET == 44
      unsigned pos=3*(j/4);
      uint32_t group=(uint32_t)flags[pos]|((uint32_t)flags[pos+1]<<8)|
                     ((uint32_t)flags[pos+2]<<16);
      unsigned high=(group>>(6*(j%4)))&63u;
#else
      unsigned high=(flags[j/2]>>(4*(j%2)))&15u;
#endif
#else
      unsigned high=(flags[j/8]>>(j%8))&1u;
#endif
      total+=lc_make_hint_secret(low->coeffs[j],high);
    }
  }
  return total>MLDSA_OMEGA;
#endif
}

static int lc_pack_sig_h_bitmap(uint8_t sig[MLDSA_CRYPTO_BYTES],
    const uint8_t *w0,mld_poly *low) {
  unsigned int j,k,n=0;
  uint8_t *sig_h=sig+MLDSA_SIG_H_OFFSET;
  mld_memset(sig_h,0,MLDSA_POLYVECH_PACKEDBYTES);
  /* Called only after ALL original norm checks and declassification. */
  for(k=0;k<MLDSA_K;k++) {
    const uint8_t *row=w0+k*LC_W0_FLAG_STRIDE;
#if LC_DSA_RETAIN_FULL_HIGH
    const uint8_t *flags=((const lc_sign_w0_storage*)w0)->high_encoded[k];
#else
    const uint8_t *flags=row+LC_W0_ROW_BYTES;
#endif
#if !LC_DSA_EARLY_HINT_FLAGS
    lc_unpack_w0_row(low,row);
#else
    (void)low;
#endif
    for(j=0;j<MLDSA_N;j++) {
#if LC_DSA_RETAIN_FULL_HIGH
#if MLD_CONFIG_PARAMETER_SET == 44
      unsigned int pos=3*(j/4);
      uint32_t group=(uint32_t)flags[pos]|((uint32_t)flags[pos+1]<<8)|((uint32_t)flags[pos+2]<<16);
      unsigned int retained_high=(group>>(6*(j%4)))&63u;
#else
      unsigned int retained_high=(flags[j/2]>>(4*(j%2)))&15u;
#endif
#else
      unsigned int retained_high=(flags[j/8]>>(j%8))&1u;
#endif
#if LC_DSA_EARLY_HINT_FLAGS
      unsigned int bit=retained_high;
#else
      unsigned int bit=mld_make_hint(low->coeffs[j],(int32_t)retained_high);
#endif
      if(bit) {
        if(n==MLDSA_OMEGA) return MLD_ERR_FAIL;
        sig_h[n]=(uint8_t)j;n++;
      }
    }
    sig_h[MLDSA_OMEGA+k]=(uint8_t)n;
  }
  return 0;
}

#endif


/* Parameter set namespacing
 * This is to facilitate building multiple instances
 * of mldsa-native (e.g. with varying parameter sets)
 * within a single compilation unit. */
#define mld_check_pct MLD_ADD_PARAM_SET(mld_check_pct) MLD_CONTEXT_PARAMETERS_2
#define mld_sample_s1_s2 MLD_ADD_PARAM_SET(mld_sample_s1_s2)
#define mld_validate_hash_length MLD_ADD_PARAM_SET(mld_validate_hash_length)
#define mld_get_hash_oid MLD_ADD_PARAM_SET(mld_get_hash_oid)
#define mld_H MLD_ADD_PARAM_SET(mld_H)
#define mld_compute_pack_z MLD_ADD_PARAM_SET(mld_compute_pack_z)
#define mld_attempt_signature_generation \
  MLD_ADD_PARAM_SET(mld_attempt_signature_generation) MLD_CONTEXT_PARAMETERS_9
#define mld_compute_pack_t0_t1 \
  MLD_ADD_PARAM_SET(mld_compute_pack_t0_t1) MLD_CONTEXT_PARAMETERS_5
#define mld_get_max_signing_attempts \
  MLD_ADD_PARAM_SET(mld_get_max_signing_attempts)

#if !defined(MLD_CONFIG_NO_KEYPAIR_API)
static int mld_check_pct(uint8_t const pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                         uint8_t const sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                         MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(pk, MLDSA_CRYPTO_PUBLICKEYBYTES))
  requires(memory_no_alias(sk, MLDSA_CRYPTO_SECRETKEYBYTES))
  ensures(return_value == 0 || return_value == MLD_ERR_OUT_OF_MEMORY ||
          return_value == MLD_ERR_RNG_FAIL ||
          return_value == MLD_ERR_SIGNING_PAUSED ||
          return_value == MLD_ERR_PCT_FAIL)
);

#if defined(MLD_CONFIG_KEYGEN_PCT)
/**
 * Pair-wise Consistency Test (PCT) for DSA keypairs.
 *
 * @[FIPS140_3_IG] TE10.35.02
 * (https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf).
 *
 * Validates that a generated public/private key pair can correctly sign and
 * verify data. Performs signature generation using the private key (sk),
 * followed by signature verification using the public key (pk).
 *
 * @note @[FIPS204] requires that public/private key pairs are to be used
 * only for the calculation and/or verification of digital signatures.
 *
 * @param[in] pk      Public key.
 * @param[in] sk      Secret key.
 * @param     context Application context. Only present when
 *                    MLD_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                    MLD_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @retval 0                      Success.
 * @retval MLD_ERR_OUT_OF_MEMORY  MLD_CONFIG_CUSTOM_ALLOC_FREE was used and an
 *                                allocation via MLD_CUSTOM_ALLOC returned NULL.
 * @retval MLD_ERR_RNG_FAIL       Random number generation failed.
 * @retval MLD_ERR_SIGNING_PAUSED The PCT's signing step was paused by a
 *                                MLD_CONFIG_SIGN_HOOK_ATTEMPT hook.
 * @retval MLD_ERR_PCT_FAIL       The consistency check failed.
 */
static int mld_check_pct(uint8_t const pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                         uint8_t const sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                         MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t message[1] = {0};
  int ret;
  MLD_ALLOC(signature, uint8_t, MLDSA_CRYPTO_BYTES, context);
  MLD_ALLOC(pk_test, uint8_t, MLDSA_CRYPTO_PUBLICKEYBYTES, context);

  if (signature == NULL || pk_test == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Copy public key for testing */
  mld_memcpy(pk_test, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);

  /* Sign a test message using the original secret key */
  ret = mld_sign_signature(signature, message, sizeof(message), NULL, 0, sk,
                           context);
  if (ret != 0)
  {
    goto cleanup;
  }

#if defined(MLD_CONFIG_KEYGEN_PCT_BREAKAGE_TEST)
  /* Deliberately break public key for testing purposes */
  if (mld_break_pct())
  {
    pk_test[0] = ~pk_test[0];
  }
#endif /* MLD_CONFIG_KEYGEN_PCT_BREAKAGE_TEST */

  /* Verify the signature using the (potentially corrupted) public key. */
  ret = mld_sign_verify(signature, message, sizeof(message), NULL, 0, pk_test,
                        context);
  if (ret != 0)
  {
    goto cleanup;
  }

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(pk_test, uint8_t, MLDSA_CRYPTO_PUBLICKEYBYTES, context);
  MLD_FREE(signature, uint8_t, MLDSA_CRYPTO_BYTES, context);

  /* A failed signing operation or an invalid signature hint at a faulty
   * implementation and map to a dedicated error code for PCT failure. */
  if (ret == MLD_ERR_INVALID_SIGNATURE ||
      ret == MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED)
  {
    ret = MLD_ERR_PCT_FAIL;
  }

  /* Other error codes, e.g. platform failures like out of memory or
   * randomness failure, are passed on unmodified. */

  return ret;
}
#else  /* MLD_CONFIG_KEYGEN_PCT */
static int mld_check_pct(uint8_t const pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                         uint8_t const sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                         MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  /* Skip PCT */
  ((void)pk);
  ((void)sk);
  MLD_CONTEXT_UNUSED(context);
  return 0;
}
#endif /* !MLD_CONFIG_KEYGEN_PCT */

/**
 * Sample the short secret vectors s1 (length MLDSA_L) and s2 (length MLDSA_K)
 * with coefficients in [-MLDSA_ETA, MLDSA_ETA] from the seed.
 *
 * @spec{Implements @[FIPS204, Algorithm 33, ExpandS].}
 *
 * @param[out] s1   Output vector s1.
 * @param[out] s2   Output vector s2.
 * @param[in]  seed Byte array with seed of length MLDSA_CRHBYTES.
 */
static void mld_sample_s1_s2(mld_polyvecl *s1, mld_polyveck *s2,
                             const uint8_t seed[MLDSA_CRHBYTES])
__contract__(
  requires(memory_no_alias(s1, sizeof(mld_polyvecl)))
  requires(memory_no_alias(s2, sizeof(mld_polyveck)))
  requires(memory_no_alias(seed, MLDSA_CRHBYTES))
  assigns(object_whole(s1), object_whole(s2))
  ensures(forall(l0, 0, MLDSA_L, array_abs_bound(s1->vec[l0].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
  ensures(forall(k0, 0, MLDSA_K, array_abs_bound(s2->vec[k0].coeffs, 0, MLDSA_N, MLDSA_ETA + 1)))
)
{
/* Sample short vectors s1 and s2 */
#if defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  int i;
  uint16_t nonce = 0;
  /* Safety: The nonces are at most 14 (MLDSA_L + MLDSA_K - 1), and, hence, the
   * casts are safe. */
  for (i = 0; i < MLDSA_L; i++)
  {
    mld_poly_uniform_eta(&s1->vec[i], seed, (uint8_t)(nonce + i));
  }
  for (i = 0; i < MLDSA_K; i++)
  {
    mld_poly_uniform_eta(&s2->vec[i], seed, (uint8_t)(nonce + MLDSA_L + i));
  }
#else /* MLD_CONFIG_SERIAL_FIPS202_ONLY */
#if MLD_CONFIG_PARAMETER_SET == 44
  mld_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                          seed, 0, 1, 2, 3);
  mld_poly_uniform_eta_4x(&s2->vec[0], &s2->vec[1], &s2->vec[2], &s2->vec[3],
                          seed, 4, 5, 6, 7);
#elif MLD_CONFIG_PARAMETER_SET == 65
  mld_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                          seed, 0, 1, 2, 3);
  mld_poly_uniform_eta_4x(&s1->vec[4], &s2->vec[0], &s2->vec[1],
                          &s2->vec[2] /* irrelevant */, seed, 4, 5, 6,
                          0xFF /* irrelevant */);
  mld_poly_uniform_eta_4x(&s2->vec[2], &s2->vec[3], &s2->vec[4], &s2->vec[5],
                          seed, 7, 8, 9, 10);
#elif MLD_CONFIG_PARAMETER_SET == 87
  mld_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                          seed, 0, 1, 2, 3);
  mld_poly_uniform_eta_4x(&s1->vec[4], &s1->vec[5], &s1->vec[6],
                          &s2->vec[0] /* irrelevant */, seed, 4, 5, 6,
                          0xFF /* irrelevant */);
  mld_poly_uniform_eta_4x(&s2->vec[0], &s2->vec[1], &s2->vec[2], &s2->vec[3],
                          seed, 7, 8, 9, 10);
  mld_poly_uniform_eta_4x(&s2->vec[4], &s2->vec[5], &s2->vec[6], &s2->vec[7],
                          seed, 11, 12, 13, 14);
#endif /* MLD_CONFIG_PARAMETER_SET == 87 */
#endif /* !MLD_CONFIG_SERIAL_FIPS202_ONLY */
}

/**
 * Compute t = A*s1hat + s2 row by row, decompose each row into t0[k] and
 * t1[k] via power2round, and bit-pack t1[k] into pk_t1 and t0[k] into the
 * t0_packed buffer. Used by both keygen and pk_from_sk.
 *
 * @spec{Partially implements @[FIPS204, Algorithm 22, pkEncode] (t1) and
 * @[FIPS204, Algorithm 24, skEncode] (t0).}
 *
 * @param[out] pk_t1     Output buffer for packed t1 (size
 *                       MLDSA_K * MLDSA_POLYT1_PACKEDBYTES; i.e. the t1
 *                       region of pk).
 * @param[out] t0_packed Output buffer for packed t0 (size
 *                       MLDSA_K * MLDSA_POLYT0_PACKEDBYTES).
 * @param[in]  s1hat     s1 in NTT domain.
 * @param[in]  s2        s2.
 * @param[in]  rho       Byte array containing seed rho.
 * @param      context   Application context. Only present when
 *                       MLD_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                       MLD_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @return - 0: Success.
 *         - MLD_ERR_OUT_OF_MEMORY: If MLD_CONFIG_CUSTOM_ALLOC_FREE is used and
 *           an allocation via MLD_CUSTOM_ALLOC returned NULL.
 */
MLD_MUST_CHECK_RETURN_VALUE
static int mld_compute_pack_t0_t1(
    uint8_t pk_t1[MLDSA_K * MLDSA_POLYT1_PACKEDBYTES],
    uint8_t t0_packed[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES],
    const mld_polyvecl *s1hat, const mld_polyveck *s2,
    const uint8_t rho[MLDSA_SEEDBYTES],
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(pk_t1, MLDSA_K * MLDSA_POLYT1_PACKEDBYTES))
  requires(memory_no_alias(t0_packed, MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  requires(memory_no_alias(s1hat, sizeof(mld_polyvecl)))
  requires(memory_no_alias(s2, sizeof(mld_polyveck)))
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  requires(forall(l1, 0, MLDSA_L,
    array_abs_bound(s1hat->vec[l1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  requires(forall(k2, 0, MLDSA_K,
    array_bound(s2->vec[k2].coeffs, 0, MLDSA_N,
      MLD_POLYETA_UNPACK_LOWER_BOUND, MLDSA_ETA + 1)))
  assigns(memory_slice(pk_t1, MLDSA_K * MLDSA_POLYT1_PACKEDBYTES))
  assigns(memory_slice(t0_packed, MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  ensures(return_value == 0 || return_value == MLD_ERR_OUT_OF_MEMORY))
{
  unsigned int k;
  int ret;
  MLD_ALLOC(mat, mld_polymat, 1, context);
  MLD_ALLOC(t0k, mld_poly, 1, context);
  MLD_ALLOC(t1k, mld_poly, 1, context);

  if (mat == NULL || t0k == NULL || t1k == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Expand matrix */
  mld_polyvec_matrix_expand(mat, rho);

  for (k = 0; k < MLDSA_K; k++)
  __loop__(
    assigns(k, memory_slice(pk_t1, MLDSA_K * MLDSA_POLYT1_PACKEDBYTES),
            memory_slice(t0_packed, MLDSA_K * MLDSA_POLYT0_PACKEDBYTES),
            memory_slice(t0k, sizeof(mld_poly)),
            memory_slice(t1k, sizeof(mld_poly))
            MLD_IF_REDUCE_RAM(, memory_slice(mat, sizeof(mld_polymat))))
    invariant(k <= MLDSA_K)
    decreases(MLDSA_K - k)
  )
  {
    /* t0k = (A * s1hat)_k in NTT domain */
    mld_polyvec_matrix_pointwise_montgomery_row(t0k, mat, s1hat, k);

    /* t0k = invNTT(t0k) */
    mld_poly_invntt_tomont(t0k);

    /* t0k += s2[k] */
    mld_poly_add(t0k, &s2->vec[k]);

    /* Reference: The following reduction is not present in the reference
     *            implementation. Omitting this reduction requires the output
     *            of the invntt to be small enough such that the addition of
     *            s2 does not result in absolute values >= MLDSA_Q. While our
     *            C, x86_64, and AArch64 invntt implementations produce small
     *            enough values for this to work out, it complicates the
     *            bounds reasoning. We instead add an additional reduction,
     *            and can consequently, relax the bounds requirements for the
     *            invntt.
     */
    mld_poly_reduce(t0k);

    /* Decompose into t1[k] and t0[k] (in place into t0k). */
    mld_poly_caddq(t0k);
    mld_poly_power2round(t1k, t0k, t0k);

    /* Pack t1[k] into pk and t0[k] into the t0 output buffer. */
    mld_polyt1_pack(pk_t1 + k * MLDSA_POLYT1_PACKEDBYTES, t1k);
    mld_polyt0_pack(t0_packed + k * MLDSA_POLYT0_PACKEDBYTES, t0k);
  }

  ret = 0;
cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(t1k, mld_poly, 1, context);
  MLD_FREE(t0k, mld_poly, 1, context);
  MLD_FREE(mat, mld_polymat, 1, context);
  return ret;
}

#if LC_DSA_FUSED_KEYGEN_PACK
#if !defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE
/* Canonical t is split and encoded in one vector pass. Each pair contains
 * 20 public high bits or 26 secret low bits; two machine words cover
 * respectively 80 and 104 exact output bits without overlapping rows. */
static void lc_keygen_pack_t(uint8_t *high_bytes,uint8_t *low_bytes,
                          const mld_poly *sum,const mld_poly *error) {
  const __m256i q=_mm256_set1_epi32(8380417),add=_mm256_set1_epi32(4095);
  const __m256i mid=_mm256_set1_epi32(4096);
  for(unsigned i=0;i<256;i+=8) {
    __m256i x=_mm256_add_epi32(_mm256_load_si256((const __m256i*)(sum->coeffs+i)),_mm256_load_si256((const __m256i*)(error->coeffs+i)));
    x=lc_s4_reduce(x);x=_mm256_add_epi32(x,_mm256_and_si256(_mm256_srai_epi32(x,31),q));
    __m256i hi=_mm256_srli_epi32(_mm256_add_epi32(x,add),13);
    __m256i lo=_mm256_sub_epi32(mid,_mm256_sub_epi32(x,_mm256_slli_epi32(hi,13)));
    __m256i hp=_mm256_and_si256(_mm256_or_si256(hi,_mm256_srli_epi64(hi,22)),_mm256_set1_epi64x(0xfffff));
    __m256i lp=_mm256_and_si256(_mm256_or_si256(lo,_mm256_srli_epi64(lo,19)),_mm256_set1_epi64x(0x3ffffff));
    uint64_t h0=(uint64_t)_mm256_extract_epi64(hp,0),h1=(uint64_t)_mm256_extract_epi64(hp,1),h2=(uint64_t)_mm256_extract_epi64(hp,2),h3=(uint64_t)_mm256_extract_epi64(hp,3);
    uint64_t l0=(uint64_t)_mm256_extract_epi64(lp,0),l1=(uint64_t)_mm256_extract_epi64(lp,1),l2=(uint64_t)_mm256_extract_epi64(lp,2),l3=(uint64_t)_mm256_extract_epi64(lp,3);
    uint64_t hw=h0|(h1<<20)|(h2<<40)|(h3<<60),lw=l0|(l1<<26)|(l2<<52);
    uint16_t ht=(uint16_t)(h3>>4);uint64_t lt=(l2>>12)|(l3<<14);
    mld_memcpy(high_bytes+10*(i/8),&hw,8);mld_memcpy(high_bytes+10*(i/8)+8,&ht,2);
    mld_memcpy(low_bytes+13*(i/8),&lw,8);mld_memcpy(low_bytes+13*(i/8)+8,&lt,4);low_bytes[13*(i/8)+12]=(uint8_t)(lt>>32);
  }
}
#else
/* Canonical t is split and encoded in one NEON pass. */
static void lc_keygen_pack_t(uint8_t *high_bytes,uint8_t *low_bytes,
                          const mld_poly *sum,const mld_poly *error) {
  for(unsigned i=0;i<256;i+=8) {
      int32x4_t x0=vaddq_s32(vld1q_s32(sum->coeffs+i+0),vld1q_s32(error->coeffs+i+0));
      int32x4_t t0=vshrq_n_s32(vaddq_s32(x0,vdupq_n_s32(1<<22)),23);
      x0=vsubq_s32(x0,vmulq_n_s32(t0,8380417));
      x0=vaddq_s32(x0,vandq_s32(vshrq_n_s32(x0,31),vdupq_n_s32(8380417)));
      uint32x4_t hi0=vreinterpretq_u32_s32(vshrq_n_s32(vaddq_s32(x0,vdupq_n_s32(4095)),13));
      uint32x4_t lo0=vreinterpretq_u32_s32(vsubq_s32(vdupq_n_s32(4096),vsubq_s32(x0,vreinterpretq_s32_u32(vshlq_n_u32(hi0,13)))));
      uint64x2_t h0=vreinterpretq_u64_u32(hi0),l0=vreinterpretq_u64_u32(lo0);
      h0=vandq_u64(vorrq_u64(h0,vshrq_n_u64(h0,22)),vdupq_n_u64(0xfffff));
      l0=vandq_u64(vorrq_u64(l0,vshrq_n_u64(l0,19)),vdupq_n_u64(0x3ffffff));
      int32x4_t x1=vaddq_s32(vld1q_s32(sum->coeffs+i+4),vld1q_s32(error->coeffs+i+4));
      int32x4_t t1=vshrq_n_s32(vaddq_s32(x1,vdupq_n_s32(1<<22)),23);
      x1=vsubq_s32(x1,vmulq_n_s32(t1,8380417));
      x1=vaddq_s32(x1,vandq_s32(vshrq_n_s32(x1,31),vdupq_n_s32(8380417)));
      uint32x4_t hi1=vreinterpretq_u32_s32(vshrq_n_s32(vaddq_s32(x1,vdupq_n_s32(4095)),13));
      uint32x4_t lo1=vreinterpretq_u32_s32(vsubq_s32(vdupq_n_s32(4096),vsubq_s32(x1,vreinterpretq_s32_u32(vshlq_n_u32(hi1,13)))));
      uint64x2_t h1=vreinterpretq_u64_u32(hi1),l1=vreinterpretq_u64_u32(lo1);
      h1=vandq_u64(vorrq_u64(h1,vshrq_n_u64(h1,22)),vdupq_n_u64(0xfffff));
      l1=vandq_u64(vorrq_u64(l1,vshrq_n_u64(l1,19)),vdupq_n_u64(0x3ffffff));
    uint64_t h0a=vgetq_lane_u64(h0,0),h0b=vgetq_lane_u64(h0,1),h1a=vgetq_lane_u64(h1,0),h1b=vgetq_lane_u64(h1,1);
    uint64_t l0a=vgetq_lane_u64(l0,0),l0b=vgetq_lane_u64(l0,1),l1a=vgetq_lane_u64(l1,0),l1b=vgetq_lane_u64(l1,1);
    uint64_t hw=h0a|(h0b<<20)|(h1a<<40)|(h1b<<60),lw=l0a|(l0b<<26)|(l1a<<52);
    uint16_t ht=(uint16_t)(h1b>>4);uint64_t lt=(l1a>>12)|(l1b<<14);
    mld_memcpy(high_bytes+10*(i/8),&hw,8);mld_memcpy(high_bytes+10*(i/8)+8,&ht,2);
    mld_memcpy(low_bytes+13*(i/8),&lw,8);mld_memcpy(low_bytes+13*(i/8)+8,&lt,4);low_bytes[13*(i/8)+12]=(uint8_t)(lt>>32);
  }
}
#endif
#endif
/* Small owners use natural-aligned automatic storage only in the explicitly
 * bounded scalar compact profile. Their cleanup remains at the original
 * release points; moving an owner does not remove its zeroization. */
#ifndef LC_DSA_STACK_SMALL
#define LC_DSA_STACK_SMALL 0
#endif
#if LC_DSA_STACK_SMALL
#if !defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_CONFIG_USE_NATIVE_BACKEND_ARITH) || LC_DSA_PACKED_ACCUM || !LC_DSA_PACK_W0 || !LC_DSA_ALIAS_SIGN_CP || !LC_DSA_ALIAS_VERIFY_TMP || !LC_DSA_STREAM_KEYGEN || (LC_DSA_STACK_SMALL==1 && (LC_DSA_A_CACHE_POLYS || LC_DSA_S1_CACHE_POLYS)) || LC_DSA_RETAIN_FULL_HIGH || LC_DSA_MASK_PIPELINE || LC_DSA_ROW_BATCH4 || LC_DSA_NATIVE_MATRIX_ROWS || LC_DSA_STREAM_RECOMPUTE || LC_DSA_VERIFY_HASH3 || LC_DSA_VERIFY_HASH_BATCH
#error "Stack-small requires the scalar uncached compact allocation profile"
#endif
#if LC_DSA_STACK_SMALL!=1 && LC_DSA_STACK_SMALL!=2
#error "Stack-small mode must be compact(1) or scalar cached(2)"
#endif
#if LC_DSA_STACK_SMALL==2 && (!LC_DSA_A_CACHE_SIGN_ONLY || LC_DSA_A_CACHE_BITS!=24 || LC_DSA_A_CACHE_BATCH4 || LC_DSA_A_STREAM_BATCH4 || LC_DSA_PUBLIC_A_SESSION)
#error "Cached stack-small requires call-owned scalar sign-only matrix cache"
#endif
#define LC_SMALL_ALLOC(v,T,N,ctx) T lc_small_##v[N]; T *v=lc_small_##v
#define LC_SMALL_FREE(v,T,N,ctx) do { mld_zeroize(lc_small_##v,sizeof(lc_small_##v)); v=NULL; } while(0)
_Static_assert(sizeof(mld_poly)==1024,"scalar polynomial size");
#if LC_DSA_DIRECT_MATRIX_ACTIVE
_Static_assert(sizeof(mld_polymat)<=64,"matrix owns metadata only");
_Static_assert(LC_DSA_LAST_ROW_HASH && LC_DSA_PACK_W0 && !LC_DSA_PACKED_ACCUM,
               "Direct matrix signing requires last-row hash and dense outputs");
#else
_Static_assert(sizeof(mld_polymat)==(LC_DSA_A_CACHE_POLYS ? 1088 : 1056),"fixed scalar matrix owner");
#endif
_Static_assert(sizeof(mld_sk_s1hat)<=32 && sizeof(mld_sk_s2hat)<=32 && sizeof(mld_sk_t0hat)<=32,"no retained secret cache");
_Static_assert(sizeof(mld_yvec)<=32,"no retained mask cache");
#else
#define LC_SMALL_ALLOC MLD_ALLOC
#define LC_SMALL_FREE MLD_FREE
#endif
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_keypair_internal(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                              uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                              const uint8_t seed[MLDSA_SEEDBYTES],
                              MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
#if LC_DSA_STREAM_KEYGEN
  int ret;
  unsigned int i;
  const uint8_t *rho, *rhoprime, *key;
  MLD_ALLOC(seedbuf,uint8_t,2*MLDSA_SEEDBYTES+MLDSA_CRHBYTES,context);
  MLD_ALLOC(inbuf,uint8_t,MLDSA_SEEDBYTES+2,context);
  MLD_ALLOC(tr,uint8_t,MLDSA_TRBYTES,context);
#if LC_DSA_STREAM_RECOMPUTE
  MLD_ALLOC(s1,uint8_t,1,context);
#elif LC_DSA_PACKED_ACCUM
  MLD_ALLOC(s1,lc_packed_vecl,1,context);
#else
  MLD_ALLOC(s1,mld_polyvecl,1,context);
#endif
  MLD_ALLOC(mat,mld_polymat,1,context);
  MLD_ALLOC(trow,mld_poly,1,context);
#if LC_DSA_KEYGEN_ETA4
  MLD_ALLOC(eta_tile,mld_poly,4,context);
#if LC_DSA_KEYGEN_ETA_ARENA
  MLD_ALLOC(eta_workspace,lc_eta4_workspace,1,context);
#endif
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#else
#if LC_DSA_FLAT_KEYGEN && MLDSA_K > 4 && !LC_DSA_NATIVE_MATRIX_ROWS
  MLD_ALLOC(flat_keygen_extra,mld_poly,1,context);
  mld_poly *flat_keygen_current=trow,*flat_keygen_carry=flat_keygen_extra;
  unsigned flat_keygen_cursor=0;
#endif
#endif
#if LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  MLD_ALLOC(row_tile,mld_poly,3,context);
#endif
#if LC_DSA_NATIVE_MATRIX_ROWS
  MLD_ALLOC(dense_a,mld_poly,2*MLDSA_L,context);
#if LC_DSA_MATRIX4_ARENA
  MLD_ALLOC(matrix_workspace,lc_matrix4_workspace,1,context);
#endif
#endif
#if LC_DSA_KEYGEN_RETAIN_S2
  MLD_ALLOC(s2plain,mld_poly,MLDSA_K,context);
#endif
#if LC_DSA_DIRECT_MATRIX_ACTIVE
  MLD_ALLOC(tmp,mld_poly,1,context);
#else
  mld_poly *tmp = mat == NULL ? NULL : &mat->cur;
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#else
#if LC_DSA_FLAT_KEYGEN && MLDSA_K > 4 && !LC_DSA_NATIVE_MATRIX_ROWS
  if(flat_keygen_extra==NULL) {ret=MLD_ERR_OUT_OF_MEMORY;goto cleanup;}
#endif
#endif
  if(
#if LC_DSA_KEYGEN_RETAIN_S2
     s2plain==NULL ||
#endif
#if LC_DSA_KEYGEN_ETA4
     eta_tile==NULL ||
#if LC_DSA_KEYGEN_ETA_ARENA
     eta_workspace==NULL ||
#endif
#endif
#if LC_DSA_NATIVE_MATRIX_ROWS
     dense_a==NULL ||
#if LC_DSA_MATRIX4_ARENA
     matrix_workspace==NULL ||
#endif
#endif
     seedbuf==NULL || inbuf==NULL || tr==NULL || s1==NULL || mat==NULL || trow==NULL || tmp==NULL) {
    ret=MLD_ERR_OUT_OF_MEMORY; goto cleanup;
  }
#if LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  if(row_tile==NULL) {ret=MLD_ERR_OUT_OF_MEMORY;goto cleanup;}
#endif
  mld_memcpy(inbuf,seed,MLDSA_SEEDBYTES);
  inbuf[MLDSA_SEEDBYTES]=MLDSA_K;
  inbuf[MLDSA_SEEDBYTES+1]=MLDSA_L;
  mld_shake256(seedbuf,2*MLDSA_SEEDBYTES+MLDSA_CRHBYTES,inbuf,MLDSA_SEEDBYTES+2);
  rho=seedbuf; rhoprime=rho+MLDSA_SEEDBYTES; key=rhoprime+MLDSA_CRHBYTES;
  MLD_CT_TESTING_DECLASSIFY(rho,MLDSA_SEEDBYTES);
#if LC_DSA_STREAM_RECOMPUTE
  /* The first row generates and serializes s1 in the standard nonce order. */
#elif LC_DSA_PACKED_ACCUM
#if LC_DSA_KEYGEN_ETA4
  /* Consecutive standardized nonces fill each SIMD group across s1/s2.
   * Store all small rows directly in the caller's secret-key encoding;
   * transformed s1 rows survive while the scratch tile is recycled. */
  for(i=0;i<MLDSA_L+MLDSA_K;i+=4) {
#if LC_DSA_KEYGEN_RETAIN_S2
    mld_poly *eta_dest[4];
    for(unsigned lane=0;lane<4;lane++) {
      unsigned at=i+lane;
      eta_dest[lane]=at<MLDSA_L?(mld_poly*)(void*)(*s1)[at]:at<MLDSA_L+MLDSA_K?&s2plain[at-MLDSA_L]:&eta_tile[lane];
    }
#if LC_DSA_KEYGEN_ETA_ARENA
    lc_poly_uniform_eta4_arena(eta_dest[0],eta_dest[1],eta_dest[2],eta_dest[3],
                          rhoprime,(uint8_t)i,(uint8_t)(i+1),(uint8_t)(i+2),(uint8_t)(i+3),eta_workspace);
#else
    mld_poly_uniform_eta_4x(eta_dest[0],eta_dest[1],eta_dest[2],eta_dest[3],
                          rhoprime,(uint8_t)i,(uint8_t)(i+1),(uint8_t)(i+2),(uint8_t)(i+3));
#endif
#else
#if LC_DSA_KEYGEN_ETA_ARENA
    lc_poly_uniform_eta4_arena(&eta_tile[0],&eta_tile[1],&eta_tile[2],&eta_tile[3],
                          rhoprime,(uint8_t)i,(uint8_t)(i+1),(uint8_t)(i+2),(uint8_t)(i+3),eta_workspace);
#else
    mld_poly_uniform_eta_4x(&eta_tile[0],&eta_tile[1],&eta_tile[2],&eta_tile[3],
                          rhoprime,(uint8_t)i,(uint8_t)(i+1),(uint8_t)(i+2),(uint8_t)(i+3));
#endif
#endif
    for(unsigned lane=0;lane<4 && i+lane<MLDSA_L+MLDSA_K;lane++) {
      unsigned at=i+lane;
#if LC_DSA_KEYGEN_RETAIN_S2
      mld_poly *ep=eta_dest[lane];
#else
      mld_poly *ep=&eta_tile[lane];
#endif
      if(at<MLDSA_L) {
        mld_polyeta_pack(sk+MLDSA_SK_S1_OFFSET+at*MLDSA_POLYETA_PACKEDBYTES,ep);
        mld_poly_ntt(ep);
#if !LC_DSA_KEYGEN_RETAIN_S2
        lc_pack_matrix_ntt24((*s1)[at],ep);
#endif
      } else mld_polyeta_pack(sk+MLDSA_SK_S2_OFFSET+(at-MLDSA_L)*MLDSA_POLYETA_PACKEDBYTES,ep);
    }
  }
#else
  for(i=0;i<MLDSA_L;i++) {
    mld_poly_uniform_eta(tmp,rhoprime,(uint8_t)i);
    mld_polyeta_pack(sk+MLDSA_SK_S1_OFFSET+i*MLDSA_POLYETA_PACKEDBYTES,tmp);
    mld_poly_ntt(tmp);lc_pack_matrix_ntt24((*s1)[i],tmp);
  }
#endif
#else
  for(i=0;i<MLDSA_L;i++) mld_poly_uniform_eta(&s1->vec[i],rhoprime,(uint8_t)i);
  mld_pack_sk_s1(sk,s1);
  mld_polyvecl_ntt(s1);
#endif
  mld_memcpy(pk+MLDSA_PK_RHO_OFFSET,rho,MLDSA_SEEDBYTES);
  mld_polyvec_matrix_expand(mat,rho);
#if LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  mat->row_tile=row_tile;
#endif
#if LC_DSA_NATIVE_MATRIX_ROWS
/* Matrix rows are generated directly into the bounded two-row owner. */
#endif
  for(i=0;i<MLDSA_K;i++) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#if LC_DSA_STREAM_RECOMPUTE
    lc_stream_s1_row(trow,mat,rhoprime,tmp,i,sk);
#elif LC_DSA_PACKED_ACCUM
    lc_packed_matrix_row(trow,mat,s1,i);
#else
    mld_polyvec_matrix_pointwise_montgomery_row(trow,mat,s1,i);
#endif
#else
#if LC_DSA_NATIVE_MATRIX_ROWS
    lc_native_matrix_row(trow,dense_a,s1,i,rho,0 LC_MATRIX4_PASS);
#elif LC_DSA_FLAT_KEYGEN && MLDSA_K > 4
    /* The row roles swap after serialization; allocation owners stay fixed. */
    mld_poly *trow=flat_keygen_current;
    lc_flat_verify_row(trow,flat_keygen_carry,mat,s1,i,&flat_keygen_cursor);
#elif LC_DSA_STREAM_RECOMPUTE
    lc_stream_s1_row(trow,mat,rhoprime,tmp,i,sk);
#elif LC_DSA_PACKED_ACCUM
    lc_packed_matrix_row(trow,mat,s1,i);
#else
    mld_polyvec_matrix_pointwise_montgomery_row(trow,mat,s1,i);
#endif
#endif
    mld_poly_invntt_tomont(trow);
    /* Sampling s2 after the matrix product uses the same public nonce L+i.
     * Encode while its small coefficients are live, then reuse cur for t1. */
#if LC_DSA_KEYGEN_ETA4
#if !LC_DSA_KEYGEN_RETAIN_S2
    mld_polyeta_unpack(tmp,sk+MLDSA_SK_S2_OFFSET+i*MLDSA_POLYETA_PACKEDBYTES);
#endif
#else
    mld_poly_uniform_eta(tmp,rhoprime,(uint8_t)(MLDSA_L+i));
    mld_polyeta_pack(sk+MLDSA_SK_S2_OFFSET+i*MLDSA_POLYETA_PACKEDBYTES,tmp);
#endif
#if LC_DSA_FUSED_KEYGEN_PACK
    lc_keygen_pack_t(pk+MLDSA_PK_T1_OFFSET+i*MLDSA_POLYT1_PACKEDBYTES,
                  sk+MLDSA_SK_T0_OFFSET+i*MLDSA_POLYT0_PACKEDBYTES,trow,
#if LC_DSA_KEYGEN_RETAIN_S2
                  &s2plain[i]
#else
                  tmp
#endif
                  );
#else
    mld_poly_add(trow,tmp);
    mld_poly_reduce(trow); mld_poly_caddq(trow);
    mld_poly_power2round(tmp,trow,trow);
    mld_polyt1_pack(pk+MLDSA_PK_T1_OFFSET+i*MLDSA_POLYT1_PACKEDBYTES,tmp);
    mld_polyt0_pack(sk+MLDSA_SK_T0_OFFSET+i*MLDSA_POLYT0_PACKEDBYTES,trow);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#else
#if LC_DSA_FLAT_KEYGEN && MLDSA_K > 4 && !LC_DSA_NATIVE_MATRIX_ROWS
    flat_keygen_current=flat_keygen_carry; flat_keygen_carry=trow;
#endif
#endif
  }
  mld_shake256(tr,MLDSA_TRBYTES,pk,MLDSA_CRYPTO_PUBLICKEYBYTES);
  mld_memcpy(sk+MLDSA_SK_RHO_OFFSET,rho,MLDSA_SEEDBYTES);
  mld_memcpy(sk+MLDSA_SK_KEY_OFFSET,key,MLDSA_SEEDBYTES);
  mld_memcpy(sk+MLDSA_SK_TR_OFFSET,tr,MLDSA_TRBYTES);
  MLD_CT_TESTING_DECLASSIFY(pk,MLDSA_CRYPTO_PUBLICKEYBYTES);
  ret=0;
cleanup:
#if LC_DSA_DIRECT_MATRIX_ACTIVE
  MLD_FREE(tmp,mld_poly,1,context);
#endif
#if LC_DSA_KEYGEN_RETAIN_S2
  MLD_FREE(s2plain,mld_poly,MLDSA_K,context);
#endif
#if LC_DSA_NATIVE_MATRIX_ROWS
  #if LC_DSA_MATRIX4_ARENA
  MLD_FREE(matrix_workspace,lc_matrix4_workspace,1,context);
#endif
  MLD_FREE(dense_a,mld_poly,2*MLDSA_L,context);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#if LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  MLD_FREE(row_tile,mld_poly,3,context);
#endif
#else
#if LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  MLD_FREE(row_tile,mld_poly,3,context);
#endif
#if LC_DSA_FLAT_KEYGEN && MLDSA_K > 4 && !LC_DSA_NATIVE_MATRIX_ROWS
  MLD_FREE(flat_keygen_extra,mld_poly,1,context);
#endif
#endif
#if LC_DSA_KEYGEN_ETA4
#if LC_DSA_KEYGEN_ETA_ARENA
  MLD_FREE(eta_workspace,lc_eta4_workspace,1,context);
#endif
  MLD_FREE(eta_tile,mld_poly,4,context);
#endif
  MLD_FREE(trow,mld_poly,1,context);
  MLD_FREE(mat,mld_polymat,1,context);
#if LC_DSA_STREAM_RECOMPUTE
  MLD_FREE(s1,uint8_t,1,context);
#elif LC_DSA_PACKED_ACCUM
  MLD_FREE(s1,lc_packed_vecl,1,context);
#else
  MLD_FREE(s1,mld_polyvecl,1,context);
#endif
  MLD_FREE(tr,uint8_t,MLDSA_TRBYTES,context);
  MLD_FREE(inbuf,uint8_t,MLDSA_SEEDBYTES+2,context);
  MLD_FREE(seedbuf,uint8_t,2*MLDSA_SEEDBYTES+MLDSA_CRHBYTES,context);
  if(ret==0) ret=mld_check_pct(pk,sk,context);
  if(ret!=0) { mld_zeroize(pk,MLDSA_CRYPTO_PUBLICKEYBYTES);mld_zeroize(sk,MLDSA_CRYPTO_SECRETKEYBYTES); }
  return ret;
#else

  int ret;
  const uint8_t *rho, *rhoprime, *key;

  MLD_ALLOC(seedbuf, uint8_t, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES, context);
  MLD_ALLOC(inbuf, uint8_t, MLDSA_SEEDBYTES + 2, context);
  MLD_ALLOC(tr, uint8_t, MLDSA_TRBYTES, context);
  MLD_ALLOC(s1, mld_polyvecl, 1, context);
  MLD_ALLOC(s2, mld_polyveck, 1, context);

  if (seedbuf == NULL || inbuf == NULL || tr == NULL || s1 == NULL ||
      s2 == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Get randomness for rho, rhoprime and key */
  mld_memcpy(inbuf, seed, MLDSA_SEEDBYTES);
  inbuf[MLDSA_SEEDBYTES + 0] = MLDSA_K;
  inbuf[MLDSA_SEEDBYTES + 1] = MLDSA_L;
  mld_shake256(seedbuf, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES, inbuf,
               MLDSA_SEEDBYTES + 2);
  rho = seedbuf;
  rhoprime = rho + MLDSA_SEEDBYTES;
  key = rhoprime + MLDSA_CRHBYTES;

  /* Constant time: rho is part of the public key and, hence, public. */
  MLD_CT_TESTING_DECLASSIFY(rho, MLDSA_SEEDBYTES);

  /* Sample s1 and s2 */
  mld_sample_s1_s2(s1, s2, rhoprime);

  /* Pack s1 into sk before NTT */
  mld_pack_sk_s1(sk, s1);

  /* NTT s1 in place to use as s1hat */
  mld_polyvecl_ntt(s1);

  /* Pack rho into pk */
  mld_memcpy(pk + MLDSA_PK_RHO_OFFSET, rho, MLDSA_SEEDBYTES);

  /* Compute t = A*s1hat + s2 row by row, decompose into t1/t0, and pack
   * t1 into pk and t0 directly into the t0 region of sk. */
  ret = mld_compute_pack_t0_t1(pk + MLDSA_PK_T1_OFFSET, sk + MLDSA_SK_T0_OFFSET,
                               s1, s2, rho, context);
  if (ret != 0)
  {
    goto cleanup;
  }

  /* Compute tr = H(pk) */
  mld_shake256(tr, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);

  /* Pack remaining secret key components (s1 and t0 already packed) */
  mld_pack_sk_rho_key_tr_s2(sk, rho, tr, key, s2);

  /* Constant time: pk is the public key, inherently public data */
  MLD_CT_TESTING_DECLASSIFY(pk, MLDSA_CRYPTO_PUBLICKEYBYTES);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(s2, mld_polyveck, 1, context);
  MLD_FREE(s1, mld_polyvecl, 1, context);
  MLD_FREE(tr, uint8_t, MLDSA_TRBYTES, context);
  MLD_FREE(inbuf, uint8_t, MLDSA_SEEDBYTES + 2, context);
  MLD_FREE(seedbuf, uint8_t, 2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES, context);

  /* Pairwise Consistency Test (PCT) @[FIPS140_3_IG, p.87] */
  /* Do this after freeing all temporaries. */
  if (ret == 0)
  {
    ret = mld_check_pct(pk, sk, context);
  }

  if (ret != 0)
  {
    /* Clear caller outputs on failure. */
    mld_zeroize(pk, MLDSA_CRYPTO_PUBLICKEYBYTES);
    mld_zeroize(sk, MLDSA_CRYPTO_SECRETKEYBYTES);
  }

  return ret;

#endif
}

#if !defined(MLD_CONFIG_CORE_API_ONLY)
#if !defined(MLD_CONFIG_NO_RANDOMIZED_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_keypair(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                     uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                     MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  MLD_ALLOC(seed, uint8_t, MLDSA_SEEDBYTES, context);

  if (seed == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  if (mld_randombytes(seed, MLDSA_SEEDBYTES) != 0)
  {
    ret = MLD_ERR_RNG_FAIL;
    goto cleanup;
  }
  MLD_CT_TESTING_SECRET(seed, MLDSA_SEEDBYTES);
  ret = mld_sign_keypair_internal(pk, sk, seed, context);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(seed, uint8_t, MLDSA_SEEDBYTES, context);
  return ret;
}
#endif /* !MLD_CONFIG_NO_RANDOMIZED_API */
#endif /* !MLD_CONFIG_CORE_API_ONLY */
#endif /* !MLD_CONFIG_NO_KEYPAIR_API */

#if !defined(MLD_CONFIG_NO_SIGN_API) || !defined(MLD_CONFIG_NO_VERIFY_API)
/**
 * Abstracts application of SHAKE256 to one, two or three blocks of data,
 * yielding a user-requested size of output.
 *
 * @param[out] out    Pointer to output.
 * @param      outlen Requested output length in bytes.
 * @param[in]  in1    Pointer to input block 1. Must NOT be NULL.
 * @param      in1len Length of input in1 in bytes.
 * @param[in]  in2    Pointer to input block 2. May be NULL if in2len == 0,
 *                    in which case this block is ignored.
 * @param      in2len Length of input in2 in bytes.
 * @param[in]  in3    Pointer to input block 3. May be NULL if in3len == 0,
 *                    in which case this block is ignored.
 * @param      in3len Length of input in3 in bytes.
 */
static void mld_H(uint8_t *out, size_t outlen, const uint8_t *in1,
                  size_t in1len, const uint8_t *in2, size_t in2len,
                  const uint8_t *in3, size_t in3len)
__contract__(
  requires(in1len <= MLD_MAX_BUFFER_SIZE)
  requires(in2len <= MLD_MAX_BUFFER_SIZE)
  requires(in3len <= MLD_MAX_BUFFER_SIZE)
  requires(outlen <= 8 * SHAKE256_RATE /* somewhat arbitrary bound */)
  requires(memory_no_alias(in1, in1len))
  requires(in2len == 0 || memory_no_alias(in2, in2len))
  requires(in3len == 0 || memory_no_alias(in3, in3len))
  requires(memory_no_alias(out, outlen))
  assigns(memory_slice(out, outlen))
)
{
  mld_shake256ctx state;
  mld_shake256_init(&state);
  mld_shake256_absorb(&state, in1, in1len);
  if (in2len != 0)
  {
    mld_shake256_absorb(&state, in2, in2len);
  }
  if (in3len != 0)
  {
    mld_shake256_absorb(&state, in3, in3len);
  }
  mld_shake256_finalize(&state);
  mld_shake256_squeeze(out, outlen, &state);
  mld_shake256_release(&state);

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(&state, sizeof(state));
}
#endif /* !MLD_CONFIG_NO_SIGN_API || !MLD_CONFIG_NO_VERIFY_API */

#ifndef LC_DSA_SCALAR_SWAR32
#define LC_DSA_SCALAR_SWAR32 0
#endif
#define LC_DSA_SCALAR_SWAR32_ACTIVE (LC_DSA_SCALAR_SWAR32 && MLDSA_ETA == 2)
#if LC_DSA_SCALAR_SWAR32_ACTIVE
static unsigned lc_scalar_eta_encoding_valid(const uint8_t *sk) {
  const uint8_t *v=sk+128;
  uint32_t bad=0;
  for(unsigned i=0;i<(MLDSA_L+MLDSA_K)*96;i+=3) {
    uint32_t x=(uint32_t)v[i]|((uint32_t)v[i+1]<<8)|((uint32_t)v[i+2]<<16);
    for(unsigned j=0;j<8;j++)bad|=(4u-((x>>(3*j))&7u))>>31;
  }
  return bad==0;
}
#if !defined(MLD_CONFIG_REDUCE_RAM) || LC_DSA_SPARSE_PRODUCT || LC_DSA_SPARSE_NEON || LC_DSA_EARLY_LOW_ROWS
#error "Scalar SWAR requires the ordinary reduced-RAM schedule"
#endif

/* Optional scalar SWAR path. For eta=2 and
 * tau<=60 the four byte lanes sum at most 4*tau<=240, so integer word
 * addition has no carry between lanes. The three alternating copies fit
 * in the first 768 bytes of the output; the 64 accumulators use its tail.
 * A forward expansion cannot overwrite an unread accumulator: 4*i<=192+i.
 * Input secret must be canonical. Challenge descriptors are public under
 * the same random-oracle disclosure model already used by this project.
 */
static void lc_scalar_swar32(int32_t out[256], const uint8_t packed[96],
                            const uint16_t shifts[60], unsigned tau)
{
  uint32_t *w=(uint32_t *)(void *)out;
  uint8_t *b=(uint8_t *)(void *)out;
  for(unsigned i=0;i<256;i++) {
    unsigned bit=3*i;
    unsigned t=packed[bit>>3]>>(bit&7);
    if((bit&7)>5) t|=(unsigned)packed[(bit>>3)+1]<<(8-(bit&7));
    t&=7;
    /* The packed input stores eta-s, and canonicality ensures t<=4. */
    b[i]=(uint8_t)t;
    b[256+i]=(uint8_t)(4-t);
    b[512+i]=(uint8_t)t;
  }
  for(unsigned i=0;i<64;i++) w[192+i]=0;
  for(unsigned k=0;k<tau;k++) {
    const unsigned start=shifts[k], r=start&3;
    const uint32_t *p=w+(start>>2);
    if(r==0) {
      for(unsigned i=0;i<64;i++) w[192+i]+=p[i];
    } else {
      const unsigned sh=8*r;
      for(unsigned i=0;i<64;i++)
        w[192+i]+=(p[i]>>sh)|(p[i+1]<<(32-sh));
    }
  }
  for(unsigned i=0;i<64;i++) {
    uint32_t v=w[192+i];
    for(unsigned k=0;k<4;k++) out[4*i+k]=(int32_t)((v>>(8*k))&255)-(int32_t)(2*tau);
  }
}

/* Each descriptor selects a public rotation in the alternating copies. */
static unsigned lc_scalar_sparse_shifts(uint16_t out[60],const int32_t c[256])
{
  unsigned n=0;
  for(unsigned i=0;i<256;i++) if(c[i]!=0)
    out[n++]=(uint16_t)((256-i+(c[i]<0?256:0))&511);
  return n;
}

#endif

#if !defined(MLD_CONFIG_NO_SIGN_API)
/* MLD_MAX_KAPPA (see params.h) bounds the rejection-sampling counter kappa;
 * MLD_MAX_SIGNING_ATTEMPTS below turns that into a bound on attempts. */

/**
 * Compute z = y + s1*c, check that z has coefficients smaller than
 * MLDSA_GAMMA1 - MLDSA_BETA, and pack z into the signature buffer.
 *
 * @reference{This function is inlined into mld_sign_signature in the
 * reference implementation.}
 *
 * @param[in,out] sig   Output signature.
 * @param[in]     cp    Challenge polynomial.
 * @param[in]     s1hat Secret vector s1 in NTT domain.
 * @param[in]     y     Masking vector y (or seed in REDUCE_RAM mode).
 * @param[out]    z     Scratch polynomial for z computation.
 * @param[out]    tmp   Scratch polynomial.
 *
 * @return - 0: Success (z has coefficients smaller than
 *           MLDSA_GAMMA1 - MLDSA_BETA).
 *         - MLD_ERR_FAIL: z rejected (norm check failed).
 *         - MLD_ERR_OUT_OF_MEMORY: If MLD_CONFIG_CUSTOM_ALLOC_FREE is used and
 *           an allocation via MLD_CUSTOM_ALLOC returned NULL.
 */
MLD_MUST_CHECK_RETURN_VALUE
static int mld_compute_pack_z(uint8_t sig[MLDSA_CRYPTO_BYTES],
                              const mld_poly *cp, const mld_sk_s1hat *s1hat,
                              const mld_yvec *y, mld_poly *z, mld_poly *tmp, unsigned lc_canonical_secret
#if LC_DSA_SCALAR_SWAR32_ACTIVE
                              , const uint16_t *lc_swar_shifts
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_SPARSE_NEON
                              ,const uint8_t sparse_index[61]
#endif
#else
#if LC_DSA_SPARSE_PRODUCT
                              ,const uint8_t sparse_index[61]
#endif
#endif
                              )
__contract__(
  requires(memory_no_alias(sig, MLDSA_CRYPTO_BYTES))
  requires(memory_no_alias(cp, sizeof(mld_poly)))
  requires(memory_no_alias(s1hat, sizeof(mld_sk_s1hat)))
  requires(memory_no_alias(y, sizeof(mld_yvec)))
  requires(memory_no_alias(z, sizeof(mld_poly)))
  requires(memory_no_alias(tmp, sizeof(mld_poly)))
  requires(array_abs_bound(cp->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
  MLD_IF_NOT_REDUCE_RAM(
    requires(forall(k0, 0, MLDSA_L,
      array_bound(y->vec.vec[k0].coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1)))
    requires(forall(k1, 0, MLDSA_L, array_abs_bound(s1hat->vec.vec[k1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  )
  MLD_IF_REDUCE_RAM(
    requires(memory_no_alias(s1hat->packed, MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
    requires(memory_no_alias(y->rhoprime, MLDSA_CRHBYTES))
    requires(y->kappa <= MLD_MAX_KAPPA)
  )
  assigns(memory_slice(sig, MLDSA_CRYPTO_BYTES))
  assigns(memory_slice(z, sizeof(mld_poly)))
  assigns(memory_slice(tmp, sizeof(mld_poly)))
  ensures(return_value == 0 || return_value == MLD_ERR_FAIL ||
          return_value == MLD_ERR_OUT_OF_MEMORY)
)
{
  unsigned int i;
  uint32_t z_invalid;
#if LC_DSA_EARLY_LOW_ROWS >= MLDSA_K && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44) && !(LC_DSA_POLY_REJECT & 1)
  uint32_t lc_z_any_invalid = 0;
#endif
  for (i = 0; i < MLDSA_L; i++)
  __loop__(
    assigns(i, memory_slice(z, sizeof(mld_poly)),
            memory_slice(tmp, sizeof(mld_poly)),
            memory_slice(sig, MLDSA_CRYPTO_BYTES))
    invariant(i <= MLDSA_L)
    decreases(MLDSA_L - i)
  )
  {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_SPARSE_NEON
#if LC_DSA_CHECKED_SPARSE
    lc_sparse8_product_packed_i16_eta(z->coeffs,s1hat->packed+i*MLDSA_POLYETA_PACKEDBYTES,sparse_index,MLDSA_TAU,lc_canonical_secret?(MLDSA_ETA==2?60:31):(MLDSA_ETA==2?25:11),MLDSA_ETA);
#else
    lc_sparse8_product_packed_i16(z->coeffs,s1hat->packed+i*MLDSA_POLYETA_PACKEDBYTES,sparse_index,MLDSA_TAU,(MLDSA_ETA==2?25:11));
#endif
    (void)cp;
#else
#if LC_DSA_SCALAR_SWAR32_ACTIVE
    if(lc_canonical_secret) {
      lc_scalar_swar32(z->coeffs,s1hat->packed+i*MLDSA_POLYETA_PACKEDBYTES,lc_swar_shifts,MLDSA_TAU);
    } else
#endif
    {
    mld_sk_s1hat_get_poly(z, s1hat, i);
    mld_poly_pointwise_montgomery(z, cp);
    mld_poly_invntt_tomont(z);
    }
#endif
    mld_yvec_get_poly(tmp, y, i);
#else
    const unsigned column=LC_DSA_LAST_Z_FIRST?(i==0?MLDSA_L-1:i-1):i;
#if LC_DSA_LAST_Y_CACHE
    /* Read the cache fully before z overwrites the same tail allocation. */
    if(i==0)lc_restore_last_y(tmp,(const uint8_t*)z+sizeof(mld_poly)-LC_PACKED_ROW_BYTES);
#endif
#if LC_DSA_SPARSE_PRODUCT
    lc_sparse8_product_i16(z->coeffs,s1hat->packed+column*MLDSA_POLYETA_PACKEDBYTES,sparse_index,MLDSA_TAU,lc_canonical_secret ? (MLDSA_ETA==2?60:31) : (MLDSA_ETA==2?25:11));
    (void)cp;
#else
#if LC_DSA_SCALAR_SWAR32_ACTIVE
    if(lc_canonical_secret) {
      lc_scalar_swar32(z->coeffs,s1hat->packed+column*MLDSA_POLYETA_PACKEDBYTES,lc_swar_shifts,MLDSA_TAU);
    } else
#endif
    {
    mld_sk_s1hat_get_poly(z, s1hat, column);
    mld_poly_pointwise_montgomery(z, cp);
    mld_poly_invntt_tomont(z);
    }
#endif
#if LC_DSA_LAST_Y_CACHE
    if(i!=0)
#endif
    mld_yvec_get_poly(tmp, y, column);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && LC_DSA_SPARSE_NEON
    z_invalid = lc_sparse8_consume(z->coeffs,tmp->coeffs,z->coeffs,
                                   MLDSA_GAMMA1-MLDSA_BETA,0);
#elif LC_DSA_SPARSE_PRODUCT && (!defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE)
    z_invalid=lc_sparse16_consume(z->coeffs,tmp->coeffs,
        (const uint8_t *)(const void *)z,MLDSA_GAMMA1-MLDSA_BETA,0);
#else
    mld_poly_add(z, tmp);
    mld_poly_reduce(z);

    z_invalid = mld_poly_chknorm(z, MLDSA_GAMMA1 - MLDSA_BETA);
#endif
    /* Constant time: It is fine (and prohibitively expensive to avoid)
     * to leak the result of the norm check and which polynomial in z caused a
     * rejection. It would even be okay to leak which coefficient led to
     * rejection as the candidate signature will be discarded anyway.
     * See Section 5.5 of @[Round3_Spec]. */
#if LC_DSA_EARLY_LOW_ROWS >= MLDSA_K && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44) && !(LC_DSA_POLY_REJECT & 1)
    /* Finish every response row before exposing the vector norm result.
     * An invalid row is masked to a valid zero row for fixed-format packing;
     * the aggregate rejection discards the entire candidate afterwards. */
    lc_z_any_invalid |= z_invalid;
    const uint32_t lc_z_keep = 0u - (uint32_t)(z_invalid == 0);
    for (unsigned j = 0; j < MLDSA_N; j++)
      z->coeffs[j] = (int32_t)((uint32_t)z->coeffs[j] & lc_z_keep);
#else
    MLD_CT_TESTING_DECLASSIFY(&z_invalid, sizeof(uint32_t));
    if (z_invalid)
    {
      return MLD_ERR_FAIL; /* reject */
    }
#endif
    /* If z is valid, then its coefficients are bounded by
     * MLDSA_GAMMA1 - MLDSA_BETA. This will be needed below
     * to prove the pre-condition of pack_sig_z() */
    mld_assert_abs_bound(z, MLDSA_N, (MLDSA_GAMMA1 - MLDSA_BETA));

    /* After the norm check, the distribution of each coefficient of z is
     * independent of the secret key and it can, hence, be considered
     * public. It is, hence, okay to immediately pack it into the user-provided
     * signature buffer. */
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    mld_pack_sig_z(sig, z, i);
#else
    mld_pack_sig_z(sig, z, column);
#endif
  }
#if LC_DSA_EARLY_LOW_ROWS >= MLDSA_K && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44) && !(LC_DSA_POLY_REJECT & 1)
  MLD_CT_TESTING_DECLASSIFY(&lc_z_any_invalid, sizeof(lc_z_any_invalid));
  return lc_z_any_invalid ? MLD_ERR_FAIL : 0;
#else
  return 0;
#endif
}

/* Effective bound on signing attempts: the configured bound
 * MLD_CONFIG_MAX_SIGNING_ATTEMPTS (see mldsa_native_config.h) if set, otherwise
 * the hard type-safety bound MLD_MAX_KAPPA / MLDSA_L (see MLD_MAX_KAPPA in
 * params.h). */
#if defined(MLD_CONFIG_MAX_SIGNING_ATTEMPTS)

#if !defined(MLD_ALLOW_NONCOMPLIANT_SIGNING_BOUND) && \
    MLD_CONFIG_MAX_SIGNING_ATTEMPTS < 821
#error Bad configuration: MLD_CONFIG_MAX_SIGNING_ATTEMPTS must be >= 821 for FIPS 204 compliance @[FIPS204, Appendix C] @[FIPS204_UPDATES]
#endif

#if MLD_CONFIG_MAX_SIGNING_ATTEMPTS < 1
#error Bad configuration: MLD_CONFIG_MAX_SIGNING_ATTEMPTS must be >= 1
#endif

#if MLD_CONFIG_MAX_SIGNING_ATTEMPTS > MLD_MAX_KAPPA / MLDSA_L
#error Bad configuration: MLD_CONFIG_MAX_SIGNING_ATTEMPTS exceeds the maximum allowed value.
#endif

#define MLD_MAX_SIGNING_ATTEMPTS MLD_CONFIG_MAX_SIGNING_ATTEMPTS
#else /* MLD_CONFIG_MAX_SIGNING_ATTEMPTS */
#define MLD_MAX_SIGNING_ATTEMPTS (MLD_MAX_KAPPA / MLDSA_L)
#endif /* !MLD_CONFIG_MAX_SIGNING_ATTEMPTS */

MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE uint16_t mld_get_max_signing_attempts(void)
__contract__(
  ensures(return_value >= 1)
  ensures(return_value <= MLD_MAX_KAPPA / MLDSA_L)
)
{
  /* cassert(0) ensures CBMC uses the contract rather than inlining the body,
   * keeping proofs agnostic of the configured value. */
  cassert(0);
  return MLD_MAX_SIGNING_ATTEMPTS;
}

/**
 * Attempt to generate a single signature: one iteration of the
 * ML-DSA.Sign_internal rejection-sampling loop.
 *
 * @spec{Implements one iteration of the rejection-sampling loop body of
 * @[FIPS204, Algorithm 7, ML-DSA.Sign_internal] (lines 11-30) plus, on success,
 * the sigEncode step (line 33). The per-signature setup (Algorithm 7 lines 1-7:
 * skDecode, NTT of s1/s2/t0, ExpandA, and computation of mu and rhoprime) and
 * the loop itself (lines 8-10, 31-32) live in the caller
 * mld_sign_signature_internal; kappa is this iteration's counter, used to
 * sample y.}
 *
 * @reference{This code differs from the reference implementation in that it
 * factors out the core signature generation step into a distinct function
 * here in order to improve efficiency of CBMC proof.}
 *
 * @param[out] sig      Pointer to output signature.
 * @param[in]  mu       Pointer to message or hash of exactly MLDSA_CRHBYTES
 *                      bytes.
 * @param[in]  rhoprime Pointer to randomness seed.
 * @param      kappa    Counter for this iteration (= attempt*MLDSA_L).
 * @param[in]  mat      Expanded matrix.
 * @param[in]  s1hat    Secret vector s1 in NTT domain.
 * @param[in]  s2hat    Secret vector s2 in NTT domain.
 * @param[in]  t0hat    Vector t0 in NTT domain.
 * @param      context  Application context. Only present when
 *                      MLD_CONFIG_CONTEXT_PARAMETER is defined; type set by
 *                      MLD_CONFIG_CONTEXT_PARAMETER_TYPE.
 *
 * @return - 0: Signature generation succeeded.
 *         - MLD_ERR_FAIL: Signature rejected (norm check failed).
 *         - MLD_ERR_OUT_OF_MEMORY: If MLD_CONFIG_CUSTOM_ALLOC_FREE is used and
 *           an allocation via MLD_CUSTOM_ALLOC returned NULL.
 */
MLD_MUST_CHECK_RETURN_VALUE
/* NOLINTNEXTLINE(readability-function-cognitive-complexity) */
static int mld_attempt_signature_generation(
    uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *mu,
    const uint8_t rhoprime[MLDSA_CRHBYTES], uint16_t kappa, mld_polymat *mat,
    const mld_sk_s1hat *s1hat, const mld_sk_s2hat *s2hat,
    const mld_sk_t0hat *t0hat, unsigned lc_canonical_secret, MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
__contract__(
  requires(memory_no_alias(sig, MLDSA_CRYPTO_BYTES))
  requires(memory_no_alias(mu, MLDSA_CRHBYTES))
  requires(memory_no_alias(rhoprime, MLDSA_CRHBYTES))
  requires(memory_no_alias(mat, sizeof(mld_polymat)))
  requires(memory_no_alias(s1hat, sizeof(mld_sk_s1hat)))
  requires(memory_no_alias(s2hat, sizeof(mld_sk_s2hat)))
  requires(memory_no_alias(t0hat, sizeof(mld_sk_t0hat)))
  requires(kappa <= MLD_MAX_KAPPA)
  MLD_IF_NOT_REDUCE_RAM(
    requires(forall(k1, 0, MLDSA_K, forall(l1, 0, MLDSA_L,
                                           array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
    requires(forall(k2, 0, MLDSA_K, array_abs_bound(t0hat->vec.vec[k2].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
    requires(forall(k3, 0, MLDSA_L, array_abs_bound(s1hat->vec.vec[k3].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
    requires(forall(k4, 0, MLDSA_K, array_abs_bound(s2hat->vec.vec[k4].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  )
  MLD_IF_REDUCE_RAM(
    requires(memory_no_alias(s1hat->packed, MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
    requires(memory_no_alias(s2hat->packed, MLDSA_K * MLDSA_POLYETA_PACKEDBYTES))
    requires(memory_no_alias(t0hat->packed, MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  )
  assigns(memory_slice(sig, MLDSA_CRYPTO_BYTES))
  MLD_IF_REDUCE_RAM(
    assigns(memory_slice(mat, sizeof(mld_polymat)))
  )
  ensures(return_value == 0 || return_value == MLD_ERR_FAIL ||
          return_value == MLD_ERR_OUT_OF_MEMORY)
)
{
  unsigned int k;
  uint32_t w0_invalid, h_invalid;
  int ret;

  typedef union
  {
    mld_yvec_scratch y;
    mld_poly w;
  } scratch_u;
  mld_yvec_scratch *scratch_yvec;
  mld_poly *scratch_w;

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  LC_SMALL_ALLOC(challenge_bytes, uint8_t, MLDSA_CTILDEBYTES+64*LC_DSA_SPARSE_NEON, context);
#else
  LC_SMALL_ALLOC(challenge_bytes, uint8_t, MLDSA_CTILDEBYTES+64*LC_DSA_SPARSE_SEPARATE_CP, context);
#endif
  LC_SMALL_ALLOC(y, mld_yvec, 1, context);
  MLD_ALLOC(scratch, scratch_u, 1, context);
  MLD_ALLOC(w0_storage,lc_sign_w0_storage,1,context);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_PAIR_COLUMN && MLDSA_K == 4 && !LC_DSA_STREAM_CACHE24
  MLD_ALLOC(pair_second,mld_poly,1,context);
#endif
#endif
#if LC_DSA_PACKED_ACCUM
  uint8_t *w0=w0_storage==NULL?NULL:w0_storage->bytes;
#else
  mld_polyveck *w0=w0_storage==NULL ? NULL : &w0_storage->full;
#endif
#if LC_DSA_DIRECT_MATRIX_ACTIVE
  _Static_assert(MLDSA_K*LC_W0_FLAG_STRIDE%_Alignof(mld_poly)==0,
                 "Compact-prefix challenge alignment");
  _Static_assert(MLDSA_K*LC_W0_FLAG_STRIDE+sizeof(mld_poly)<=
                 (MLDSA_K-1)*sizeof(mld_poly),"Challenge and t must be disjoint");
  mld_poly *cp=w0==NULL?NULL:(mld_poly*)(void*)
      ((uint8_t*)w0+MLDSA_K*LC_W0_FLAG_STRIDE);
#elif LC_DSA_ALIAS_SIGN_CP
  /* cur is dead after A*y, and regenerated before use on the next attempt.
   * This pointer borrows mat storage: it must not be passed to MLD_FREE. */
  mld_poly *cp = &mat->cur;
#else
  MLD_ALLOC(cp, mld_poly, 1, context);
#endif
#if LC_DSA_PACK_W0
#if LC_DSA_STREAM_RECOMPUTE
  mld_poly *t=(mld_poly*)w0;
#elif LC_DSA_PACKED_ACCUM
  mld_poly *t=w0==NULL?NULL:(mld_poly*)(w0+LC_SIGN_T_OFFSET);
#else
  mld_poly *t=w0==NULL ? NULL : &w0->vec[MLDSA_K-1];
#endif
#else
  MLD_ALLOC(t,mld_poly,1,context);
#endif

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_CROSSCOL6 == 2 && MLDSA_K == 6 && (!LC_DSA_STREAM_CACHE24 || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE))
  MLD_ALLOC(cross_saved,uint8_t,1024,context);
#if LC_DSA_MIXED_HEAD65
  MLD_ALLOC(head_gamma,uint8_t,640,context);
#endif
#endif
#if LC_DSA_Y_CACHE_COUNT > 0
#if LC_DSA_BORROW_SIG_Y_ACTIVE
  uint8_t *raw_y4=sig+MLDSA_SIG_Z_OFFSET;
  _Static_assert(LC_DSA_Y_CACHE_BYTES<=MLDSA_SIG_Z_BYTES,"borrowed prefix must fit z");
#else
  MLD_ALLOC(raw_y4,uint8_t,LC_DSA_Y_CACHE_BYTES,context);
#endif
#endif
#else
#if LC_DSA_CROSSCOL6 == 2 && MLDSA_K == 6 && (!LC_DSA_STREAM_CACHE24 || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE))
  MLD_ALLOC(cross_saved,uint8_t,1024,context);
#endif
#if (LC_DSA_RAW_Y4_CACHE && MLDSA_K == 4) || LC_DSA_RAW_Y_ALL_CACHE
#if LC_DSA_RAW_Y_ALL_CACHE
#if LC_DSA_BORROW_SIG_Y_ACTIVE
  uint8_t *raw_y4=sig+MLDSA_SIG_Z_OFFSET;
  _Static_assert(MLDSA_L*MLDSA_POLYZ_PACKEDBYTES<=MLDSA_SIG_Z_BYTES,"borrowed prefix must fit z");
#else
  MLD_ALLOC(raw_y4,uint8_t,MLDSA_L*MLDSA_POLYZ_PACKEDBYTES,context);
#endif
#else
#if LC_DSA_BORROW_SIG_Y_ACTIVE
  uint8_t *raw_y4=sig+MLDSA_SIG_Z_OFFSET;
  _Static_assert(2304<=MLDSA_SIG_Z_BYTES,"borrowed prefix must fit z");
#else
  MLD_ALLOC(raw_y4,uint8_t,2304,context);
#endif
#endif
#endif
#endif
#if LC_DSA_CACHED_DOT_TILE
#if LC_DSA_PARTIAL_DENSE_ACTIVE
  MLD_ALLOC(lc_cached_y,mld_poly,LC_DSA_PARTIAL_DENSE_SAVED_COUNT(MLDSA_L),context);
#elif LC_DSA_INPLACE_AY
  mld_poly *lc_cached_y=(mld_poly *)(void *)w0;
#else
  MLD_ALLOC(lc_cached_y,mld_poly,MLDSA_L,context);
#endif
#endif
  if (
#if LC_DSA_CACHED_DOT_TILE
      lc_cached_y == NULL ||
#endif
      challenge_bytes == NULL || y == NULL || scratch == NULL ||
      w0 == NULL || cp == NULL || t == NULL
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_CROSSCOL6 == 2 && MLDSA_K == 6 && (!LC_DSA_STREAM_CACHE24 || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE))
      || cross_saved == NULL
#if LC_DSA_MIXED_HEAD65
      || head_gamma == NULL
#endif
#endif
#if LC_DSA_Y_CACHE_COUNT > 0
      || raw_y4 == NULL
#endif
#else
#if LC_DSA_PAIR_COLUMN && MLDSA_K == 4 && !LC_DSA_STREAM_CACHE24
      || pair_second == NULL
#endif
#if LC_DSA_CROSSCOL6 == 2 && MLDSA_K == 6 && (!LC_DSA_STREAM_CACHE24 || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE))
      || cross_saved == NULL
#endif
#if (LC_DSA_RAW_Y4_CACHE && MLDSA_K == 4) || LC_DSA_RAW_Y_ALL_CACHE
      || raw_y4 == NULL
#endif
#endif
      )
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }
  scratch_yvec = &scratch->y;
  scratch_w = &scratch->w;

  /* @[FIPS204, Algorithm 7, line 11] y <- ExpandMask(rhoprime, kappa). */
  mld_yvec_init(y, rhoprime, kappa
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
   ,sig+MLDSA_SIG_Z_OFFSET
#endif
#if LC_DSA_XOF_OWNER
   ,scratch_w
#endif
  );
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_Y_CACHE_COUNT > 0
  lc_raw_y4_fill(y,mat,raw_y4);
#endif
#else
#if (LC_DSA_RAW_Y4_CACHE && MLDSA_K == 4) || LC_DSA_RAW_Y_ALL_CACHE
  lc_raw_y4_fill(y,mat,raw_y4);
#endif
#endif

  /* @[FIPS204, Algorithm 7, line 12] w <- invNTT(A_hat o NTT(y)). This call
   * performs the whole line: it NTTs y, accumulates the pointwise product with
   * A_hat, and applies the inverse NTT. In REDUCE_RAM mode the y sampling is
   * fused into the same pass. */
#if LC_DSA_STREAM_RECOMPUTE
  lc_stream_hash(challenge_bytes,mu,w0_storage,mat,y,scratch_w);
#elif LC_DSA_PACKED_ACCUM
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_ARM_SPEED32
  lc_packed_ay(w0,mat,y,scratch_yvec,lc_cached_y);
#elif defined(LC_DSA_CROSSCOL6) && LC_DSA_CROSSCOL6 && MLDSA_K == 6
#if LC_DSA_CROSSCOL6 == 2
#if LC_DSA_MIXED_HEAD65
  lc_crosscol6_ay_head(w0,mat,y,scratch_yvec,cross_saved,head_gamma);
#else
  lc_crosscol6_ay(w0,mat,y,scratch_yvec,cross_saved);
#endif
#else
  lc_crosscol6_ay(w0,mat,y,scratch_yvec,sig);
#endif
#else
  lc_packed_ay(w0,mat,y,scratch_yvec
#if LC_DSA_CACHED_DOT_TILE
               ,lc_cached_y
#endif
               );
#endif
#else
#if LC_DSA_STREAM_CACHE24
  lc_packed_ay(w0,mat,y,scratch_yvec
#if LC_DSA_CACHED_DOT_TILE
               ,lc_cached_y
#endif
               );
#elif LC_DSA_PAIR_COLUMN && MLDSA_K == 4
  lc_pair_ay(w0,mat,y,scratch_w,pair_second);
#elif LC_DSA_CROSSCOL6 == 2 && MLDSA_K == 6
#if LC_DSA_HYBRID_NEXTY
  lc_nexty5_ay(w0,mat,y,scratch_yvec,cross_saved);
#else
  lc_crosscol6_ay(w0,mat,y,scratch_yvec,cross_saved);
#endif
#else
  lc_packed_ay(w0,mat,y,scratch_yvec
#if LC_DSA_CACHED_DOT_TILE
               ,lc_cached_y
#endif
               );
#endif
#endif
#elif defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_A_STREAM_BATCH4 && LC_DSA_A_CACHE_COUNT < MLDSA_K*MLDSA_L && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  {
    MLD_ALLOC(matrix_tile,mld_poly,3,context);
    if (matrix_tile==NULL) { ret=MLD_ERR_OUT_OF_MEMORY; goto cleanup; }
    mld_polyvec_matrix_pointwise_montgomery_yvec_stream4(w0,mat,y,scratch_yvec,matrix_tile);
    MLD_FREE(matrix_tile,mld_poly,3,context);
  }
#else
  mld_polyvec_matrix_pointwise_montgomery_yvec(w0, mat, y, scratch_yvec);
#endif

#if LC_DSA_STREAM_CACHE24
  /* Every retained public entry has been consumed and copied completely.
   * Publish readiness before any candidate-dependent rejection occurs. */
  mat->cache_ready=1;
#endif

#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  /* Every row was sampled exactly once by the unchanged A*y traversal.
   * The descriptor phase is public and independent of the rejection value. */
  y->natural_ready=1;
#endif

  /* @[FIPS204, Algorithm 7, lines 13+15] Consume each HighBits row in
   * w1Encode order directly into H(mu || w1Encode(w1)). Retain its nonzero
   * predicate beside compressed LowBits for the later exact MakeHint test.
   * cp aliases dead mat->cur until the oracle returns; t is not yet live. */
#if !LC_DSA_PACKED_ACCUM
  mld_polyveck_caddq(w0);
#endif
#if !LC_DSA_STREAM_RECOMPUTE
  lc_sign_decompose_hash_bitmap(challenge_bytes,mu,w0_storage,cp,scratch_w);
#endif
  /* Constant time: Leaking challenge_bytes does not reveal any information
   * about the secret key as H() is modelled as random oracle.
   * This also applies to challenges for rejected signatures.
   * See Section 5.5 of @[Round3_Spec]. */
  MLD_CT_TESTING_DECLASSIFY(challenge_bytes, MLDSA_CTILDEBYTES);
  /* @[FIPS204, Algorithm 7, line 16] c <- SampleInBall(ctilde) and
   * @[FIPS204, Algorithm 7, line 17] c_hat <- NTT(c). */
#if LC_DSA_XOF_OWNER
  lc_dsa_challenge_scratch(cp,challenge_bytes,MLDSA_CTILDEBYTES,MLDSA_TAU,scratch_w);
#else
  mld_poly_challenge(cp, challenge_bytes);
#endif
#if LC_DSA_SCALAR_SWAR32_ACTIVE
  uint16_t lc_swar_shifts[60];
  (void)lc_scalar_sparse_shifts(lc_swar_shifts,cp->coeffs);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_SPARSE_NEON
  uint8_t *sparse_indices=challenge_bytes+MLDSA_CTILDEBYTES;
  lc_sparse16_challenge(sparse_indices,cp->coeffs,MLDSA_TAU);
#endif
#if !LC_DSA_SPARSE_T0_NEON
  mld_poly_ntt(cp);
#endif
#else
#if LC_DSA_SPARSE_PRODUCT
#if LC_DSA_SPARSE_SEPARATE_CP
  uint8_t *sparse_indices=challenge_bytes+MLDSA_CTILDEBYTES;
  lc_sparse16_challenge(sparse_indices,cp->coeffs,MLDSA_TAU);
#else
  uint8_t *sparse_indices=mat->sign_challenge.index;
  lc_sparse16_challenge((uint8_t*)t,cp->coeffs,MLDSA_TAU);
#endif
#endif
#if !LC_DSA_DEFER_CHALLENGE_NTT
  mld_poly_ntt(cp);
#endif
#if LC_DSA_SPARSE_PRODUCT && !LC_DSA_SPARSE_SEPARATE_CP
  lc_pack_ntt24(mat->sign_challenge.big,cp);
  mld_memcpy(sparse_indices,t,MLDSA_TAU+1);
#endif
#endif

#if !(LC_DSA_EARLY_LOW_ROWS >= MLDSA_K && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44))
#if LC_DSA_EARLY_LOW_ROWS && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44)
  /* Check a public fixed prefix of LowBits rows before regenerating z.
   * Each accepted row stays in its original compact owner; its high-nonzero
   * bitmap is untouched. Both predicates and the first accepted attempt are
   * unchanged. A failed norm is the same declassified rejection event. */
  for(unsigned low_row=0;low_row<LC_DSA_EARLY_LOW_ROWS && low_row<MLDSA_K;low_row++) {
#if LC_DSA_DIRECT_DENSE_ROWS
    /* This local view never replaces the call-owned tail scratch pointer. */
    mld_poly *t=(mld_poly *)(void *)(w0+low_row*LC_W0_FLAG_STRIDE);
#else
    lc_unpack_w0_row(t,(const uint8_t *)w0+low_row*LC_W0_FLAG_STRIDE);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_CHECKED_SPARSE
    lc_sparse8_product_packed_i16_eta(scratch_w->coeffs,s2hat->packed+low_row*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,lc_canonical_secret?(MLDSA_ETA==2?60:31):(MLDSA_ETA==2?25:11),MLDSA_ETA);
#else
    lc_sparse8_product_packed_i16(scratch_w->coeffs,s2hat->packed+low_row*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,(MLDSA_ETA==2?25:11));
#endif
#else
    lc_sparse8_product_i16(scratch_w->coeffs,s2hat->packed+low_row*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,lc_canonical_secret ? (MLDSA_ETA==2?60:31) : (MLDSA_ETA==2?25:11));
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    uint32_t low_invalid=lc_sparse8_consume(t->coeffs,t->coeffs,scratch_w->coeffs,
                                          MLDSA_GAMMA2-MLDSA_BETA,1);
#elif LC_DSA_SPARSE_PRODUCT && (!defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE)
    uint32_t low_invalid=lc_sparse16_consume(t->coeffs,t->coeffs,
        (const uint8_t *)(const void *)scratch_w,MLDSA_GAMMA2-MLDSA_BETA,1);
#else
    mld_poly_sub(t,scratch_w);
    mld_poly_reduce(t);
    uint32_t low_invalid=mld_poly_chknorm(t,MLDSA_GAMMA2-MLDSA_BETA);
#endif
    MLD_CT_TESTING_DECLASSIFY(&low_invalid,sizeof(low_invalid));
    if(low_invalid) {ret=MLD_ERR_FAIL;goto cleanup;}
#if !LC_DSA_DIRECT_DENSE_ROWS
    lc_pack_w0_row((uint8_t *)w0+low_row*LC_W0_FLAG_STRIDE,t);
#endif
  }
#endif

#endif

  /* @[FIPS204, Algorithm 7, lines 18+20] cs1 <- invNTT(c_hat o s1_hat) and
   * z <- y + cs1, followed by the line-23 norm check ||z||_inf >= GAMMA1 -
   * BETA. mld_compute_pack_z fuses all three per polynomial and, on success,
   * packs z into sig; it returns MLD_ERR_FAIL if the norm check rejects z. */
  ret = mld_compute_pack_z(sig, cp, s1hat, y, t, scratch_w, lc_canonical_secret
#if LC_DSA_SCALAR_SWAR32_ACTIVE
                         ,lc_swar_shifts
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_SPARSE_NEON
                         ,sparse_indices
#endif
                         );
#else
#if LC_DSA_SPARSE_PRODUCT
                           ,sparse_indices
#endif
                           );
#endif
  if (ret != 0)
  {
    goto cleanup;
  }

#if LC_DSA_EARLY_LOW_ROWS >= MLDSA_K && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44)
#if LC_DSA_EARLY_LOW_ROWS && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44)
  /* Response norm has accepted. Complete the low-vector norm before ct0.
   * Every corrected row remains in its compact owner. The high-nonzero
   * bitmap is untouched; the norm result is exposed after the fixed scan. */
  uint32_t lc_low_any_invalid = 0;
  for(unsigned low_row=0;low_row<LC_DSA_EARLY_LOW_ROWS && low_row<MLDSA_K;low_row++) {
#if LC_DSA_DIRECT_DENSE_ROWS
    /* This local view never replaces the call-owned tail scratch pointer. */
    mld_poly *t=(mld_poly *)(void *)(w0+low_row*LC_W0_FLAG_STRIDE);
#else
    lc_unpack_w0_row(t,(const uint8_t *)w0+low_row*LC_W0_FLAG_STRIDE);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_CHECKED_SPARSE
    lc_sparse8_product_packed_i16_eta(scratch_w->coeffs,s2hat->packed+low_row*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,lc_canonical_secret?(MLDSA_ETA==2?60:31):(MLDSA_ETA==2?25:11),MLDSA_ETA);
#else
    lc_sparse8_product_packed_i16(scratch_w->coeffs,s2hat->packed+low_row*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,(MLDSA_ETA==2?25:11));
#endif
#else
    lc_sparse8_product_i16(scratch_w->coeffs,s2hat->packed+low_row*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,lc_canonical_secret ? (MLDSA_ETA==2?60:31) : (MLDSA_ETA==2?25:11));
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    uint32_t low_invalid=lc_sparse8_consume(t->coeffs,t->coeffs,scratch_w->coeffs,
                                          MLDSA_GAMMA2-MLDSA_BETA,1);
#elif LC_DSA_SPARSE_PRODUCT && (!defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE)
    uint32_t low_invalid=lc_sparse16_consume(t->coeffs,t->coeffs,
        (const uint8_t *)(const void *)scratch_w,MLDSA_GAMMA2-MLDSA_BETA,1);
#else
    mld_poly_sub(t,scratch_w);
    mld_poly_reduce(t);
    uint32_t low_invalid=mld_poly_chknorm(t,MLDSA_GAMMA2-MLDSA_BETA);
#endif
#if LC_DSA_POLY_REJECT & 2
    /* The public rejection result is exposed after the full polynomial scan,
     * in the same row order as the native implementation. */
    MLD_CT_TESTING_DECLASSIFY(&low_invalid,sizeof(low_invalid));
    if(low_invalid) {ret=MLD_ERR_FAIL;goto cleanup;}
#else
    lc_low_any_invalid |= low_invalid;
#endif
#if !LC_DSA_DIRECT_DENSE_ROWS
    lc_pack_w0_row((uint8_t *)w0+low_row*LC_W0_FLAG_STRIDE,t);
#endif
  }
  MLD_CT_TESTING_DECLASSIFY(&lc_low_any_invalid,sizeof(lc_low_any_invalid));
  if(lc_low_any_invalid) {ret=MLD_ERR_FAIL;goto cleanup;}
#endif

#endif

#if LC_DSA_DEFER_CHALLENGE_NTT
  mld_poly_ntt(cp);
#endif

  /* The remaining steps realize @[FIPS204, Algorithm 7, lines 21-28] (the
   * low-bits norm check and the hint h) via the faster alternative formulation
   * of @[Round3_Spec, Section 5.1]. @[FIPS204] explicitly permits this: the
   * note accompanying Algorithm 7 states that the validity checks on z and the
   * computation of h may instead be implemented "as described in Section 5.1 of
   * [6]", and that reference is @[Round3_Spec, Section 5.1].
   *
   * The loop below updates the compressed low rows of w0 - cs2 + ct0;
   * each adjacent high-nonzero bitmap remains unchanged. Those are the
   * inputs to the streamlined computation of MakeHint explained below.
   *
   * Low-bits norm check:
   *   @[FIPS204, Algorithm 7, line 21] computes r0 = LowBits(w - cs2) and line
   *   23 rejects when ||r0||_inf >= GAMMA2 - BETA. By @[Round3_Spec, Section
   *   5.1] (Lemma 3), this line-23 check on r0 = LowBits(w - cs2) is implied by
   *   ||w0 - cs2||_inf < GAMMA2 - BETA, where w0 is the low part of w. In our
   *   context, w0 already holds the low part of w from the line-13 Decompose;
   *   after subtracting cs2 from it in place, the mld_poly_chknorm(w0, GAMMA2 -
   *   BETA) call below is exactly that check.
   *
   * Hint:
   *   @[FIPS204, Algorithm 7, line 26] sets h = MakeHint(-ct0, w - cs2 + ct0),
   *   and line 28 rejects when ||ct0||_inf >= GAMMA2 or h has more than OMEGA
   *   nonzero coefficients. @[Round3_Spec, Section 5.1] provides the following
   *   alternative description for MakeHint(-ct0, w - cs2 + ct0): a hint bit is
   *   zero exactly when the coefficient of w0 - cs2 + ct0 lies in
   *   (-GAMMA2, GAMMA2], or equals -GAMMA2 while the matching w1 coefficient is
   *   zero (the Decompose border case), and is set otherwise. This equivalence
   *   is precisely what mld_pack_sig_h -> mld_make_hint compute from w0
   *   (= w0 - cs2 + ct0) and the retained predicate w1 != 0. The line-28
   *   ||ct0||_inf >= GAMMA2 check is the mld_poly_chknorm(scratch_w, GAMMA2)
   *   call on ct0 below; the weight bound is enforced by mld_pack_sig_h.
   *
   * Building w0 per-component and checking norms incrementally also avoids
   * allocating a full polyveck for h. */
#if LC_DSA_PACK_W0
  for (k = 0; k < MLDSA_K; k++)
  __loop__(
    assigns(k,object_whole(scratch_w),object_whole(w0))
    invariant(k <= MLDSA_K)
    decreases(MLDSA_K-k)
  )
  {
#if LC_DSA_DIRECT_DENSE_ROWS
    mld_poly *t=(mld_poly *)(void *)(w0+k*LC_W0_FLAG_STRIDE);
#endif
#if LC_DSA_STREAM_RECOMPUTE
    uint8_t *flags=w0+sizeof(mld_poly)+32*k;
    lc_stream_y_row(t,mat,y,scratch_w,k);mld_poly_decompose(scratch_w,t);
    mld_memset(flags,0,32);
    for(unsigned j=0;j<MLDSA_N;j++)flags[j/8]|=(uint8_t)((uint32_t)(scratch_w->coeffs[j]!=0)<<(j%8));
#elif !LC_DSA_DIRECT_DENSE_ROWS
    lc_unpack_w0_row(t,(const uint8_t*)w0+k*LC_W0_FLAG_STRIDE);
#endif
#if LC_DSA_EARLY_LOW_ROWS && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44)
    if(k>=LC_DSA_EARLY_LOW_ROWS) {
#endif
    /* @[FIPS204, Algorithm 7, line 19] cs2[k] <- invNTT(c_hat o s2_hat)[k],
     * then subtract from w0[k] to form (w0 - cs2)[k]. */
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_SPARSE_NEON
#if LC_DSA_CHECKED_SPARSE
    lc_sparse8_product_packed_i16_eta(scratch_w->coeffs,s2hat->packed+k*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,lc_canonical_secret?(MLDSA_ETA==2?60:31):(MLDSA_ETA==2?25:11),MLDSA_ETA);
#else
    lc_sparse8_product_packed_i16(scratch_w->coeffs,s2hat->packed+k*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,(MLDSA_ETA==2?25:11));
#endif
#else
#if LC_DSA_SCALAR_SWAR32_ACTIVE
    if(lc_canonical_secret) {
      lc_scalar_swar32(scratch_w->coeffs,s2hat->packed+k*MLDSA_POLYETA_PACKEDBYTES,lc_swar_shifts,MLDSA_TAU);
    } else
#endif
    {
    mld_sk_s2hat_get_poly(scratch_w, s2hat, k);
    mld_poly_pointwise_montgomery(scratch_w, cp);
    mld_poly_invntt_tomont(scratch_w);
    }
#endif
#else
#if LC_DSA_SPARSE_PRODUCT
    lc_sparse8_product_i16(scratch_w->coeffs,s2hat->packed+k*MLDSA_POLYETA_PACKEDBYTES,sparse_indices,MLDSA_TAU,lc_canonical_secret ? (MLDSA_ETA==2?60:31) : (MLDSA_ETA==2?25:11));
#else
#if LC_DSA_SCALAR_SWAR32_ACTIVE
    if(lc_canonical_secret) {
      lc_scalar_swar32(scratch_w->coeffs,s2hat->packed+k*MLDSA_POLYETA_PACKEDBYTES,lc_swar_shifts,MLDSA_TAU);
    } else
#endif
    {
    mld_sk_s2hat_get_poly(scratch_w, s2hat, k);
    mld_poly_pointwise_montgomery(scratch_w, cp);
    mld_poly_invntt_tomont(scratch_w);
    }
#endif
#endif

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && LC_DSA_SPARSE_NEON
    w0_invalid = lc_sparse8_consume(t->coeffs,t->coeffs,scratch_w->coeffs,
                                    MLDSA_GAMMA2-MLDSA_BETA,1);
#elif LC_DSA_SPARSE_PRODUCT && (!defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE)
    w0_invalid=lc_sparse16_consume(t->coeffs,t->coeffs,
        (const uint8_t *)(const void *)scratch_w,MLDSA_GAMMA2-MLDSA_BETA,1);
#else
    mld_poly_sub(t, scratch_w);
    mld_poly_reduce(t);

    /* Low-bits norm check (see block comment above): the line-23 check on
     * r0 = LowBits(w - cs2) holds via ||w0 - cs2||_inf < GAMMA2 - BETA. */
    w0_invalid = mld_poly_chknorm(t, MLDSA_GAMMA2 - MLDSA_BETA);
#endif
    /* Constant time: w0_invalid may be leaked - see comment for z_invalid. */
    MLD_CT_TESTING_DECLASSIFY(&w0_invalid, sizeof(uint32_t));
    if (w0_invalid)
    {
      ret = MLD_ERR_FAIL; /* reject */
      goto cleanup;
    }

#if LC_DSA_EARLY_LOW_ROWS && (MLDSA_K > 4 || LC_DSA_EARLY_LOW_44)
    }
#endif

    /* @[FIPS204, Algorithm 7, line 25] ct0[k] <- invNTT(c_hat o t0_hat)[k]. */
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_SPARSE_T0_NEON
    /* The public challenge is retained in sparse_indices. Reuse its dense
     * storage for the signed16 cyclic extension of this secret t0 row. */
    mld_polyt0_unpack(cp,t0hat->packed+k*MLDSA_POLYT0_PACKEDBYTES);
    lc_sparse_t0_product(scratch_w->coeffs,cp->coeffs,sparse_indices,MLDSA_TAU);
#else
    mld_sk_t0hat_get_poly(scratch_w, t0hat, k);
    mld_poly_pointwise_montgomery(scratch_w, cp);
    mld_poly_invntt_tomont(scratch_w);
    mld_poly_reduce(scratch_w);
#endif
#else
    mld_sk_t0hat_get_poly(scratch_w, t0hat, k);
#if LC_DSA_SPARSE_PRODUCT && !LC_DSA_SPARSE_SEPARATE_CP
    lc_signed24_product(scratch_w,mat->sign_challenge.big,scratch_w,0);
#else
    mld_poly_pointwise_montgomery(scratch_w, cp);
#endif
    mld_poly_invntt_tomont(scratch_w);
    mld_poly_reduce(scratch_w);
#endif

    /* @[FIPS204, Algorithm 7, line 28] reject when ||ct0||_inf >= GAMMA2 (the
     * second part, the OMEGA weight bound, is enforced by mld_pack_sig_h). */
#if LC_DSA_PROVEN_CT0_BOUND && (MLDSA_TAU * (1 << (MLDSA_D-1)) < MLDSA_GAMMA2)
    /* Every t0 decoding is in [-4095,4096], and c has exactly TAU
     * signed unit coefficients. Its integer negacyclic product is bounded
     * by TAU*4096, strictly below GAMMA2 for 65 and 87. The reduction
     * above is retained; this predicate is therefore identically false.
     * ML-DSA-44 does not satisfy the inequality and keeps its full check.
     * This parameter fact was discussed on NIST pqc-forum in 2024. */
    h_invalid = 0;
#else
    h_invalid = mld_poly_chknorm(scratch_w, MLDSA_GAMMA2);
#endif
    /* Constant time: h_invalid may be leaked - see comment for z_invalid. */
    MLD_CT_TESTING_DECLASSIFY(&h_invalid, sizeof(uint32_t));
    if (h_invalid)
    {
      ret = MLD_ERR_FAIL; /* reject */
      goto cleanup;
    }

#if LC_DSA_FUSED_HINT_NEON && LC_DSA_EARLY_HINT_FLAGS && !LC_DSA_STREAM_RECOMPUTE
    uint8_t *flags=(uint8_t*)w0+k*LC_W0_FLAG_STRIDE+LC_W0_ROW_BYTES;
    lc_hint_fused_neon(flags,t->coeffs,scratch_w->coeffs,MLDSA_GAMMA2);
#elif LC_DSA_FUSED_HINT_BITMAP
    /* Both norm checks have accepted. Form MakeHint directly in the bitmap;
     * the dense low row is dead after this point. */
    uint8_t *flags=(uint8_t*)w0+k*LC_W0_FLAG_STRIDE+LC_W0_ROW_BYTES;
    lc_hint_fused_avx2(flags,t->coeffs,scratch_w->coeffs,MLDSA_GAMMA2);
#else
    /* Add ct0[k] to (w0 - cs2)[k], leaving (w0 - cs2 + ct0)[k] in w0[k] -- the
     * MakeHint input prepared for mld_pack_sig_h (see block comment above). */
    mld_poly_add(t, scratch_w);
#if LC_DSA_STREAM_RECOMPUTE || LC_DSA_EARLY_HINT_FLAGS
#if LC_DSA_EARLY_HINT_FLAGS
    uint8_t *flags=(uint8_t*)w0+k*LC_W0_FLAG_STRIDE+LC_W0_ROW_BYTES;
#endif
    for(unsigned j=0;j<MLDSA_N;j++) {
      unsigned bit=lc_make_hint_secret(t->coeffs[j],(flags[j/8]>>(j%8))&1u);
      flags[j/8]=(uint8_t)((flags[j/8]&~(1u<<(j%8)))|(bit<<(j%8)));
    }
#else
#if !LC_DSA_DIRECT_DENSE_ROWS
    lc_pack_w0_row((uint8_t*)w0+k*LC_W0_FLAG_STRIDE,t);
#endif
#endif
#endif
  }

#else
  for (k = 0; k < MLDSA_K; k++)
  __loop__(
    assigns(k,
            object_whole(scratch_w),
            object_whole(w0))
    invariant(k <= MLDSA_K)
    invariant(forall(k0, k, MLDSA_K,
      array_abs_bound(w0->vec[k0].coeffs, 0, MLDSA_N, MLDSA_GAMMA2 + 1)))
    decreases(MLDSA_K - k)
  )
  {
    /* @[FIPS204, Algorithm 7, line 19] cs2[k] <- invNTT(c_hat o s2_hat)[k],
     * then subtract from w0[k] to form (w0 - cs2)[k]. */
#if LC_DSA_SCALAR_SWAR32_ACTIVE
    if(lc_canonical_secret) {
      lc_scalar_swar32(scratch_w->coeffs,s2hat->packed+k*MLDSA_POLYETA_PACKEDBYTES,lc_swar_shifts,MLDSA_TAU);
    } else
#endif
    {
    mld_sk_s2hat_get_poly(scratch_w, s2hat, k);
    mld_poly_pointwise_montgomery(scratch_w, cp);
    mld_poly_invntt_tomont(scratch_w);
    }

    mld_poly_sub(&w0->vec[k], scratch_w);
    mld_poly_reduce(&w0->vec[k]);

    /* Low-bits norm check (see block comment above): the line-23 check on
     * r0 = LowBits(w - cs2) holds via ||w0 - cs2||_inf < GAMMA2 - BETA. */
    w0_invalid = mld_poly_chknorm(&w0->vec[k], MLDSA_GAMMA2 - MLDSA_BETA);
    /* Constant time: w0_invalid may be leaked - see comment for z_invalid. */
    MLD_CT_TESTING_DECLASSIFY(&w0_invalid, sizeof(uint32_t));
    if (w0_invalid)
    {
      ret = MLD_ERR_FAIL; /* reject */
      goto cleanup;
    }

    /* @[FIPS204, Algorithm 7, line 25] ct0[k] <- invNTT(c_hat o t0_hat)[k]. */
    mld_sk_t0hat_get_poly(scratch_w, t0hat, k);
    mld_poly_pointwise_montgomery(scratch_w, cp);
    mld_poly_invntt_tomont(scratch_w);
    mld_poly_reduce(scratch_w);

    /* @[FIPS204, Algorithm 7, line 28] reject when ||ct0||_inf >= GAMMA2 (the
     * second part, the OMEGA weight bound, is enforced by mld_pack_sig_h). */
#if LC_DSA_PROVEN_CT0_BOUND && (MLDSA_TAU * (1 << (MLDSA_D-1)) < MLDSA_GAMMA2)
    /* Every t0 decoding is in [-4095,4096], and c has exactly TAU
     * signed unit coefficients. Its integer negacyclic product is bounded
     * by TAU*4096, strictly below GAMMA2 for 65 and 87. The reduction
     * above is retained; this predicate is therefore identically false.
     * ML-DSA-44 does not satisfy the inequality and keeps its full check.
     * This parameter fact was discussed on NIST pqc-forum in 2024. */
    h_invalid = 0;
#else
    h_invalid = mld_poly_chknorm(scratch_w, MLDSA_GAMMA2);
#endif
    /* Constant time: h_invalid may be leaked - see comment for z_invalid. */
    MLD_CT_TESTING_DECLASSIFY(&h_invalid, sizeof(uint32_t));
    if (h_invalid)
    {
      ret = MLD_ERR_FAIL; /* reject */
      goto cleanup;
    }

    /* Add ct0[k] to (w0 - cs2)[k], leaving (w0 - cs2 + ct0)[k] in w0[k] -- the
     * MakeHint input prepared for mld_pack_sig_h (see block comment above). */
    mld_poly_add(&w0->vec[k], scratch_w);
  }

#endif
  /* The weight decision discloses one final rejection predicate. Hint
   * positions remain secret for every rejected attempt, including omega
   * overflow. The original variable-position encoding follows only after
   * all acceptance conditions have succeeded. */
  {
    unsigned hint_invalid=lc_check_hint_weight_before_disclosure(
        (const uint8_t*)w0,t);
    MLD_CT_TESTING_DECLASSIFY(&hint_invalid,sizeof(hint_invalid));
    if(hint_invalid) {
      ret=MLD_ERR_FAIL;
      goto cleanup;
    }
  }
  /* All norm and hint-weight conditions now hold. The following values
   * determine the signature returned by this successful attempt. */
#if LC_DSA_PACK_W0
  /* Declassify precisely the final retained values. Early-hint rows keep
   * initial LowBits(A*y) secret and expose only their final 32-byte flags.
   * Deferred-hint rows expose the updated prefix; unused tail bytes retain
   * their existing labels. */
#if LC_DSA_STREAM_RECOMPUTE
  MLD_CT_TESTING_DECLASSIFY(w0+sizeof(mld_poly),MLDSA_K*32);
#elif LC_DSA_EARLY_HINT_FLAGS
  for(unsigned k=0;k<MLDSA_K;k++)
    MLD_CT_TESTING_DECLASSIFY(w0+k*LC_W0_FLAG_STRIDE+LC_W0_ROW_BYTES,LC_W1_FLAG_BYTES);
#else
  MLD_CT_TESTING_DECLASSIFY(w0, MLDSA_K * LC_W0_FLAG_STRIDE);
#endif
#if LC_DSA_RETAIN_FULL_HIGH
  MLD_CT_TESTING_DECLASSIFY(w0_storage->high_encoded,
                          sizeof(w0_storage->high_encoded));
#endif
#else
  MLD_CT_TESTING_DECLASSIFY(w0, sizeof(*w0));
#endif

  /* @[FIPS204, Algorithm 7, line 33] sigEncode(ctilde, z mod+/- q, h) is split
   * across three calls: z was already packed by mld_compute_pack_z, this call
   * packs ctilde, and mld_pack_sig_h below packs the hint h. */
  mld_pack_sig_c(sig, challenge_bytes);

  /* @[FIPS204, Algorithm 7, line 26] h <- MakeHint(-ct0, w - cs2 + ct0),
   * computed from (w0 = w0 - cs2 + ct0, w1) as described in the block comment
   * above, and packed as the h component of the line-33 sigEncode. Only
   * the retained w1 != 0 predicate is needed by mld_make_hint.
   * Returns MLD_ERR_FAIL if h would exceed OMEGA nonzero coefficients (the
   * remaining part of the line-28 check), in which case we reject. */
#if LC_DSA_PACK_W0
#if LC_DSA_STREAM_RECOMPUTE
  ret=lc_pack_hint_flags(sig,w0+sizeof(mld_poly));
#else
  ret=lc_pack_sig_h_bitmap(sig,(const uint8_t*)w0,t);
#endif
#else
  #error "bitmap signing requires LC_DSA_PACK_W0"
#endif
  if (ret != 0)
  {
    goto cleanup;
  }

  /* Constant time: At this point it is clear that the signature is valid - it
   * can, hence, be considered public. */
  MLD_CT_TESTING_DECLASSIFY(sig, MLDSA_CRYPTO_BYTES);
  ret = 0; /* success */

cleanup:
#if LC_DSA_BORROW_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  /* The lifetime of the masking encodings ends at this attempt boundary.
   * Preserve prompt destruction even when an early norm rejects before all
   * masking rows have been consumed. Successful z encoding has replaced each
   * borrowed byte; failure destroys the complete temporary/output z slice. */
  if(ret != 0)mld_zeroize(sig+MLDSA_SIG_Z_OFFSET,MLDSA_SIG_Z_BYTES);
#endif
#if LC_DSA_PARTIAL_DENSE_ACTIVE
  MLD_FREE(lc_cached_y,mld_poly,LC_DSA_PARTIAL_DENSE_SAVED_COUNT(MLDSA_L),context);
#elif LC_DSA_CACHED_DOT_TILE && !LC_DSA_INPLACE_AY
  MLD_FREE(lc_cached_y,mld_poly,MLDSA_L,context);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
#if LC_DSA_SPARSE_T0_NEON
  if(cp!=NULL)mld_zeroize(cp,sizeof(*cp));
#endif
#if LC_DSA_Y_CACHE_COUNT > 0
#if !LC_DSA_BORROW_SIG_Y_ACTIVE
  MLD_FREE(raw_y4,uint8_t,LC_DSA_Y_CACHE_BYTES,context);
#endif
#endif
#else
#if (LC_DSA_RAW_Y4_CACHE && MLDSA_K == 4) || LC_DSA_RAW_Y_ALL_CACHE
#if LC_DSA_RAW_Y_ALL_CACHE
#if !LC_DSA_BORROW_SIG_Y_ACTIVE
  MLD_FREE(raw_y4,uint8_t,MLDSA_L*MLDSA_POLYZ_PACKEDBYTES,context);
#endif
#else
#if !LC_DSA_BORROW_SIG_Y_ACTIVE
  MLD_FREE(raw_y4,uint8_t,2304,context);
#endif
#endif
#endif
#endif
#if LC_DSA_CROSSCOL6 == 2 && MLDSA_K == 6 && (!LC_DSA_STREAM_CACHE24 || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE))
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_MIXED_HEAD65
  MLD_FREE(head_gamma,uint8_t,640,context);
#endif
#else
#endif
  MLD_FREE(cross_saved,uint8_t,1024,context);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
#endif
#if !LC_DSA_PACK_W0
  MLD_FREE(t,mld_poly,1,context);
#endif
#if !LC_DSA_ALIAS_SIGN_CP
  MLD_FREE(cp, mld_poly, 1, context);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_PAIR_COLUMN && MLDSA_K == 4 && !LC_DSA_STREAM_CACHE24
  MLD_FREE(pair_second,mld_poly,1,context);
#endif
#endif
  MLD_FREE(w0_storage,lc_sign_w0_storage,1,context);
  MLD_FREE(scratch, scratch_u, 1, context);
  LC_SMALL_FREE(y, mld_yvec, 1, context);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  LC_SMALL_FREE(challenge_bytes, uint8_t, MLDSA_CTILDEBYTES+64*LC_DSA_SPARSE_NEON, context);
#else
  LC_SMALL_FREE(challenge_bytes, uint8_t, MLDSA_CTILDEBYTES+64*LC_DSA_SPARSE_SEPARATE_CP, context);
#endif

  return ret;
}
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_signature_internal(uint8_t sig[MLDSA_CRYPTO_BYTES],
                                const uint8_t *m, size_t mlen,
                                const uint8_t *pre, size_t prelen,
                                const uint8_t rnd[MLDSA_RNDBYTES],
                                const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                                int externalmu,
                                MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t attempt;
  /* Scan all packed s1/s2 codewords once. Only the aggregate validity bit
   * chooses byte accumulation bounds; malformed internal inputs retain the
   * full encoded eta domains and original fallback chunks. */
#if LC_DSA_SCALAR_SWAR32_ACTIVE
  const unsigned lc_canonical_secret=lc_scalar_eta_encoding_valid(sk);
  MLD_CT_TESTING_DECLASSIFY(&lc_canonical_secret,sizeof(lc_canonical_secret));
#elif LC_DSA_CHECKED_SPARSE
  const unsigned lc_canonical_secret =
      (unsigned)lc_dsa_secret_encoding_valid(MLD_CONFIG_PARAMETER_SET,sk);
  MLD_CT_TESTING_DECLASSIFY(&lc_canonical_secret,sizeof(lc_canonical_secret));
#else
  const unsigned lc_canonical_secret = 0;
#endif
  const uint16_t max_signing_attempts = mld_get_max_signing_attempts();
  LC_SMALL_ALLOC(seedbuf, uint8_t,
            2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2 * MLDSA_CRHBYTES, context);
  MLD_ALLOC(mat, mld_polymat, 1, context);
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_A_CACHE_POLYS > 0 && LC_DSA_A_CACHE_SIGN_ONLY
#if LC_DSA_PUBLIC_A_SESSION
  /* Zero bytes preserve LIFO accounting; retained public bytes are disjoint. */
  const size_t matrix_owned_bytes=context->a_cache ? 0 : LC_DSA_A_CACHE_COUNT*MLDSA_N*(LC_DSA_A_CACHE_BITS/8);
  MLD_ALLOC(matrix_cache,uint8_t,matrix_owned_bytes,context);
#else
  MLD_ALLOC(matrix_cache, uint8_t, LC_DSA_A_CACHE_COUNT*MLDSA_N*(LC_DSA_A_CACHE_BITS/8), context);
#endif
#endif
#if LC_DSA_MASK_PIPELINE && MLDSA_K > 4
  MLD_ALLOC(mask_future,uint8_t,3*MLDSA_POLYZ_PACKEDBYTES,context);
#endif
  LC_SMALL_ALLOC(s1hat, mld_sk_s1hat, 1, context);
  LC_SMALL_ALLOC(t0hat, mld_sk_t0hat, 1, context);
  LC_SMALL_ALLOC(s2hat, mld_sk_s2hat, 1, context);
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_S1_CACHE_POLYS > 0
  MLD_ALLOC(s1_prefix,mld_poly,LC_DSA_S1_CACHE_POLYS,context);
#endif

  if (
#if LC_DSA_MASK_PIPELINE && MLDSA_K > 4
      mask_future == NULL ||
#endif
      seedbuf == NULL || mat == NULL || s1hat == NULL || t0hat == NULL ||
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_A_CACHE_POLYS > 0 && LC_DSA_A_CACHE_SIGN_ONLY
      matrix_cache == NULL ||
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_S1_CACHE_POLYS > 0
      s1_prefix == NULL ||
#endif
      s2hat == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* If a resume hook is configured via MLD_CONFIG_SIGN_HOOK_RESUME, it provides
   * the attempt to resume from after an earlier pause. Otherwise, we start at
   * 0. Clamp to max_signing_attempts. */
  attempt = mld_sign_resume(context);
  if (attempt > max_signing_attempts)
  {
    attempt = max_signing_attempts;
  }

  rho = seedbuf;
  tr = rho + MLDSA_SEEDBYTES;
  key = tr + MLDSA_TRBYTES;
  mu = key + MLDSA_SEEDBYTES;
  rhoprime = mu + MLDSA_CRHBYTES;
  /* @[FIPS204, Algorithm 7, line 1] (rho, K, tr, s1, s2, t0) <- skDecode(sk)
   * and @[FIPS204, Algorithm 7, lines 2-4] s1_hat/s2_hat/t0_hat <- NTT(...):
   * mld_unpack_sk returns s1hat, s2hat, t0hat already in NTT domain. The spec's
   * private random seed K is held in the local variable key. */
  mld_unpack_sk(rho, tr, key, t0hat, s1hat, s2hat, sk);
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_S1_CACHE_POLYS > 0
  /* Fill while prefix is NULL, so the existing unpack/NTT path is the
   * representation oracle. Publish only after all fixed public indices
   * have been initialized. No secret-dependent cache replacement occurs. */
  for (unsigned i=0;i<LC_DSA_S1_CACHE_POLYS;i++)
    mld_sk_s1hat_get_poly(&s1_prefix[i],s1hat,i);
  s1hat->prefix=s1_prefix;
#endif

  if (!externalmu)
  {
    /* @[FIPS204, Algorithm 7, line 6] mu <- H(BytesToBits(tr) || M', 64). */
    mld_H(mu, MLDSA_CRHBYTES, tr, MLDSA_TRBYTES, pre, prelen, m, mlen);
  }
  else
  {
    /* mu has been provided directly (external-mu variant; line 6 done by the
     * caller in a separate cryptographic module). */
    mld_memcpy(mu, m, MLDSA_CRHBYTES);
  }

  /* @[FIPS204, Algorithm 7, line 7] rhoprime <- H(K || rnd || mu, 64). */
  mld_H(rhoprime, MLDSA_CRHBYTES, key, MLDSA_SEEDBYTES, rnd, MLDSA_RNDBYTES, mu,
        MLDSA_CRHBYTES);

  /* Constant time: rho is part of the public key and, hence, public. */
  MLD_CT_TESTING_DECLASSIFY(rho, MLDSA_SEEDBYTES);
  /* @[FIPS204, Algorithm 7, line 5] A_hat <- ExpandA(rho). */
  mld_polyvec_matrix_expand(mat, rho);
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_A_CACHE_POLYS > 0 && LC_DSA_A_CACHE_SIGN_ONLY
#if LC_DSA_PUBLIC_A_SESSION
  mat->cache=(uint8_t (*)[MLDSA_N*(LC_DSA_A_CACHE_BITS/8)])(context->a_cache ? context->a_cache : matrix_cache);
  mat->cache_ready=context->a_cache!=NULL;
#else
  mat->cache=(uint8_t (*)[MLDSA_N*(LC_DSA_A_CACHE_BITS/8)])matrix_cache;
#endif
#if LC_DSA_MASK_PIPELINE && MLDSA_K > 4
  mat->mask_future=mask_future;mat->mask_count=0;mat->mask_nonce=0;
#endif
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_A_CACHE_POLYS > 0 && LC_DSA_A_CACHE_BATCH4
  {
    /* This arena phase finishes before attempt scratch is allocated.
     * Four-lane SHAKE stack usage is measured separately from arena bytes. */
    _Static_assert(3*sizeof(mld_poly)<=sizeof(lc_sign_w0_storage)+sizeof(mld_poly),
                   "prefill arena must fit below the attempt scratch peak");
    MLD_ALLOC(tile, mld_poly, 3, context);
    if(tile==NULL) {ret=MLD_ERR_OUT_OF_MEMORY;goto cleanup;}
    mld_polymat_cache_prefill(mat,tile);
    MLD_FREE(tile,mld_poly,3,context);
  }
#endif

  /* @[FIPS204, Algorithm 7, lines 8-10 and 31-32] the rejection-sampling loop,
   * tracked by attempt (kappa = attempt*MLDSA_L). Each iteration's body (lines
   * 11-30) plus, on success, the line-33 sigEncode are performed by
   * mld_attempt_signature_generation. */

  /* Reference: the reference loops unboundedly; we instead iterate over the
   * bounded range [0, max_signing_attempts) for predictable termination.
   * A success or fatal error exits via goto cleanup; running to completion
   * means every attempt was rejected; with a FIPS compliant choice of
   * MLD_CONFIG_MAX_SIGNING_ATTEMPTS, this should never happen. */
  for (; attempt < max_signing_attempts; attempt++)
  __loop__(
    MLD_IF_NOT_REDUCE_RAM(
      assigns(attempt, ret, memory_slice(sig, MLDSA_CRYPTO_BYTES))
    )
    MLD_IF_REDUCE_RAM(
      assigns(attempt, ret, memory_slice(sig, MLDSA_CRYPTO_BYTES),
              memory_slice(mat, sizeof(mld_polymat)))
    )
    invariant(attempt <= max_signing_attempts)

    /* t0, s1, s2, and mat are initialized above and are NOT changed by this */
    /* loop. We can therefore re-assert their bounds here as part of the     */
    /* loop invariant. This makes proof noticeably faster with CBMC          */
    MLD_IF_NOT_REDUCE_RAM(
      invariant(forall(k1, 0, MLDSA_K, forall(l1, 0, MLDSA_L,
                array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
      invariant(forall(k2, 0, MLDSA_K, array_abs_bound(t0hat->vec.vec[k2].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
      invariant(forall(k3, 0, MLDSA_L, array_abs_bound(s1hat->vec.vec[k3].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
      invariant(forall(k4, 0, MLDSA_K, array_abs_bound(s2hat->vec.vec[k4].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
    )
    decreases(max_signing_attempts - attempt)
  )
  {
    /* Safety: attempt < max_signing_attempts <= MLD_MAX_KAPPA / MLDSA_L, so
     * kappa <= MLD_MAX_KAPPA and the cast is safe. */
    const uint16_t kappa = (uint16_t)(attempt * MLDSA_L);

    /* Query configurable signing hook whether signing should be paused.
     * This is skipped by default and only used if the user sets the
     * configuration option MLD_CONFIG_SIGN_HOOK_ATTEMPT. */
    if (mld_sign_attempt(attempt, context) != 0)
    {
      ret = MLD_ERR_SIGNING_PAUSED;
      goto cleanup;
    }

    ret = mld_attempt_signature_generation(sig, mu, rhoprime, kappa, mat, s1hat,
                                           s2hat, t0hat, lc_canonical_secret, context);

    /* Decide whether to keep trying based on the return value:
     *  - ret == 0: a valid signature was produced; we are done.
     *  - ret == MLD_ERR_FAIL: this candidate was rejected by one of the norm
     *    or hint checks. We continue the loop and try again with the next
     *    nonce.
     *  - any other value (e.g. MLD_ERR_OUT_OF_MEMORY): an unrecoverable error
     *    occurred, so we propagate it to the caller. */
    if (ret == 0)
    {
      /* Signing succeeded: record the attempt that succeeded. No-op in the
       * default build. */
      mld_sign_finish(attempt, context);
      goto cleanup;
    }
    if (ret != MLD_ERR_FAIL)
    {
      goto cleanup;
    }
  }

  /* Loop ran to completion: all attempts rejected, budget exhausted.
   * This should never happen with a FIPS compliant choice of
   * MLD_CONFIG_MAX_SIGNING_ATTEMPTS. */
  ret = MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED;

cleanup:

  if (ret != 0)
  {
    /* To be on the safe-side, we zeroize the signature buffer. */
    mld_zeroize(sig, MLDSA_CRYPTO_BYTES);
  }

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_S1_CACHE_POLYS > 0
  MLD_FREE(s1_prefix,mld_poly,LC_DSA_S1_CACHE_POLYS,context);
#endif
  LC_SMALL_FREE(s2hat, mld_sk_s2hat, 1, context);
  LC_SMALL_FREE(t0hat, mld_sk_t0hat, 1, context);
  LC_SMALL_FREE(s1hat, mld_sk_s1hat, 1, context);
#if LC_DSA_MASK_PIPELINE && MLDSA_K > 4
  MLD_FREE(mask_future,uint8_t,3*MLDSA_POLYZ_PACKEDBYTES,context);
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_A_CACHE_POLYS > 0 && LC_DSA_A_CACHE_SIGN_ONLY
#if LC_DSA_PUBLIC_A_SESSION
  MLD_FREE(matrix_cache,uint8_t,matrix_owned_bytes,context);
#else
  MLD_FREE(matrix_cache,uint8_t,LC_DSA_A_CACHE_COUNT*MLDSA_N*(LC_DSA_A_CACHE_BITS/8),context);
#endif
#endif
  MLD_FREE(mat, mld_polymat, 1, context);
  LC_SMALL_FREE(seedbuf, uint8_t,
           2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES + 2 * MLDSA_CRHBYTES, context);
  return ret;
}

#if !defined(MLD_CONFIG_CORE_API_ONLY)
#if !defined(MLD_CONFIG_NO_RANDOMIZED_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_signature(uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *m,
                       size_t mlen, const uint8_t *ctx, size_t ctxlen,
                       const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                       MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  size_t pre_len;
  int ret;
  MLD_ALLOC(pre, uint8_t, MLD_DOMAIN_SEPARATION_MAX_BYTES, context);
  MLD_ALLOC(rnd, uint8_t, MLDSA_RNDBYTES, context);

  if (pre == NULL || rnd == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Prepare domain separation prefix for pure ML-DSA */
  pre_len = mld_prepare_domain_separation_prefix(pre, NULL, 0, ctx, ctxlen,
                                                 MLD_PREHASH_NONE);
  if (pre_len == 0)
  {
    ret = MLD_ERR_INVALID_ARG;
    goto cleanup;
  }

  /* Randomized variant of ML-DSA. If you need the deterministic variant,
   * call mld_sign_signature_internal directly with all-zero rnd. */
  if (mld_randombytes(rnd, MLDSA_RNDBYTES) != 0)
  {
    ret = MLD_ERR_RNG_FAIL;
    goto cleanup;
  }
  MLD_CT_TESTING_SECRET(rnd, MLDSA_RNDBYTES);

  ret = mld_sign_signature_internal(sig, m, mlen, pre, pre_len, rnd, sk, 0,
                                    context);

cleanup:
  if (ret != 0)
  {
    /* To be on the safe-side, make sure sig has a well-defined value, even in
     * the case of error.
     *
     * If we come from mld_sign_signature_internal, this is redundant, but the
     * error case should not be the norm, and the added cost of the zeroization
     * insignificant. */
    mld_zeroize(sig, MLDSA_CRYPTO_BYTES);
  }

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(rnd, uint8_t, MLDSA_RNDBYTES, context);
  MLD_FREE(pre, uint8_t, MLD_DOMAIN_SEPARATION_MAX_BYTES, context);

  return ret;
}
#endif /* !MLD_CONFIG_NO_RANDOMIZED_API */

#if !defined(MLD_CONFIG_NO_RANDOMIZED_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_signature_extmu(uint8_t sig[MLDSA_CRYPTO_BYTES],
                             const uint8_t mu[MLDSA_CRHBYTES],
                             const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret;
  MLD_ALLOC(rnd, uint8_t, MLDSA_RNDBYTES, context);

  if (rnd == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Randomized variant of ML-DSA. If you need the deterministic variant,
   * call mld_sign_signature_internal directly with all-zero rnd. */
  if (mld_randombytes(rnd, MLDSA_RNDBYTES) != 0)
  {
    ret = MLD_ERR_RNG_FAIL;
    goto cleanup;
  }
  MLD_CT_TESTING_SECRET(rnd, MLDSA_RNDBYTES);

  ret = mld_sign_signature_internal(sig, mu, MLDSA_CRHBYTES, NULL, 0, rnd, sk,
                                    1, context);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(rnd, uint8_t, MLDSA_RNDBYTES, context);

  return ret;
}
#endif /* !MLD_CONFIG_NO_RANDOMIZED_API */
#endif /* !MLD_CONFIG_CORE_API_ONLY */
#endif /* !MLD_CONFIG_NO_SIGN_API */

#if !defined(MLD_CONFIG_NO_VERIFY_API)
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
/* Four independent absorption lengths preserve the exact formatted message
 * without constructing a257-byte prefix in a live caller frame. */
#define lc_verify_segments MLD_NAMESPACE_KL(verify_segments) MLD_CONTEXT_PARAMETERS_9
#define lc_verify_mu_segments MLD_ADD_PARAM_SET(lc_verify_mu_segments)
static void lc_verify_mu_segments(uint8_t out[64],const uint8_t tr[64],
 const uint8_t *pre,size_t prelen,const uint8_t *pre1,size_t prelen1,
 const uint8_t *message,size_t message_length) {
 mld_shake256ctx state;
 mld_shake256_init(&state);
 mld_shake256_absorb(&state,tr,64);
 if(prelen)mld_shake256_absorb(&state,pre,prelen);
 if(prelen1)mld_shake256_absorb(&state,pre1,prelen1);
 if(message_length)mld_shake256_absorb(&state,message,message_length);
 mld_shake256_finalize(&state);mld_shake256_squeeze(out,64,&state);
 mld_shake256_release(&state);mld_zeroize(&state,sizeof(state));
}
#endif
MLD_MUST_CHECK_RETURN_VALUE
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
MLD_EXTERNAL_API
int mld_sign_verify_internal(const uint8_t sig[MLDSA_CRYPTO_BYTES],
#else
static int lc_verify_segments(const uint8_t sig[MLDSA_CRYPTO_BYTES],
#endif
                             const uint8_t *m, size_t mlen, const uint8_t *pre,
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
                             size_t prelen,
#else
                             size_t prelen,const uint8_t *pre1,size_t prelen1,
#endif
                             const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                             int externalmu,
                             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret, cmp;
  unsigned int i;
  int hash_live = 0;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
  lc_verify_hash3_state verify_hash={0};
  unsigned encoded_rows=0;
#endif
#endif

  /* Retain only the incremental oracle state, not every encoded w1 row.
   * Its arena lifetime is independent of the stack used by SHAKE helpers. */
  LC_SMALL_ALLOC(hash_state, mld_shake256ctx, 1, context);
  LC_SMALL_ALLOC(mu, uint8_t, MLDSA_CRHBYTES, context);
  /* c is already a read-only prefix of the caller's signature. */
  const uint8_t *c = sig;
  /* mu is dead after its absorb, before c2 is squeezed. Its 64 bytes cover
   * every ctilde length. This is a borrow, not a separate allocation. */
  uint8_t *c2 = mu;
#if LC_DSA_STREAM_RECOMPUTE
  MLD_ALLOC(z,uint8_t,1,context);
#elif LC_DSA_PACKED_ACCUM
  MLD_ALLOC(z,lc_packed_vecl,1,context);
#else
  MLD_ALLOC(z, mld_polyvecl, 1, context);
#endif
#if LC_DSA_PACK_VERIFY_CP
  MLD_ALLOC(cp,uint8_t,LC_PACKED_ROW_BYTES,context);
#else
  MLD_ALLOC(cp, mld_poly, 1, context);
#endif
  MLD_ALLOC(mat, mld_polymat, 1, context);
  MLD_ALLOC(w1, mld_poly, 1, context);
#if LC_DSA_NATIVE_MATRIX_ROWS
  MLD_ALLOC(dense_a,mld_poly,LC_DSA_VERIFY_MATRIX_POLYS,context);
#if LC_DSA_MATRIX4_ARENA
  MLD_ALLOC(matrix_workspace,lc_matrix4_workspace,1,context);
#endif
#if LC_DSA_VERIFY_HASH_BATCH_ARM
  MLD_ALLOC(dense_spare,mld_poly,4,context);
#endif
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#else
#if LC_DSA_FLAT_VERIFY && (MLDSA_K > 4 || LC_DSA_VERIFY_HASH_BATCH) && !LC_DSA_NATIVE_MATRIX_ROWS
  MLD_ALLOC(flat_extra,mld_poly,1,context);
  mld_poly *flat_current=w1,*flat_carry=flat_extra;
  unsigned flat_cursor=0;
#endif
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
  uint8_t *verify_rows=NULL;
  if(!externalmu){MLD_ALLOC(rows_owner,uint8_t,2*MLDSA_POLYW1_PACKEDBYTES,context);verify_rows=rows_owner;}
#endif
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  MLD_ALLOC(row_tile,mld_poly,3,context);
#endif
#if LC_DSA_DIRECT_MATRIX_ACTIVE
  MLD_ALLOC(tmp,mld_poly,1,context);
#elif LC_DSA_ALIAS_VERIFY_TMP
  /* Every matrix row finishes before tmp is used; the next row fully
   * regenerates cur. Challenge cp remains separate and is transformed once. */
  mld_poly *tmp = mat == NULL ? NULL : &mat->cur;
#else
  MLD_ALLOC(tmp, mld_poly, 1, context);
#endif

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#else
#if LC_DSA_FLAT_VERIFY && (MLDSA_K > 4 || LC_DSA_VERIFY_HASH_BATCH) && !LC_DSA_NATIVE_MATRIX_ROWS
  if(flat_extra==NULL) {ret=MLD_ERR_OUT_OF_MEMORY;goto cleanup;}
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
  if(!externalmu && verify_rows==NULL){ret=MLD_ERR_OUT_OF_MEMORY;goto cleanup;}
#endif
#endif
#endif
  if (
#if LC_DSA_NATIVE_MATRIX_ROWS
      dense_a==NULL ||
#if LC_DSA_MATRIX4_ARENA
     matrix_workspace==NULL ||
#endif
#if LC_DSA_VERIFY_HASH_BATCH_ARM
      dense_spare==NULL ||
#endif
#endif
      hash_state == NULL || mu == NULL || c == NULL || c2 == NULL || z == NULL ||
      cp == NULL || mat == NULL || w1 == NULL || tmp == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  if(row_tile==NULL) {ret=MLD_ERR_OUT_OF_MEMORY;goto cleanup;}
#endif
#if LC_DSA_PACKED_ACCUM
  for(unsigned j=0;j<MLDSA_L;j++) {
    mld_polyz_unpack(tmp,sig+MLDSA_SIG_Z_OFFSET+j*MLDSA_POLYZ_PACKEDBYTES);
    if(mld_poly_chknorm(tmp,MLDSA_GAMMA1-MLDSA_BETA)) {ret=MLD_ERR_INVALID_SIGNATURE;goto cleanup;}
#if !LC_DSA_STREAM_RECOMPUTE
    mld_poly_ntt(tmp);lc_pack_matrix_ntt24((*z)[j],tmp);
#endif
  }
#else
  mld_polyvecl_unpack_z(z, sig + MLDSA_SIG_Z_OFFSET);

  /* mld_polyvecl_chknorm signals failure through a single non-zero error code
   * that's not yet aligned with MLD_ERR_XXX. A norm-check failure here means
   * the signature is invalid, so map it to MLD_ERR_INVALID_SIGNATURE. */
  if (mld_polyvecl_chknorm(z, MLDSA_GAMMA1 - MLDSA_BETA))
  {
    ret = MLD_ERR_INVALID_SIGNATURE;
    goto cleanup;
  }

#endif
  if (!externalmu)
  {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_VERIFY_HASH_BATCH_ARM
    lc_expand_matrix_hash_batch(dense_a,dense_spare,mat,hash_state,mu,pk,pre,prelen,NULL,0,m,mlen LC_MATRIX4_PASS);
#else
    /* Compute CRH(H(rho, t1), pre, msg) */
    MLD_ALIGN uint8_t hpk[MLDSA_CRHBYTES];
    mld_H(hpk, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES, NULL, 0, NULL,
          0);
    mld_H(mu, MLDSA_CRHBYTES, hpk, MLDSA_TRBYTES, pre, prelen, m, mlen);

    /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
    mld_zeroize(hpk, sizeof(hpk));
#endif
#else
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
    lc_vh_start(&verify_hash,hash_state,mu,pk,pre,prelen,pre1,prelen1,m,mlen);
#else
    /* Compute CRH(H(rho, t1), pre, msg) */
    MLD_ALIGN uint8_t hpk[MLDSA_CRHBYTES];
    mld_H(hpk, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES, NULL, 0, NULL,
          0);
    lc_verify_mu_segments(mu,hpk,pre,prelen,pre1,prelen1,m,mlen);

    /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
    mld_zeroize(hpk, sizeof(hpk));
#endif
#endif
  }
  else
  {
    /* mu has been provided directly */
    mld_memcpy(mu, m, MLDSA_CRHBYTES);
  }

  /* H(mu || row_0 || ... || row_(K-1)) uses the same byte string as the
   * previous contiguous buffer. mu is consumed before any optional reuse. */
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
  if(externalmu)
#endif
  {
#endif
  mld_shake256_init(hash_state);
  hash_live = 1;
  mld_shake256_absorb(hash_state, mu, MLDSA_CRHBYTES);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
  }
#endif

  /* Matrix-vector multiplication and per-row reconstruction of w1. */
#if !LC_DSA_PACKED_ACCUM
  mld_polyvecl_ntt(z);
#endif
  mld_polyvec_matrix_expand(mat, pk);
#if LC_DSA_NATIVE_MATRIX_ROWS && LC_DSA_VERIFY_HASH_BATCH_ARM
  if(externalmu)lc_expand_native_matrix(dense_a,dense_spare,pk LC_MATRIX4_PASS);
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  mat->row_tile=row_tile;
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_VERIFY_T1_CENTERED_NEON
  mld_poly_challenge(w1,c);
  lc_verify_t1_neon_prepare(cp,w1->coeffs,MLDSA_TAU);
#elif LC_DSA_PACK_VERIFY_CP
  /* w1 is empty until the first row product. Its dense slot is borrowed
   * to transform c once, then reduced and retained in 768 bytes. */
  mld_poly_challenge(w1,c);mld_poly_ntt(w1);lc_pack_ntt24(cp,w1);
#else
  mld_poly_challenge(cp, c);
  mld_poly_ntt(cp);
#endif
#else
#if LC_DSA_PACK_VERIFY_CP
  /* w1 is empty until the first row product. Its dense slot is borrowed
   * to transform c once, then reduced and retained in 768 bytes. */
#if LC_DSA_XOF_OWNER
  lc_dsa_challenge_scratch(w1,c,MLDSA_CTILDEBYTES,MLDSA_TAU,tmp);
#else
  mld_poly_challenge(w1,c);
#endif
  mld_poly_ntt(w1);lc_pack_ntt24(cp,w1);
#else
  mld_poly_challenge(cp, c);
  mld_poly_ntt(cp);
#endif
#endif

  for (i = 0; i < MLDSA_K; i++)
  __loop__(
    assigns(MLD_IF_REDUCE_RAM(memory_slice(mat, sizeof(mld_polymat)),)
            i, ret,
            memory_slice(w1, sizeof(mld_poly)),
            memory_slice(tmp, sizeof(mld_poly)),
            memory_slice(hash_state, sizeof(mld_shake256ctx))
    )
    invariant(i <= MLDSA_K)
    decreases(MLDSA_K - i)
  )
  {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#else
#if LC_DSA_FLAT_VERIFY && (MLDSA_K > 4 || LC_DSA_VERIFY_HASH_BATCH) && !LC_DSA_NATIVE_MATRIX_ROWS
    /* The two owning allocations remain fixed; only the public row roles swap. */
    mld_poly *w1=flat_current;
#endif
#endif
    /* w1 = (A * z)_i in NTT domain */
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#if LC_DSA_STREAM_RECOMPUTE
    lc_stream_z_row(w1,mat,sig,tmp,i);
#elif LC_DSA_PACKED_ACCUM
    lc_packed_matrix_row(w1,mat,z,i);
#else
    mld_polyvec_matrix_pointwise_montgomery_row(w1, mat, z, i);
#endif
#else
#if LC_DSA_NATIVE_MATRIX_ROWS
    lc_native_matrix_row(w1,dense_a,z,i,pk,LC_DSA_VERIFY_HASH_BATCH_ARM LC_MATRIX4_PASS);
#elif LC_DSA_FLAT_VERIFY && (MLDSA_K > 4 || LC_DSA_VERIFY_HASH_BATCH)
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
    if(!hash_live) {
      lc_vh_row(w1,flat_carry,mat,z,i,&flat_cursor,&verify_hash,hash_state);
      if(verify_hash.done || i==2) {
        if(!verify_hash.done)lc_vh_finish(&verify_hash,hash_state,mat);
        mld_shake256_init(hash_state);hash_live=1;
        mld_shake256_absorb(hash_state,mu,64);
        if(encoded_rows)mld_shake256_absorb(hash_state,verify_rows,encoded_rows*MLDSA_POLYW1_PACKEDBYTES);
        encoded_rows=0;
      }
    } else
#endif
    lc_flat_verify_row(w1,flat_carry,mat,z,i,&flat_cursor);
#elif LC_DSA_STREAM_RECOMPUTE
    lc_stream_z_row(w1,mat,sig,tmp,i);
#elif LC_DSA_PACKED_ACCUM
    lc_packed_matrix_row(w1,mat,z,i);
#else
    mld_polyvec_matrix_pointwise_montgomery_row(w1, mat, z, i);
#endif
#endif

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_VERIFY_T1_CENTERED_NEON
    /* Finish the matrix row before borrowing cur for the centered t1 row. */
    mld_poly_reduce(w1);
    mld_poly_invntt_tomont(w1);
    mld_unpack_pk_t1(tmp,pk,i);
    lc_verify_t1_neon_subtract(w1->coeffs,tmp->coeffs,cp,MLDSA_TAU);
#else
    /* tmp = c * t1_i * 2^d in NTT domain */
    mld_unpack_pk_t1(tmp, pk, i);
    mld_poly_shiftl(tmp);
    mld_poly_ntt(tmp);
#if LC_DSA_PACK_VERIFY_CP
    lc_signed24_product(tmp,cp,tmp,0);
#else
    mld_poly_pointwise_montgomery(tmp, cp);
#endif

    /* w1 = invNTT(w1 - c * t1_i * 2^d) */
    mld_poly_sub(w1, tmp);
    mld_poly_reduce(w1);
    mld_poly_invntt_tomont(w1);
    mld_poly_caddq(w1);
#endif
#else
    /* tmp = c * t1_i * 2^d in NTT domain */
#if defined(_WIN32) && defined(__AVX2__)
    mld_polyt1_unpack_shift13(tmp, pk + MLDSA_PK_T1_OFFSET + i * MLDSA_POLYT1_PACKEDBYTES);
#else
    mld_unpack_pk_t1(tmp, pk, i);
    mld_poly_shiftl(tmp);
#endif
    mld_poly_ntt(tmp);
#if LC_DSA_PACK_VERIFY_CP
    lc_signed24_product(tmp,cp,tmp,0);
#else
    mld_poly_pointwise_montgomery(tmp, cp);
#endif

    /* w1 = invNTT(w1 - c * t1_i * 2^d) */
    mld_poly_sub(w1, tmp);
    mld_poly_reduce(w1);
    mld_poly_invntt_tomont(w1);
    mld_poly_caddq(w1);
#endif

#if LC_DSA_SPARSE_VERIFY_ENCODE
    /* Public verification HighBits are encoded directly; only nonzero public
     * hints reconstruct LowBits. Both buffers keep their existing owners. */
    if(lc_verify_encode_hints_scalar((uint8_t*)tmp,w1->coeffs,
          sig+MLDSA_SIG_H_OFFSET,i,MLDSA_K,MLDSA_OMEGA,MLDSA_GAMMA2)!=0) {
      ret=MLD_ERR_INVALID_SIGNATURE;goto cleanup;
    }
#else
    /* tmp = h_i (decoded and validated from signature). A non-zero return
     * means the hint encoding is malformed, i.e. the signature is invalid. */
    if (mld_sig_unpack_hints(tmp, sig, i) != 0)
    {
      ret = MLD_ERR_INVALID_SIGNATURE;
      goto cleanup;
    }

    /* The decoded hint in tmp has its last use in use_hint. The next
     * matrix row fully regenerates mat->cur. Borrow its first 128/192 bytes
     * for the current encoded row, absorb it, then permit regeneration.
     * No public input/output buffer is repurposed as hidden workspace. */
    mld_poly_use_hint(w1, tmp);
    mld_polyw1_pack((uint8_t *)tmp, w1);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
    if(!hash_live){mld_memcpy(verify_rows+MLDSA_POLYW1_PACKEDBYTES*encoded_rows,(const uint8_t *)tmp,MLDSA_POLYW1_PACKEDBYTES);encoded_rows++;}
    else
#endif
#endif
    mld_shake256_absorb(hash_state, (const uint8_t *)tmp,
                        MLDSA_POLYW1_PACKEDBYTES);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#else
#if LC_DSA_FLAT_VERIFY && (MLDSA_K > 4 || LC_DSA_VERIFY_HASH_BATCH) && !LC_DSA_NATIVE_MATRIX_ROWS
    flat_current=flat_carry; flat_carry=w1;
#endif
#endif
  }

  /* Call random oracle and verify challenge */
  mld_shake256_finalize(hash_state);
  mld_shake256_squeeze(c2, MLDSA_CTILDEBYTES, hash_state);

  cmp = mld_ct_memcmp(c, c2, MLDSA_CTILDEBYTES);

  /* Declassify the result of the verification. */
  MLD_CT_TESTING_DECLASSIFY(&cmp, sizeof(cmp));

  ret = cmp == 0 ? 0 : MLD_ERR_INVALID_SIGNATURE;

cleanup:
  /* Release only initialized SHAKE state, including malformed-hint exits.
   * MLD_FREE below erases and releases its owning arena allocation once. */
  if (hash_live)
  {
    mld_shake256_release(hash_state);
  }
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
#if !LC_DSA_ALIAS_VERIFY_TMP || LC_DSA_DIRECT_MATRIX_ACTIVE
  MLD_FREE(tmp, mld_poly, 1, context);
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  MLD_FREE(row_tile,mld_poly,3,context);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_FLAT_MATRIX_NEON
#else
#if LC_DSA_FLAT_VERIFY && (MLDSA_K > 4 || LC_DSA_VERIFY_HASH_BATCH) && !LC_DSA_NATIVE_MATRIX_ROWS
#if LC_DSA_VERIFY_HASH3 && (MLDSA_K == 6 || LC_DSA_VERIFY_HASH_BATCH)
  MLD_FREE(verify_rows,uint8_t,2*MLDSA_POLYW1_PACKEDBYTES,context);
  mld_zeroize(&verify_hash,sizeof(verify_hash));
#endif
  MLD_FREE(flat_extra,mld_poly,1,context);
#endif
#endif
#if LC_DSA_NATIVE_MATRIX_ROWS
#if LC_DSA_VERIFY_HASH_BATCH_ARM
  MLD_FREE(dense_spare,mld_poly,4,context);
#endif
  #if LC_DSA_MATRIX4_ARENA
  MLD_FREE(matrix_workspace,lc_matrix4_workspace,1,context);
#endif
  MLD_FREE(dense_a,mld_poly,LC_DSA_VERIFY_MATRIX_POLYS,context);
#endif
  MLD_FREE(w1, mld_poly, 1, context);
  MLD_FREE(mat, mld_polymat, 1, context);
#if LC_DSA_PACK_VERIFY_CP
  MLD_FREE(cp,uint8_t,LC_PACKED_ROW_BYTES,context);
#else
  MLD_FREE(cp, mld_poly, 1, context);
#endif
#if LC_DSA_STREAM_RECOMPUTE
  MLD_FREE(z,uint8_t,1,context);
#elif LC_DSA_PACKED_ACCUM
  MLD_FREE(z,lc_packed_vecl,1,context);
#else
  MLD_FREE(z, mld_polyvecl, 1, context);
#endif
  LC_SMALL_FREE(mu, uint8_t, MLDSA_CRHBYTES, context);
  LC_SMALL_FREE(hash_state, mld_shake256ctx, 1, context);
  return ret;
}

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_verify_internal(const uint8_t sig[MLDSA_CRYPTO_BYTES],
                             const uint8_t *m, size_t mlen, const uint8_t *pre,
                             size_t prelen,
                             const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                             int externalmu,
                             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  return lc_verify_segments(sig,m,mlen,pre,prelen,NULL,0,pk,externalmu,context);
}

#endif
#if !defined(MLD_CONFIG_CORE_API_ONLY)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_verify(const uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *m,
                    size_t mlen, const uint8_t *ctx, size_t ctxlen,
                    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  MLD_ALIGN uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
  size_t pre_len;
  int ret;

  pre_len = mld_prepare_domain_separation_prefix(pre, NULL, 0, ctx, ctxlen,
                                                 MLD_PREHASH_NONE);
  if (pre_len == 0)
  {
    ret = MLD_ERR_INVALID_ARG;
    goto cleanup;
  }

  ret = mld_sign_verify_internal(sig, m, mlen, pre, pre_len, pk, 0, context);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(pre, sizeof(pre));

#else
  uint8_t pre[2];int ret;
  if(ctxlen>255)return MLD_ERR_INVALID_ARG;
  pre[0]=0;pre[1]=(uint8_t)ctxlen;
  ret=lc_verify_segments(sig,m,mlen,pre,2,ctx,ctxlen,pk,0,context);
  mld_zeroize(pre,sizeof(pre));
#endif
  return ret;
}

MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_verify_extmu(const uint8_t sig[MLDSA_CRYPTO_BYTES],
                          const uint8_t mu[MLDSA_CRHBYTES],
                          const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                          MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  return mld_sign_verify_internal(sig, mu, MLDSA_CRHBYTES, NULL, 0, pk, 1,
                                  context);
}
#endif /* !MLD_CONFIG_CORE_API_ONLY */
#endif /* !MLD_CONFIG_NO_VERIFY_API */

#if !defined(MLD_CONFIG_CORE_API_ONLY)
#if !defined(MLD_CONFIG_NO_SIGN_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_signature_pre_hash_internal(
    uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES], int hashalg,
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
  size_t pre_len;
  int ret;

  if (hashalg == MLD_PREHASH_NONE)
  {
    ret = MLD_ERR_INVALID_ARG;
    goto cleanup;
  }

  pre_len = mld_prepare_domain_separation_prefix(pre, ph, phlen, ctx, ctxlen,
                                                 hashalg);
  if (pre_len == 0)
  {
    ret = MLD_ERR_INVALID_ARG;
    goto cleanup;
  }

  ret = mld_sign_signature_internal(sig, pre, pre_len, NULL, 0, rnd, sk, 0,
                                    context);
cleanup:
  if (ret != 0)
  {
    /* To be on the safe-side, make sure sig has a well-defined value, even in
     * the case of error.
     *
     * If we come from mld_sign_signature_internal, this is redundant, but the
     * error case should not be the norm, and the added cost of the zeroization
     * insignificant. */
    mld_zeroize(sig, MLDSA_CRYPTO_BYTES);
  }

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(pre, sizeof(pre));
  return ret;
}
#endif /* !MLD_CONFIG_NO_SIGN_API */

#if !defined(MLD_CONFIG_NO_VERIFY_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_verify_pre_hash_internal(
    const uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *ph, size_t phlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES], int hashalg,
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
  size_t pre_len;
  int ret;

  if (hashalg == MLD_PREHASH_NONE)
  {
    ret = MLD_ERR_INVALID_ARG;
    goto cleanup;
  }

  pre_len = mld_prepare_domain_separation_prefix(pre, ph, phlen, ctx, ctxlen,
                                                 hashalg);
  if (pre_len == 0)
  {
    ret = MLD_ERR_INVALID_ARG;
    goto cleanup;
  }

  ret = mld_sign_verify_internal(sig, pre, pre_len, NULL, 0, pk, 0, context);

cleanup:
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(pre, sizeof(pre));
  return ret;
}
#endif /* !MLD_CONFIG_NO_VERIFY_API */

#if !defined(MLD_CONFIG_NO_SIGN_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_signature_pre_hash_shake256(
    uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen, const uint8_t rnd[MLDSA_RNDBYTES],
    const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t ph[64];
  int ret;
  mld_shake256(ph, sizeof(ph), m, mlen);
  ret = mld_sign_signature_pre_hash_internal(sig, ph, sizeof(ph), ctx, ctxlen,
                                             rnd, sk, MLD_PREHASH_SHAKE_256,
                                             context);
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(ph, sizeof(ph));
  return ret;
}
#endif /* !MLD_CONFIG_NO_SIGN_API */

#if !defined(MLD_CONFIG_NO_VERIFY_API)
MLD_MUST_CHECK_RETURN_VALUE
MLD_EXTERNAL_API
int mld_sign_verify_pre_hash_shake256(
    const uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
    MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLD_ALIGN uint8_t ph[64];
  int ret;
  mld_shake256(ph, sizeof(ph), m, mlen);
  ret = mld_sign_verify_pre_hash_internal(sig, ph, sizeof(ph), ctx, ctxlen, pk,
                                          MLD_PREHASH_SHAKE_256, context);
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(ph, sizeof(ph));
  return ret;
}
#endif /* !MLD_CONFIG_NO_VERIFY_API */

#if !defined(MLD_CONFIG_NO_SIGN_API) || !defined(MLD_CONFIG_NO_VERIFY_API)
#define MLD_PRE_HASH_OID_LEN 11

/**
 * Return the OID of a given SHA-2/SHA-3 hash function.
 *
 * @param[out] oid     Pointer to output OID.
 * @param      hashalg Hash algorithm constant (MLD_PREHASH_*).
 */
static void mld_get_hash_oid(uint8_t oid[MLD_PRE_HASH_OID_LEN], int hashalg)
{
  unsigned int i;
  static const struct
  {
    int alg;
    uint8_t oid[MLD_PRE_HASH_OID_LEN];
  } oid_map[] = {
      {MLD_PREHASH_SHA2_224,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04}},
      {MLD_PREHASH_SHA2_256,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}},
      {MLD_PREHASH_SHA2_384,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}},
      {MLD_PREHASH_SHA2_512,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}},
      {MLD_PREHASH_SHA2_512_224,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05}},
      {MLD_PREHASH_SHA2_512_256,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06}},
      {MLD_PREHASH_SHA3_224,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07}},
      {MLD_PREHASH_SHA3_256,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08}},
      {MLD_PREHASH_SHA3_384,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09}},
      {MLD_PREHASH_SHA3_512,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A}},
      {MLD_PREHASH_SHAKE_128,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B}},
      {MLD_PREHASH_SHAKE_256,
       {0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C}}};

  for (i = 0; i < sizeof(oid_map) / sizeof(oid_map[0]); i++)
  __loop__(
    invariant(i <= sizeof(oid_map) / sizeof(oid_map[0]))
    decreases(sizeof(oid_map) / sizeof(oid_map[0]) - i)
  )
  {
    if (oid_map[i].alg == hashalg)
    {
      mld_memcpy(oid, oid_map[i].oid, MLD_PRE_HASH_OID_LEN);
      return;
    }
  }
}

static int mld_validate_hash_length(int hashalg, size_t len)
{
  switch (hashalg)
  {
    case MLD_PREHASH_SHA2_224:
      return (len == 224 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA2_256:
      return (len == 256 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA2_384:
      return (len == 384 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA2_512:
      return (len == 512 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA2_512_224:
      return (len == 224 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA2_512_256:
      return (len == 256 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA3_224:
      return (len == 224 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA3_256:
      return (len == 256 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA3_384:
      return (len == 384 / 8) ? 0 : -1;
    case MLD_PREHASH_SHA3_512:
      return (len == 512 / 8) ? 0 : -1;
    case MLD_PREHASH_SHAKE_128:
      return (len == 256 / 8) ? 0 : -1;
    case MLD_PREHASH_SHAKE_256:
      return (len == 512 / 8) ? 0 : -1;
    default:
      return -1;
  }
}

MLD_EXTERNAL_API
size_t mld_prepare_domain_separation_prefix(
    uint8_t prefix[MLD_DOMAIN_SEPARATION_MAX_BYTES], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen, int hashalg)
{
  if (ctxlen > 255)
  {
    return 0;
  }

  if (hashalg != MLD_PREHASH_NONE)
  {
    if (ph == NULL || mld_validate_hash_length(hashalg, phlen) != 0)
    {
      return 0;
    }
  }

  /* Common prefix: 0x00/0x01 || ctxlen || ctx */
  prefix[0] = (hashalg == MLD_PREHASH_NONE) ? 0 : 1;
  prefix[1] = (uint8_t)ctxlen;
  if (ctxlen > 0)
  {
    mld_memcpy(prefix + 2, ctx, ctxlen);
  }

  if (hashalg == MLD_PREHASH_NONE)
  {
    return 2 + ctxlen;
  }

  /* HashML-DSA: append oid || ph */
  mld_get_hash_oid(prefix + 2 + ctxlen, hashalg);
  mld_memcpy(prefix + 2 + ctxlen + MLD_PRE_HASH_OID_LEN, ph, phlen);
  return 2 + ctxlen + MLD_PRE_HASH_OID_LEN + phlen;
}
#endif /* !MLD_CONFIG_NO_SIGN_API || !MLD_CONFIG_NO_VERIFY_API */

#if !defined(MLD_CONFIG_NO_KEYPAIR_API)
MLD_EXTERNAL_API
int mld_sign_pk_from_sk(uint8_t pk[MLDSA_CRYPTO_PUBLICKEYBYTES],
                        const uint8_t sk[MLDSA_CRYPTO_SECRETKEYBYTES],
                        MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  uint8_t check, cmp0, cmp1, chk1, chk2;
  int ret;
  MLD_ALLOC(rho, uint8_t, MLDSA_SEEDBYTES, context);
  MLD_ALLOC(tr, uint8_t, MLDSA_TRBYTES, context);
  MLD_ALLOC(tr_computed, uint8_t, MLDSA_TRBYTES, context);
  MLD_ALLOC(key, uint8_t, MLDSA_SEEDBYTES, context);
  MLD_ALLOC(s1, mld_polyvecl, 1, context);
  MLD_ALLOC(s2, mld_polyveck, 1, context);
  MLD_ALLOC(t0_packed, uint8_t, MLDSA_K *MLDSA_POLYT0_PACKEDBYTES, context);

  if (rho == NULL || tr == NULL || tr_computed == NULL || key == NULL ||
      s1 == NULL || s2 == NULL || t0_packed == NULL)
  {
    ret = MLD_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  /* Inline unpack_sk: mld_unpack_sk uses lazy types for s1/s2/t0 which
   * we cannot use here. t0 stays in packed form -- we compare it against
   * the recomputed value below. */
  mld_memcpy(rho, sk + MLDSA_SK_RHO_OFFSET, MLDSA_SEEDBYTES);
  mld_memcpy(key, sk + MLDSA_SK_KEY_OFFSET, MLDSA_SEEDBYTES);
  mld_memcpy(tr, sk + MLDSA_SK_TR_OFFSET, MLDSA_TRBYTES);
  mld_polyvecl_unpack_eta(s1, sk + MLDSA_SK_S1_OFFSET);
  mld_polyveck_unpack_eta(s2, sk + MLDSA_SK_S2_OFFSET);

  /* Validate s1 and s2 coefficients are within [-MLDSA_ETA, MLDSA_ETA] */
  chk1 = mld_polyvecl_chknorm(s1, MLDSA_ETA + 1) & 0xFF;
  chk2 = mld_polyveck_chknorm(s2, MLDSA_ETA + 1) & 0xFF;

  /* NTT s1 in place to use as s1hat */
  mld_polyvecl_ntt(s1);

  /* Pack rho into pk */
  mld_memcpy(pk + MLDSA_PK_RHO_OFFSET, rho, MLDSA_SEEDBYTES);

  /* Recompute t row by row, decompose, and pack t1 into pk and t0 into
   * t0_packed. */
  ret = mld_compute_pack_t0_t1(pk + MLDSA_PK_T1_OFFSET, t0_packed, s1, s2, rho,
                               context);
  if (ret != 0)
  {
    goto cleanup;
  }

  /* Compare recomputed packed t0 against the t0 region of sk. */
  cmp0 = mld_ct_memcmp(t0_packed, sk + MLDSA_SK_T0_OFFSET,
                       MLDSA_K * MLDSA_POLYT0_PACKEDBYTES);

  /* Compute tr_computed = H(pk) and compare to the stored tr */
  mld_shake256(tr_computed, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES);
  cmp1 = mld_ct_memcmp((const uint8_t *)tr, (const uint8_t *)tr_computed,
                       MLDSA_TRBYTES);
  check = mld_value_barrier_u8(cmp0 | cmp1 | chk1 | chk2);

  /* Declassify the final result of the validity check. */
  MLD_CT_TESTING_DECLASSIFY(&check, sizeof(check));
  ret = (check != 0) ? MLD_ERR_INVALID_KEY : 0;

cleanup:

  if (ret != 0)
  {
    mld_zeroize(pk, MLDSA_CRYPTO_PUBLICKEYBYTES);
  }

  /* Constant time: pk is either the valid public key or zeroed on error */
  MLD_CT_TESTING_DECLASSIFY(pk, MLDSA_CRYPTO_PUBLICKEYBYTES);

  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  MLD_FREE(t0_packed, uint8_t, MLDSA_K *MLDSA_POLYT0_PACKEDBYTES, context);
  MLD_FREE(s2, mld_polyveck, 1, context);
  MLD_FREE(s1, mld_polyvecl, 1, context);
  MLD_FREE(key, uint8_t, MLDSA_SEEDBYTES, context);
  MLD_FREE(tr_computed, uint8_t, MLDSA_TRBYTES, context);
  MLD_FREE(tr, uint8_t, MLDSA_TRBYTES, context);
  MLD_FREE(rho, uint8_t, MLDSA_SEEDBYTES, context);

  return ret;
}
#endif /* !MLD_CONFIG_NO_KEYPAIR_API */
#endif /* !MLD_CONFIG_CORE_API_ONLY */

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef mld_check_pct
#undef mld_sample_s1_s2
#undef mld_validate_hash_length
#undef mld_get_hash_oid
#undef mld_H
#undef mld_compute_pack_z
#undef mld_attempt_signature_generation
#undef mld_compute_pack_t0_t1
#undef mld_get_max_signing_attempts
#undef MLD_MAX_SIGNING_ATTEMPTS
#undef MLD_PRE_HASH_OID_LEN
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else

#undef lc_verify_segments
#undef lc_verify_mu_segments
#endif

#include "lc_a_session_impl.h"
