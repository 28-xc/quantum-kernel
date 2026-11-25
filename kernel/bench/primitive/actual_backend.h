/* Test/benchmark ABI adapter to EXISTING static archive entities.
 * No arithmetic implementation is included here. Layouts mirror the named
 * upstream poly/polyvec declarations (Apache-2.0 OR ISC OR MIT); see README.
 * This is a research adapter, not one of the eight public crypto APIs. */
#ifndef LC_ACTUAL_BACKEND_H
#define LC_ACTUAL_BACKEND_H
#include <stdint.h>
#define ALIGN __attribute__((aligned(32)))
typedef struct { int16_t coeffs[256]; } ALIGN KPoly;
typedef struct { int16_t coeffs[128]; } ALIGN KCache;
typedef struct { int32_t coeffs[256]; } ALIGN DPoly;
typedef struct { KPoly vec[2]; } ALIGN KVec2;
typedef struct { KPoly vec[3]; } ALIGN KVec3;
typedef struct { KPoly vec[4]; } ALIGN KVec4;
typedef struct { KCache vec[2]; } ALIGN KCache2;
typedef struct { KCache vec[3]; } ALIGN KCache3;
typedef struct { KCache vec[4]; } ALIGN KCache4;
typedef union { KVec2 k2; KVec3 k3; KVec4 k4; } KVectors;
typedef union { KCache2 k2; KCache3 k3; KCache4 k4; } KCaches;
_Static_assert(sizeof(KPoly)==512 && sizeof(KCache)==256 && sizeof(DPoly)==1024,"Archive poly ABI");
_Static_assert(sizeof(KVec2)==1024 && sizeof(KVec3)==1536 && sizeof(KVec4)==2048,"Archive vector ABI");

#if LC_ACTUAL_BACKEND
static KPoly *kp(KVectors *x,int k,int i){return k==2?&x->k2.vec[i]:k==3?&x->k3.vec[i]:&x->k4.vec[i];}
static KCache *kc(KCaches *x,int k,int i){return k==2?&x->k2.vec[i]:k==3?&x->k3.vec[i]:&x->k4.vec[i];}

#if LC_KEM_DIRECT_AVX2
#if defined(_WIN32) && defined(__x86_64__)
#define SYSV __attribute__((sysv_abi))
#else
#define SYSV
#endif
extern const int16_t lc_base_mlk_qdata[];
extern void SYSV lc_base_mlk_ntt_avx2_asm(int16_t*,const int16_t*);
extern void SYSV lc_base_mlk_invntt_avx2_asm(int16_t*,const int16_t*);
extern void SYSV lc_base_mlk_reduce_avx2_asm(int16_t*);
extern void SYSV lc_base_mlk_poly_mulcache_compute_avx2_asm(int16_t*,const int16_t*,const int16_t*);
extern void SYSV lc_base_mlk_polyvec_basemul_acc_montgomery_cached_k2_avx2_asm(int16_t*,const int16_t*,const int16_t*,const int16_t*);
extern void SYSV lc_base_mlk_polyvec_basemul_acc_montgomery_cached_k3_avx2_asm(int16_t*,const int16_t*,const int16_t*,const int16_t*);
extern void SYSV lc_base_mlk_polyvec_basemul_acc_montgomery_cached_k4_avx2_asm(int16_t*,const int16_t*,const int16_t*,const int16_t*);
static void kn(KPoly *x){lc_base_mlk_ntt_avx2_asm(x->coeffs,lc_base_mlk_qdata);}
static void ki(KPoly *x){lc_base_mlk_invntt_avx2_asm(x->coeffs,lc_base_mlk_qdata);}
static void kr(KPoly *x){lc_base_mlk_reduce_avx2_asm(x->coeffs);}
static void kmc(KCache *c,const KPoly *x){lc_base_mlk_poly_mulcache_compute_avx2_asm(c->coeffs,x->coeffs,lc_base_mlk_qdata);}
static void kd(KPoly *r,KVectors *a,KVectors *b,KCaches *c,int k){
 if(k==2)lc_base_mlk_polyvec_basemul_acc_montgomery_cached_k2_avx2_asm(r->coeffs,kp(a,k,0)->coeffs,kp(b,k,0)->coeffs,kc(c,k,0)->coeffs);
 else if(k==3)lc_base_mlk_polyvec_basemul_acc_montgomery_cached_k3_avx2_asm(r->coeffs,kp(a,k,0)->coeffs,kp(b,k,0)->coeffs,kc(c,k,0)->coeffs);
 else lc_base_mlk_polyvec_basemul_acc_montgomery_cached_k4_avx2_asm(r->coeffs,kp(a,k,0)->coeffs,kp(b,k,0)->coeffs,kc(c,k,0)->coeffs);
}
#else
extern void lc_base_mlk_poly_ntt(KPoly*);
extern void lc_base_mlk_poly_invntt_tomont(KPoly*);
extern void lc_base_mlk_poly_reduce(KPoly*);
extern void lc_base_mlk_poly_mulcache_compute(KCache*,const KPoly*);
extern void lc_base_mlk512_polyvec_basemul_acc_montgomery_cached(KPoly*,const KVec2*,const KVec2*,const KCache2*);
extern void lc_base_mlk768_polyvec_basemul_acc_montgomery_cached(KPoly*,const KVec3*,const KVec3*,const KCache3*);
extern void lc_base_mlk1024_polyvec_basemul_acc_montgomery_cached(KPoly*,const KVec4*,const KVec4*,const KCache4*);
#define kn lc_base_mlk_poly_ntt
#define ki lc_base_mlk_poly_invntt_tomont
#define kr lc_base_mlk_poly_reduce
#define kmc lc_base_mlk_poly_mulcache_compute
static void kd(KPoly *r,KVectors *a,KVectors *b,KCaches *c,int k){
 if(k==2)lc_base_mlk512_polyvec_basemul_acc_montgomery_cached(r,&a->k2,&b->k2,&c->k2);
 else if(k==3)lc_base_mlk768_polyvec_basemul_acc_montgomery_cached(r,&a->k3,&b->k3,&c->k3);
 else lc_base_mlk1024_polyvec_basemul_acc_montgomery_cached(r,&a->k4,&b->k4,&c->k4);
}
#endif
extern void lcbase_poly_ntt(DPoly*);
extern void lcbase_poly_invntt_tomont(DPoly*);
extern void lcbase_poly_reduce(DPoly*);
extern void lcbase_poly_pointwise_montgomery(DPoly*,const DPoly*);
#define dn lcbase_poly_ntt
#define di lcbase_poly_invntt_tomont
#define dr lcbase_poly_reduce
#define dp lcbase_poly_pointwise_montgomery

/* This conversion is used only by the test oracle, never added inside a
 * measured actual-backend call. AArch64 and portable use bitreverse order. */
#if LC_CUSTOM_AVX2
#ifndef SYSV
#if defined(_WIN32) && defined(__x86_64__)
#define SYSV __attribute__((sysv_abi))
#else
#define SYSV
#endif
#endif
extern void SYSV lc_base_mlk_nttunpack_avx2_asm(int16_t*);
extern void SYSV lcbase_nttunpack_avx2_asm(int32_t*);
static void kperm(KPoly *x){lc_base_mlk_nttunpack_avx2_asm(x->coeffs);}
static void dperm(DPoly *x){lcbase_nttunpack_avx2_asm(x->coeffs);}
#else
static void kperm(KPoly *x){(void)x;}
static void dperm(DPoly *x){(void)x;}
#endif
#endif
#endif
