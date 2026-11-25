/* SPDX-License-Identifier: Apache-2.0
 * Shared coefficient-domain t1 multiplication for ML-DSA verification.
 * Public challenge indices determine every indirect input address.
 * Eight16-bit lanes require at most60*512=30720 magnitude per partialsum.
 * Character views and memcpy preserve the existing int32 owner type. */
#include "lc_verify_t1_centered_neon.h"
#include <arm_neon.h>
#if defined(__GNUC__) && !defined(__clang__)
#define LC_T1_SHARED __attribute__((noinline,noclone,aligned(32)))
#else
#define LC_T1_SHARED __attribute__((noinline,aligned(32)))
#endif
static inline int16x8_t load16(const uint8_t*p){
 int16x8_t v;__builtin_memcpy(&v,p,sizeof v);return v;
}
static inline void store16(uint8_t*p,int16x8_t v){__builtin_memcpy(p,&v,sizeof v);}
LC_T1_SHARED void lc_verify_t1_neon_prepare(uint8_t owner[768],const int32_t c[256],unsigned tau){
 unsigned positive=1,negative=tau;int total=0,prefix=0;
 for(unsigned j=0;j<256;j++){
  total+=c[j];
  if(c[j]==1)owner[positive++]=(uint8_t)j;
  if(c[j]==-1)owner[negative--]=(uint8_t)j;
 }
 owner[0]=(uint8_t)(positive-1);
 for(unsigned j=0;j<256;j++){
  prefix+=c[j];int16_t h=(int16_t)(2*prefix-total);
  __builtin_memcpy(owner+64+2*j,&h,sizeof h);
 }
}
static inline int32x4_t canonical(int32x4_t x){
 const int32x4_t q=vdupq_n_s32(8380417);
 int32x4_t t=vshrq_n_s32(vaddq_s32(x,vdupq_n_s32(4194304)),23);
 x=vsubq_s32(x,vmulq_s32(t,q));
 return vaddq_s32(x,vandq_s32(vshrq_n_s32(x,31),q));
}
static inline void finish8(int32_t *w,const uint8_t *owner,unsigned j,int16x8_t s){
 int16x8_t h=load16(owner+64+2*j);
 int32x4_t lo=vaddq_s32(vmovl_s16(vget_low_s16(s)),vshlq_n_s32(vmovl_s16(vget_low_s16(h)),9));
 int32x4_t hi=vaddq_s32(vmovl_high_s16(s),vshlq_n_s32(vmovl_high_s16(h),9));
 lo=vsubq_s32(vld1q_s32(w+j),vshlq_n_s32(lo,13));
 hi=vsubq_s32(vld1q_s32(w+j+4),vshlq_n_s32(hi,13));
 vst1q_s32(w+j,canonical(lo));vst1q_s32(w+j+4,canonical(hi));
}
LC_T1_SHARED void lc_verify_t1_neon_subtract(int32_t w[256],int32_t tmp[256],
                                          const uint8_t owner[768],unsigned tau){
 uint8_t*p=(uint8_t*)tmp;
 /* Load all eight source coefficients before the16-byte in-place store.
    The next read begins at4*(j+8), strictly beyond the storedprefix. */
 for(unsigned j=0;j<256;j+=8){
  int32x4_t a=vsubq_s32(vld1q_s32(tmp+j),vdupq_n_s32(512));
  int32x4_t b=vsubq_s32(vld1q_s32(tmp+j+4),vdupq_n_s32(512));
  store16(p+2*j,vcombine_s16(vmovn_s32(a),vmovn_s32(b)));
 }
 for(unsigned j=0;j<256;j+=8){
  int16x8_t x=load16(p+2*j);store16(p+512+2*j,x);store16(p+2*j,vnegq_s16(x));
 }
 for(unsigned j=0;j<256;j+=32){
  int16x8_t a=vdupq_n_s16(0),b=a,c=a,d=a;
  for(unsigned k=1;k<=(unsigned)owner[0];k++){
   const uint8_t *q=p+512+2*j-2*(unsigned)owner[k];
   a=vaddq_s16(a,load16(q));b=vaddq_s16(b,load16(q+16));
   c=vaddq_s16(c,load16(q+32));d=vaddq_s16(d,load16(q+48));
  }
  for(unsigned k=(unsigned)owner[0]+1;k<=tau;k++){
   const uint8_t *q=p+512+2*j-2*(unsigned)owner[k];
   a=vsubq_s16(a,load16(q));b=vsubq_s16(b,load16(q+16));
   c=vsubq_s16(c,load16(q+32));d=vsubq_s16(d,load16(q+48));
  }
  finish8(w,owner,j,a);finish8(w,owner,j+8,b);finish8(w,owner,j+16,c);finish8(w,owner,j+24,d);
 }
}
#undef LC_T1_SHARED
