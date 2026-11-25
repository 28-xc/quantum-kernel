/* SPDX-License-Identifier: Apache-2.0
 * Exact negacyclic c*t0, standard t0 coefficients [-4095,4096].
 * Public challenge indices contain tau<=60 signs; seven signed16 additions
 * have magnitude<=28672, then signed32 accumulates the full<=245760 result.
 * Storage: independent input scratch1024 and output1024, no hidden array. */
#ifndef LC_SPARSE_T0_NEON_H
#define LC_SPARSE_T0_NEON_H
#include <stdint.h>
#include <string.h>
#include <arm_neon.h>
#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || defined(MLD_CONFIG_MULTILEVEL_NO_SHARED)
#define LC_T0_OWNER __attribute__((visibility("hidden"),noipa,optimize("O3")))
LC_T0_OWNER void lc_sparse_t0_product(int32_t[256],int32_t[256],const uint8_t[61],unsigned);
#else
#define LC_T0_OWNER static __attribute__((noinline,optimize("O3")))
#endif
#if !defined(MLD_CONFIG_MULTILEVEL_NO_SHARED)
LC_T0_OWNER void lc_sparse_t0_product(
    int32_t out[256],int32_t scratch[256],const uint8_t index[61],unsigned tau) {
  uint8_t *bytes=(uint8_t *)(void *)scratch;
  for(unsigned j=0;j<256;j+=8) {
    int16x8_t x=vcombine_s16(vmovn_s32(vld1q_s32(scratch+j)),vmovn_s32(vld1q_s32(scratch+j+4)));
    vst1q_u8(bytes+2*j,vreinterpretq_u8_s16(x));
  }
  for(unsigned j=0;j<256;j+=8) {
    int16x8_t x=vreinterpretq_s16_u8(vld1q_u8(bytes+2*j));
    vst1q_u8(bytes+512+2*j,vreinterpretq_u8_s16(x));
    vst1q_u8(bytes+2*j,vreinterpretq_u8_s16(vnegq_s16(x)));
  }
#if LC_DSA_SPARSE_T0_WIDE
  for(unsigned j=0;j<256;j+=64) {
    int32x4_t r0=vdupq_n_s32(0),r1=vdupq_n_s32(0),r2=vdupq_n_s32(0),r3=vdupq_n_s32(0),r4=vdupq_n_s32(0),r5=vdupq_n_s32(0),r6=vdupq_n_s32(0),r7=vdupq_n_s32(0),r8=vdupq_n_s32(0),r9=vdupq_n_s32(0),r10=vdupq_n_s32(0),r11=vdupq_n_s32(0),r12=vdupq_n_s32(0),r13=vdupq_n_s32(0),r14=vdupq_n_s32(0),r15=vdupq_n_s32(0);
    for(unsigned phase=0;phase<2;phase++) {
      unsigned begin=phase?(unsigned)index[0]+1:1,end=phase?tau:(unsigned)index[0];
      for(unsigned first=begin;first<=end;first+=7) {
        unsigned last=end-first<6?end:first+6;
        int16x8_t s0=vdupq_n_s16(0),s1=vdupq_n_s16(0),s2=vdupq_n_s16(0),s3=vdupq_n_s16(0),s4=vdupq_n_s16(0),s5=vdupq_n_s16(0),s6=vdupq_n_s16(0),s7=vdupq_n_s16(0);
        for(unsigned k=first;k<=last;k++) {
          const uint8_t *p=bytes+2*(256+j-index[k]);
          s0=vaddq_s16(s0,vreinterpretq_s16_u8(vld1q_u8(p+0)));
          s1=vaddq_s16(s1,vreinterpretq_s16_u8(vld1q_u8(p+16)));
          s2=vaddq_s16(s2,vreinterpretq_s16_u8(vld1q_u8(p+32)));
          s3=vaddq_s16(s3,vreinterpretq_s16_u8(vld1q_u8(p+48)));
          s4=vaddq_s16(s4,vreinterpretq_s16_u8(vld1q_u8(p+64)));
          s5=vaddq_s16(s5,vreinterpretq_s16_u8(vld1q_u8(p+80)));
          s6=vaddq_s16(s6,vreinterpretq_s16_u8(vld1q_u8(p+96)));
          s7=vaddq_s16(s7,vreinterpretq_s16_u8(vld1q_u8(p+112)));
        }
        int32x4_t t0=vmovl_s16(vget_low_s16(s0));
        int32x4_t t1=vmovl_high_s16(s0);
        int32x4_t t2=vmovl_s16(vget_low_s16(s1));
        int32x4_t t3=vmovl_high_s16(s1);
        int32x4_t t4=vmovl_s16(vget_low_s16(s2));
        int32x4_t t5=vmovl_high_s16(s2);
        int32x4_t t6=vmovl_s16(vget_low_s16(s3));
        int32x4_t t7=vmovl_high_s16(s3);
        int32x4_t t8=vmovl_s16(vget_low_s16(s4));
        int32x4_t t9=vmovl_high_s16(s4);
        int32x4_t t10=vmovl_s16(vget_low_s16(s5));
        int32x4_t t11=vmovl_high_s16(s5);
        int32x4_t t12=vmovl_s16(vget_low_s16(s6));
        int32x4_t t13=vmovl_high_s16(s6);
        int32x4_t t14=vmovl_s16(vget_low_s16(s7));
        int32x4_t t15=vmovl_high_s16(s7);
        if(phase){r0=vsubq_s32(r0,t0);r1=vsubq_s32(r1,t1);r2=vsubq_s32(r2,t2);r3=vsubq_s32(r3,t3);r4=vsubq_s32(r4,t4);r5=vsubq_s32(r5,t5);r6=vsubq_s32(r6,t6);r7=vsubq_s32(r7,t7);r8=vsubq_s32(r8,t8);r9=vsubq_s32(r9,t9);r10=vsubq_s32(r10,t10);r11=vsubq_s32(r11,t11);r12=vsubq_s32(r12,t12);r13=vsubq_s32(r13,t13);r14=vsubq_s32(r14,t14);r15=vsubq_s32(r15,t15);}
        else{r0=vaddq_s32(r0,t0);r1=vaddq_s32(r1,t1);r2=vaddq_s32(r2,t2);r3=vaddq_s32(r3,t3);r4=vaddq_s32(r4,t4);r5=vaddq_s32(r5,t5);r6=vaddq_s32(r6,t6);r7=vaddq_s32(r7,t7);r8=vaddq_s32(r8,t8);r9=vaddq_s32(r9,t9);r10=vaddq_s32(r10,t10);r11=vaddq_s32(r11,t11);r12=vaddq_s32(r12,t12);r13=vaddq_s32(r13,t13);r14=vaddq_s32(r14,t14);r15=vaddq_s32(r15,t15);}
      }
    }
    vst1q_s32(out+j+0,r0);
    vst1q_s32(out+j+4,r1);
    vst1q_s32(out+j+8,r2);
    vst1q_s32(out+j+12,r3);
    vst1q_s32(out+j+16,r4);
    vst1q_s32(out+j+20,r5);
    vst1q_s32(out+j+24,r6);
    vst1q_s32(out+j+28,r7);
    vst1q_s32(out+j+32,r8);
    vst1q_s32(out+j+36,r9);
    vst1q_s32(out+j+40,r10);
    vst1q_s32(out+j+44,r11);
    vst1q_s32(out+j+48,r12);
    vst1q_s32(out+j+52,r13);
    vst1q_s32(out+j+56,r14);
    vst1q_s32(out+j+60,r15);
  }
#else
  for(unsigned j=0;j<256;j+=16) {
    int32x4_t r0=vdupq_n_s32(0),r1=r0,r2=r0,r3=r0;
    for(unsigned phase=0;phase<2;phase++) {
      unsigned begin=phase?(unsigned)index[0]+1:1,end=phase?tau:(unsigned)index[0];
      for(unsigned first=begin;first<=end;first+=7) {
        unsigned last=end-first<6?end:first+6;
        int16x8_t s0=vdupq_n_s16(0),s1=s0;
        for(unsigned k=first;k<=last;k++) {
          const uint8_t *p=bytes+2*(256+j-index[k]);
          s0=vaddq_s16(s0,vreinterpretq_s16_u8(vld1q_u8(p)));
          s1=vaddq_s16(s1,vreinterpretq_s16_u8(vld1q_u8(p+16)));
        }
        int32x4_t t0=vmovl_s16(vget_low_s16(s0)),t1=vmovl_high_s16(s0);
        int32x4_t t2=vmovl_s16(vget_low_s16(s1)),t3=vmovl_high_s16(s1);
        if(phase){r0=vsubq_s32(r0,t0);r1=vsubq_s32(r1,t1);r2=vsubq_s32(r2,t2);r3=vsubq_s32(r3,t3);}
        else{r0=vaddq_s32(r0,t0);r1=vaddq_s32(r1,t1);r2=vaddq_s32(r2,t2);r3=vaddq_s32(r3,t3);}
      }
    }
    vst1q_s32(out+j,r0);vst1q_s32(out+j+4,r1);vst1q_s32(out+j+8,r2);vst1q_s32(out+j+12,r3);
  }
#endif
}
#endif
#undef LC_T0_OWNER
#endif
