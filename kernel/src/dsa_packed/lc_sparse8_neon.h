/* SPDX-License-Identifier: Apache-2.0
 * Exact negacyclic product with a public sparse challenge. Every eta decode
 * is supported: eta2 [-5,2], eta4 [-11,4]. Public chunks25/11 bound signed
 * byte partial sums by125/121; the complete signed16 bound is539.
 */
#ifndef LC_SPARSE8_NEON_H
#define LC_SPARSE8_NEON_H
#include <stdint.h>
#include <string.h>
#include <arm_neon.h>
#ifndef LC_DSA_NEON_BYTE_PACK
#define LC_DSA_NEON_BYTE_PACK 0
#endif
static void lc_sparse16_challenge(uint8_t index[61],const int32_t c[256],unsigned tau){
  unsigned head=1,tail=tau;
  for(unsigned j=0;j<256;j++){
    if(c[j]==1)index[head++]=(uint8_t)j;
    if(c[j]==-1)index[tail--]=(uint8_t)j;
  }
  index[0]=(uint8_t)(head-1);
}
static inline void lc_sparse8_decode_packed(uint8_t bytes[256],const uint8_t *packed,unsigned eta_value) {
  if(eta_value==4) {
    const uint8x16_t mask=vdupq_n_u8(15);const int8x16_t eta=vdupq_n_s8(4);
    for(unsigned i=0;i<128;i+=16) {
      uint8x16_t v=vld1q_u8(packed+i);
      int8x16_t lo=vsubq_s8(eta,vreinterpretq_s8_u8(vandq_u8(v,mask)));
      int8x16_t hi=vsubq_s8(eta,vreinterpretq_s8_u8(vshrq_n_u8(v,4)));
      int8x16x2_t z=vzipq_s8(lo,hi);
      vst1q_s8((int8_t*)(bytes+2*i),z.val[0]);vst1q_s8((int8_t*)(bytes+2*i+16),z.val[1]);
    }
  } else {
#if LC_DSA_NEON_BYTE_PACK
    /* Sixteen independent 24-bit codewords are decoded as three byte planes.
     * zip plus interleaved stores restores the exact coefficient order.
     * Both canonical and noncanonical 3-bit encodings are preserved. */
    const uint8x16_t mask=vdupq_n_u8(7),eta=vdupq_n_u8(2);
    for(unsigned group=0;group<2;group++) {
      uint8x16x3_t x=vld3q_u8(packed+48*group);
      uint8x16_t a=x.val[0],b=x.val[1],c=x.val[2];
      uint8x16_t f0=vsubq_u8(eta,vandq_u8(a,mask));
      uint8x16_t f1=vsubq_u8(eta,vandq_u8(vshrq_n_u8(a,3),mask));
      uint8x16_t f2=vsubq_u8(eta,vandq_u8(vorrq_u8(vshrq_n_u8(a,6),vshlq_n_u8(b,2)),mask));
      uint8x16_t f3=vsubq_u8(eta,vandq_u8(vshrq_n_u8(b,1),mask));
      uint8x16_t f4=vsubq_u8(eta,vandq_u8(vshrq_n_u8(b,4),mask));
      uint8x16_t f5=vsubq_u8(eta,vandq_u8(vorrq_u8(vshrq_n_u8(b,7),vshlq_n_u8(c,1)),mask));
      uint8x16_t f6=vsubq_u8(eta,vandq_u8(vshrq_n_u8(c,2),mask));
      uint8x16_t f7=vsubq_u8(eta,vshrq_n_u8(c,5));
      uint8x16x4_t lo={{vzip1q_u8(f0,f4),vzip1q_u8(f1,f5),vzip1q_u8(f2,f6),vzip1q_u8(f3,f7)}};
      uint8x16x4_t hi={{vzip2q_u8(f0,f4),vzip2q_u8(f1,f5),vzip2q_u8(f2,f6),vzip2q_u8(f3,f7)}};
      vst4q_u8(bytes+128*group,lo);vst4q_u8(bytes+128*group+64,hi);
    }
#else
    const int32x4_t shifts={0,-3,-6,-9};
    const uint8x8_t mask=vdup_n_u8(7),eta=vdup_n_u8(2);
    for(unsigned i=0;i<32;i++) {
      uint32_t x=(uint32_t)packed[3*i]|((uint32_t)packed[3*i+1]<<8)|((uint32_t)packed[3*i+2]<<16);
      uint32x4_t lo=vshlq_u32(vdupq_n_u32(x),shifts);
      uint32x4_t hi=vshlq_u32(vdupq_n_u32(x>>12),shifts);
      uint16x8_t words=vcombine_u16(vmovn_u32(lo),vmovn_u32(hi));
      uint8x8_t fields=vand_u8(vmovn_u16(words),mask);
      vst1_u8(bytes+8*i,vsub_u8(eta,fields));
    }
#endif
  }
}
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3"),noinline,noclone))
#endif
static void lc_sparse8_product_packed_i16_eta(int32_t out[256],const uint8_t *packed,const uint8_t index[61],unsigned tau,unsigned chunk,unsigned eta_value){
  uint8_t *bytes=(uint8_t*)out;
  lc_sparse8_decode_packed(bytes,packed,eta_value);
  for(unsigned j=0;j<256;j+=16){
    int8x16_t v=vld1q_s8((const int8_t*)(bytes+j));
    vst1q_s8((int8_t*)(bytes+256+j),v);
    vst1q_s8((int8_t*)(bytes+j),vnegq_s8(v));
  }
#if LC_DSA_SPARSE_ETA_WIDE
  for(unsigned j=0;j<256;j+=128){
    int16x8_t r0=vdupq_n_s16(0),r1=vdupq_n_s16(0),r2=vdupq_n_s16(0),r3=vdupq_n_s16(0),r4=vdupq_n_s16(0),r5=vdupq_n_s16(0),r6=vdupq_n_s16(0),r7=vdupq_n_s16(0),r8=vdupq_n_s16(0),r9=vdupq_n_s16(0),r10=vdupq_n_s16(0),r11=vdupq_n_s16(0),r12=vdupq_n_s16(0),r13=vdupq_n_s16(0),r14=vdupq_n_s16(0),r15=vdupq_n_s16(0);
    for(unsigned phase=0;phase<2;phase++){
      unsigned begin=phase?(unsigned)index[0]+1:1,end=phase?tau:(unsigned)index[0];
      for(unsigned first=begin;first<=end;first+=chunk){
        unsigned last=end-first<chunk-1?end:first+chunk-1;
        int8x16_t s0=vdupq_n_s8(0),s1=vdupq_n_s8(0),s2=vdupq_n_s8(0),s3=vdupq_n_s8(0),s4=vdupq_n_s8(0),s5=vdupq_n_s8(0),s6=vdupq_n_s8(0),s7=vdupq_n_s8(0);
        for(unsigned k=first;k<=last;k++){
          const int8_t *p=(const int8_t*)(bytes+256+j-index[k]);
          s0=vaddq_s8(s0,vld1q_s8(p+0));
          s1=vaddq_s8(s1,vld1q_s8(p+16));
          s2=vaddq_s8(s2,vld1q_s8(p+32));
          s3=vaddq_s8(s3,vld1q_s8(p+48));
          s4=vaddq_s8(s4,vld1q_s8(p+64));
          s5=vaddq_s8(s5,vld1q_s8(p+80));
          s6=vaddq_s8(s6,vld1q_s8(p+96));
          s7=vaddq_s8(s7,vld1q_s8(p+112));
        }
        int16x8_t t0=vmovl_s8(vget_low_s8(s0));
        int16x8_t t1=vmovl_high_s8(s0);
        int16x8_t t2=vmovl_s8(vget_low_s8(s1));
        int16x8_t t3=vmovl_high_s8(s1);
        int16x8_t t4=vmovl_s8(vget_low_s8(s2));
        int16x8_t t5=vmovl_high_s8(s2);
        int16x8_t t6=vmovl_s8(vget_low_s8(s3));
        int16x8_t t7=vmovl_high_s8(s3);
        int16x8_t t8=vmovl_s8(vget_low_s8(s4));
        int16x8_t t9=vmovl_high_s8(s4);
        int16x8_t t10=vmovl_s8(vget_low_s8(s5));
        int16x8_t t11=vmovl_high_s8(s5);
        int16x8_t t12=vmovl_s8(vget_low_s8(s6));
        int16x8_t t13=vmovl_high_s8(s6);
        int16x8_t t14=vmovl_s8(vget_low_s8(s7));
        int16x8_t t15=vmovl_high_s8(s7);
        if(phase){r0=vsubq_s16(r0,t0);r1=vsubq_s16(r1,t1);r2=vsubq_s16(r2,t2);r3=vsubq_s16(r3,t3);r4=vsubq_s16(r4,t4);r5=vsubq_s16(r5,t5);r6=vsubq_s16(r6,t6);r7=vsubq_s16(r7,t7);r8=vsubq_s16(r8,t8);r9=vsubq_s16(r9,t9);r10=vsubq_s16(r10,t10);r11=vsubq_s16(r11,t11);r12=vsubq_s16(r12,t12);r13=vsubq_s16(r13,t13);r14=vsubq_s16(r14,t14);r15=vsubq_s16(r15,t15);}
        else{r0=vaddq_s16(r0,t0);r1=vaddq_s16(r1,t1);r2=vaddq_s16(r2,t2);r3=vaddq_s16(r3,t3);r4=vaddq_s16(r4,t4);r5=vaddq_s16(r5,t5);r6=vaddq_s16(r6,t6);r7=vaddq_s16(r7,t7);r8=vaddq_s16(r8,t8);r9=vaddq_s16(r9,t9);r10=vaddq_s16(r10,t10);r11=vaddq_s16(r11,t11);r12=vaddq_s16(r12,t12);r13=vaddq_s16(r13,t13);r14=vaddq_s16(r14,t14);r15=vaddq_s16(r15,t15);}
      }
    }
    vst1q_u8(bytes+512+2*j+0,vreinterpretq_u8_s16(r0));
    vst1q_u8(bytes+512+2*j+16,vreinterpretq_u8_s16(r1));
    vst1q_u8(bytes+512+2*j+32,vreinterpretq_u8_s16(r2));
    vst1q_u8(bytes+512+2*j+48,vreinterpretq_u8_s16(r3));
    vst1q_u8(bytes+512+2*j+64,vreinterpretq_u8_s16(r4));
    vst1q_u8(bytes+512+2*j+80,vreinterpretq_u8_s16(r5));
    vst1q_u8(bytes+512+2*j+96,vreinterpretq_u8_s16(r6));
    vst1q_u8(bytes+512+2*j+112,vreinterpretq_u8_s16(r7));
    vst1q_u8(bytes+512+2*j+128,vreinterpretq_u8_s16(r8));
    vst1q_u8(bytes+512+2*j+144,vreinterpretq_u8_s16(r9));
    vst1q_u8(bytes+512+2*j+160,vreinterpretq_u8_s16(r10));
    vst1q_u8(bytes+512+2*j+176,vreinterpretq_u8_s16(r11));
    vst1q_u8(bytes+512+2*j+192,vreinterpretq_u8_s16(r12));
    vst1q_u8(bytes+512+2*j+208,vreinterpretq_u8_s16(r13));
    vst1q_u8(bytes+512+2*j+224,vreinterpretq_u8_s16(r14));
    vst1q_u8(bytes+512+2*j+240,vreinterpretq_u8_s16(r15));
  }
#else
  for(unsigned j=0;j<256;j+=32){
    int16x8_t r0=vdupq_n_s16(0),r1=r0,r2=r0,r3=r0;
    for(unsigned phase=0;phase<2;phase++){
      unsigned begin=phase?(unsigned)index[0]+1:1,end=phase?tau:(unsigned)index[0];
      for(unsigned first=begin;first<=end;first+=chunk){
        unsigned last=end-first<chunk-1?end:first+chunk-1;
        int8x16_t s0=vdupq_n_s8(0),s1=s0;
        for(unsigned k=first;k<=last;k++){
          const int8_t *p=(const int8_t*)(bytes+256+j-index[k]);
          s0=vaddq_s8(s0,vld1q_s8(p));s1=vaddq_s8(s1,vld1q_s8(p+16));
        }
        int16x8_t t0=vmovl_s8(vget_low_s8(s0)),t1=vmovl_high_s8(s0);
        int16x8_t t2=vmovl_s8(vget_low_s8(s1)),t3=vmovl_high_s8(s1);
        if(phase){r0=vsubq_s16(r0,t0);r1=vsubq_s16(r1,t1);r2=vsubq_s16(r2,t2);r3=vsubq_s16(r3,t3);}
        else{r0=vaddq_s16(r0,t0);r1=vaddq_s16(r1,t1);r2=vaddq_s16(r2,t2);r3=vaddq_s16(r3,t3);}
      }
    }
    /* Character stores preserve the declared int32 effective type. */
    vst1q_u8(bytes+512+2*j,vreinterpretq_u8_s16(r0));
    vst1q_u8(bytes+512+2*j+16,vreinterpretq_u8_s16(r1));
    vst1q_u8(bytes+512+2*j+32,vreinterpretq_u8_s16(r2));
    vst1q_u8(bytes+512+2*j+48,vreinterpretq_u8_s16(r3));
  }
#endif

}

/* Decode parameter and accumulation chunk are independent: eta4's legal
 * chunk31 must still decode four-bit eta4 codewords. Bounds:60*2=120,
 * 31*4=124; encoded fallback25*5=125,11*11=121, all below int8 max. */
static inline void lc_sparse8_product_packed_i16(int32_t out[256],const uint8_t *packed,
    const uint8_t index[61],unsigned tau,unsigned chunk) {
  lc_sparse8_product_packed_i16_eta(out,packed,index,tau,chunk,chunk==11?4:2);
}

#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3"),noinline,noclone))
#endif
static uint32_t lc_sparse8_consume(int32_t out[256],const int32_t base[256],const int32_t narrow_owner[256],uint32_t bound,unsigned subtract) {
  const uint8_t *tail=(const uint8_t*)narrow_owner+512;
  const uint32x4_t mask=vdupq_n_u32(0u-(uint32_t)(subtract!=0));
  uint32x4_t invalid=vdupq_n_u32(0),limit=vdupq_n_u32(bound);
  for(unsigned j=0;j<256;j+=8) {
    int16x8_t n=vreinterpretq_s16_u8(vld1q_u8(tail+2*j));
    int32x4_t a=vmovl_s16(vget_low_s16(n)),b=vmovl_high_s16(n);
    a=vsubq_s32(vreinterpretq_s32_u32(veorq_u32(vreinterpretq_u32_s32(a),mask)),vreinterpretq_s32_u32(mask));
    b=vsubq_s32(vreinterpretq_s32_u32(veorq_u32(vreinterpretq_u32_s32(b),mask)),vreinterpretq_s32_u32(mask));
    a=vaddq_s32(vld1q_s32(base+j),a);b=vaddq_s32(vld1q_s32(base+j+4),b);
    invalid=vorrq_u32(invalid,vcgeq_u32(vreinterpretq_u32_s32(vabsq_s32(a)),limit));
    invalid=vorrq_u32(invalid,vcgeq_u32(vreinterpretq_u32_s32(vabsq_s32(b)),limit));
    vst1q_s32(out+j,a);vst1q_s32(out+j+4,b);
  }
  return vmaxvq_u32(invalid)>>31;
}
#endif
