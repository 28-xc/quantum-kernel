/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "lc_inplace_sampling.h"
typedef union {int32_t coeff[256];uint8_t byte[1024];} poly;
static unsigned oracle(int32_t *out,unsigned n,const uint8_t *src,unsigned len) {
  for(unsigned p=0;n<256 && p+3<=len;p+=3) {
    uint32_t x=((uint32_t)src[p]|((uint32_t)src[p+1]<<8)|((uint32_t)src[p+2]<<16))&0x7fffff;
    if(x<8380417)out[n++]=(int32_t)x;
  }
  return n;
}
int main(void) {
  const uint32_t edges[]={0,1,8380416,8380417,8380418,8388607,0xffffff,0x800000};
  unsigned cases=0;
  for(unsigned before=0;before<256;before++)for(unsigned mode=0;mode<9;mode++)for(unsigned len=0;len<=168;len++) {
    struct {uint32_t left[8];poly p;uint32_t right[8];} b;
    uint8_t src[840];int32_t expected[256];memset(&b,0xa5,sizeof(b));
    for(unsigned j=0;j<before;j++) {expected[j]=(int32_t)(j*1237);lc_store_signed24(b.p.byte+3*j,expected[j]);}
    for(unsigned j=0;j<sizeof(src);j+=3) {
      uint32_t x=edges[mode==8?(j/3)%8:mode];src[j]=(uint8_t)x;src[j+1]=(uint8_t)(x>>8);src[j+2]=(uint8_t)(x>>16);
    }
    memcpy(b.p.byte+3*before,src,len);
    unsigned want=oracle(expected,before,src,len),got=lc_reject_compact24(b.p.byte,before,3*before,len);
    assert(want==got);
    for(unsigned j=0;j<got;j++)assert(lc_load_signed24(b.p.byte+3*j)==expected[j]);
    for(unsigned j=0;j<8;j++)assert(b.left[j]==0xa5a5a5a5u && b.right[j]==0xa5a5a5a5u);
    cases++;
  }
  for(unsigned mode=0;mode<9;mode++) {
    poly p;uint8_t src[840];int32_t ref[256];
    memset(&p,0xa5,sizeof(p));
    for(unsigned j=0;j<840;j+=3) {uint32_t x=edges[mode==8?(j/3)%8:mode];src[j]=(uint8_t)x;src[j+1]=(uint8_t)(x>>8);src[j+2]=(uint8_t)(x>>16);}
    memcpy(p.byte,src,840);unsigned want=oracle(ref,0,src,840),got=lc_reject_compact24(p.byte,0,0,840);assert(got==want);
    /* Artificially force multiple rejecting continuation blocks, then accept. */
    for(unsigned round=0;round<8 && got<256;round++) {
      memset(src,round<7?0xff:0,168);memcpy(p.byte+3*got,src,168);
      want=oracle(ref,want,src,168);got=lc_reject_compact24(p.byte,got,3*got,168);assert(want==got);
    }
    while(got<256) {memset(src,0,168);memcpy(p.byte+3*got,src,168);want=oracle(ref,want,src,168);got=lc_reject_compact24(p.byte,got,3*got,168);assert(want==got);}
    lc_expand_unsigned24(p.coeff);assert(memcmp(p.coeff,ref,sizeof(ref))==0);cases++;
  }
  for(unsigned bits=18;bits<=20;bits+=2)for(unsigned mode=0;mode<256;mode++) {
    poly p;uint8_t src[680];int32_t expected[256];
    for(unsigned j=0;j<sizeof(src);j++)src[j]=(uint8_t)(mode<4?(unsigned[]){0,255,0x55,0xaa}[mode]:mode*17+j*13);
    memcpy(p.byte,src,sizeof(src));
    for(unsigned j=0;j<256;j++) {unsigned bit=j*bits,pos=bit/8;uint32_t x=(uint32_t)src[pos]|((uint32_t)src[pos+1]<<8)|((uint32_t)src[pos+2]<<16);expected[j]=(1<<(bits-1))-(int32_t)((x>>(bit%8))&((1u<<bits)-1));}
    lc_expand_gamma(p.coeff,bits,1<<(bits-1));assert(memcmp(p.coeff,expected,sizeof(expected))==0);cases++;
  }
  const int32_t signed_edges[]={-8388608,-8380417,-6283009,-1,0,1,6283009,8380417,8388607};
  for(unsigned j=0;j<sizeof(signed_edges)/sizeof(signed_edges[0]);j++) {uint8_t p[3];lc_store_signed24(p,signed_edges[j]);assert(lc_load_signed24(p)==signed_edges[j]);cases++;}
  printf("PASS fixed_boundary_cases=%u rejection_prefixes=256 short_tails=169 gamma_widths=18,20\n",cases);
  return 0;
}
