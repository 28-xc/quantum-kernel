/* SPDX-License-Identifier: Apache-2.0
 * ML-DSA-65 first two public A entries and first two ExpandMask streams.
 * Four independent canonical Keccak states use rates168/168/136/136.
 * Each disjoint destination has its exact byte extent; no external output
 * is borrowed. Only public matrix rejection counts control the loop. */
#ifndef LC_MIXED_HEAD65_H
#define LC_MIXED_HEAD65_H
static void lc_mixed_head65_fill(uint64_t state[100],const uint8_t rho[32],
    const uint8_t rhoprime[64],uint16_t kappa,uint8_t matrix[1536],
    uint8_t gamma0[640],uint8_t gamma1[640]) {
  unsigned ctr[2]={0,0},block=0;
  mld_memset(state,0,800);
  for(unsigned lane=0;lane<4;lane++) {
    uint8_t *s=(uint8_t *)(state+25*lane);
    if(lane<2) {
      mld_memcpy(s,rho,32);s[32]=0;s[33]=(uint8_t)lane;s[34]=0x1f;s[167]=0x80;
    } else {
      uint16_t nonce=(uint16_t)(kappa+lane-2);
      mld_memcpy(s,rhoprime,64);s[64]=(uint8_t)nonce;s[65]=(uint8_t)(nonce>>8);
      s[66]=0x1f;s[135]=0x80;
    }
  }
  do {
    mld_keccakf1600x4_permute(state);
    if(block<5) {
      unsigned bytes=block==4?96:136;
      mld_memcpy(gamma0+136*block,state+50,bytes);
      mld_memcpy(gamma1+136*block,state+75,bytes);
    }
    for(unsigned lane=0;lane<2;lane++) {
      const uint8_t *rate=(const uint8_t *)(state+25*lane);
      uint8_t *out=matrix+768*lane;
      for(unsigned j=0;ctr[lane]<256 && j+3<=168;) {
        uint32x4_t a,b;
        if(j+24<=168 && ctr[lane]+8<=256 && lc_stream_public8(rate+j,&a,&b)) {
          lc_stream_pack8(out+3*ctr[lane],vreinterpretq_s32_u32(a),vreinterpretq_s32_u32(b));
          ctr[lane]+=8;j+=24;continue;
        }
        uint32_t x=((uint32_t)rate[j]|((uint32_t)rate[j+1]<<8)|((uint32_t)rate[j+2]<<16))&0x7fffffu;
        j+=3;
        if(x<8380417u) {unsigned i=3*ctr[lane]++;out[i]=(uint8_t)x;out[i+1]=(uint8_t)(x>>8);out[i+2]=(uint8_t)(x>>16);}
      }
    }
    block++;
  } while(ctr[0]<256 || ctr[1]<256);
  /* Four rate168 blocks contain224 candidates: gamma always completes its
   * five blocks before the public matrix streams can finish. */
  mld_zeroize(state,800);
}
#endif
