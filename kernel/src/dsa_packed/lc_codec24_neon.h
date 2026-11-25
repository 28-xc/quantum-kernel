/* SPDX-License-Identifier: Apache-2.0
 * Exact signed 24-bit NTT storage, with canonical coefficient order.
 * Packing accepts the reduce32 input range used by the NTT interfaces.
 * The buffers may be disjoint or share exactly the same starting address.
 */
#ifndef LC_CODEC24_NEON_H
#define LC_CODEC24_NEON_H
#include "lc_stream_neon.h"
static void lc_codec24_pack_neon(uint8_t *out,const int32_t *in) {
  for(unsigned i=0;i<256;i+=8) {
    int32x4_t lo=vld1q_s32(in+i),hi=vld1q_s32(in+i+4);
    lc_stream_pack8(out+3*i,lc_stream_reduce32(lo),lc_stream_reduce32(hi));
  }
}
static void lc_codec24_unpack_neon(int32_t *out,const uint8_t *in) {
  /* Reverse expansion preserves every unread input byte for exact aliasing. */
  for(unsigned end=256;end>0;end-=8) {
    unsigned i=end-8;uint32x4_t lo,hi;
    lc_stream_unpack8(in+3*i,&lo,&hi);
    vst1q_s32(out+i,lc_stream_signed24(lo));
    vst1q_s32(out+i+4,lc_stream_signed24(hi));
  }
}
#endif
