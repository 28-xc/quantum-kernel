/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Little-endian Keccak byte access. The caller retains the upstream contract:
 * offset+length <=200; the state and data ranges do not overlap. Zero length
 * performs no access. memcpy gives defined unaligned loads and stores. */
#ifndef LC_KECCAK_BYTEOPS_H
#define LC_KECCAK_BYTEOPS_H
#include <stdint.h>
#include <string.h>
static inline void lc_keccak_extract_bulk(uint64_t *state,unsigned char *data,
                                          unsigned offset,unsigned length) {
  if(length)memcpy(data,(const unsigned char *)state+offset,length);
}
static inline void lc_keccak_xor_bulk(uint64_t *state,const unsigned char *data,
                                      unsigned offset,unsigned length) {
  unsigned char *dest=(unsigned char *)state+offset;
  unsigned i=0;
  for(;length-i>=8;i+=8) {
    uint64_t left,right;
    memcpy(&left,dest+i,8);memcpy(&right,data+i,8);left^=right;
    memcpy(dest+i,&left,8);
  }
  for(;i<length;i++)dest[i]^=data[i];
}
#endif
