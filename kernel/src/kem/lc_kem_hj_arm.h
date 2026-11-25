/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * AArch64 canonical-state schedule: H(pk), J(z || ciphertext), and two
 * independent public matrix streams share a four-lane permutation.
 * Public streams are replaced only after all 256 coefficients are retained.
 * Uses the existing SHA3/SHAKE padding, matrix order and rejection rules.
 */
#ifndef LC_KEM_HJ_ARM_H
#define LC_KEM_HJ_ARM_H
typedef struct {
  MLK_ALIGN uint64_t state[100];
  MLK_ALIGN int16_t polynomial[2][256];
  MLK_ALIGN int16_t decoded[256];
  MLK_ALIGN uint8_t rate[168];
} lc_kem_hj_arm_scratch;
static void lc_hja_xor(uint64_t *state, const uint8_t *bytes,
                       unsigned first, unsigned words)
{
  for (unsigned i = 0; i < words; ++i) {
    uint64_t word; mlk_memcpy(&word, bytes + 8*i, 8);
    state[first+i] ^= word;
  }
}
static void lc_hja_matrix(uint64_t *state, const uint8_t rho[32],
                          unsigned index, unsigned rank)
{
  mlk_memset(state, 0, 200);
  lc_hja_xor(state, rho, 0, 4);
  state[4] = (uint64_t)(index/rank) | ((uint64_t)(index%rank) << 8)
             | ((uint64_t)0x1f << 16);
  state[20] = (uint64_t)0x80 << 56;
}
static MLK_NOINLINE
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((noclone))
#endif
void lc_kem_hj_arm(uint8_t h[32], uint8_t j[32], uint8_t *prefix,
    const uint8_t *pk, const uint8_t *ct, const uint8_t z[32],
    unsigned rank, unsigned ctbytes, unsigned prefix_rows,
    lc_kem_hj_arm_scratch *scratch)
{
  uint64_t *state = scratch->state;
  const unsigned pkbytes = 384*rank+32, hash_blocks = 3*rank;
  const unsigned matrices = prefix_rows*rank;
  unsigned count[2] = {0,0}, index[2] = {0,1};
  mlk_memset(state, 0, sizeof(scratch->state));
  for (unsigned lane = 0; lane < 2; ++lane)
    lc_hja_matrix(state+25*(lane+2),pk+pkbytes-32,lane,rank);
  for (unsigned round = 0;
       round < hash_blocks || index[0] < matrices || index[1] < matrices;
       ++round) {
    if (round < hash_blocks) {
      unsigned pos = 136*round, hn = pkbytes-pos, jn = ctbytes+32-pos;
      if (hn > 136) hn = 136;
      if (jn > 136) jn = 136;
      lc_hja_xor(state,pk+pos,0,hn/8);
      if (round == 0) {
        lc_hja_xor(state+25,z,0,4);lc_hja_xor(state+25,ct,4,13);
      } else lc_hja_xor(state+25,ct+pos-32,0,jn/8);
      if (round+1 == hash_blocks) {
        state[hn/8] ^= 6; state[25+jn/8] ^= 31;
        state[16] ^= (uint64_t)0x80 << 56;
        state[25+16] ^= (uint64_t)0x80 << 56;
      }
    }
    /* Canonical 25-word lane order is the AArch64 Keccak API contract. */
    if (index[0] >= matrices && index[1] >= matrices) {
      mlk_keccakf1600_permute(state);mlk_keccakf1600_permute(state+25);
    } else mlk_keccakf1600x4_permute(state);
    if (round+1 == hash_blocks) {
      mlk_memcpy(h,state,32);mlk_memcpy(j,state+25,32);
      mlk_zeroize(state+25,200);
    }
    for (unsigned lane = 0; lane < 2; ++lane) if (index[lane] < matrices) {
      mlk_memcpy(scratch->rate,state+25*(lane+2),168);
      unsigned n=lc_kem_reject_rate(scratch->decoded,0,scratch->rate,168);
      if (n > 256-count[lane]) n = 256-count[lane];
      mlk_memcpy(scratch->polynomial[lane]+count[lane],scratch->decoded,2*n);
      count[lane] += n;
      if (count[lane] == 256) {
        uint8_t *out = prefix+384*index[lane];
        for (unsigned i=0;i<128;++i) {
          unsigned a=(uint16_t)scratch->polynomial[lane][2*i];
          unsigned b=(uint16_t)scratch->polynomial[lane][2*i+1];
          out[3*i]=(uint8_t)a;out[3*i+1]=(uint8_t)((a>>8)|(b<<4));
          out[3*i+2]=(uint8_t)(b>>4);
        }
        index[lane]+=2;count[lane]=0;
        if(index[lane]<matrices)
          lc_hja_matrix(state+25*(lane+2),pk+pkbytes-32,index[lane],rank);
      }
    }
  }
  mlk_zeroize(scratch,sizeof(*scratch));
}
#endif
