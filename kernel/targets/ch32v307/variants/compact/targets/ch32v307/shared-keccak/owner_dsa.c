/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [mupq]
 *   Common files for pqm4, pqm3, pqriscv
 *   Kannwischer, Petri, Rijneveld, Schwabe, Stoffelen
 *   https://github.com/mupq/mupq
 *
 * - [supercop]
 *   SUPERCOP benchmarking framework
 *   Daniel J. Bernstein
 *   http://bench.cr.yp.to/supercop.html
 *
 * - [tweetfips]
 *   'tweetfips202' FIPS202 implementation
 *   Van Assche, Bernstein, Schwabe
 *   https://keccak.team/2015/tweetfips202.html
 */

/* Based on the CC0 implementation from @[mupq] and the public domain
 * implementation @[supercop, crypto_hash/keccakc512/simple/]
 * by Ronny Van Keer, and the public domain @[tweetfips] implementation. */

/* Isolated sharing candidate: constants and complete two-round function
 * below are copied exactly from the frozen portable DSA source, except the
 * exported function name. Normal portable annotations expand to nothing;
 * MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202 is intentionally not defined for
 * this standalone owner, matching the original portable Os function. */
#include "shared.h"
#define MLD_STATIC_TESTABLE
#define __contract__(...)
#define __loop__(...)
#define MLD_KECCAK_NROUNDS 24
#define MLD_KECCAK_ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))
static const uint64_t mld_KeccakF_RoundConstants[MLD_KECCAK_NROUNDS] = {
    (uint64_t)0x0000000000000001ULL, (uint64_t)0x0000000000008082ULL,
    (uint64_t)0x800000000000808aULL, (uint64_t)0x8000000080008000ULL,
    (uint64_t)0x000000000000808bULL, (uint64_t)0x0000000080000001ULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008009ULL,
    (uint64_t)0x000000000000008aULL, (uint64_t)0x0000000000000088ULL,
    (uint64_t)0x0000000080008009ULL, (uint64_t)0x000000008000000aULL,
    (uint64_t)0x000000008000808bULL, (uint64_t)0x800000000000008bULL,
    (uint64_t)0x8000000000008089ULL, (uint64_t)0x8000000000008003ULL,
    (uint64_t)0x8000000000008002ULL, (uint64_t)0x8000000000000080ULL,
    (uint64_t)0x000000000000800aULL, (uint64_t)0x800000008000000aULL,
    (uint64_t)0x8000000080008081ULL, (uint64_t)0x8000000000008080ULL,
    (uint64_t)0x0000000080000001ULL, (uint64_t)0x8000000080008008ULL};

MLD_STATIC_TESTABLE
#if defined(MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202)
__attribute__((optimize("O3")))
#endif
void lc_shared_keccakf1600(uint64_t *state)
__contract__(
    requires(memory_no_alias(state, sizeof(uint64_t) * MLD_KECCAK_LANES))
    assigns(memory_slice(state, sizeof(uint64_t) * MLD_KECCAK_LANES))
)
{
  unsigned round;

  uint64_t Aba, Abe, Abi, Abo, Abu;
  uint64_t Aga, Age, Agi, Ago, Agu;
  uint64_t Aka, Ake, Aki, Ako, Aku;
  uint64_t Ama, Ame, Ami, Amo, Amu;
  uint64_t Asa, Ase, Asi, Aso, Asu;
  uint64_t BCa, BCe, BCi, BCo, BCu;
  uint64_t Da, De, Di, Do, Du;
  uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
  uint64_t Ega, Ege, Egi, Ego, Egu;
  uint64_t Eka, Eke, Eki, Eko, Eku;
  uint64_t Ema, Eme, Emi, Emo, Emu;
  uint64_t Esa, Ese, Esi, Eso, Esu;

  /* copyFromState(A, state) */
  Aba = state[0];
  Abe = state[1];
  Abi = state[2];
  Abo = state[3];
  Abu = state[4];
  Aga = state[5];
  Age = state[6];
  Agi = state[7];
  Ago = state[8];
  Agu = state[9];
  Aka = state[10];
  Ake = state[11];
  Aki = state[12];
  Ako = state[13];
  Aku = state[14];
  Ama = state[15];
  Ame = state[16];
  Ami = state[17];
  Amo = state[18];
  Amu = state[19];
  Asa = state[20];
  Ase = state[21];
  Asi = state[22];
  Aso = state[23];
  Asu = state[24];

  for (round = 0; round < MLD_KECCAK_NROUNDS; round += 2)
  __loop__(invariant(round <= MLD_KECCAK_NROUNDS && round % 2 == 0)
           decreases(MLD_KECCAK_NROUNDS - round))
  {
    /* prepareTheta */
    BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    /* thetaRhoPiChiIotaPrepareTheta(round, A, E) */
    Da = BCu ^ MLD_KECCAK_ROL(BCe, 1);
    De = BCa ^ MLD_KECCAK_ROL(BCi, 1);
    Di = BCe ^ MLD_KECCAK_ROL(BCo, 1);
    Do = BCi ^ MLD_KECCAK_ROL(BCu, 1);
    Du = BCo ^ MLD_KECCAK_ROL(BCa, 1);

    Aba ^= Da;
    BCa = Aba;
    Age ^= De;
    BCe = MLD_KECCAK_ROL(Age, 44);
    Aki ^= Di;
    BCi = MLD_KECCAK_ROL(Aki, 43);
    Amo ^= Do;
    BCo = MLD_KECCAK_ROL(Amo, 21);
    Asu ^= Du;
    BCu = MLD_KECCAK_ROL(Asu, 14);
    Eba = BCa ^ ((~BCe) & BCi);
    Eba ^= (uint64_t)mld_KeccakF_RoundConstants[round];
    Ebe = BCe ^ ((~BCi) & BCo);
    Ebi = BCi ^ ((~BCo) & BCu);
    Ebo = BCo ^ ((~BCu) & BCa);
    Ebu = BCu ^ ((~BCa) & BCe);

    Abo ^= Do;
    BCa = MLD_KECCAK_ROL(Abo, 28);
    Agu ^= Du;
    BCe = MLD_KECCAK_ROL(Agu, 20);
    Aka ^= Da;
    BCi = MLD_KECCAK_ROL(Aka, 3);
    Ame ^= De;
    BCo = MLD_KECCAK_ROL(Ame, 45);
    Asi ^= Di;
    BCu = MLD_KECCAK_ROL(Asi, 61);
    Ega = BCa ^ ((~BCe) & BCi);
    Ege = BCe ^ ((~BCi) & BCo);
    Egi = BCi ^ ((~BCo) & BCu);
    Ego = BCo ^ ((~BCu) & BCa);
    Egu = BCu ^ ((~BCa) & BCe);

    Abe ^= De;
    BCa = MLD_KECCAK_ROL(Abe, 1);
    Agi ^= Di;
    BCe = MLD_KECCAK_ROL(Agi, 6);
    Ako ^= Do;
    BCi = MLD_KECCAK_ROL(Ako, 25);
    Amu ^= Du;
    BCo = MLD_KECCAK_ROL(Amu, 8);
    Asa ^= Da;
    BCu = MLD_KECCAK_ROL(Asa, 18);
    Eka = BCa ^ ((~BCe) & BCi);
    Eke = BCe ^ ((~BCi) & BCo);
    Eki = BCi ^ ((~BCo) & BCu);
    Eko = BCo ^ ((~BCu) & BCa);
    Eku = BCu ^ ((~BCa) & BCe);

    Abu ^= Du;
    BCa = MLD_KECCAK_ROL(Abu, 27);
    Aga ^= Da;
    BCe = MLD_KECCAK_ROL(Aga, 36);
    Ake ^= De;
    BCi = MLD_KECCAK_ROL(Ake, 10);
    Ami ^= Di;
    BCo = MLD_KECCAK_ROL(Ami, 15);
    Aso ^= Do;
    BCu = MLD_KECCAK_ROL(Aso, 56);
    Ema = BCa ^ ((~BCe) & BCi);
    Eme = BCe ^ ((~BCi) & BCo);
    Emi = BCi ^ ((~BCo) & BCu);
    Emo = BCo ^ ((~BCu) & BCa);
    Emu = BCu ^ ((~BCa) & BCe);

    Abi ^= Di;
    BCa = MLD_KECCAK_ROL(Abi, 62);
    Ago ^= Do;
    BCe = MLD_KECCAK_ROL(Ago, 55);
    Aku ^= Du;
    BCi = MLD_KECCAK_ROL(Aku, 39);
    Ama ^= Da;
    BCo = MLD_KECCAK_ROL(Ama, 41);
    Ase ^= De;
    BCu = MLD_KECCAK_ROL(Ase, 2);
    Esa = BCa ^ ((~BCe) & BCi);
    Ese = BCe ^ ((~BCi) & BCo);
    Esi = BCi ^ ((~BCo) & BCu);
    Eso = BCo ^ ((~BCu) & BCa);
    Esu = BCu ^ ((~BCa) & BCe);

    /* prepareTheta */
    BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
    BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
    BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
    BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
    BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

    /* thetaRhoPiChiIotaPrepareTheta(round+1, E, A) */
    Da = BCu ^ MLD_KECCAK_ROL(BCe, 1);
    De = BCa ^ MLD_KECCAK_ROL(BCi, 1);
    Di = BCe ^ MLD_KECCAK_ROL(BCo, 1);
    Do = BCi ^ MLD_KECCAK_ROL(BCu, 1);
    Du = BCo ^ MLD_KECCAK_ROL(BCa, 1);

    Eba ^= Da;
    BCa = Eba;
    Ege ^= De;
    BCe = MLD_KECCAK_ROL(Ege, 44);
    Eki ^= Di;
    BCi = MLD_KECCAK_ROL(Eki, 43);
    Emo ^= Do;
    BCo = MLD_KECCAK_ROL(Emo, 21);
    Esu ^= Du;
    BCu = MLD_KECCAK_ROL(Esu, 14);
    Aba = BCa ^ ((~BCe) & BCi);
    Aba ^= (uint64_t)mld_KeccakF_RoundConstants[round + 1];
    Abe = BCe ^ ((~BCi) & BCo);
    Abi = BCi ^ ((~BCo) & BCu);
    Abo = BCo ^ ((~BCu) & BCa);
    Abu = BCu ^ ((~BCa) & BCe);

    Ebo ^= Do;
    BCa = MLD_KECCAK_ROL(Ebo, 28);
    Egu ^= Du;
    BCe = MLD_KECCAK_ROL(Egu, 20);
    Eka ^= Da;
    BCi = MLD_KECCAK_ROL(Eka, 3);
    Eme ^= De;
    BCo = MLD_KECCAK_ROL(Eme, 45);
    Esi ^= Di;
    BCu = MLD_KECCAK_ROL(Esi, 61);
    Aga = BCa ^ ((~BCe) & BCi);
    Age = BCe ^ ((~BCi) & BCo);
    Agi = BCi ^ ((~BCo) & BCu);
    Ago = BCo ^ ((~BCu) & BCa);
    Agu = BCu ^ ((~BCa) & BCe);

    Ebe ^= De;
    BCa = MLD_KECCAK_ROL(Ebe, 1);
    Egi ^= Di;
    BCe = MLD_KECCAK_ROL(Egi, 6);
    Eko ^= Do;
    BCi = MLD_KECCAK_ROL(Eko, 25);
    Emu ^= Du;
    BCo = MLD_KECCAK_ROL(Emu, 8);
    Esa ^= Da;
    BCu = MLD_KECCAK_ROL(Esa, 18);
    Aka = BCa ^ ((~BCe) & BCi);
    Ake = BCe ^ ((~BCi) & BCo);
    Aki = BCi ^ ((~BCo) & BCu);
    Ako = BCo ^ ((~BCu) & BCa);
    Aku = BCu ^ ((~BCa) & BCe);

    Ebu ^= Du;
    BCa = MLD_KECCAK_ROL(Ebu, 27);
    Ega ^= Da;
    BCe = MLD_KECCAK_ROL(Ega, 36);
    Eke ^= De;
    BCi = MLD_KECCAK_ROL(Eke, 10);
    Emi ^= Di;
    BCo = MLD_KECCAK_ROL(Emi, 15);
    Eso ^= Do;
    BCu = MLD_KECCAK_ROL(Eso, 56);
    Ama = BCa ^ ((~BCe) & BCi);
    Ame = BCe ^ ((~BCi) & BCo);
    Ami = BCi ^ ((~BCo) & BCu);
    Amo = BCo ^ ((~BCu) & BCa);
    Amu = BCu ^ ((~BCa) & BCe);

    Ebi ^= Di;
    BCa = MLD_KECCAK_ROL(Ebi, 62);
    Ego ^= Do;
    BCe = MLD_KECCAK_ROL(Ego, 55);
    Eku ^= Du;
    BCi = MLD_KECCAK_ROL(Eku, 39);
    Ema ^= Da;
    BCo = MLD_KECCAK_ROL(Ema, 41);
    Ese ^= De;
    BCu = MLD_KECCAK_ROL(Ese, 2);
    Asa = BCa ^ ((~BCe) & BCi);
    Ase = BCe ^ ((~BCi) & BCo);
    Asi = BCi ^ ((~BCo) & BCu);
    Aso = BCo ^ ((~BCu) & BCa);
    Asu = BCu ^ ((~BCa) & BCe);
  }

  /* copyToState(state, A) */
  state[0] = Aba;
  state[1] = Abe;
  state[2] = Abi;
  state[3] = Abo;
  state[4] = Abu;
  state[5] = Aga;
  state[6] = Age;
  state[7] = Agi;
  state[8] = Ago;
  state[9] = Agu;
  state[10] = Aka;
  state[11] = Ake;
  state[12] = Aki;
  state[13] = Ako;
  state[14] = Aku;
  state[15] = Ama;
  state[16] = Ame;
  state[17] = Ami;
  state[18] = Amo;
  state[19] = Amu;
  state[20] = Asa;
  state[21] = Ase;
  state[22] = Asi;
  state[23] = Aso;
  state[24] = Asu;
}

