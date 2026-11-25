/* Derived from mlkem-native's portable Keccak-f[1600].
 * Copyright (c) The mlkem-native project authors.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Original sources: mupq, SUPERCOP Keccak and tweetfips202, credited in the
 * bundled upstream source. One-round loop derived by generate_single_round.py;
 * standard 24-round permutation, round constants and Boolean equations intact.
 */
#include "shared.h"
#define MLK_KECCAK_NROUNDS 24
#define MLK_KECCAK_ROL(a, n) (((a) << (n)) ^ ((a) >> (64 - (n))))
/* Upstream SHA-256: f3f4adef946db4159567550c2b80d542df6d466b39b0c6696a1162f8754adcff */
static const uint64_t mlk_KeccakF_RoundConstants[MLK_KECCAK_NROUNDS] = {
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

void lc_shared_keccakf1600(uint64_t *state)
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

  for (round = 0; round < MLK_KECCAK_NROUNDS; round++)
  {
    /* prepareTheta */
    BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
    BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
    BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
    BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
    BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

    /* thetaRhoPiChiIotaPrepareTheta(round, A, E) */
    Da = BCu ^ MLK_KECCAK_ROL(BCe, 1);
    De = BCa ^ MLK_KECCAK_ROL(BCi, 1);
    Di = BCe ^ MLK_KECCAK_ROL(BCo, 1);
    Do = BCi ^ MLK_KECCAK_ROL(BCu, 1);
    Du = BCo ^ MLK_KECCAK_ROL(BCa, 1);

    Aba ^= Da;
    BCa = Aba;
    Age ^= De;
    BCe = MLK_KECCAK_ROL(Age, 44);
    Aki ^= Di;
    BCi = MLK_KECCAK_ROL(Aki, 43);
    Amo ^= Do;
    BCo = MLK_KECCAK_ROL(Amo, 21);
    Asu ^= Du;
    BCu = MLK_KECCAK_ROL(Asu, 14);
    Eba = BCa ^ ((~BCe) & BCi);
    Eba ^= (uint64_t)mlk_KeccakF_RoundConstants[round];
    Ebe = BCe ^ ((~BCi) & BCo);
    Ebi = BCi ^ ((~BCo) & BCu);
    Ebo = BCo ^ ((~BCu) & BCa);
    Ebu = BCu ^ ((~BCa) & BCe);

    Abo ^= Do;
    BCa = MLK_KECCAK_ROL(Abo, 28);
    Agu ^= Du;
    BCe = MLK_KECCAK_ROL(Agu, 20);
    Aka ^= Da;
    BCi = MLK_KECCAK_ROL(Aka, 3);
    Ame ^= De;
    BCo = MLK_KECCAK_ROL(Ame, 45);
    Asi ^= Di;
    BCu = MLK_KECCAK_ROL(Asi, 61);
    Ega = BCa ^ ((~BCe) & BCi);
    Ege = BCe ^ ((~BCi) & BCo);
    Egi = BCi ^ ((~BCo) & BCu);
    Ego = BCo ^ ((~BCu) & BCa);
    Egu = BCu ^ ((~BCa) & BCe);

    Abe ^= De;
    BCa = MLK_KECCAK_ROL(Abe, 1);
    Agi ^= Di;
    BCe = MLK_KECCAK_ROL(Agi, 6);
    Ako ^= Do;
    BCi = MLK_KECCAK_ROL(Ako, 25);
    Amu ^= Du;
    BCo = MLK_KECCAK_ROL(Amu, 8);
    Asa ^= Da;
    BCu = MLK_KECCAK_ROL(Asa, 18);
    Eka = BCa ^ ((~BCe) & BCi);
    Eke = BCe ^ ((~BCi) & BCo);
    Eki = BCi ^ ((~BCo) & BCu);
    Eko = BCo ^ ((~BCu) & BCa);
    Eku = BCu ^ ((~BCa) & BCe);

    Abu ^= Du;
    BCa = MLK_KECCAK_ROL(Abu, 27);
    Aga ^= Da;
    BCe = MLK_KECCAK_ROL(Aga, 36);
    Ake ^= De;
    BCi = MLK_KECCAK_ROL(Ake, 10);
    Ami ^= Di;
    BCo = MLK_KECCAK_ROL(Ami, 15);
    Aso ^= Do;
    BCu = MLK_KECCAK_ROL(Aso, 56);
    Ema = BCa ^ ((~BCe) & BCi);
    Eme = BCe ^ ((~BCi) & BCo);
    Emi = BCi ^ ((~BCo) & BCu);
    Emo = BCo ^ ((~BCu) & BCa);
    Emu = BCu ^ ((~BCa) & BCe);

    Abi ^= Di;
    BCa = MLK_KECCAK_ROL(Abi, 62);
    Ago ^= Do;
    BCe = MLK_KECCAK_ROL(Ago, 55);
    Aku ^= Du;
    BCi = MLK_KECCAK_ROL(Aku, 39);
    Ama ^= Da;
    BCo = MLK_KECCAK_ROL(Ama, 41);
    Ase ^= De;
    BCu = MLK_KECCAK_ROL(Ase, 2);
    Esa = BCa ^ ((~BCe) & BCi);
    Ese = BCe ^ ((~BCi) & BCo);
    Esi = BCi ^ ((~BCo) & BCu);
    Eso = BCo ^ ((~BCu) & BCa);
    Esu = BCu ^ ((~BCa) & BCe);

    /* Next iteration uses the completed round. */
    Aba = Eba;
    Abe = Ebe;
    Abi = Ebi;
    Abo = Ebo;
    Abu = Ebu;
    Aga = Ega;
    Age = Ege;
    Agi = Egi;
    Ago = Ego;
    Agu = Egu;
    Aka = Eka;
    Ake = Eke;
    Aki = Eki;
    Ako = Eko;
    Aku = Eku;
    Ama = Ema;
    Ame = Eme;
    Ami = Emi;
    Amo = Emo;
    Amu = Emu;
    Asa = Esa;
    Ase = Ese;
    Asi = Esi;
    Aso = Eso;
    Asu = Esu;
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
