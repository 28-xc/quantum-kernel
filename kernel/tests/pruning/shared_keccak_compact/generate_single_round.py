"""Derive a one-round loop from the attributed two-round portable body.

The transformation changes loop unrolling only. Every theta/rho/pi/chi/iota
operation and each of the 24 round constants is retained. See oracle.c for
an independently compiled original mldsa-native permutation comparison.
"""
from pathlib import Path
import hashlib, re
ROOT=Path(__file__).resolve().parents[3]
SOURCE=ROOT/'third_party/mlkem-native/mlkem/src/fips202/keccakf1600.c'
def generate():
    source=SOURCE.read_text(encoding='utf-8')
    constants=source[source.index('static const uint64_t mlk_KeccakF_RoundConstants'):source.index('MLK_STATIC_TESTABLE\nvoid mlk_keccakf1600_permute_c')]
    body=source[source.index('  unsigned round;',source.index('void mlk_keccakf1600_permute_c')):source.index('\nvoid mlk_keccakf1600_permute(uint64_t *state)')]
    second=body.index('    /* prepareTheta */\n    BCa = Eba')
    copyback=body.index('  /* copyToState(state, A) */')
    names=re.findall(r'  (A\w{2}) = state\[\d+\];',body)
    assert len(names)==25 and len(set(names))==25
    first=body[:second]
    first=first.replace('round += 2','round++')
    first=re.sub(r'  __loop__\(invariant\(round <= MLK_KECCAK_NROUNDS && round % 2 == 0\)\n           decreases\(MLK_KECCAK_NROUNDS - round\)\)\n','',first)
    assert '__loop__' not in first and 'round + 1' not in first
    result='''/* Derived from mlkem-native's portable Keccak-f[1600].
 * Copyright (c) The mlkem-native project authors.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Original sources: mupq, SUPERCOP Keccak and tweetfips202, credited in the
 * bundled upstream source. One-round loop derived by generate_single_round.py;
 * standard 24-round permutation, round constants and Boolean equations intact.
 */
#include "shared.h"
#define MLK_KECCAK_NROUNDS 24
#define MLK_KECCAK_ROL(a, n) (((a) << (n)) ^ ((a) >> (64 - (n))))
'''
    result+='/* Upstream SHA-256: '+hashlib.sha256(SOURCE.read_bytes()).hexdigest()+' */\n'
    result+=constants+'void lc_shared_keccakf1600(uint64_t *state)\n{\n'+first
    result+='    /* Next iteration uses the completed round. */\n'
    result+=''.join('    '+n+' = E'+n[1:]+';\n' for n in names)
    result+='  }\n\n'+body[copyback:]
    return result
if __name__=='__main__':
    out=ROOT/'configs/shared_keccak_compact/owner_single.c'
    out.write_text(generate(),encoding='utf-8')
    print(out)
