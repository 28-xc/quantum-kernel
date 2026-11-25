"""Derive the canonical scalar component's FIPS roots; no copied root table."""
from pathlib import Path
import argparse
ROOT=Path(__file__).resolve().parents[1]

def generate():
 parts=['/* Generated from FIPS 203/204 roots. Regenerate with tools/generate_arithmetic.py. */']
 for q,root,bits in [(3329,17,7),(8380417,1753,8)]:
  pref=f'q{q}'
  br=lambda n:int(f'{n:0{bits}b}'[::-1],2)
  z=[pow(root,br(i),q) for i in range(1<<bits)]
  table=',\n'.join('  '+', '.join(str(v)+'u' for v in z[i:i+8]) for i in range(0,len(z),8))
  parts.append(f'''static const uint32_t {pref}_z[{1<<bits}] = {{\n{table}\n}};
#define Q {q}u
#define PREFIX {pref}
#define LAYERS {bits}
#define INVERSE_N {pow(1<<bits,-1,q)}u
#include "canonical_template.inc"
#undef Q
#undef PREFIX
#undef LAYERS
#undef INVERSE_N
''')
 return '\n'.join(parts)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,default=ROOT/'src/backends/canonical_generated.inc');p.add_argument('--check',action='store_true');a=p.parse_args();text=generate()
 if a.check:
  if a.output.read_text(encoding='utf-8')!=text:raise SystemExit('Generated roots differ')
  print('PASS: canonical roots and template parameters match modular exponentiation')
 else:
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(text.encode('utf-8'));print(a.output)
