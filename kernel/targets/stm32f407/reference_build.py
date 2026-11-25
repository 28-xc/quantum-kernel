"""Use the delivered PQClean portable implementations and their existing validated ABI."""
import re
from pathlib import Path
HERE=Path(__file__).resolve().parent
def reference_units(param,src,objd):
    root=src/'baselines/pqclean'
    ref=root/'upstream'
    family='crypto_kem' if param>100 else 'crypto_sign'
    level=ref/family/(('ml-kem-' if param>100 else 'ml-dsa-')+str(param))/'clean'
    prefix=f'PQCLEAN_{"MLKEM" if param>100 else "MLDSA"}{param}_CLEAN'
    text=(root/'adapter.c').read_text(encoding='utf-8')
    def matched(m):
        head,scope=m.groups()
        call=re.search(r'return ('+prefix+r'_[a-z0-9_]+\([^;]+\));',scope)
        return head+'{(void)p;return '+(call[1] if call else 'LC_E_ARGUMENT')+';}'
    text,n=re.subn(r'(static int raw_(?:keypair|enc|dec|sign|verify)\([^\n{}]+\))\{switch\(p\) \{?(.*?)\}\}',matched,text,flags=re.S)
    if n!=5:
        # Original adapter uses "switch(p){" without a space.
        text=(root/'adapter.c').read_text(encoding='utf-8')
        text,n=re.subn(r'(static int raw_(?:keypair|enc|dec|sign|verify)\([^\n{}]+\))\{switch\(p\)\s*\{(.*?)\}\}',matched,text,flags=re.S)
    if n!=5:raise ValueError('PQClean dispatch source changed')
    adapter=objd/'reference_adapter.c';adapter.write_text(text,encoding='utf-8')
    units=[(adapter,[]),(ref/'common/fips202.c',[]),(HERE/'reference_heap.c',[]),(HERE/'reference_jump.S',[])]
    large=param in (65,87)
    if large:
        from large_reference import source_sign,shorter_vectors
        vector_path=objd/'vectors.h'
        vector_path.write_text(shorter_vectors(vector_path),encoding='ascii')
        heap=objd/'reference_heap.c'
        heap.write_text((HERE/'reference_heap.c').read_text().replace('static uint64_t slots[16][26];','static uint64_t slots[16][26] __attribute__((section(".low_heap")));'),encoding='utf-8')
        units[2]=(heap,[])
    for p in sorted(level.glob('*.c')):
        flags=[]
        if large and p.name=='sign.c':
            adjusted=objd/'sign.c';adjusted.write_text(source_sign(p.read_text(encoding='utf-8')),encoding='utf-8');p=adjusted
        if param<100 and p.name=='polyvec.c': flags=[f'-D{prefix}_polyvecl_uniform_gamma1={prefix}_polyvecl_uniform_gamma1_original']
        units.append((p,flags))
    if param<100:
        p=objd/'nonce_guard.c'
        p.write_text((root/'nonce_guard.c.in').read_text().replace('@PREFIX@',prefix),encoding='utf-8')
        units.append((p,[]))
    return units,['-DLC_RNG_CALLBACK_ONLY=1','-D_Thread_local=','-I'+str(root),'-I'+str(ref/'common'),'-I'+str(level)]

