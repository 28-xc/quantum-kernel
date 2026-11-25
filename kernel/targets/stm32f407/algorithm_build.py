"""Parameter pruning and schedule flags shared by all STM32F407 builds."""
import hashlib
from pathlib import Path
import sys
import threading

PARAMETERS=(512,768,1024,44,65,87)
_GENERATE_LOCK=threading.Lock()
def algorithm_units(param,profile,capacity,src,objd):
    if param not in PARAMETERS or profile not in ("compact","cached","reference"):
        raise ValueError("unknown compiled parameter/profile")
    sys.dont_write_bytecode=True
    sys.path[:0]=[str(src),str(src/'tools'),str(src/'tests/targets')]
    from pruning_sources import kem_source,public_source,adapter_source
    from generate_vectors import generate
    cache=objd.parent.parent/'vectors'/str(param)
    with _GENERATE_LOCK:
        generate(src,cache,{(param,op) for op in range(3)})
    for name in ('vectors.h','vectors.xml'):
        (objd/name).write_bytes((cache/name).read_bytes())
    if profile=="reference":
        from reference_build import reference_units
        return reference_units(param,src,objd)
    dsaroot=src/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted'
    for name,text in (('kem.c',kem_source(src,[param])),('public.c',public_source(src,[param])),('adapter.c',adapter_source(src/'src/dsa_packed/adapter.c',[param]))):
        (objd/name).write_text(text,encoding='utf-8')
    common=['-DLC_RNG_CALLBACK_ONLY=1','-DLC_DSA_W0_CODEC=1']+['-I'+str(src/j) for j in ('src/common','configs/pruned','src/dsa_packed','configs/hosted','build/adapted_mlkem','src/kem','targets/common')]
    cached=profile=='cached'
    kem=['-DMLK_CONFIG_FILE="mlkem_config.h"',f'-DLC_KEM_ROWS={2 if cached else 1}','-DLC_KEM_BATCH=1','-DLC_KEM_NOISE_CACHE=0']
    defs=['ALIAS_SIGN_CP=1','ALIAS_VERIFY_TMP=1','STREAM_KEYGEN=1','PACK_W0=1',f'A_CACHE_POLYS={4 if cached else 0}','A_CACHE_SIGN_ONLY=1' if cached else 'A_CACHE_SIGN_ONLY=0','A_CACHE_BATCH4=0','A_STREAM_BATCH4=0','S1_CACHE_POLYS=0','RETAIN_FULL_HIGH=0','INPLACE_SAMPLE=2','PACKED_ACCUM=1','FUSED_PACKED_MATRIX=1','STREAM_RECOMPUTE=1']
    dsa=['-I'+str(dsaroot),'-DMLD_CONFIG_FILE="lc_dsa_config.h"','-DMLD_CONFIG_REDUCE_RAM','-DLC_DSA_A_CACHE_BITS=32']+['-DLC_DSA_'+j for j in defs]
    units=[(objd/'kem.c',kem),(objd/'public.c',[]),(objd/'adapter.c',dsa),(src/'src/common/arena.c',[])]
    if param<100:units.append((dsaroot/'mldsa_native.c',dsa+[f'-DMLD_CONFIG_PARAMETER_SET={param}','-DMLD_CONFIG_MULTILEVEL_WITH_SHARED']))
    return units, common

