"""Exact finite layout/range arithmetic and source-anchored lifecycle checks.

These checks are not a general C proof or whole-program constant-time proof.
"""
from pathlib import Path
# Shared typed XML persistence; transport JSON remains in memory.
import sys as _record_sys
from pathlib import Path as _RecordPath
for _record_parent in _RecordPath(__file__).resolve().parents:
    _record_candidate = _record_parent / 'record_io.py'
    if not _record_candidate.is_file():
        _record_candidate = _record_parent / '01_源代码/可参数化格运算内核/record_io.py'
    if _record_candidate.is_file():
        _record_sys.path.insert(0, str(_record_candidate.parent))
        break
import argparse, hashlib, record_io as json
ROOT=Path(__file__).resolve().parents[2];SRC=ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted/src'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def function_body(text,name):
    start=text.index(name+'(');brace=text.index('{',start);depth=1;end=brace+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[brace:end]
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve()
    if out.exists():raise ValueError('Use fresh output')
    lazy=(SRC/'polyvec_lazy.c').read_text(encoding='utf-8');sign=(SRC/'sign.c').read_text(encoding='utf-8');rounding=(SRC/'rounding.h').read_text(encoding='utf-8')
    helper=function_body(lazy,'lc_polymat_sign_entry');init=function_body(lazy,'mld_polyvec_matrix_expand_lazy')
    body=function_body(rounding,'mld_make_hint');pointwise=function_body(lazy,'mld_polyvec_matrix_pointwise_montgomery_yvec_lazy')
    checks={
     'fixed_column_major_index':'index=l*MLDSA_K+k' in helper,
     'new_seed_invalidates_cache':'mat->cache_ready = 0;' in init,
     'cache_hit_requires_ready':'index<LC_DSA_A_CACHE_COUNT && mat->cache_ready' in helper,
     'fill_before_product_modifies_input':pointwise.index('LC_SIGN_MATRIX_ENTRY(&w->vec[k]')<pointwise.index('mld_poly_pointwise_montgomery(&w->vec[k]'),
     'ready_committed_after_traversal':pointwise.index('mat->cache_ready=1;')>pointwise.index('LC_SIGN_MATRIX_ENTRY(&mat->cur'),
     'makehint_highpart_only_nonzero':body.count('a1')==1 and 'a1 != 0' in body,
     'matrix_owner_cleared_on_free':'mld_zeroize(v, sizeof(T) * (N));' in (SRC/'common.h').read_text(encoding='utf-8'),
     'outer_signature_frees_matrix':'MLD_FREE(mat, mld_polymat, 1, context);' in sign,
    }
    if not all(checks.values()):raise ValueError('Reviewed source shape changed: '+str(checks))
    rows=[]
    for level,k,l,gamma,beta,w1 in ((44,4,4,95232,78,192),(65,6,5,261888,196,128),(87,8,7,261888,120,128)):
        for codec in (0,1,2):
            bits=19 if level==44 else 24 if codec==2 else 20;row=256*bits//8;stride=row+32
            max_final=(gamma-beta-1)+(gamma-1)
            geometry=[]
            for i in range(k):
                encoded_begin=(i+1)*stride;encoded_end=encoded_begin+w1
                next_source=(i+1)*1024 if i<k-1 else (k-1)*1024
                geometry.append({'row':i,'packed_begin':i*stride,'encoded_begin':encoded_begin,'encoded_end':encoded_end,
                  'unread_next_source_or_hash_start':next_source,'safe':encoded_end<=next_source})
            assert all(x['safe'] for x in geometry) and max_final<(1<<(bits-1))
            rows.append({'parameter':level,'codec':codec,'signed_bits':bits,'row_bytes':row,'stride_bytes':stride,
              'original_w0_allocation_bytes':k*1024,'tail_hash_start':(k-1)*1024,'row_geometry':geometry,
              'post_ct0_max_abs_from_strict_norms':max_final,'signed_capacity_max':(1<<(bits-1))-1,
              'earlier_initial_lowbit_width_is_insufficient':max_final>((1<<((19 if level==44 else 20)-2))-1)})
    # An explicit tempting but illegal reuse for ML-DSA-44.
    illegal={'parameter':44,'hypothetical_signed_bits':24,'compact_end_with_last_w1':4*(768+32)+192,
      'tail_hash_start':3*1024,'overlap_bytes':4*(768+32)+192-3*1024,'rejected':True}
    assert illegal['overlap_bytes']>0
    caches=[]
    for count in (1,4,8,16):
        for bits in (24,32):caches.append({'count':count,'bits':bits,'payload_bytes':count*256*bits//8,
          'extra_allocation_bytes':count*256*bits//8+32,'applies_to_operations':['keygen','sign','verify']})
    result={'status':'FINITE_ARITHMETIC_AND_SOURCE_SHAPE_CHECKS_PASSED','source_sha256':{p.name:sha(p) for p in (SRC/'sign.c',SRC/'polyvec_lazy.c',SRC/'polyvec_lazy.h',SRC/'rounding.h',SRC/'common.h')},
      'source_checks':checks,'lowpart_layouts':rows,'illegal_layout_positive_control':illegal,'cache_sizes':caches,
      'cache_contract':{'q':8380417,'unsigned24_capacity':16777216,'required_input':'Each already permuted A coefficient lies in [0,Q); copying positions does not change native order.',
        'not_supported_without_new_proof':['Centered negative coefficients','Montgomery/lazy values outside 24 bits','Different backend representation whose sampler is not a pure permutation of [0,Q)']},
      'lifecycle_scope':'Source-anchored review and finite address inequalities, not CFG formal verification or a claim that old upstream CBMC contracts prove the new cache.'}
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(result['status'])
if __name__=='__main__':main()
