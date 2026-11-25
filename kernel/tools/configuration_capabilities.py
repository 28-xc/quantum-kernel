"""Validate enabled fields against the sole actual builder's mapping reads."""
import ast
from functools import lru_cache
from pathlib import Path

@lru_cache(maxsize=2)
def mapped_configuration_fields(backend=None):
    path = Path(__file__).with_name('build_variants_arm.py' if backend=='aarch64' else 'build_variants.py')
    fields = set()
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
                and node.value.id == 'cfg' and isinstance(node.slice, ast.Constant)):
            fields.add(node.slice.value)
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'cfg'
                and node.func.attr == 'get' and node.args and isinstance(node.args[0], ast.Constant)):
            fields.add(node.args[0].value)
    return frozenset(fields)

def validate_pruned_configuration(name, configuration, backend=None):
    from public_recipes import validate_backend
    validate_backend(name, backend)
    if configuration.get('runtime_cache'):
        required=('modified','reduce_ram','dense_sign_rows','packed_accum',
                  'cached_dot_tile','stream_cache24','inplace_ay','a_planes24',
                  'matrix_cache_sign_only','borrow_sig_y','mask_pipeline')
        if backend not in ('x86_64','aarch64') or not all(configuration.get(k) for k in required):
            raise ValueError('Runtime cache requires the native call-local dense signing schedule')
        if configuration.get('partial_dense_rows') or configuration.get('public_a_session') or configuration.get('matrix_cache_87_cap')!=56:
            raise ValueError('Runtime cache needs full compile-time capacity and no session/partial override')
        if configuration.get('matrix_cache_bits')!=24 or configuration.get('matrix_cache_polys')!=56:
            raise ValueError('Runtime cache supports the 56-polynomial split-plane layout only')

    # Public recipe values are checked before compiler commands are emitted.
    for key in ('direct_dense_rows','partial_dense_separate_y','public_a_session','compact_batch87'):
        if type(configuration.get(key,0)) is not int or configuration.get(key,0) not in (0,1):
            raise ValueError('Binary feature required: '+key)
    arm_features=('neon_byte_pack','fused_hint_neon','neon_packz','neon_sample16','arm_compact_batch87')
    for feature in arm_features:
        if type(configuration.get(feature,0)) is not int or configuration.get(feature,0) not in (0,1):
            raise ValueError('Binary ARM feature required: '+feature)
    if any(configuration.get(k) for k in arm_features):
        if backend!='aarch64' or not configuration.get('modified') or not configuration.get('reduce_ram'):
            raise ValueError('NEON features require the modified reduced-memory ARM implementation')
    if configuration.get('arm_compact_batch87') and (configuration.get('full_y_batch') or configuration.get('borrow_sig_y') or configuration.get('matrix_cache_polys',0)):
        raise ValueError('Compact ARM masks require the uncached current-attempt schedule')
    if configuration.get('neon_sample16') and not (configuration.get('arm_speed32') and configuration.get('a_planes24')):
        raise ValueError('Public sample16 requires the ARM split-plane matrix implementation')
    rows=configuration.get('partial_dense_rows',0)
    if type(rows) is not int or not 0<=rows<=6:
        raise ValueError('Partial dense rows must be zero or 1..6')
    if configuration.get('partial_dense_separate_y') and not rows:
        raise ValueError('Separate Y requires the partial dense product')
    if rows:
        required=('modified','reduce_ram','dense_sign_rows','packed_accum',
                  'cached_dot_tile','stream_cache24','inplace_ay','a_planes24','matrix_cache_sign_only')
        if not all(configuration.get(k) for k in required) or configuration.get('matrix_cache_bits')!=24:
            raise ValueError('Partial dense rows require the split-plane call-owned dense product')
        if configuration.get('matrix_cache_polys',0)<56 or configuration.get('matrix_cache_87_cap')!=7*rows:
            raise ValueError('Partial87 cache must contain exactly whole rows;44/65 stay complete')
        if configuration.get('matrix_cache_batch4') or configuration.get('stream_recompute'):
            raise ValueError('Partial dense cache has its own public prefill and complete product')
        if backend=='x86_64' and not configuration.get('matrix_interleaved'):
            raise ValueError('Partial x86 requires interleaved Keccak')
        if backend=='aarch64' and not configuration.get('stream_neon'):
            raise ValueError('Partial ARM requires canonical NEON/direct-state sampling')
    if configuration.get('direct_dense_rows') and (not configuration.get('dense_sign_rows') or not configuration.get('packed_accum') or configuration.get('stream_recompute')):
        raise ValueError('Direct row views require complete dense packed signing rows')
    for key,limit in [('native_matrix_cache',56),('native_s1_cache',7),('native_s2_cache',8),('native_t0_cache',8),('native_a_session_polys',56)]:
        n=configuration.get(key,0)
        if type(n) is not int or not 0<=n<=limit:
            raise ValueError('Invalid native prefix length: '+key)
        if n and (configuration.get('modified') or not configuration.get('reduce_ram')):
            raise ValueError('Native prefixes require the upstream reduced-memory adapter')
    session=configuration.get('public_a_session',0)
    if configuration.get('native_a_session_polys') and not session:
        raise ValueError('Persistent native prefix requires the session API')
    if session:
        if backend not in ('x86_64','aarch64') or not configuration.get('reduce_ram'):
            raise ValueError('Session prototype requires a native reduced-memory backend')
        if rows:
            raise ValueError('Row-major partial cache and column-major session format are distinct')
        if configuration.get('modified'):
            if configuration.get('matrix_cache_batch4'):
                raise ValueError('Public session forbids call-owned batch prefill of the retained cache')
            if configuration.get('matrix_cache_polys',0)<56 or not configuration.get('stream_cache24'):
                raise ValueError('Project session requires the complete pipeline matrix representation')
        elif not configuration.get('native_a_session_polys') or configuration.get('native_matrix_cache'):
            raise ValueError('Native session requires an external positive prefix and no duplicate call-owned A')
    if configuration.get('kem_enc_hybrid') and backend != 'x86_64':
        raise ValueError('Encapsulation hybrid configuration requires the x86_64 backend')
    if configuration.get('a_planes24'):
        if backend not in ('x86_64','aarch64') or configuration.get('matrix_cache_bits') != 24:
            raise ValueError('Split matrix planes require native SIMD and 24-bit coefficients')
    if configuration.get('inplace_ay'):
        required=('dense_sign_rows','cached_dot_tile','stream_cache24')
        if not all(configuration.get(k) for k in required) or configuration.get('matrix_cache_polys',0) < 56:
            raise ValueError('In-place matrix product requires dense rows and a complete six-parameter matrix cache')
        if configuration.get('matrix_cache_bits') != 32 and not configuration.get('a_planes24'):
            raise ValueError('In-place matrix product requires 32-bit or split-plane matrix storage')
        if backend not in ('x86_64','aarch64') or (backend=='aarch64' and not configuration.get('arm_speed32')):
            raise ValueError('In-place matrix product requires the native SIMD product implementation')
    if configuration.get('keygen_eta_arena') and not configuration.get('keygen_eta4'):
        raise ValueError('Noise sampling workspace requires the four-way key-generation sampler')
    if configuration.get('matrix4_arena') and backend != 'aarch64':
        raise ValueError('Public matrix sampling workspace is supported by the AArch64 implementation')
    if configuration.get('matrix4_arena') and not configuration.get('native_matrix_rows'):
        raise ValueError('Public matrix sampling workspace requires native matrix rows')
    if configuration.get('kem_matrix4_arena') and (backend != 'aarch64' or not configuration.get('kem_full_matrix768')):
        raise ValueError('ML-KEM matrix sampling workspace requires the complete AArch64 ML-KEM-768 matrix path')
    kem_arm_features=('kem_joint_noise3','kem_full_noise_neon','kem_retain_mulcache')
    for feature in kem_arm_features:
        if type(configuration.get(feature,0)) is not int or configuration.get(feature,0) not in (0,1):
            raise ValueError('Binary ARM KEM field required: '+feature)
    hj=configuration.get('kem_arm_hj_prefix',0)
    if type(hj) is not int or hj not in (0,1,2):
        raise ValueError('ARM H/J matrix prefix must be zero, one or two rows')
    if hj or any(configuration.get(k) for k in kem_arm_features):
        if backend!='aarch64' or not configuration.get('modified') or not configuration.get('kem_tile_borrow'):
            raise ValueError('ARM KEM schedules require the modified borrowed-state implementation')
    if (configuration.get('kem_joint_noise3') or configuration.get('kem_full_noise_neon')) and not configuration.get('kem_full_matrix768'):
        raise ValueError('Rank-three mixed noise and NEON CBD require the complete matrix schedule')
    if hj and (configuration.get('kem_rows')!=1 or configuration.get('kem_batch')!=4):
        raise ValueError('ARM H/J prefix requires the one-row four-lane schedule')
    features=('borrow_sig_y','natural_sig_y','checked_sparse','defer_challenge_ntt','parameter_a32','early_low_44')
    for feature in features:
        if configuration.get(feature,0) not in (0,1):
            raise ValueError('Binary optimization field required: '+feature)
    if any(configuration.get(k) for k in features):
        if backend not in ('x86_64','aarch64') or not configuration.get('modified') or not configuration.get('reduce_ram'):
            raise ValueError('Selected signing features require a modified native reduced-memory configuration')
    if configuration.get('compact_batch87'):
        required=('modified','reduce_ram','borrow_sig_y','natural_sig_y')
        forbidden=('stream_cache24','stream_recompute','mask_pipeline')
        if backend!='x86_64' or not all(configuration.get(k) for k in required) or any(configuration.get(k) for k in forbidden):
            raise ValueError('Compact87 batching requires the uncached AVX2 natural-mask schedule')
    if configuration.get('natural_sig_y'):
        required=('borrow_sig_y','first_gamma_cache','raw_y4_cache','packed_accum','signed24_native')
        forbidden=('raw_y_all_cache','stream_cache24','stream_recompute')
        if backend!='x86_64' or not all(configuration.get(k) for k in required) or any(configuration.get(k) for k in forbidden):
            raise ValueError('Natural mask retention requires the compact AVX2 sampling schedule')
    if configuration.get('borrow_sig_y'):
        if backend=='x86_64' and not (configuration.get('raw_y_all_cache') or configuration.get('natural_sig_y')):
            raise ValueError('Signature-backed AVX2 masks require full or natural retention')
        if backend=='aarch64' and not configuration.get('full_y_batch'):
            raise ValueError('Signature-backed AArch64 masks require the complete public raw-mask prefix')
    if configuration.get('checked_sparse') and backend=='x86_64' and not configuration.get('sparse_product'):
        raise ValueError('Checked AVX2 accumulation requires sparse products')
    if configuration.get('defer_challenge_ntt'):
        if backend!='x86_64' or not configuration.get('sparse_product') or not configuration.get('sparse_separate_cp'):
            raise ValueError('Deferred challenge NTT requires the separate AVX2 sparse challenge path')
    matrix_fast=configuration.get('lowmem_matrix_fast',0)
    if type(matrix_fast) is not int or matrix_fast not in (0,1):
        raise ValueError('Binary optimization field required: lowmem_matrix_fast')
    if matrix_fast:
        required=('modified','reduce_ram','packed_accum','fused_matrix','matrix_stream_direct4',
                  'matrix_stream_vector','matrix_interleaved','signed24_native',
                  'hybrid_nexty','first_gamma_cache','gamma_reverse_avx2')
        forbidden=('stream_cache24','stream_recompute','matrix_cache_polys','runtime_cache')
        if backend!='x86_64' or configuration.get('crosscol6')!=2 or not all(configuration.get(k) for k in required) or any(configuration.get(k) for k in forbidden):
            raise ValueError('Low-memory matrix prefixes require the uncached AVX2 interleaved/hybrid stream')
    if configuration.get('parameter_a32'):
        required=('a_planes24','matrix_cache_sign_only')
        if backend!='x86_64' or configuration.get('matrix_cache_bits')!=24 or configuration.get('matrix_cache_polys',0)<56 or not all(configuration.get(k) for k in required):
            raise ValueError('Parameter-selected matrix words require the complete AVX2 split-plane sign cache')
    if configuration.get('early_low_44') and backend=='x86_64':
        if configuration.get('early_low_rows',0)<4 or not configuration.get('sparse_product') or configuration.get('stream_recompute'):
            raise ValueError('Early44 low checks require the complete packed sparse low-row path')
    unknown = sorted(k for k, v in configuration.items() if v and k not in mapped_configuration_fields(backend))
    if unknown:
        raise ValueError('Configuration ' + repr(name) + ' has enabled fields without build mappings: ' + ', '.join(unknown))
