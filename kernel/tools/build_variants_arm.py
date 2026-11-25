"""Build explicit hosted reference and resource configurations from source.

Backend and compiler options apply equally to reference and modified schedules.
Build manifests bind every project dependency and command to its output.
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
import argparse, datetime, hashlib, record_io as json, os, platform, re, shlex, shutil, struct, subprocess, time
from binary_build_utils import pe_exports

ROOT=Path(__file__).resolve().parents[1]
PUBLIC=['lc_get_sizes','lc_context_init','lc_keypair','lc_encaps','lc_decaps','lc_sign','lc_verify','lc_error_string']
from public_recipes import CONFIGS

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,x):
 p.parent.mkdir(parents=True,exist_ok=True)
 q=p.with_name(p.name+'.tmp');q.write_text(json.dumps(x,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');q.replace(p)
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--output',type=Path,required=True)
 ap.add_argument('--config',choices=CONFIGS,required=True)
 ap.add_argument('--backend',choices=['portable','aarch64','x86_64'],required=True)
 ap.add_argument('--opt',choices=['O3','Os','Oz'],default='O3')
 ap.add_argument('--cc',default='gcc');ap.add_argument('--ar',default='gcc-ar')
 ap.add_argument('--nm',default='nm');ap.add_argument('--size',default='size')
 ap.add_argument('--lto',action='store_true')
 from native_options import add_arm_arguments
 add_arm_arguments(ap)
 ap.add_argument('--parameters',help='Explicit selected standard parameters')
 ap.add_argument('--operations',help='JSON object: required operations for each selected parameter')
 ap.add_argument('--probe-workspace',type=int,default=262144)
 ap.add_argument('--extra-defs',nargs='*',default=[])
 ap.add_argument('--probe-count',type=int,default=200)
 ap.add_argument('--sanitize',choices=['none','undefined','address,undefined'],default='none')
 a=ap.parse_args();cfg=CONFIGS[a.config].copy()
 public_symbols=PUBLIC+(['lc_resource_query','lc_resource_make_plan','lc_resource_algorithm_bytes'] if cfg.get('runtime_cache') else [])+(['lc_a_session_cache_bytes', 'lc_a_session_workspace_bound', 'lc_a_session_init', 'lc_a_session_prepare', 'lc_a_session_sign', 'lc_a_session_verify', 'lc_a_session_close'] if cfg.get('public_a_session',0) else [])
 if any(v.split('=',1)[0] in ('LC_DSA_DIRECT_DENSE_ROWS', 'LC_DSA_PARTIAL_DENSE_ROWS', 'LC_DSA_PARTIAL_DENSE_SEPARATE_Y', 'LC_NATIVE_MATRIX_CACHE', 'LC_NATIVE_S1_CACHE', 'LC_NATIVE_S2_CACHE', 'LC_NATIVE_T0_CACHE', 'LC_DSA_PUBLIC_A_SESSION', 'LC_NATIVE_A_SESSION_POLYS', 'LC_DSA_RUNTIME_CACHE', 'LC_RESOURCE_OPERATION_MASK') for v in a.extra_defs):raise ValueError('Use an explicit public recipe for integrated features')
 from configuration_capabilities import validate_pruned_configuration
 from pruning_sources import selected_parameters, public_source, kem_source, adapter_source, shared_kem_constants
 validate_pruned_configuration(a.config,cfg,backend='aarch64')
 levels=selected_parameters(a.parameters) if a.parameters is not None else [512,768,1024,44,65,87]
 if a.backend!='aarch64':raise ValueError('Native ARM dispatcher requires aarch64')
 if any(not re.fullmatch(r'[A-Z][A-Z0-9_]*(?:=[0-9]+)?',v) for v in a.extra_defs):raise ValueError('Explicit integer feature macros required')
 from operation_selection import normalize, cells
 operations=normalize(a.operations,levels)
 if operations is not None and a.parameters is None:raise ValueError('Operation subsets require explicit --parameters')
 if a.probe_workspace<32 or a.probe_workspace%32:raise ValueError('Probe workspace must be a positive multiple of 32')
 klevels=[p for p in levels if p>100];dlevels=[p for p in levels if p<100]
 out=a.output.resolve()
 if os.name=='nt' and out.drive.upper()!='D:':raise ValueError('Windows output must stay on D:')
 if out.exists() or out==ROOT or out in ROOT.parents:raise ValueError('Use a fresh dedicated output directory')
 if not 1<=a.probe_count<=10000:raise ValueError('Invalid probe count')
 cc=shutil.which(a.cc);ar=shutil.which(a.ar)
 if not cc or not ar:raise ValueError('Compiler/archiver not found')
 out.mkdir(parents=True);(out/'obj').mkdir();(out/'tmp').mkdir()
 env=os.environ.copy();env.update(TMPDIR=str(out/'tmp'),TMP=str(out/'tmp'),TEMP=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 records=[];sources={};generated_sources={};began=time.monotonic()
 def run(argv,label):
  t=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
  log=out/(label+'.log');log.write_text(json.capture_text(p.stdout+p.stderr),encoding='utf-8')
  records.append(dict(argv=list(map(str,argv)),exit_code=p.returncode,elapsed_seconds=time.monotonic()-t,log=log.name,log_sha256=sha(log)))
  write(out/'commands.xml',records)
  if p.returncode:raise RuntimeError(label+' failed; inspect '+str(log))
  return p.stdout
 try:
  target=run([cc,'-dumpmachine'],'target').strip()
  windows=any(x in target for x in ('mingw','windows','w64'))
  if not windows and 'linux' not in target:raise ValueError('Unsupported hosted target')
  if a.backend=='aarch64' and 'aarch64' not in target:raise ValueError('AArch64 backend requires AArch64 compiler')
  if a.backend=='x86_64' and 'x86_64' not in target:raise ValueError('x86_64 backend requires x86_64 compiler')
  version=run([cc,'--version'],'compiler').splitlines()[0]
  compiler_family='clang' if 'clang' in version.lower() else 'gcc'
  if a.opt=='Oz' and compiler_family!='clang':raise ValueError('This Oz study requires Clang')
  whole_program=[] if compiler_family=='clang' or not a.lto else ['-fwhole-program']
  flags=['-'+a.opt,*whole_program,'-g','-std=c11','-ffunction-sections','-fdata-sections','-fomit-frame-pointer' if a.omit_frame_pointer else '-fno-omit-frame-pointer','-fstack-usage','-Wall','-Wextra']
  if not windows:flags+=['-fPIC']
  linkflags=['-'+a.opt,*whole_program]
  if a.linker!='default':linkflags+=['-fuse-ld='+a.linker]
  if a.safe_icf:
   if compiler_family!='clang' or a.linker!='lld-14':raise ValueError('Safe ICF study requires Clang+LLD14')
   linkflags+=['-Wl,--icf=safe','-Wl,--print-icf-sections']
  if a.machine_outline:
   if compiler_family!='clang' or a.backend!='aarch64' or not a.lto or a.linker not in ('gold','lld-14'):raise ValueError('Machine outlining requires Clang AArch64 full LTO with explicit linker')
   flags+=['-mllvm','-enable-machine-outliner=always']
   linkflags+=(['-Wl,-plugin-opt=-enable-machine-outliner=always'] if a.linker=='gold' else ['-Wl,-mllvm,-enable-machine-outliner=always'])
  if a.omit_frame_pointer:linkflags+=['-fomit-frame-pointer']
  if not a.inline_single_call:flags+=['-fno-inline-functions-called-once'];linkflags+=['-fno-inline-functions-called-once']
  if a.omit_unwind_metadata:flags+=['-fno-asynchronous-unwind-tables','-fno-unwind-tables'];linkflags+=['-fno-asynchronous-unwind-tables','-fno-unwind-tables']
  if a.lto:flags+=['-flto'];linkflags+=['-flto']
  if a.backend=='aarch64':flags+=['-mcpu=neoverse-n1'];linkflags+=['-mcpu=neoverse-n1']
  if a.backend=='x86_64':flags+=['-march=native'];linkflags+=['-march=native']
  if a.sanitize!='none':flags+=['-fsanitize='+a.sanitize,'-fno-sanitize-recover=all'];linkflags+=['-fsanitize='+a.sanitize,'-fno-sanitize-recover=all']
  flags+=['-DLC_BUILD_ARM_PROFILE=1']
  general=['-I'+str(ROOT/'include'),'-DLC_DSA_PUBLIC_A_SESSION='+str(cfg.get('public_a_session',0))]
  general+=['-DLC_DSA_RUNTIME_CACHE='+str(cfg.get('runtime_cache',0))]
  if cfg.get('runtime_cache'):
   order=[512,768,1024,44,65,87]
   general+=['-DLC_RESOURCE_OPERATION_MASK='+str(sum(1<<(order.index(p)*3+op) for p,op in cells(operations,levels)))+'u']
  if a.parameters is not None:general+=['-I'+str(ROOT/'configs/pruned'),'-I'+str(ROOT/'src/common')]
  kemroot=ROOT/('build/adapted_mlkem' if cfg['modified'] else 'third_party/mlkem-native/mlkem')
  dsaroot=ROOT/('src/dsa_compact/build/sign_bitmap_stream_alias/adapted' if cfg['modified'] else 'third_party/mldsa-native/mldsa')
  dsaconfig=ROOT/('src/dsa_packed' if cfg['modified'] else 'baselines/mldsa')
  if cfg.get('kem_full_matrix768') and (not cfg['modified'] or a.backend!='aarch64'):raise ValueError('Complete ML-KEM-768 matrix requires the native ARM speed configuration')
  kflags=[*general,'-I'+str(ROOT/'configs/hosted'),'-I'+str(kemroot),'-I'+str(ROOT/'src/kem'),'-DMLK_CONFIG_FILE="mlkem_config.h"']
  kflags += ['-DLC_KEM_FULL_MATRIX768='+str(cfg.get('kem_full_matrix768',0)),
             '-DLC_KEM_MATRIX4_ARENA='+str(cfg.get('kem_matrix4_arena',0)),
             '-DLC_KEM_JOINT_NOISE3='+str(cfg.get('kem_joint_noise3',0)),
             '-DLC_KEM_FULL_NOISE_NEON='+str(cfg.get('kem_full_noise_neon',0)),
             '-DLC_KEM_RETAIN_MULCACHE='+str(cfg.get('kem_retain_mulcache',0)),
             '-DLC_KEM_ARM_HJ_PREFIX='+str(cfg.get('kem_arm_hj_prefix',0)),
             '-DLC_KEM_SHARED_CBD_NEON='+str(cfg.get('kem_shared_cbd_neon',0)),
             '-DLC_KEM_REJECTION_BYTE_TABLE='+str(cfg.get('kem_rejection_byte_table',0))]
  if cfg.get('kem_matrix_rate_blocks'):
   kflags += ['-DMLKEM_GEN_MATRIX_NBLOCKS='+str(cfg['kem_matrix_rate_blocks'])]
  if a.shared_kem_sampler:
   if not cfg['modified'] or compiler_family!='gcc' or not cfg.get('kem_tile_borrow') or not cfg.get('kem_rate_native_stage'):raise ValueError('Shared KEM sampler requires the GCC fixed decoded-scratch schedule')
   kflags+=['-DLC_KEM_SHARED_SAMPLE4=1']
  if a.ct_memcmp_neon:kflags+=['-DLC_KEM_CT_MEMCMP_NEON=1']
  if a.kem_k2rows:kflags+=['-DLC_KEM_K2_ROWS2=1']
  if a.canonical12_neon:
   if a.backend!='aarch64' or not cfg['modified']:raise ValueError('Canonical12 NEON requires the modified AArch64 path')
   kflags+=['-DLC_KEM_CANONICAL12_NEON=1']
  dflags=[*general,'-I'+str(dsaconfig),'-I'+str(dsaroot),'-DMLD_CONFIG_FILE="lc_dsa_config.h"']
  dflags += ['-DLC_DSA_DIRECT_DENSE_ROWS='+str(cfg.get('direct_dense_rows',0))]
  dflags += ['-DLC_DSA_PARTIAL_DENSE_ROWS='+str(cfg.get('partial_dense_rows',0))]
  dflags += ['-DLC_DSA_PARTIAL_DENSE_SEPARATE_Y='+str(cfg.get('partial_dense_separate_y',0))]
  dflags += ['-DLC_NATIVE_MATRIX_CACHE='+str(cfg.get('native_matrix_cache',0))]
  dflags += ['-DLC_NATIVE_S1_CACHE='+str(cfg.get('native_s1_cache',0))]
  dflags += ['-DLC_NATIVE_S2_CACHE='+str(cfg.get('native_s2_cache',0))]
  dflags += ['-DLC_NATIVE_T0_CACHE='+str(cfg.get('native_t0_cache',0))]
  dflags += ['-DLC_DSA_PUBLIC_A_SESSION='+str(cfg.get('public_a_session',0))]
  dflags += ['-DLC_NATIVE_A_SESSION_POLYS='+str(cfg.get('native_a_session_polys',0))]
  dflags += ['-DLC_DSA_BORROW_SIG_Y='+str(cfg.get('borrow_sig_y',0))]
  dflags += ['-DLC_DSA_NATURAL_SIG_Y='+str(cfg.get('natural_sig_y',0))]
  dflags += ['-DLC_DSA_CHECKED_SPARSE='+str(cfg.get('checked_sparse',0))]
  dflags += ['-DLC_DSA_DEFER_CHALLENGE_NTT='+str(cfg.get('defer_challenge_ntt',0))]
  dflags += ['-DLC_DSA_PARAMETER_A32='+str(cfg.get('parameter_a32',0))]
  dflags += ['-DLC_DSA_EARLY_LOW_44='+str(cfg.get('early_low_44',0))]
  dflags += ['-DLC_DSA_DENSE_SIGN_ROWS='+str(cfg.get('dense_sign_rows',0)), '-DLC_DSA_MASK_PIPELINE='+str(cfg.get('mask_pipeline',0)),
             '-DLC_DSA_SPARSE_ETA_WIDE='+str(cfg.get('sparse_eta_wide',0)), '-DLC_DSA_SPARSE_T0_WIDE='+str(cfg.get('sparse_t0_wide',0)),
             '-DLC_DSA_DECOMPOSE_INLINE='+str(cfg.get('decompose_inline',0)), '-DLC_DSA_FLAT_MATRIX_NEON='+str(cfg.get('flat_matrix_neon',0)),
             '-DLC_DSA_FLAT_KEYGEN='+str(cfg.get('flat_keygen',0)), '-DLC_DSA_FLAT_VERIFY='+str(cfg.get('flat_verify',0))]
  dflags+=['-DLC_DSA_POLY_REJECT='+str(cfg.get('poly_reject',3 if cfg.get('arm_speed32') else 0))]
  if cfg.get('arm_speed32'):
   dflags+=['-DLC_DSA_ARM_SPEED32=1','-DLC_DSA_CACHED_DOT_TILE='+str(cfg.get('cached_dot_tile',0))]
  if a.packed_rejection_table:
   if a.backend!='aarch64' or not cfg['modified']:raise ValueError('Packed rejection table requires modified AArch64')
   kflags+=['-I'+str(ROOT/'src/common'),'-DLC_ARM_PACKED_REJECTION_TABLE=1']
   dflags+=['-I'+str(ROOT/'src/common'),'-DLC_ARM_PACKED_REJECTION_TABLE=1']
  if a.shared_sensitive_free or a.shared_challenge:
   if not cfg['modified'] or compiler_family!='gcc':raise ValueError('Shared bounded helpers currently require the modified GCC path')
   if a.shared_sensitive_free:dflags+=['-DLC_DSA_SHARED_SENSITIVE_FREE=1']
   if a.shared_challenge:dflags+=['-DLC_DSA_SHARED_CHALLENGE=1']
  if a.early_low_all:
   if a.backend!='aarch64' or not cfg['modified'] or not a.sparse_neon:raise ValueError('Early low rows require the modified sparse ARM schedule')
   dflags+=['-DLC_DSA_EARLY_LOW_ROWS=8']
  if a.mixed_head65:
   if a.backend!='aarch64' or not cfg['modified'] or not a.gamma_neon or not a.crosscol6_workspace or a.raw_y_prefix!='none':raise ValueError('Mixed head65 requires ARM cross-column arena and no raw prefix')
   dflags+=['-DLC_DSA_MIXED_HEAD65=1']
  if a.raw_y_prefix!='none':
   if a.backend!='aarch64' or not cfg['modified'] or not a.gamma_neon:raise ValueError('Raw gamma prefix requires selected modified ARM gamma decoder')
   dflags+=['-DLC_DSA_RAW_Y_PREFIX65='+str(2 if a.raw_y_prefix in ('65','both') else 0),'-DLC_DSA_RAW_Y_PREFIX87='+str(1 if a.raw_y_prefix in ('87','both') else 0)]
  if a.raw_y4_cache:
   if a.backend!='aarch64' or not cfg['modified'] or not a.gamma_neon:raise ValueError('Raw gamma4 cache requires selected modified ARM gamma decoder')
   dflags+=['-DLC_DSA_RAW_Y4_CACHE=1']
  if a.compact_dsa_fused3:
   if not a.compact_dsa_barrett:raise ValueError('Fused DSA layers require compact Barrett transforms')
   dflags+=['-DLC_DSA_COMPACT_NTT_FUSED3=1']
  if a.compact_kem_ntt:
   if a.backend!='aarch64' or not cfg['modified']:raise ValueError('Compact KEM NTT requires modified AArch64')
   kflags+=['-DLC_KEM_COMPACT_NTT_NEON=1']
  if a.compact_dsa_barrett:
   if not a.compact_dsa_ntt:raise ValueError('Barrett transforms require compact DSA NTT')
   dflags+=['-DLC_DSA_COMPACT_NTT_BARRETT=1']
  if a.compact_dsa_ntt:
   if a.backend!='aarch64' or not cfg['modified']:raise ValueError('Compact DSA NTT requires modified AArch64')
   dflags+=['-DLC_DSA_COMPACT_NTT_NEON=1']
  if a.gamma_neon:
   if a.backend!='aarch64' or not cfg['modified']:raise ValueError('Gamma NEON requires the modified AArch64 path')
   dflags+=['-DLC_DSA_GAMMA_REVERSE_NEON=1']
  if a.crosscol6 and a.crosscol6_workspace:raise ValueError('Choose one cross-column storage mode')
  if a.crosscol6 or a.crosscol6_workspace:
   if a.backend!='aarch64' or not cfg['modified'] or not a.direct_stream_state:raise ValueError('Crosscol6 requires the selected modified AArch64 direct-state schedule')
   dflags+=['-DLC_DSA_CROSSCOL6='+str(2 if a.crosscol6_workspace else 1)]
  if cfg.get('keccak_byte_bulk'):
   kflags += ['-I'+str(ROOT/'src/common'),'-DLC_KECCAK_BYTE_BULK=1']
   dflags += ['-I'+str(ROOT/'src/common'),'-DLC_KECCAK_BYTE_BULK=1']
  if cfg.get('full_y_batch'):
   if a.mixed_head65:raise ValueError('Full y cache owns masks instead of mixed head65')
   dflags+=['-DLC_DSA_FULL_Y_BATCH=1','-DLC_DSA_RAW_Y_PREFIX65=5','-DLC_DSA_RAW_Y_PREFIX87=7']
  if cfg['modified']:
   dflags += ['-DLC_DSA_NEON_BYTE_PACK='+str(cfg.get('neon_byte_pack',0)),
              '-DLC_DSA_FUSED_HINT_NEON='+str(cfg.get('fused_hint_neon',0)),
              '-DLC_DSA_NEON_PACKZ='+str(cfg.get('neon_packz',0)),
              '-DLC_DSA_NEON_SAMPLE16='+str(cfg.get('neon_sample16',0))]
   if cfg.get('arm_compact_batch87'):
    if cfg.get('full_y_batch') or cfg.get('borrow_sig_y') or a.raw_y_prefix!='none' or cfg.get('matrix_cache_polys',0):
     raise ValueError('Current87 mask retention requires the compact ARM schedule')
    dflags += ['-DLC_DSA_ARM_COMPACT_BATCH87=1']
  if cfg['modified']:
   kflags += ['-DLC_KEM_ROWS='+str(cfg['kem_rows']),'-DLC_KEM_BATCH='+str(cfg['kem_batch']),'-DLC_KEM_NOISE_CACHE='+str(cfg.get('kem_noise_cache',0))]
   initial3=('(MLKEM_K>='+str(cfg['kem_matrix_initial3_min_k'])+')') if cfg.get('kem_matrix_initial3_min_k') else str(cfg.get('kem_matrix_initial3',0))
   kflags += ['-DLC_KEM_TILE_BORROW='+str(cfg.get('kem_tile_borrow',0)),'-DLC_KEM_RATE_NATIVE_STAGE='+str(cfg.get('kem_rate_native_stage',0)),'-DLC_KEM_MATRIX_INITIAL3='+initial3]
   kflags += ['-DLC_KEM_COMPACT_NOISE4='+str(cfg.get('kem_compact_noise4',0)),'-DLC_KEM_NOISE_RAW='+str(cfg.get('kem_noise_raw',0)),'-DLC_KEM_NOISE_NEON='+str(cfg.get('kem_noise_neon',0))]
   dflags += ['-DLC_DSA_ALIAS_SIGN_CP=1','-DLC_DSA_ALIAS_VERIFY_TMP='+str(cfg.get('alias_verify_tmp',1)),'-DLC_DSA_STREAM_KEYGEN='+str(cfg.get('stream_keygen',1)),'-DLC_DSA_PACK_W0=1']
   dflags += ['-DLC_DSA_W0_CODEC='+str(cfg.get('lowbits_codec',0))]
   dflags += ['-DLC_DSA_STREAM_CACHE24='+str(cfg.get('stream_cache24',0))]
   dflags += ['-DLC_DSA_A_CACHE_POLYS='+str(cfg.get('matrix_cache_polys',0)),'-DLC_DSA_A_CACHE_BITS='+str(cfg.get('matrix_cache_bits',24))]
   dflags += ['-DLC_DSA_A_CACHE_87_CAP='+str(cfg.get('matrix_cache_87_cap',56))]
   dflags += ['-DLC_DSA_A_CACHE_SIGN_ONLY='+str(cfg.get('matrix_cache_sign_only',0)),'-DLC_DSA_A_CACHE_BATCH4='+str(cfg.get('matrix_cache_batch4',0))]
   dflags += ['-DLC_DSA_A_STREAM_BATCH4='+str(cfg.get('matrix_stream_batch4',0))]
   dflags += ['-DLC_DSA_S1_CACHE_POLYS='+str(cfg.get('secret_prefix_polys',0))]
   dflags += ['-DLC_DSA_S1_CACHE_DISABLE87='+str(cfg.get('secret_prefix_disable87',0))]
   dflags += ['-DLC_DSA_CACHE_FUSED='+str(cfg.get('cache_fused',0))]
   dflags += ['-DLC_DSA_STREAM_NEON='+str(cfg.get('stream_neon',0)),'-DLC_DSA_STREAM_ACTIVE_TAIL='+str(cfg.get('stream_active_tail',0))]
   dflags += ['-DLC_DSA_ROW_BATCH4='+str(cfg.get('row_batch4',0))]
   dflags += ['-DLC_DSA_Y_BATCH4='+str(cfg.get('y_batch4',0))]
   dflags += ['-DLC_DSA_RETAIN_FULL_HIGH='+str(cfg.get('retain_full_high',0))]
  dflags += ['-DLC_DSA_INPLACE_SAMPLE='+str(cfg.get('inplace_sample',0)),'-DLC_DSA_PACKED_ACCUM='+str(cfg.get('packed_accum',0))]
  dflags += ['-DLC_DSA_FUSED_PACKED_MATRIX='+str(cfg.get('fused_matrix',0))]
  dflags += ['-DLC_DSA_STREAM_RECOMPUTE='+str(cfg.get('stream_recompute',0))]
  dflags += ['-DLC_DSA_GAMMA_REVERSE_AVX2='+str(cfg.get('gamma_reverse_avx2',0))]
  dflags += ['-DLC_DSA_EARLY_HINT_FLAGS='+str(cfg.get('early_hint_flags',0)),'-DLC_DSA_SIGNED24_NATIVE='+str(cfg.get('signed24_native',0)),'-DLC_DSA_PACK_VERIFY_CP='+str(cfg.get('pack_verify_cp',0))]
  dflags += ['-DLC_DSA_MATRIX_STREAM_DIRECT4='+str(cfg.get('matrix_stream_direct4',0)),'-DLC_DSA_MATRIX_STREAM_VECTOR='+str(cfg.get('matrix_stream_vector',0)),'-DLC_DSA_MATRIX_TAIL_SINGLE='+str(cfg.get('matrix_tail_single',0))]
  dflags += ['-DLC_DSA_DECOMPOSE_NEON='+str(cfg.get('decompose_neon',0))]
  dflags += ['-DLC_DSA_KEYGEN_ETA4='+str(cfg.get('keygen_eta4',0))]
  dflags += ['-DLC_DSA_A_PLANES24='+str(cfg.get('a_planes24',0)),
              '-DLC_DSA_INPLACE_AY='+str(cfg.get('inplace_ay',0)),
              '-DLC_DSA_KEYGEN_ETA_ARENA='+str(cfg.get('keygen_eta_arena',0)),
              '-DLC_DSA_MATRIX4_ARENA='+str(cfg.get('matrix4_arena',0))]
  dflags += ['-DLC_DSA_KEYVERIFY_DENSE='+str(cfg.get('keyverify_dense',0))]
  dflags += ['-DLC_DSA_NATIVE_MATRIX_ROWS='+str(cfg.get('native_matrix_rows',0))]
  dflags += ['-DLC_DSA_FUSED_KEYGEN_PACK='+str(cfg.get('fused_keygen_pack',0))]
  dflags += ['-DLC_DSA_KEYGEN_RETAIN_S2='+str(cfg.get('keygen_retain_s2',0))]
  dflags += ['-DLC_DSA_VERIFY_HASH_BATCH='+str(cfg.get('verify_hash_batch',0))]
  if a.inline_stream_leaves:
   if a.backend!='aarch64':raise ValueError('NEON inline-leaf policy requires AArch64')
   dflags += ['-DLC_DSA_STREAM_INLINE_LEAVES=1']
  if a.direct_stream_state:
   if a.backend!='aarch64':raise ValueError('Direct stream state requires AArch64')
   dflags += ['-DLC_DSA_STREAM_DIRECT_STATE=1']
  if a.codec24_neon:
   if a.backend!='aarch64':raise ValueError('NEON signed24 codec requires AArch64')
   dflags += ['-DLC_DSA_CODEC24_NEON=1']
  if a.shared_c_owners:
   if a.backend!='aarch64' or not a.sparse_neon or not a.direct_stream_state:raise ValueError('Shared C owners require selected ARM direct stream and sparse schedule')
   dflags+=['-DLC_DSA_SHARED_C_OWNERS=1']
  if a.sparse_neon:
   if a.backend!='aarch64':raise ValueError('NEON sparse products require AArch64')
   dflags += ['-DLC_DSA_SPARSE_NEON=1']
  if a.sparse_t0_neon:
   if a.backend!='aarch64' or not a.sparse_neon:raise ValueError('Sparse t0 requires the ARM sparse eta schedule')
   dflags += ['-DLC_DSA_SPARSE_T0_NEON=1']
  if a.verify_t1_centered_neon:
   if a.backend!='aarch64' or not cfg['modified'] or not cfg.get('pack_verify_cp'):raise ValueError('Centered t1 requires the modified ARM packed-challenge schedule')
   dflags += ['-DLC_DSA_VERIFY_T1_CENTERED_NEON=1']
  if cfg.get('shared_keccak'):
   general += ['-I'+str(ROOT/'configs/shared_keccak_compact')]
   kflags += ['-I'+str(ROOT/'configs/shared_keccak_compact'),'-DMLK_CONFIG_USE_NATIVE_BACKEND_FIPS202','-DMLK_CONFIG_FIPS202_BACKEND_FILE="lc_shared_mlk.h"']
   dflags += ['-I'+str(ROOT/'configs/shared_keccak_compact'),'-DMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202','-DMLD_CONFIG_FIPS202_BACKEND_FILE="lc_shared_mld.h"']
  if cfg.get('shared_native_aarch64'):
   if a.backend!='aarch64':raise ValueError('Shared native Keccak owner requires the AArch64 six-parameter build')
   dflags += ['-I'+str(ROOT/'configs/shared_native_aarch64'),'-DMLD_CONFIG_FIPS202_BACKEND_FILE="lc_shared_mld.h"']
  if cfg.get('shared_native_rejection_table'):
   if a.backend!='aarch64':raise ValueError('Shared native rejection table requires AArch64')
   dflags += ['-DLC_ARM_SHARED_REJECTION_TABLE=1']
  if cfg['reduce_ram']:dflags+=['-DMLD_CONFIG_REDUCE_RAM']
  if a.backend!='portable':
   kflags+=['-DLC_NATIVE']
   dflags+=['-DMLD_CONFIG_USE_NATIVE_BACKEND_ARITH','-DMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202']
  kem_entry=ROOT/'baselines/mlkem/all.c';dsa_entry=dsaconfig/'adapter.c';public_entry=ROOT/'src/common/public_api.c'
  shared_kem_owner=bool(not klevels and dlevels and (cfg.get('shared_native_aarch64') or cfg.get('shared_native_rejection_table')))
  if a.parameters is not None:
   generated=out/'generated';generated.mkdir()
   entries={'public_api.c':public_source(ROOT,levels,operations),'mlkem_selected.c':kem_source(ROOT,levels,operations),'dsa_adapter.c':adapter_source(dsaconfig/'adapter.c',levels,operations)}
   if shared_kem_owner:entries['mlkem_selected.c']+=shared_kem_constants('aarch64',bool(cfg.get('shared_native_rejection_table')))
   for name,body in entries.items():
    path=generated/name;path.write_text(body,encoding='utf-8');generated_sources[path.relative_to(out).as_posix()]=sha(path)
   kem_entry=generated/'mlkem_selected.c';dsa_entry=generated/'dsa_adapter.c';public_entry=generated/'public_api.c'
  units=[(kem_entry,kflags),(ROOT/'src/common/arena.c',general)]
  if cfg.get('runtime_cache'):units.append((ROOT/'src/common/resource_plan.c',general+['-I'+str(dsaconfig)]))
  for i,level in enumerate(dlevels):
   units.append((dsaroot/'mldsa_native.c',dflags+['-DMLD_CONFIG_PARAMETER_SET='+str(level),'-DMLD_CONFIG_MULTILEVEL_'+('WITH_SHARED' if i==0 else 'NO_SHARED')]))
  units += [(dsa_entry,dflags),(public_entry,general+['-I'+str(dsaconfig)]),(ROOT/'src/platform/random.c',general)]
  if dlevels and a.verify_t1_centered_neon:
   units.append((ROOT/'src/dsa_packed/lc_verify_t1_centered_neon.c',general))
  if a.backend!='portable':
   if a.assembly_archive:
    if a.backend!='aarch64':raise ValueError('Individual assembly archive currently supports AArch64')
    groups=[]
    if klevels or shared_kem_owner:groups.append((kemroot,kflags+['-DMLK_CONFIG_PARAMETER_SET='+str(klevels[0] if klevels else 512),'-DMLK_CONFIG_MULTILEVEL_WITH_SHARED'],bool(klevels)))
    if dlevels:groups.append((dsaroot,dflags+['-DMLD_CONFIG_PARAMETER_SET='+str(dlevels[0]),'-DMLD_CONFIG_MULTILEVEL_WITH_SHARED'],True))
    for root,options,arithmetic in groups:
     for folder in (['src/native/aarch64/src','src/fips202/native/aarch64/src'] if arithmetic else ['src/fips202/native/aarch64/src']):
      units += [(p,options) for p in sorted((root/folder).glob('*.S'))]
   else:
    if klevels:units.append((kemroot/'mlkem_native_asm.S',kflags+['-DMLK_CONFIG_PARAMETER_SET='+str(klevels[0]),'-DMLK_CONFIG_MULTILEVEL_WITH_SHARED']))
    if shared_kem_owner:raise ValueError('DSA-only shared native owners require assembly-archive mode')
    if dlevels:units.append((dsaroot/'mldsa_native_asm.S',dflags+['-DMLD_CONFIG_PARAMETER_SET='+str(dlevels[0]),'-DMLD_CONFIG_MULTILEVEL_WITH_SHARED']))
  if cfg.get('shared_keccak'):units.append((ROOT/'configs/shared_keccak_compact/owner_single.c',general))
  objects=[];assembly_objects=[]
  for i,(source,options) in enumerate(units):
   obj=out/'obj'/('%02d_%s.o'%(i,source.stem));dep=obj.with_suffix('.d')
   run([cc,*flags,*options,*['-D'+v for v in a.extra_defs],'-MMD','-MF',dep,'-c',source,'-o',obj],'compile_%02d'%i);objects.append(obj)
   if source.suffix=='.S':assembly_objects.append(obj)
   deptext=dep.read_text(encoding='utf-8').replace('\\\n',' ');dependency_list=deptext.split(': ',1)[1]
   paths=[x.replace('\\ ',' ') for x in re.split(r'(?<!\\)\s+',dependency_list.strip())] if windows else shlex.split(dependency_list)
   for name in paths:
    p=Path(name);p=(ROOT/p).resolve() if not p.is_absolute() else p.resolve()
    if p.is_relative_to(ROOT):sources[p.relative_to(ROOT).as_posix()]=sha(p)
    elif p.is_relative_to(out):generated_sources[p.relative_to(out).as_posix()]=sha(p)
  for rel in ['tools/build_variants.py','tools/build_variants_arm.py','tools/native_options.py','tools/configuration_capabilities.py','tools/pruning_sources.py','tools/binary_build_utils.py','tests/public_api/probe.c']:sources[rel]=sha(ROOT/rel)
  if a.parameters is not None:
   for rel in ['tests/pruning/probe.c','configs/pruned/latticecore_pruned.h','src/common/public_api.c','baselines/mlkem/all.c']:sources[rel]=sha(ROOT/rel)
   sources[(dsaconfig/'adapter.c').relative_to(ROOT).as_posix()]=sha(dsaconfig/'adapter.c')
  static=out/'liblatticecore.a'
  if windows:
   export=out/'exports.def';export.write_text('EXPORTS\n'+''.join(x+'\n' for x in public_symbols))
   lib=out/'latticecore.dll'
   sharedflags=[export,'-lbcrypt','-Wl,--out-implib,'+str(out/'liblatticecore.dll.a')]
  else:
   export=out/'exports.map';export.write_text('{\n global:\n'+''.join('  '+x+';\n' for x in public_symbols)+' local: *;\n};\n')
   lib=out/'liblatticecore.so'
   sharedflags=(['-Wl,--save-temps'] if a.linker=='lld-14' else [])+['-Wl,-z,defs','-Wl,-z,noexecstack','-Wl,--version-script='+str(export)]
  if a.minimal_elf_startup:
   if windows:raise ValueError('Minimal ELF startup requires a Linux shared library')
   sharedflags+=['-nostartfiles']
  link_objects=objects
  if a.assembly_archive:
   assembly_archive=out/'libnative_assembly.a'
   run([ar,'rcs',assembly_archive,*assembly_objects],'archive_native_assembly')
   link_objects=[p for p in objects if p not in assembly_objects]+[assembly_archive]
  run([cc,*linkflags,'-shared',*link_objects,*sharedflags,'-Wl,--gc-sections','-Wl,-Map,'+str(out/'latticecore.map'),'-o',lib],'link_shared')
  run([ar,'rcs',static,*objects],'archive_static')
  if windows:
   binary=pe_exports(lib)
   if binary['machine']!=0x8664 or binary['bits']!=64 or binary['exports']!=sorted(public_symbols):raise ValueError('Unexpected PE target/export set')
  else:
   exported=run([a.nm,'-D','--defined-only','--format=posix',lib],'exports')
   if sorted(line.split()[0].split('@')[0] for line in exported.splitlines())!=sorted(public_symbols):raise ValueError('Unexpected export set')
   raw=lib.read_bytes();machine=struct.unpack_from('<H',raw,18)[0]
   if raw[:4]!=b'\x7fELF' or (a.backend=='aarch64' and machine!=183):raise ValueError('Wrong ELF target')
   binary=dict(format='ELF',machine=machine,bits=64 if raw[4]==2 else 32)
  symbols=run([a.nm,'-S','--defined-only',lib],'entities')
  run([a.size,'-A',lib],'sections')
  checks={}
  probe_source=ROOT/('tests/pruning/probe.c' if a.parameters is not None else 'tests/public_api/probe.c')
  probe_flags=['-I'+str(ROOT/'include')]
  if a.parameters is not None:probe_flags+=['-I'+str(ROOT/'configs/pruned'),'-DLC_SELECTED_PARAMETERS='+','.join(map(str,levels))]
  if operations is not None:
   import importlib.util
   spec=importlib.util.spec_from_file_location('lc_deployment_vectors',ROOT/'tests/targets/generate_vectors.py');vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
   vector_record=vm.generate(ROOT,out/'generated',cells(operations,levels))
   sources.update(vector_record['source_files'])
   for rel in ['tests/pruning/operation_probe.c','tests/targets/generate_vectors.py','tools/operation_selection.py']:sources[rel]=sha(ROOT/rel)
   for rel in ['generated/vectors.h','generated/vectors.xml']:generated_sources[rel]=sha(out/rel)
   probe_source=ROOT/'tests/pruning/operation_probe.c';probe_flags+=['-I'+str(out/'generated'),'-DLC_PROBE_WORKSPACE='+str(a.probe_workspace)]
  probe_extra=[]
  if operations is not None:
   stack_name='stack_windows_x64.S' if windows else 'stack_aarch64.S' if a.backend=='aarch64' else 'stack_linux_x64.S'
   probe_extra=[ROOT/'tests/resources'/stack_name];sources[probe_extra[0].relative_to(ROOT).as_posix()]=sha(probe_extra[0])
  for linkage in ['shared','static']:
   exe=out/('probe_'+linkage+('.exe' if windows else ''))
   libraries=[static] if linkage=='static' else ([out/'liblatticecore.dll.a'] if windows else ['-L'+str(out),'-llatticecore','-Wl,-rpath,$ORIGIN'])
   if windows:libraries+=['-lbcrypt']
   run([cc,*linkflags,*probe_flags,probe_source,*probe_extra,*libraries,'-o',exe],'probe_'+linkage+'_compile')
   text=run([exe,str(a.probe_count)],'probe_'+linkage+'_run');checks[linkage]=dict(exit_code=0,stdout=json.capture_text(text),sha256=sha(exe))
   if cfg.get('runtime_cache'):
    resource_source=ROOT/'tests/public_api'/('resource_plan_probe.c' if a.parameters is None else 'resource_subset_probe.c')
    sources[resource_source.relative_to(ROOT).as_posix()]=sha(resource_source)
    resource_exe=out/('resource_probe_'+linkage+('.exe' if windows else ''))
    mask=sum(1<<([512,768,1024,44,65,87].index(p)*3+op) for p,op in cells(operations,levels))
    run([cc,*linkflags,'-I'+str(ROOT/'include'),'-DLC_RESOURCE_OPERATION_MASK='+str(mask)+'u',resource_source,*libraries,'-o',resource_exe],'resource_probe_'+linkage+'_compile')
    text=run([resource_exe],'resource_probe_'+linkage+'_run')
    checks['resources_'+linkage]=dict(exit_code=0,stdout=json.capture_text(text),sha256=sha(resource_exe))
  for rel,digest in sources.items():
   if sha(ROOT/rel)!=digest:raise ValueError('Source changed during build: '+rel)
  write(out/'build.xml',dict(schema='latticecore.build.v2',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),configuration=a.config,parameters=levels,operations=operations,probe_workspace=a.probe_workspace,selected_dispatch=a.parameters is not None,shared_kem_constants_owner=shared_kem_owner,extra_definitions=a.extra_defs,
    schedule=cfg,backend=a.backend,compiler=version,compiler_family=compiler_family,linker=a.linker,whole_program_flag=bool(whole_program),safe_icf=a.safe_icf,shared_c_owners=a.shared_c_owners,machine_outline=a.machine_outline,target=target,optimization=a.opt,lto=a.lto,sanitizer=a.sanitize,minimal_elf_startup=a.minimal_elf_startup,inline_single_call=a.inline_single_call,omit_unwind_metadata=a.omit_unwind_metadata,inline_stream_leaves=a.inline_stream_leaves,direct_stream_state=a.direct_stream_state,codec24_neon=a.codec24_neon,sparse_neon=a.sparse_neon,sparse_t0_neon=a.sparse_t0_neon,verify_t1_centered_neon=a.verify_t1_centered_neon,assembly_archive=a.assembly_archive,omit_frame_pointer=a.omit_frame_pointer,kem_k2rows=a.kem_k2rows,shared_kem_sampler=a.shared_kem_sampler,canonical12_neon=a.canonical12_neon,gamma_neon=a.gamma_neon,compact_dsa_ntt=a.compact_dsa_ntt,compact_dsa_barrett=a.compact_dsa_barrett,compact_kem_ntt=a.compact_kem_ntt,packed_rejection_table=a.packed_rejection_table,mixed_head65=a.mixed_head65,early_low_all=a.early_low_all,compact_dsa_fused3=a.compact_dsa_fused3,raw_y4_cache=a.raw_y4_cache,raw_y_prefix=a.raw_y_prefix,shared_sensitive_free=a.shared_sensitive_free,shared_challenge=a.shared_challenge,crosscol6=a.crosscol6,crosscol6_workspace=a.crosscol6_workspace,caller_output_scratch_bytes_by_parameter={'65':1024} if a.crosscol6 else {},
    source_hashes=sources,generated_source_hashes=generated_sources,binary=dict(**binary,sha256=sha(lib),static_sha256=sha(static)),
    public_checks=checks,commands_sha256=sha(out/'commands.xml'),map_sha256=sha(out/'latticecore.map'),elapsed_seconds=time.monotonic()-began))
  print(a.config+' / '+a.backend+': built and public probes passed',flush=True)
 except Exception as e:
  write(out/'failure.xml',dict(error=str(e),elapsed_seconds=time.monotonic()-began));raise
if __name__=='__main__':main()
