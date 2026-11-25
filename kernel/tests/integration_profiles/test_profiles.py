"""Validate explicit recipe contracts without compiling cryptographic code."""
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
import ast, copy, hashlib, record_io as json, sys, tempfile, unittest
from argparse import Namespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from public_recipes import RECIPES
from configuration_capabilities import validate_pruned_configuration
import build as public_build
from statistics_source_manifest import verify as verify_statistics

class Profiles(unittest.TestCase):
    def valid(self,name):
        for backend in RECIPES[name]['backends']:
            validate_pruned_configuration(name,RECIPES[name]['algorithm'],backend)
    def reject(self,name,changes,backend=None):
        cfg=copy.deepcopy(RECIPES[name]['algorithm']);cfg.update(changes)
        with self.assertRaises(ValueError):validate_pruned_configuration(name,cfg,backend or RECIPES[name]['backends'][0])
    def test_statistics_identity(self):
        self.assertEqual(verify_statistics(json.loads((ROOT/'publicschemas/pooled_provenance.xml').read_text(encoding='utf-8')),ROOT),11)
    def test_native_source_receipt_matches_supplied_files(self):
        value=json.loads((ROOT/'docs/native_reference.xml').read_text(encoding='utf-8'))
        expected={'mldsa-native':'7625016fca797896fa7b87cf5455b587a0199682','mlkem-native':'6b12c8cd67e1edd07c43f581386449a6b064e6e2'}
        for repo in value['repositories']:
            self.assertEqual(repo['commit'],expected[repo['repository']])
            changed={x['path']:x['supplied_sha256']for x in repo['local_adaptations']}
            supplied_paths={x['path']:x.get('supplied_path',x['path']) for x in repo['local_adaptations']}
            for row in repo['files']:
                path=ROOT/'third_party'/repo['repository']/supplied_paths.get(row['path'],row['path'])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),changed.get(row['path'],row['sha256']))
    def test_partial_saved_count_rule(self):
        for rows in range(1,7):
            for separate in (0,1):
                count=7 if separate else 7-rows
                self.assertGreater(count,0)
                self.assertEqual(rows*7*768+count*1024,rows*5376+count*1024)
        text=(ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted/src/sign.c').read_text(encoding='utf-8')
        self.assertIn('MLD_ALLOC(lc_cached_y,mld_poly,LC_DSA_PARTIAL_DENSE_SAVED_COUNT(MLDSA_L),context)',text)
        self.assertIn('MLD_FREE(lc_cached_y,mld_poly,LC_DSA_PARTIAL_DENSE_SAVED_COUNT(MLDSA_L),context)',text)
        adapter=(ROOT/'src/dsa_packed/adapter.c').read_text(encoding='utf-8')
        self.assertIn('LC_DSA_PARTIAL_DENSE_SAVED_COUNT(7)',adapter)
        self.assertLess(adapter.index('extra=retained*256'),adapter.index('LC_DSA_PARTIAL_DENSE_SAVED_COUNT(7)'))
    def test_session_abi_declarations_match(self):
        texts=[(ROOT/p).read_text(encoding='utf-8')for p in ['src/dsa_packed/lc_dsa_api.h','baselines/mldsa/lc_dsa_api.h']]
        sections=[x[x.index('#if LC_DSA_PUBLIC_A_SESSION'):].strip()for x in texts]
        self.assertEqual(*sections)
    def test_speed_direct_rows(self):
        for arch in ('x86','arm'):
            self.assertEqual(RECIPES[f'native-{arch}-sign-pipeline']['algorithm']['direct_dense_rows'],1)
    def test_original_public_exports(self):
        import build_variants
        self.assertEqual(len(build_variants.PUBLIC),8)
        for name in ('build_variants.py','build_variants_arm.py'):
            text=(ROOT/'tools'/name).read_text(encoding='utf-8')
            self.assertIn("if cfg.get('public_a_session',0) else []",text)
            self.assertIn('sorted(public_symbols)',text)
    def test_session_cleanup_and_binding_hooks(self):
        text=(ROOT/'src/common/a_session_public.h').read_text(encoding='utf-8')
        self.assertIn('s->format_tag!=lc_dsa_a_format_tag(s->parameter)',text)
        self.assertLess(text.index('validate(c,r,6)'),text.index('memcmp(s->rho,sk,32)'))
        self.assertLess(text.index('memcmp(s->rho,sk,32)'),text.index('random_bytes(c,seed,32)'))
        self.assertIn('lc_zero(s->cache,s->capacity);lc_zero(s,sizeof(*s))',text)
    def test_source_path_rejects_escape(self):
        for name in ('../bad','C:/bad','tools\\build.py','/tmp/bad'):
            with self.assertRaises(ValueError):public_build.source_path(name)
    def test_source_inventory_is_explicit(self):
        inventory=json.loads((ROOT/'configs/source_files.xml').read_text(encoding='utf-8'))
        self.assertEqual(inventory['paths'],sorted(set(inventory['paths'])))
        for name in ['include/lattice_session.h','src/dsa_packed/lc_partial_dense.h','src/common/a_session_public.h',
                     'src/dsa_packed/lc_a_session_impl.h','src/dsa_packed/lc_a_session_adapter.h',
                     'examples/public_a_session/application.c','tests/integration_profiles/test_profiles.py']:
            self.assertIn(name,inventory['paths'])
        self.assertFalse(any('.git/'in p or '__pycache__/'in p for p in inventory['paths']))
    def test_partial_session_mutual_exclusion_is_in_c(self):
        text=(ROOT/'src/dsa_packed/lc_dsa_config.h').read_text(encoding='utf-8')
        self.assertIn('#if LC_DSA_PUBLIC_A_SESSION && LC_DSA_PARTIAL_DENSE_ROWS',text)
    def test_all_builder_python_syntax(self):
        for name in ['build.py','build_variants.py','build_variants_arm.py','configuration_capabilities.py']:
            ast.parse((ROOT/'tools'/name).read_text(encoding='utf-8'))
    def test_tampered_plan_rejected_before_compiler(self):
        data=dict(schema='lattice.build_plan.v1',request={},sources=[],identity='0'*64)
        with tempfile.TemporaryDirectory(prefix='lc-plan-',dir=ROOT.parent)as folder:
            p=Path(folder)/'plan.xml';p.write_text(json.dumps(data),encoding='utf-8')
            with patch.object(public_build.subprocess,'run',side_effect=AssertionError('compiler reached')):
                with self.assertRaisesRegex(ValueError,'Source or plan changed'):
                    public_build.build(Namespace(plan=p,output=Path(folder)/'never-built'))
    def test_stale_source_plan_rejected_before_compiler(self):
        body=dict(request={},sources=[dict(path='tools/build.py',sha256='0'*64,bytes=0)])
        data=dict(schema='lattice.build_plan.v1',**body,identity=public_build.identity(body))
        with tempfile.TemporaryDirectory(prefix='lc-source-plan-',dir=ROOT.parent)as folder:
            p=Path(folder)/'plan.xml';p.write_text(json.dumps(data),encoding='utf-8')
            with patch.object(public_build.subprocess,'run',side_effect=AssertionError('compiler reached')):
                with self.assertRaisesRegex(ValueError,'Source or plan changed'):
                    public_build.build(Namespace(plan=p,output=Path(folder)/'never-built'))

for name in RECIPES:
    if any(s in name for s in ('whole-row','public-a-session','reference-x86-a','reference-arm-a','reference-x86-session','reference-arm-session')):
        def valid(self,n=name):self.valid(n)
        setattr(Profiles,'test_valid_'+name.replace('-','_'),valid)

negative=[
 ('native-x86-whole-row64',{'partial_dense_rows':-1}),
 ('native-x86-whole-row64',{'partial_dense_rows':7}),
 ('native-x86-whole-row64',{'partial_dense_rows':True}),
 ('native-x86-whole-row64',{'partial_dense_rows':0,'partial_dense_separate_y':1}),
 ('native-x86-whole-row64',{'partial_dense_separate_y':2}),
 ('native-x86-whole-row64',{'matrix_cache_87_cap':28}),
 ('native-x86-whole-row64',{'matrix_interleaved':0}),
 ('native-x86-whole-row64',{'matrix_cache_bits':32}),
 ('native-x86-whole-row64',{'matrix_cache_sign_only':0}),
 ('native-x86-whole-row64',{'cached_dot_tile':0}),
 ('native-x86-whole-row64',{'matrix_cache_batch4':1}),
 ('native-x86-whole-row64',{'stream_recompute':1}),
 ('native-x86-whole-row64',{'public_a_session':1}),
 ('native-x86-whole-row64',{'undocumented_mechanism':1}),
 ('native-arm-whole-row64',{'stream_neon':0}),
 ('native-arm-whole-row64',{'direct_dense_rows':2}),
 ('reference-x86-a24',{'native_matrix_cache':57}),
 ('reference-x86-a24',{'native_matrix_cache':True}),
 ('reference-x86-a24',{'native_s1_cache':8}),
 ('reference-x86-a24',{'native_s2_cache':9}),
 ('reference-x86-a24',{'native_t0_cache':9}),
 ('reference-x86-a24',{'modified':True}),
 ('reference-x86-a24',{'reduce_ram':False}),
 ('reference-x86-session-a34',{'native_a_session_polys':0}),
 ('reference-x86-session-a34',{'native_a_session_polys':57}),
 ('reference-x86-session-a34',{'native_matrix_cache':24}),
 ('reference-arm-session-a34',{'public_a_session':0}),
 ('native-x86-public-a-session',{'public_a_session':2}),
 ('native-x86-public-a-session',{'matrix_cache_batch4':1}),
 ('native-x86-public-a-session',{'matrix_cache_polys':40})]
for i,(name,changes)in enumerate(negative):
    def reject(self,n=name,c=changes):self.reject(n,c)
    setattr(Profiles,f'test_reject_{i:02}',reject)

if __name__=='__main__':unittest.main()
