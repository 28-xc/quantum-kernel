"""Finite requirement and generated-dispatch checks; no target execution."""
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
import record_io as json, sys, unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from operation_selection import normalize,cells
from pruning_sources import public_source,kem_source,adapter_source
from deploy import validate

class OperationRequirements(unittest.TestCase):
    def setUp(self):
        self.ops={'768':['encaps'],'65':['verify']}
        self.request=dict(schema='lattice.deployment_request.v1',platform='m4',parameters=[768,65],operations=self.ops,
                          budgets=dict(program_bytes=524288,ram_bytes=589824,writable_ram_bytes=65536),workspace_bytes=12288,recipes=['compact-rate'])
    def test_explicit_selection(self):
        self.assertEqual(cells(normalize(self.ops,[768,65]),[768,65]),{(768,1),(65,2)})
        self.assertEqual(validate(self.request)['operations'],self.ops)
    def test_no_missing_parameter(self):
        for value in ({'768':['encaps']},{'768':['encaps'],'65':[]},{'768':['encaps'],'65':['encaps']},
                      {'768':['encaps','encaps'],'65':['verify']},{'768':['encaps'],'65':['verify'],'44':['sign']}):
            with self.subTest(value=value),self.assertRaises(ValueError):normalize(value,[768,65])
    def test_no_silent_budget_or_platform_downgrade(self):
        for change in ({'parameters':[768]},{'platform':'rv64'},{'recipes':['native-arm']},{'budgets':{'ram_bytes':65536}},
                       {'workspace_bytes':33},{'recipes':[]},{'test_stack_bytes':32},{'extra':'ignored'}):
            with self.subTest(change=change),self.assertRaises(ValueError):validate(dict(self.request,**change))
    def test_kem_dispatch_contains_only_encapsulation(self):
        text=kem_source(ROOT,[768,65],self.ops).split('int lc_mlk_call(')[1]
        self.assertIn('lc_base_mlk768_enc_derand(',text)
        for omitted in ('keypair_derand','_dec(','check_pk','check_sk','LC_CASE'):self.assertNotIn(omitted,text)
    def test_dsa_dispatch_contains_only_verify(self):
        text=adapter_source(ROOT/'src/dsa_packed/adapter.c',[768,65],self.ops)
        for omitted in ('ret=lcbase65_keypair','ret=lcbase65_signature'):self.assertNotIn(omitted,text)
        self.assertIn('ret=lcbase65_verify(',text)
    def test_public_omitted_operations_are_stubs(self):
        from operation_selection import body_span
        text=public_source(ROOT,[768,65],self.ops)
        for name in ('keypair','decaps','sign'):
            a,b=body_span(text,'lc_'+name);body=text[a:b]
            self.assertIn('LC_E_UNSUPPORTED',body);self.assertNotIn('lc_mlk_call',body);self.assertNotIn('lc_dsa_',body)
    def test_parameter_and_operation_are_not_confused(self):
        text=public_source(ROOT,[768,65],self.ops)
        self.assertIn('case 768:s->public_key=',text);self.assertIn('case 65:s->public_key=',text)
        self.assertNotIn('case 44:s->public_key=',text)
    def test_retained_wrong_algorithm_is_argument_error(self):
        from operation_selection import body_span
        text=public_source(ROOT,[768,65],self.ops)
        for name in ('encaps','decaps','sign','verify'):
            a,b=body_span(text,'lc_'+name);body=text[a:b]
            self.assertLess(body.index('LC_E_ARGUMENT'),body.index('LC_E_UNSUPPORTED'))

if __name__=='__main__':unittest.main()
