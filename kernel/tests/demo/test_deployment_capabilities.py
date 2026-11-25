"""Check the actual build recipe against CPU and operating-system capabilities."""
from pathlib import Path
import sys,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from demo.deployment_ui import DeploymentBuilds,recipe_availability,HOST_RECIPES

class Capabilities(unittest.TestCase):
    def test_native_x86_contract(self):
        good=dict(architecture='x86_64',query_succeeded=True,features=['avx','avx2','bmi2','avxvnni'],xcr0=6)
        self.assertTrue(recipe_availability('native-x86',good)['available'])
        for absent in good['features']:
            host=dict(good,features=[f for f in good['features'] if f!=absent])
            self.assertFalse(recipe_availability('native-x86',host)['available'],absent)
        for host in (dict(good,query_succeeded=False),dict(good,xcr0=2),dict(good,architecture='aarch64')):
            self.assertFalse(recipe_availability('native-x86',host)['available'])
    def test_native_arm_contract(self):
        good=dict(architecture='aarch64',query_succeeded=True,features=['fp','asimd'],xcr0=0)
        self.assertTrue(recipe_availability('native-arm',good)['available'])
        self.assertFalse(recipe_availability('native-arm',dict(good,features=['fp']))['available'])
        self.assertFalse(recipe_availability('native-arm',dict(good,query_succeeded=False))['available'])
    def test_available_baseline_does_not_enable_vnni_recipe(self):
        host=dict(architecture='x86_64',query_succeeded=True,features=['avx','avx2','bmi2'],xcr0=6)
        with patch('demo.deployment_ui.sys.platform','win32'),patch('demo.deployment_ui.platform.machine',return_value='AMD64'),patch('demo.deployment_ui.shutil.which',return_value='compiler'):
            catalog=DeploymentBuilds(ROOT.parent/'unused-capability-test',host).catalog()
        local=next(x for x in catalog['platforms'] if x['id']=='windows-x86_64')
        self.assertNotIn('recipes',local)
        self.assertEqual([x['id'] for x in local['strategies']],['low-memory','performance'])
        for strategy in local['strategies']:
            self.assertEqual(strategy['available'],recipe_availability(strategy['recipe'],host)['available'])
    def test_unknown_cpu_retains_portable_recipes(self):
        self.assertTrue(recipe_availability('compact-rate',{})['available'])
        self.assertTrue(recipe_availability('compact-recompute',{})['available'])
    @patch('demo.deployment_ui.sys.platform','win32')
    @patch('demo.deployment_ui.platform.machine',return_value='AMD64')
    @patch('demo.deployment_ui.shutil.which',return_value='compiler')
    def test_two_strategies_preserve_requested_functionality(self,*_):
        host=dict(architecture='x86_64',query_succeeded=True,features=['avx','avx2','bmi2','avxvnni'],xcr0=6)
        builds=DeploymentBuilds(ROOT.parent/'unused-capability-test',host)
        parameters=[512,768,1024,44,65,87]
        operations={str(p):['keypair','encaps','decaps'] if p>100 else ['keypair','sign','verify'] for p in parameters}
        for strategy in ('low-memory','performance'):
            value=dict(schema='lattice.deployment_strategy_request.v1',platform='windows-x86_64',strategy=strategy,
                parameters=parameters,operations=operations,budgets=dict(program_bytes=524288,ram_bytes=262144))
            request=builds.validate(value)
            self.assertEqual(request['recipes'],[HOST_RECIPES[('windows-x86_64',strategy)]])
            self.assertEqual(request['parameters'],parameters)
            self.assertEqual(request['operations'],operations)
            self.assertEqual(request['budgets'],value['budgets'])
            self.assertEqual(value['schema'],'lattice.deployment_strategy_request.v1')
            for invalid in (dict(value,recipes=['native-x86-cache40-gamma']),dict(value,strategy='cache40'),
                            dict(value,schema='lattice.deployment_request.v1')):
                with self.assertRaises(ValueError):builds.validate(invalid)
        for platform in ('m4','rv32'):
            entry=next(x for x in builds.catalog()['platforms'] if x['id']==platform)
            self.assertTrue(entry['emulated'])
            self.assertIn('仿真',entry['title'])
            self.assertEqual([x['id'] for x in entry['strategies']],['low-memory'])
            with self.assertRaises(ValueError):builds.validate(dict(value,platform=platform,strategy='performance'))
if __name__=='__main__':unittest.main()
