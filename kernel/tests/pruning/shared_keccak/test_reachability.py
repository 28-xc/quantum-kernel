"""Synthetic graph cases, not evidence about production binaries."""
import unittest
from reachability import analyze


class GraphCases(unittest.TestCase):
    def setUp(self):
        self.entities = [dict(address=a, symbol=s) for a, s in
                         [(0x100, 'lc_base_mlk_entry'), (0x200, 'lcbase_entry'),
                          (0x300, 'helper'), (0x400, 'lc_shared_keccakf1600')]]
        self.asm = ('00000100 <lc_base_mlk_entry>:\n 100: 140000c0 b 400 <lc_shared_keccakf1600>\n'
                    '00000200 <lcbase_entry>:\n 200: 94000040 bl 300 <helper>\n'
                    '00000300 <helper>:\n 300: 94000040 bl 400 <lc_shared_keccakf1600>\n')

    def test_direct_tail_and_helper(self):
        r = analyze(self.entities, self.asm)
        self.assertEqual(len(r['witnesses'][1]['path']), 3)

    def test_alias_address(self):
        self.entities.append(dict(address=0x200, symbol='compiler_alias'))
        r = analyze(self.entities, self.asm.replace('<lcbase_entry>:', '<compiler_alias>:'))
        self.assertIn('compiler_alias', r['witnesses'][1]['path'][0]['aliases'])

    def test_missing_family_rejected(self):
        with self.assertRaises(ValueError):
            analyze(self.entities, self.asm.split('00000200')[0])

    def test_indirect_not_proof(self):
        with self.assertRaises(ValueError):
            analyze(self.entities, self.asm.replace('bl 400 <lc_shared_keccakf1600>', 'blr x3'))

    def test_unknown_target_not_proof(self):
        with self.assertRaises(ValueError):
            analyze(self.entities, self.asm.replace('bl 400 <lc_shared_keccakf1600>', 'bl 500 <unknown>'))

    def test_provider_alias_not_a_family_path(self):
        entities = [e for e in self.entities if e['symbol'] != 'lcbase_entry']
        entities.append(dict(address=0x400, symbol='lcbase_fake_alias'))
        with self.assertRaises(ValueError):
            analyze(entities, self.asm.split('00000200')[0])

    def test_duplicate_provider_rejected(self):
        with self.assertRaises(ValueError):
            analyze(self.entities + [self.entities[-1]], self.asm)


if __name__ == '__main__':
    unittest.main()
