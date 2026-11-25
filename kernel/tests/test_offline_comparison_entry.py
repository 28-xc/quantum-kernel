"""Offline dispatch contract; synthetic targets are never executed."""
from pathlib import Path
import contextlib
import importlib.util
import io
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('offline_dispatch_test', ROOT/'tools/offline_analysis.py')
offline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(offline)


class OfflineComparisonEntry(unittest.TestCase):
    def dispatch(self, entry, relative_target):
        with tempfile.TemporaryDirectory(prefix='offline-entry-') as directory:
            bundle = Path(directory)
            target = bundle/relative_target
            target.parent.mkdir(parents=True)
            target.write_text('# Synthetic target; no execution.\n', encoding='utf-8')
            argv = ['offline_analysis.py', '--bundle', str(bundle), '--entry', entry,
                    '--', '--mode', 'replay', '--input', 'data/plan.xml', '--output', '../result']
            dependency = types.ModuleType('numpy')
            dependency.__version__ = '2.2.5'
            with patch.object(sys, 'argv', argv), patch.object(sys, 'path', list(sys.path)), \
                 patch.dict(sys.modules, {'numpy': dependency}), \
                 patch.object(offline, 'numpy_site', return_value=bundle/'dependency') as prepare, \
                 patch.object(offline.runpy, 'run_path') as run:
                offline.main()
                prepare.assert_called_once_with(bundle.resolve())
                run.assert_called_once_with(str(target), run_name='__main__')
                self.assertEqual(sys.argv, [str(target), '--mode', 'replay', '--input',
                                           'data/plan.xml', '--output', '../result'])

    def test_comparison_forwards_all_arguments(self):
        self.dispatch('comparison', 'source/tools/reproduce_comparison.py')

    def test_existing_entry_is_preserved(self):
        self.dispatch('mean-tail', 'source/analysis/mean_tail_statistics.py')

    def test_obsolete_entry_is_rejected_before_dependency_setup(self):
        with patch.object(sys, 'argv', ['offline_analysis.py', '--entry', 'lowram-budget']), \
             patch.object(offline, 'numpy_site') as prepare, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                offline.main()
            self.assertEqual(raised.exception.code, 2)
            prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
