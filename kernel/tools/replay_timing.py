"""Run the recorded timing method with explicit local tool and source paths.

The imported runner and C driver retain their own source identities. This
wrapper only selects paths and passes the original command-line arguments.
"""
from pathlib import Path
import argparse
import importlib.util
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]


def tool(value):
    found = shutil.which(value)
    if not found:
        raise ValueError('Local executable not found: ' + value)
    return Path(found).resolve()


def invoke(platform, source_root, compiler, symbols, arguments):
    source_root = Path(source_root).resolve()
    if not (source_root / 'include/latticecore.h').is_file():
        raise ValueError('Public source root is missing latticecore.h')
    script = ROOT / 'tests/timing' / ('run.py' if platform == 'windows' else 'run_linux.py')
    spec = importlib.util.spec_from_file_location('local_timing_method', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.GCC = tool(compiler)
    module.NM = tool(symbols)
    module.ROOT = source_root
    if platform == 'linux' and arguments and arguments[0] == 'prepare':
        if '--source-root' in arguments:
            raise ValueError('Pass source root to the wrapper once')
        arguments = arguments + ['--source-root', str(source_root)]
    previous = sys.argv
    try:
        sys.argv = [str(script), *arguments]
        module.main()
    finally:
        sys.argv = previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=['windows', 'linux'])
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--nm', default='nm')
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    if not arguments:
        parser.error('A method command is required after --')
    invoke(args.platform, args.source_root, args.cc, args.nm, arguments)


if __name__ == '__main__':
    main()
