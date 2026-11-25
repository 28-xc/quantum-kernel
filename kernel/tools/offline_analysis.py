"""Run published science tools with the bundled offline NumPy distribution."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import runpy
import struct
import sys
import tempfile
import zipfile

WHEEL = 'numpy-2.2.5-cp313-cp313-win_amd64.whl'
WHEEL_SHA256 = 'd8882a829fd779f0f43998e931c466802a77ca1ee0fe25a3abe50278616b1471'
ENTRIES = {'pooled': 'source/analysis/pooled_statistics.py',
           'mean-tail': 'source/analysis/mean_tail_statistics.py',
           'operation-statistics': 'source/tools/recompute_operation_statistics.py',
           'comparison': 'source/tools/reproduce_comparison.py',
           'application-pool': 'source/tests/application_workload/audit.py',
           'application-owner': 'source/tools/recompute_application_owner.py',
           'measurement-views': 'source/tests/measurement_views/audit.py',
           'compact-validation': 'source/tests/compact_memory/audit_validation.py',
           'signature-attempts': 'source/tests/compact_memory/recompute_attempts.py',
           'm4-comparison': 'source/tests/targets/recompute_comparison.py',
           'timing': 'source/tools/recompute_timing.py',
           'primitives': 'source/tools/recompute_primitives.py',
           'primitive-samples': 'source/publicschemas/primitive_samples_v1.py',
           'program-space': 'source/tools/recompute_program_space.py',
           'images': 'source/tools/recompute_archived_images.py',
           'methods': 'source/tools/recompute_method_inventory.py',
           'profiles': 'source/tools/recompute_profiling.py',
           'pmu': 'source/tools/recompute_pmu.py',
           'shared-keccak': 'source/publicschemas/shared_keccak_v1.py',
           'timing-attribution': 'source/tests/public_attribution/recompute.py',
           'verification': 'source/tools/recompute_verification.py',
           'tradeoffs': 'source/tools/export_resource_tradeoffs.py'}


def numpy_site(bundle):
    if sys.version_info[:2] != (3, 13) or sys.platform != 'win32' or struct.calcsize('P') != 8:
        raise ValueError('This offline wheel requires Windows x64 CPython 3.13')
    archive = bundle / 'bin/wheels' / WHEEL
    if hashlib.sha256(archive.read_bytes()).hexdigest() != WHEEL_SHA256:
        raise ValueError('Official offline wheel identity differs')
    site = bundle / 'analysis/site-numpy-2.2.5-cp313'
    site.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as wheel:
        members = []
        for info in wheel.infolist():
            p = PurePosixPath(info.filename)
            if p.is_absolute() or '..' in p.parts or '\\' in info.filename or ((info.external_attr >> 16) & 0o170000) == 0o120000:
                raise ValueError('Unsafe wheel entry')
            if not info.is_dir(): members.append(info)
        if not site.exists():
            with tempfile.TemporaryDirectory(prefix='numpy-offline-', dir=site.parent) as temporary:
                unpacked = Path(temporary) / 'site'; unpacked.mkdir()
                for info in members:
                    p = unpacked / info.filename; p.parent.mkdir(parents=True, exist_ok=True)
                    p.write_bytes(wheel.read(info))
                unpacked.rename(site)
        if site.is_symlink(): raise ValueError('Indirect dependency directory')
        for info in members:
            path = site / info.filename
            if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(site.resolve()) or path.read_bytes() != wheel.read(info):
                raise ValueError('Expanded offline dependency differs: ' + info.filename)
    return site


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--entry', choices=ENTRIES)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    sys.path.insert(0, str(numpy_site(bundle)))
    import numpy
    if numpy.__version__ != '2.2.5': raise ValueError('Offline NumPy version differs')
    if args.prepare_only:
        print('Offline NumPy 2.2.5 is ready.'); return
    if args.entry is None: parser.error('--entry is required unless --prepare-only is selected')
    target = bundle / ENTRIES[args.entry]
    if not target.is_file(): raise ValueError('Published analysis entry is absent')
    sys.path.insert(0, str(bundle / 'source'))
    sys.path.insert(0, str(target.parent))
    sys.argv = [str(target)] + (args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments)
    runpy.run_path(str(target), run_name='__main__')


if __name__ == '__main__': main()
