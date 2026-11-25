"""Prepare a separate native acquisition plan from the archived experiment.

No target code is executed. The user's OpenSSL installation and the verified
deployment images are copied into the fresh output directory. The original
observations and their measurement-image identities remain unchanged.
"""
from pathlib import Path
import argparse
import hashlib
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
import record_io as json
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from publicschemas.deployment_image import load_deployment_image


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def inside(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('Missing or out-of-bundle input: ' + name)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--platform', choices=['windows', 'arm'], required=True)
    parser.add_argument('--crypto-prefix', type=Path, required=True)
    parser.add_argument('--crypto-library', type=Path, required=True)
    parser.add_argument('--compiler', default='gcc')
    parser.add_argument('--cpu', type=int)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    output = args.output.resolve()
    prefix = args.crypto_prefix.resolve()
    crypto = args.crypto_library.resolve()
    if output.exists() or output.is_relative_to(bundle):
        raise ValueError('Choose a fresh output directory outside the bundle')
    if not crypto.is_file() or not crypto.is_relative_to(prefix):
        raise ValueError('The crypto library must be a file inside the OpenSSL prefix')
    if not (prefix / 'include/openssl/evp.h').is_file():
        raise ValueError('OpenSSL headers are required')
    dataset = bundle / 'data' / ('signing-pipeline-' + args.platform)
    obs = read(dataset / 'observations.xml')
    summary = read(dataset / 'mean-tail-summary.xml')
    if summary['observations_sha256'] != digest(dataset / 'observations.xml'):
        raise ValueError('Observation and summary identities differ')
    index = read(bundle / 'data/comparison-images.xml')[args.platform]
    if {r['id'] for r in index} != {r['id'] for r in obs['configurations']}:
        raise ValueError('Incomplete image index')
    validated = []
    for row in obs['configurations']:
        image = next(r for r in index if r['id'] == row['id'])
        library = inside(bundle, image['library'])
        receipt = inside(bundle, image['receipt'])
        result = load_deployment_image(library, receipt, image['receipt_sha256'],
            measured_sha256=row['library_sha256'], binary_sha256=image['library_sha256'])
        validated.append((row, library, receipt, result))
    cpu = obs['experiment']['cpu_index'] if args.cpu is None else args.cpu
    if not 0 <= cpu <= 1023:
        raise ValueError('Invalid CPU index')
    output.mkdir(parents=True)
    shutil.copytree(prefix / 'include/openssl', output / 'openssl/include/openssl')
    # GCC needs the shared-library linker name on ELF and the import archive on PE.
    for folder in ['lib', 'lib64', 'bin']:
        source = prefix / folder
        if source.is_dir():
            for path in source.iterdir():
                if path.is_file() and ('crypto' in path.name.lower()):
                    target = output / 'openssl' / folder / path.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, target)
    crypto_target = output / 'openssl' / crypto.relative_to(prefix)
    crypto_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(crypto, crypto_target)
    configurations = []
    bindings = []
    for row, library, receipt, result in validated:
        target = output / 'libraries' / row['id'] / library.name
        target.parent.mkdir(parents=True)
        shutil.copy2(library, target)
        shutil.copy2(receipt, target.parent / 'derivation.xml')
        configurations.append(dict(id=row['id'], library=dict(
            path=target.relative_to(output).as_posix(), sha256=digest(target)),
            workspace=row['workspace_reserved']))
        bindings.append(dict(configuration=row['id'], measured_sha256=row['library_sha256'],
            deployment_sha256=result['binary_sha256'], receipt_sha256=result['derivation_sha256']))
    e = obs['experiment']
    plan = dict(schema='lattice.comparison_acquisition.v1', platform=obs['platform'],
        dataset_id=args.platform + '-native-operations-replication', compiler=args.compiler,
        crypto_library=dict(path=crypto_target.relative_to(output).as_posix(), sha256=digest(crypto_target)),
        crypto_prefix='openssl', preparation_library='lattice-sign-pipeline-native', cpu=cpu,
        blocks=e['blocks'], samples=e['samples_per_run'], warmups=e['warmups_per_run'],
        seed=e['seed'], bootstrap_seed=summary['method']['bootstrap_seed'],
        resamples=summary['method']['resamples'], message_bytes=e['message_bytes'],
        context_bytes=e['context_bytes'], configurations=configurations,
        comparisons=[{k: r[k] for k in ['id', 'candidate', 'reference']} for r in summary['comparisons']])
    for name, value in [('plan.xml', plan), ('image-bindings.xml', bindings)]:
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(status='PLAN_EXPORTED', configurations=len(configurations),
        plan_sha256=digest(output / 'plan.xml'), target_execution=False)))


if __name__ == '__main__':
    main()
