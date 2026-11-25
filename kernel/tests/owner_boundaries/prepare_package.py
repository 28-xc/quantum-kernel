"""Provide original allocator compile metadata for an unchanged deployed archive."""
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


def sha(path):
    with Path(path).open('rb') as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
        return digest.hexdigest()


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def commands(path):
    rows = load(path)
    return rows['commands'] if isinstance(rows, dict) else rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    parent, package, output = (p.resolve() for p in (args.parent, args.package, args.output))
    if output.exists():
        parser.error('The output must be a new directory.')
    if output.is_relative_to(parent) or output.is_relative_to(package):
        parser.error('The output must be outside both input packages.')
    inputs = [parent / 'commands.xml', parent / 'build.xml',
              package / 'commands.xml', package / 'build.xml', package / 'liblatticecore.a']
    for path in inputs:
        if not path.is_file():
            parser.error(f'Required input not found: {path}')
    before = {str(path): sha(path) for path in inputs}
    original = commands(parent / 'commands.xml')
    final = commands(package / 'commands.xml')
    supplied = []
    selections = []
    for basename in ('arena.c', 'adapter.c'):
        matches = [(i, row) for i, row in enumerate(original)
                   if '-c' in row.get('argv', [])
                   and Path(row['argv'][row['argv'].index('-c') + 1]).name == basename]
        if len(matches) != 1 or matches[0][1].get('exit_code') != 0:
            parser.error(f'Expected one successful parent compilation of {basename}.')
        if any('-c' in row.get('argv', [])
               and Path(row['argv'][row['argv'].index('-c') + 1]).name == basename for row in final):
            parser.error(f'The deployed package already contains {basename} metadata; use run.py directly.')
        index, row = matches[0]
        source = Path(row['argv'][row['argv'].index('-c') + 1])
        if not source.is_absolute() or not source.is_file():
            parser.error(f'Original source must remain accessible by its recorded absolute path: {source}')
        supplied.append(row)
        selections.append({'parent_command_index': index, 'source': str(source),
                           'source_sha256': sha(source), 'command': row})
    output.mkdir(parents=True, exist_ok=False)
    for name in ('liblatticecore.a', 'build.xml'):
        shutil.copyfile(package / name, output / name)
        if sha(package / name) != sha(output / name):
            raise RuntimeError(f'Copy identity mismatch: {name}')
    (output / 'commands.xml').write_text(json.dumps(supplied + final, indent=2) + '\n', encoding='utf-8')
    if any(sha(path) != digest for path, digest in before.items()):
        raise RuntimeError('An input changed while preparing the observation package.')
    receipt = {'status': 'PASS', 'schema': 'lattice.owner_test_package.v1',
               'purpose': 'Final archive unchanged; two original allocator compilation records added for observation.',
               'preparer_sha256': sha(__file__), 'inputs': before, 'selections': selections,
               'final_archive_sha256': sha(package / 'liblatticecore.a'),
               'test_archive_sha256': sha(output / 'liblatticecore.a'),
               'test_build_sha256': sha(output / 'build.xml'),
               'supplied_commands_sha256': sha(output / 'commands.xml'),
               'crypto_code_modified': False}
    (output / 'view-receipt.xml').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'PASS', 'output': str(output), 'archive_sha256': receipt['test_archive_sha256']}))


if __name__ == '__main__':
    main()
