"""Build a Linux AArch64 shared library for the project's canonical polynomial API."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(source, compiler, output):
    output.mkdir(parents=True, exist_ok=True)
    binary = output / 'native_arithmetic_aarch64.so'
    # Cross builds need the C declarations, but no Windows or Android runtime.
    # memcpy resolves from libc when Linux loads the shared object.
    with TemporaryDirectory() as directory:
        header = Path(directory) / 'string.h'
        header.write_text('#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t);\n',
                          encoding='ascii')
        subprocess.run([compiler, '--target=aarch64-linux-gnu', '-fuse-ld=lld', '-ffreestanding',
                        '-fPIC', '-fno-stack-protector', '-Os', '-nostdlib', '-shared',
                        '-Wl,-z,relro,-z,now', '-I' + directory, '-I' + str(source / 'include'),
                        source / 'src/backends/canonical.c', '-o', binary], check=True)
    receipt = {'component': 'Linux AArch64 canonical polynomial API',
               'binary_sha256': sha256(binary),
               'source_hashes': {name: sha256(source / name) for name in (
                   'src/backends/canonical.c', 'src/backends/canonical_template.inc',
                   'src/backends/canonical_generated.inc', 'include/lc_poly.h')}}
    (output / 'arithmetic-aarch64.json').write_text(
        json.dumps(receipt, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--clang', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    build(args.source.resolve(), args.clang.resolve(), args.output.resolve())
