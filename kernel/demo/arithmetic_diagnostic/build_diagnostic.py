"""Build native_arithmetic.dll and write the build record."""
import argparse
from hashlib import file_digest
import json
from pathlib import Path
import shutil
import subprocess
import sys


HERE = Path(__file__).resolve().parent
KEM = 'build/adapted_mlkem'
DSA = 'src/dsa_compact/build/sign_bitmap_stream_alias/adapted'


def sha(path):
    with path.open('rb') as stream:
        return file_digest(stream, 'sha256').hexdigest()


def build(project, output, archive):
    compiler = shutil.which('gcc')
    if not compiler:
        raise SystemExit('需要 Windows x64 MinGW GCC（验证版本 15.2.0）')
    output.mkdir(parents=True)
    if archive is None:
        builder = project / 'tools' / 'build.py'
        plan = output / 'compact-rate.xml'
        core = output / 'compact-rate'
        subprocess.run([sys.executable, '-B', str(builder), 'plan', '--mode', 'hosted',
                        '--configuration', 'compact-rate', '--backend', 'portable',
                        '--opt', 'Os', '--lto', '--output', str(plan)], check=True, cwd=project)
        subprocess.run([sys.executable, '-B', str(builder), 'build', '--plan', str(plan),
                        '--output', str(core)], check=True, cwd=project)
        archive = core / 'artifacts' / 'liblatticecore.a'
    if not archive.is_file():
        raise ValueError(f'缺少正式工程静态库：{archive}')

    common = [compiler, '-Os', '-std=c11', '-Wall', '-Wextra', '-ffunction-sections',
              '-fdata-sections', '-Iinclude']
    command_list = []

    def run(command):
        subprocess.run(list(map(str, command)), check=True, cwd=project)
        command_list.append(list(map(str, command)))

    kernel = output / 'canonical.o'
    run([*common, '-c', 'src/backends/canonical.c', '-o', kernel])
    kem = output / 'kem.o'
    run([*common, '-I'+KEM, '-Iconfigs/hosted', '-I'+str(HERE),
         '-DMLK_CONFIG_FILE="mlkem_config.h"', '-DMLK_CONFIG_PARAMETER_SET=512',
         '-DMLK_CONFIG_MULTILEVEL_WITH_SHARED', '-c', HERE / 'kem.c', '-o', kem])
    dsa = []
    for parameter in (44, 65, 87):
        target = output / f'dsa{parameter}.o'
        shared = 'WITH_SHARED' if parameter == 44 else 'NO_SHARED'
        run([*common, '-I'+DSA, '-Isrc/dsa_packed', '-Isrc/common', '-I'+str(HERE),
             '-DMLD_CONFIG_FILE="lc_dsa_config.h"', '-DMLD_CONFIG_REDUCE_RAM',
             '-DLC_DSA_INPLACE_SAMPLE=2', '-DLC_DSA_STREAM_KEYGEN=1',
             f'-DMLD_CONFIG_PARAMETER_SET={parameter}',
             f'-DMLD_CONFIG_MULTILEVEL_{shared}', '-c', HERE / 'dsa.c', '-o', target])
        dsa.append(target)

    exports = output / 'diagnostic.def'
    export_names = ('lc_poly_add', 'lc_poly_sub', 'lc_poly_mul', 'lc_poly_ntt', 'lc_poly_intt',
                    'lc_demo_kem', 'lc_demo_dsa44', 'lc_demo_dsa65', 'lc_demo_dsa87')
    exports.write_text('EXPORTS\n  ' + '\n  '.join(export_names) + '\n', encoding='ascii')
    dll = output / 'native_arithmetic.dll'
    run([compiler, '-Os', '-flto', '-shared', *dsa, kem, kernel, archive, exports,
         '-lbcrypt', '-Wl,--gc-sections', '-Wl,--no-insert-timestamp', '-o', dll])
    bindings = (
        'src/backends/canonical.c', 'src/backends/canonical_template.inc',
        'src/backends/canonical_generated.inc', 'include/lc_poly.h',
        f'{KEM}/src/sampling.c', f'{KEM}/src/compress.c', f'{KEM}/src/poly.c',
        f'{DSA}/src/poly.c', f'{DSA}/src/poly_kl.c',
    )
    receipt = {
        'component': 'Windows x64',
        'build_configuration': 'compact-rate / portable / Os / LTO',
        'compiler': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
        'dll_sha256': sha(dll), 'linked_archive_sha256': sha(archive),
        'source_hashes': {name: sha(project / name) for name in bindings},
        'adapter_hashes': {name: sha(HERE / name) for name in ('kem.c', 'dsa.c')},
        'exports': export_names,
    }
    (output / 'build.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    (output / 'build-commands.json').write_text(json.dumps(command_list, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return dll


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    output, project = args.output.resolve(), args.source.resolve(strict=True)
    if output.exists() or output.is_relative_to(project):
        raise SystemExit('请指定全新的包外输出目录')
    print(build(project, output, args.archive.resolve(strict=True) if args.archive else None))


if __name__ == '__main__':
    main()
