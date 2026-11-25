"""Closed identities for measured hosted libraries and functional target images."""
from pathlib import PurePosixPath
import re

PARAMETERS = (512, 768, 1024, 44, 65, 87)


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(value, length=64):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value), 'Invalid identity')


def relative(value):
    need(type(value) is str and value and ':' not in value and '\\' not in value, 'Relative image path required')
    p = PurePosixPath(value)
    need(not p.is_absolute() and p.as_posix() == value and all(x not in ('', '.', '..') for x in value.split('/')), 'Invalid image path')
    need(not any(x.lower() in ('internal', 'private', '.git', '.ssh') for x in p.parts), 'Nonpublic image path')


def validate(data):
    need(type(data) is dict and set(data) == {'schema', 'dataset_id', 'core_source_commit', 'images'}, 'Unknown image inventory field')
    need(data['schema'] == 'lattice.archived_images.v1', 'Wrong image inventory schema')
    need(type(data['dataset_id']) is str and re.fullmatch('[a-z0-9][a-z0-9_-]{0,79}', data['dataset_id']), 'Invalid dataset name')
    digest(data['core_source_commit'], 40)
    need(type(data['images']) is list and data['images'], 'Images required')
    ids = set(); paths = set()
    for image in data['images']:
        need(type(image) is dict and set(image) == {'id', 'platform', 'configuration', 'kind', 'parameters',
             'artifact', 'bytes', 'format', 'machine', 'compiler', 'code_generation'}, 'Unknown image field')
        ident = image['id']; need(type(ident) is str and re.fullmatch('[a-z0-9][a-z0-9_.-]{0,99}', ident) and ident not in ids, 'Invalid or duplicate image id')
        ids.add(ident)
        need(image['platform'] in ('windows_x86_64', 'linux_aarch64', 'cortex_m4', 'riscv32'), 'Unknown image platform')
        need(type(image['configuration']) is str and re.fullmatch('[a-z0-9][a-z0-9_-]{0,79}', image['configuration']), 'Invalid configuration')
        need(image['kind'] in ('hosted_library', 'functional_target'), 'Unknown image kind')
        need(type(image['parameters']) is list and image['parameters'] and len(set(image['parameters'])) == len(image['parameters']) and
             all(type(p) is int and p in PARAMETERS for p in image['parameters']), 'Invalid parameter scope')
        artifact = image['artifact']; need(type(artifact) is dict and set(artifact) == {'path', 'sha256'}, 'Image descriptor required')
        relative(artifact['path']); digest(artifact['sha256'])
        need(artifact['path'].casefold() not in paths, 'Repeated image member'); paths.add(artifact['path'].casefold())
        need(type(image['bytes']) is int and image['bytes'] > 0, 'Invalid image bytes')
        expected = {'windows_x86_64': ('PE', 'x86_64', 'hosted_library'), 'linux_aarch64': ('ELF', 'aarch64', 'hosted_library'),
                    'cortex_m4': ('ELF', 'arm', 'functional_target'), 'riscv32': ('ELF', 'riscv', 'functional_target')}[image['platform']]
        need((image['format'], image['machine'], image['kind']) == expected, 'Image format/platform mismatch')
        compiler = image['compiler']
        need(type(compiler) is dict and set(compiler) == {'family', 'version'} and compiler['family'] in ('gcc', 'clang'), 'Invalid compiler')
        need(type(compiler['version']) is str and 0 < len(compiler['version']) <= 160 and not any(x in compiler['version'] for x in ('\\', '/', '\n', '\r')), 'Invalid compiler version')
        cg = image['code_generation']
        need(type(cg) is dict and set(cg) == {'optimization', 'lto', 'backend', 'definitions', 'architecture_flags', 'translation_units'}, 'Unknown code generation field')
        need(cg['optimization'] in ('O3', 'Os', 'Oz', 'O2', 'per_translation_unit_recipe') and type(cg['lto']) is bool and
             cg['backend'] in ('portable', 'x86_64', 'x86_64_native_recipe', 'aarch64', 'thumbv7em', 'rv32imac'), 'Invalid code generation')
        need(type(cg['definitions']) is dict, 'Macro definitions required')
        need(type(cg['architecture_flags']) is list and cg['architecture_flags']==sorted(set(cg['architecture_flags'])) and
             all(type(flag) is str and re.fullmatch(r'-m[A-Za-z0-9_+.,=-]+',flag) for flag in cg['architecture_flags']), 'Explicit architecture switches required')
        for name, values in cg['definitions'].items():
            need(type(name) is str and re.fullmatch('[A-Z_][A-Z0-9_]*', name), 'Invalid macro name')
            need(type(values) is list and values and all(type(value) is int for value in values) and values == sorted(set(values)), 'Integer macro values must list the values used across translation units')
        need(type(cg['translation_units']) is list and cg['translation_units'], 'Actual translation-unit settings required')
        for ordinal,unit in enumerate(cg['translation_units']):
            need(type(unit) is dict and set(unit)=={'ordinal','source_basename','optimization_flags','lto_flags','architecture_flags','integer_definitions'} and unit['ordinal']==ordinal,'Invalid translation unit')
            need(type(unit['source_basename']) is str and re.fullmatch('[A-Za-z0-9_.-]+',unit['source_basename']),'Source basename required')
            need(type(unit['optimization_flags']) is list and all(x in ('-O0','-O1','-O2','-O3','-Os','-Oz','-Ofast') for x in unit['optimization_flags']),'Invalid optimization flags')
            need(type(unit['lto_flags']) is list and all(x in ('-flto','-fno-lto','-flto=auto','-flto=thin') for x in unit['lto_flags']),'Invalid LTO flags')
            need(type(unit['architecture_flags']) is list and all(type(x) is str and re.fullmatch(r'-m[A-Za-z0-9_+.,=-]+',x) for x in unit['architecture_flags']),'Invalid unit architecture flags')
            need(type(unit['integer_definitions']) is dict and all(type(k) is str and re.fullmatch('[A-Z_][A-Z0-9_]*',k) and type(v) is int for k,v in unit['integer_definitions'].items()),'Invalid unit integer macro values')
    return data
