"""Rebuild a registered CH32V307 image from relocatable sources. No hardware IO."""
from pathlib import Path
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
import argparse, datetime, hashlib, record_io as json, os, re, shutil, struct, subprocess, traceback


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise ValueError('Duplicate JSON key: ' + k)
            result[k] = v
        return result
    return json.loads(Path(path).read_text(encoding='utf-8'), object_pairs_hook=unique)


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relative(text):
    p = Path(text)
    require(text and not p.is_absolute() and not any(x in ('..', '.') for x in p.parts)
            and ':' not in text and '\\' not in text and '\0' not in text, 'Unsafe member: ' + text)
    return p


def expand(text, roots):
    match = re.fullmatch(r'\$\{([A-Z][A-Z0-9]*)\}(?:/(.*))?', text)
    require(match is not None and match[1] in roots, 'Unknown path token: ' + text)
    base = roots[match[1]]
    if match[2] is None:
        return base
    q = (base / relative(match[2])).resolve()
    require(q.is_relative_to(base), 'Path escapes declared root')
    return q


def argument(text, roots):
    if text.startswith('${'):
        return str(expand(text, roots))
    for prefix in ('-I', '-L', '-Wl,-Map,'):
        if text.startswith(prefix + '${'):
            return prefix + str(expand(text[len(prefix):], roots))
    require('${' not in text and not re.search(r'[A-Za-z]:[/\\]', text), 'Unmapped argument path')
    return text


def parse_dependencies(path):
    raw = Path(path).read_text(encoding='utf-8').replace('\\\n', ' ')
    tail = raw.split(': ', 1)[1]
    return [Path(v.replace('\\ ', ' ')).resolve() for v in re.split(r'(?<!\\)\s+', tail.strip())]


def memory_ledger(elf, symbol_text):
    symbols = {}
    for line in symbol_text.splitlines():
        row = line.split()
        if len(row) >= 3:
            try:
                symbols[row[2]] = int(row[0], 16)
            except ValueError:
                pass
    pairs = dict(code=('__code_start', '__code_end'), data=('__data_start', '__data_end'),
        bss=('__bss_start', '__bss_end'), arena=('__arena_start', '__arena_end'),
        io=('__io_start', '__io_end'), test_stack=('__test_stack_bottom', '__test_stack_top'),
        control_stack=('__control_stack_bottom', '__control_stack_top'))
    regions = {k: (symbols[a], symbols[b]) for k, (a, b) in pairs.items()}
    for name, (a, b) in regions.items():
        require(b >= a and (name == 'code' or a % 32 == 0), 'Bad memory region: ' + name)
    for name, (a, b) in regions.items():
        for other, (c, d) in regions.items():
            if name != other and a != b and c != d:
                require(b <= c or d <= a, 'Overlapping memory regions')
    raw = Path(elf).read_bytes()
    require(raw[:7] == b'\x7fELF\x01\x01\x01', 'Little-endian ELF32 required')
    shoff = struct.unpack_from('<I', raw, 32)[0]
    shsize, count = struct.unpack_from('<HH', raw, 46)
    require(shsize == 40 and shoff + count * shsize <= len(raw), 'Invalid section table')
    allocated = []
    for i in range(count):
        _, kind, flags, address, offset, size, _, _, _, _ = struct.unpack_from('<10I', raw, shoff + i * shsize)
        if not flags & 2 or not size:
            continue
        owners = [k for k, (a, b) in regions.items() if a <= address and address + size <= b]
        require(len(owners) == 1, 'Allocated section outside or overlaps ownership regions')
        require(kind == 8 or offset + size <= len(raw), 'Truncated loaded section')
        if flags & 1:
            require(owners[0] != 'code', 'Writable code section')
        allocated.append(dict(index=i, owner=owners[0], start=address, bytes=size, flags=flags))
    names = dict(code='code_and_rodata_load_bytes', data='data_bytes',
        bss='bss_excluding_arena_io_stacks_bytes', arena='arena_reservation_with_guards_bytes',
        io='caller_io_reservation_with_guards_bytes', test_stack='test_stack_reservation_bytes',
        control_stack='control_stack_reservation_bytes')
    ledger = {names[k]: b - a for k, (a, b) in regions.items()}
    ledger['writable_image_span_bytes'] = symbols['__ram_end'] - symbols['__ram_start']
    ledger['alignment_gap_bytes'] = ledger['writable_image_span_bytes'] - sum(
        v for k, v in ledger.items() if k not in ('writable_image_span_bytes', 'code_and_rodata_load_bytes'))
    require(ledger['alignment_gap_bytes'] >= 0, 'RAM overlap')
    return ledger, allocated

