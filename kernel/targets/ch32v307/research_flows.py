"""Bounded real UART correctness/performance collection, with all samples kept."""
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
import argparse, hashlib, importlib.util, record_io as json, random, struct, time
from research_device import DRIVER, DRIVER_SHA256, sha, write


def case_data(parameter, block, repeat, boundary=False):
    if boundary:
        sizes = [(0, 0), (32, 0), (1024, 0), (0, 255), (1024, 255)]
        mn, dn = sizes[repeat % len(sizes)] if parameter < 100 else (0, 0)
    else:
        mn, dn = (32, 0) if parameter < 100 else (0, 0)
    message = bytes((i * 17 + 3) & 255 for i in range(mn))
    domain = bytes((i * 13 + 7) & 255 for i in range(dn))
    label = f'upgrade-paired-v1-{block}-{repeat}-{parameter}'
    entropy = hashlib.shake_256(label.encode()).digest(96 if parameter > 100 else 64)
    return label, message, domain, entropy


def collect(expected, output, block, repeats, boundary=False, baseline_fixture=False, port='COM13'):
    assert sha(DRIVER) == DRIVER_SHA256
    spec = importlib.util.spec_from_file_location('ch32_serial', DRIVER)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    device = driver.SerialDevice(port, expected, timeout=30)
    result = dict(status='INCOMPLETE', transport='physical_uart', block=block,
                  driver_sha256=DRIVER_SHA256, boundary_cases=boundary,
                  samples=[], policy='No timed-call removal, winsorization, automatic resend, or retry-limit change.',
                  retry_count_observed=False)
    try:
        result['hello'] = device.handshake()
        order = [(p, j) for j in range(repeats) for p in driver.PARAMETERS]
        random.Random(0xB047 + block).shuffle(order)
        for p, rep in order:
            label, message, domain, entropy = case_data(p, block, rep, boundary)
            if baseline_fixture:
                label = f'upgrade-baseline-{p}'
                entropy = hashlib.shake_256(label.encode()).digest(96 if p > 100 else 64)
            response = device.flow(p, message, domain, entropy)
            result['samples'].append(dict(parameter=p, repeat=rep, fixture=label,
                entropy_hex=entropy.hex(), message_bytes=len(message), context_bytes=len(domain),
                response=response))
            write(output, dict(result, transport_records=device.records))
            assert response['status'] == 0 and response['pass_mask'] == 255, 'Board flow failed'
        result['status'] = 'PASS'
    finally:
        result['transport_records'] = device.records
        device.close()
        write(output, result)
    return result


def main():
    global DRIVER
    ap = argparse.ArgumentParser()
    ap.add_argument('--expected', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--block', type=int, default=0)
    ap.add_argument('--repeats', type=int, default=1)
    ap.add_argument('--boundaries', action='store_true')
    ap.add_argument('--baseline-fixture', action='store_true')
    ap.add_argument('--port', default='COM13')
    ap.add_argument('--driver', type=Path, default=DRIVER)
    a = ap.parse_args()
    DRIVER = a.driver.resolve(strict=True)
    assert not a.output.exists(), 'Fresh evidence file required'
    a.output.parent.mkdir(parents=True, exist_ok=True)
    r = collect(json.loads(a.expected.read_text()), a.output, a.block, a.repeats,
                a.boundaries, a.baseline_fixture, a.port)
    print(json.dumps(dict(status=r['status'], samples=len(r['samples']),
                         ram=r['hello']['ram_reserved_bytes'], workspace=r['hello']['workspace_bytes'],
                         max_arena=max(x['response']['maximum_arena_bytes'] for x in r['samples']),
                         max_stack=max(x['response']['maximum_stack_watermark_bytes'] for x in r['samples']))))


if __name__ == '__main__':
    main()
