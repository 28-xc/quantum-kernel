"""Post-observation public-field isolation; no replacement of original flags.

prepare compiles and runs functional checks only. collect requires an explicit
coordination token and preserves all nine original parameter/seed combinations.
The experiment calls the unmodified release library's complete lc_decaps.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
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
import numpy as np

HERE = Path(__file__).resolve().parent
r = None
ORIGINAL = OUT = None


def configure(original, output):
    global r, ORIGINAL, OUT
    ORIGINAL = Path(original).resolve()
    OUT = Path(output).resolve()
    spec = importlib.util.spec_from_file_location('archived_screen_runner', ORIGINAL / 'run.py')
    r = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(r)


def original_records(p):
    records = json.loads((ORIGINAL / 'measurements/results.xml').read_text())['records']
    records = [v for v in records if v['mode'] == 'decaps_key' and not v['positive']]
    expected = {(parameter, seed) for parameter in (512, 768, 1024) for seed in p['seeds']}
    if len(p['seeds']) != 3 or len(expected) != 9 or len(records) != 9:
        raise ValueError('Require the complete three-parameter/three-seed original screen')
    if {(v['parameter'], v['seed']) for v in records} != expected:
        raise ValueError('Original cells missing or duplicated')
    return sorted(records, key=lambda v: (v['parameter'], v['seed']))


def metadata_checked(meta, parameter, samples):
    required = ['loaded_module_path_checked', 'H_ek_valid', 'fixed_dkPKE_and_z_checked',
                'independent_J_all_equal', 'input_unchanged', 'no_rng_during_decaps',
                'not_generated_matching_keypairs', 'only_public_fields_vary',
                'secret_input_to_timed_region']
    if any(meta.get(k) is not True for k in required):
        raise ValueError('Missing explicit input/domain/loading/oracle check')
    if meta.get('oracle') != 'PASS' or meta.get('parameter') != parameter or meta.get('samples') != samples:
        raise ValueError('Unexpected diagnostic identity or oracle outcome')
    if meta.get('key_pool_size') != 257 or meta.get('constructed_keys_checked') != 257:
        raise ValueError('Incomplete constructed-key precheck')
    if meta.get('warmup') != (1000 if samples else 0):
        raise ValueError('Warmup differs from the original screen')
    for key in ['input_fnv64', 'hybrid_input_fnv64', 'public_segment_fnv64']:
        value = meta.get(key)
        if not isinstance(value, str) or len(value) != 16:
            raise ValueError('Missing replay checksum')
        int(value, 16)


def public_oracle(prefix, parameter):
    publicbytes = {512: 800, 768: 1184, 1024: 1568}[parameter]
    ctbytes = {512: 768, 768: 1088, 1024: 1568}[parameter]
    public = Path(str(prefix) + '.public.bin').read_bytes()
    ct = Path(str(prefix) + '.ct.bin').read_bytes()
    sponge = Path(str(prefix) + '.sponge.bin').read_bytes()
    stride = publicbytes + 32
    if len(public) != 257 * stride or len(ct) != ctbytes or len(sponge) != 64:
        raise ValueError('Public-pool/ciphertext dimensions differ')
    for index in range(257):
        entry = public[index * stride:(index + 1) * stride]
        if hashlib.sha3_256(entry[:publicbytes]).digest() != entry[publicbytes:]:
            raise ValueError('Independent hashlib H(ek) mismatch')
    expected = hashlib.sha3_256(public[:publicbytes]).digest() + hashlib.shake_256(ct).digest(32)
    if sponge != expected:
        raise ValueError('Scalar SHA3/SHAKE reference disagrees with independent hashlib')
    return dict(public_pool_sha256=r.sha(str(prefix) + '.public.bin'),
                ciphertext_sha256=r.sha(str(prefix) + '.ct.bin'),
                sponge_answers_sha256=r.sha(str(prefix) + '.sponge.bin'),
                public_keys_checked=257,
                oracle='hashlib SHA3-256 over every public key; hashlib SHAKE256 cross-check of scalar reference; scalar independent J(z0||ct) compared against actual decaps for all 257 constructed keys')


def prepare(args):
    OUT.mkdir(parents=True, exist_ok=False)
    p = r.checked(ORIGINAL)
    originals = original_records(p)
    linux = hasattr(r, 'elf')
    if not linux and OUT.drive.upper() != 'D:':
        raise ValueError('Windows evidence must remain on D:')
    shutil.copyfile(HERE / 'public_fields.c', OUT / 'public_fields.c')
    shutil.copyfile(__file__, OUT / 'public_fields.py')
    shutil.copyfile(ORIGINAL / 'screen.c', OUT / 'archived_screen.c')
    header = ORIGINAL / 'latticecore.h'
    if not header.exists():
        if not args.source_root:
            raise ValueError('An explicit frozen --source-root is required for the public header')
        header = Path(args.source_root) / 'include/latticecore.h'
    if p.get('public_header_sha256') and r.sha(header) != p['public_header_sha256']:
        raise ValueError('Original header identity changed')
    shutil.copyfile(header, OUT / 'latticecore.h')
    exe = OUT / ('public_fields' if linux else 'public_fields.exe')
    cc = args.cc or str(r.GCC)
    r.command([cc, '-O3', '-std=c11', '-Wall', '-Wextra', '-Wno-cast-function-type',
               *([] if linux else ['-mavx2']), '-I' + str(OUT), OUT / 'public_fields.c',
               *(['-ldl'] if linux else []), '-o', exe], OUT / 'build.xml')
    jobs, validations = [], []
    for original in originals:
        parameter, seed = original['parameter'], original['seed']
        label = f'{parameter}_{seed:x}'
        prefix = OUT / ('oracle_' + label)
        proc = r.command([exe, p['dll'], parameter, 0, hex(seed), prefix, p.get('cpu', -1)],
                         OUT / ('oracle_' + label + '.xml'))
        meta = json.loads(proc.stdout)
        metadata_checked(meta, parameter, 0)
        if meta['cpu_logical'] != original['metadata']['cpu_logical']:
            raise ValueError('Diagnostic processor differs from the original screen')
        validation = dict(parameter=parameter, seed=seed, metadata=meta,
                          **public_oracle(prefix, parameter))
        validations.append(validation)
        jobs.append(dict(parameter=parameter, seed=seed, original_record_id=original['id'],
                         expected_original_input_fnv64=original['metadata']['input_fnv64'],
                         original_detected=original['detected']))
    if r.sha(p['dll']) != p['dll_sha256']:
        raise ValueError('Actual release library changed during preparation')
    protocol = dict(
        schema='r2-public-fields-attribution-v1', created_utc=r.now(),
        dll=p['dll'], dll_sha256=p['dll_sha256'], exe=str(exe), exe_sha256=r.sha(exe),
        source_sha256=r.sha(OUT / 'public_fields.c'), runner_sha256=r.sha(OUT / 'public_fields.py'),
        base_driver_sha256=r.sha(OUT / 'archived_screen.c'),
        archived_header_sha256=r.sha(OUT / 'latticecore.h'),
        header_binding='original protocol hash' if p.get('public_header_sha256') else 'explicit frozen diagnostic header; actual public ABI functionally checked',
        original_directory=str(ORIGINAL), original_protocol_sha256=r.sha(ORIGINAL / 'protocol.xml'),
        original_runner_sha256=r.sha(ORIGINAL / 'run.py'),
        original_result_sha256=r.sha(ORIGINAL / 'measurements/results.xml'),
        abi='aapcs64' if linux else 'win64', cpu=p.get('cpu', -1),
        timer_unit='ns' if linux else 'TSC ticks', samples_per_job=100000, warmup=1000,
        seeds=p['seeds'], checkpoints=p['checkpoints'], threshold_abs_t=p['threshold_abs_t'],
        statistics=['raw_mean', 'centered_second_moment'], complete_original_seed_set=True,
        no_outlier_trim=True, no_early_stop=True, no_retry=True,
        measured_region='original timing boundaries: actual lc_context_init plus actual complete lc_decaps in the unmodified release library; copying to the same fixed input address happens before timing',
        varying_fields='embedded public ek and H(ek) from the original selected key; fixed dk_PKE and z from original pool[0]; fixed original random ciphertext',
        input_domain='serialized and arithmetic-domain-valid; generally NOT matching generated key pairs; public-field isolation diagnostic only',
        secret_input_to_timed_region=True, original_input_fnv_includes_warmup=True,
        original_pool_and_classes_replayed=True,
        independent_prechecks='every one of 257 constructed keys: H(ek), unchanged secret prefix/z, no RNG consumption, API success, independent J(z0||ct) equality; check returned J and unchanged input also outside every timing observation',
        registration='post-observation attribution protocol; does not retroactively change the original screen',
        hypothesis='Changing only the public ek/H(ek) fields can reproduce timing differences in the actual complete mixed-lane decapsulation path.',
        limits=['A new flag is evidence of public-field-dependent timing under this diagnostic, not a proof of all original causes.',
                'No flag does not dismiss the original flag and is not a constant-time proof.',
                'The fixed secret arithmetic still executes and its intermediates can depend on the public fields.',
                'Constructed keys do not model a distribution of consistent generated key pairs.',
                'The original detector positive-control results are retained separately; this supplemental experiment does not create a new security certificate.'],
        jobs=jobs)
    r.write(OUT / 'protocol.xml', protocol)
    r.write(OUT / 'prepared.xml', dict(state='ORACLE_VALIDATED_NOT_TIMED',
            protocol_sha256=r.sha(OUT / 'protocol.xml'), validation=validations))
    print('PUBLIC_FIELDS_READY', len(jobs), 'jobs;', 257 * len(jobs), 'constructed keys checked; no timings collected')


def collect(token):
    original_protocol = r.checked(ORIGINAL)
    p = json.loads((OUT / 'protocol.xml').read_text())
    prep = json.loads((OUT / 'prepared.xml').read_text())
    if r.sha(OUT / 'protocol.xml') != prep['protocol_sha256']:
        raise ValueError('Diagnostic registration changed')
    for key in ['dll', 'exe']:
        if r.sha(p[key]) != p[key + '_sha256']:
            raise ValueError('Frozen diagnostic artifact changed')
    for file, key in [('public_fields.c', 'source_sha256'), ('public_fields.py', 'runner_sha256'),
                      ('archived_screen.c', 'base_driver_sha256'), ('latticecore.h', 'archived_header_sha256')]:
        if r.sha(OUT / file) != p[key]:
            raise ValueError('Archived diagnostic source changed')
    if r.sha(__file__) != p['runner_sha256']:
        raise ValueError('Execute the archived diagnostic runner')
    for file, key in [('protocol.xml', 'original_protocol_sha256'), ('run.py', 'original_runner_sha256'),
                      ('measurements/results.xml', 'original_result_sha256')]:
        if r.sha(ORIGINAL / file) != p[key]:
            raise ValueError('Original investigation identity changed')
    if str(ORIGINAL) != p['original_directory'] or original_protocol['dll_sha256'] != p['dll_sha256']:
        raise ValueError('Original directory/library binding changed')
    originals = original_records(original_protocol)
    dest = OUT / 'measurements'
    dest.mkdir(exist_ok=False)
    r.write(dest / 'session.xml', dict(token=token, start_utc=r.now(), protocol_sha256=r.sha(OUT / 'protocol.xml')))
    records = []
    for job in p['jobs']:
        label = f'{job["parameter"]}_{job["seed"]:x}'
        prefix = dest / label
        proc = r.command([p['exe'], p['dll'], job['parameter'], 100000, hex(job['seed']), prefix, p['cpu']], dest / (label + '.xml'))
        meta = json.loads(proc.stdout)
        metadata_checked(meta, job['parameter'], 100000)
        if meta['input_fnv64'] != job['expected_original_input_fnv64']:
            raise ValueError('Original key-pool input stream was not exactly replayed')
        original = next(v for v in originals if v['id'] == job['original_record_id'])
        if meta['cpu_logical'] != original['metadata']['cpu_logical']:
            raise ValueError('Diagnostic processor differs from the original screen')
        matches = list((ORIGINAL / 'measurements').glob(job['original_record_id'] + '_*.csv'))
        if len(matches) != 1 or r.sha(matches[0]) != original['raw_sha256']:
            raise ValueError('Original raw observations missing, ambiguous or changed')
        raw = Path(str(prefix) + '.csv')
        a = np.loadtxt(raw, delimiter=',', skiprows=1)
        b = np.loadtxt(matches[0], delimiter=',', skiprows=1)
        if a.shape != (100000, 3) or b.shape != (100000, 3) or not np.array_equal(a[:, 0], b[:, 0]):
            raise ValueError('Original class sequence not replayed')
        indices = np.fromfile(str(prefix) + '.keyidx.bin', dtype='<u2')
        if len(indices) != 100000 or np.any(indices > 256) or not np.array_equal(indices == 0, a[:, 0] == 0):
            raise ValueError('Key-pool selection/class mapping invalid')
        validation = next(v for v in prep['validation'] if v['parameter'] == job['parameter'] and v['seed'] == job['seed'])
        fresh = public_oracle(prefix, job['parameter'])
        for key in ['public_pool_sha256', 'ciphertext_sha256', 'sponge_answers_sha256']:
            if fresh[key] != validation[key]:
                raise ValueError('Prepared and measured public input identities differ')
        stats = r.statistics(raw, p)
        records.append(dict(**job, **stats, metadata=meta, public_inputs=fresh,
                            identical_original_classes=True, identical_original_key_selection_stream=True,
                            actual_constructed_key_stream_recorded_separately=True,
                            original_history=original['history'], key_index_sha256=r.sha(str(prefix) + '.keyidx.bin')))
        r.write(dest / 'progress.xml', records)
        print(label, stats['detected'], flush=True)
        if r.sha(p['dll']) != p['dll_sha256'] or r.sha(p['exe']) != p['exe_sha256']:
            raise ValueError('Library or diagnostic executable changed')
    r.write(dest / 'results.xml', dict(state='PUBLIC_FIELDS_ATTRIBUTION_COMPLETED_REVIEW_REQUIRED',
            records=records, original_investigation_preserved=True, end_utc=r.now()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'collect'])
    parser.add_argument('--original', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--source-root')
    parser.add_argument('--cc')
    parser.add_argument('--token')
    args = parser.parse_args()
    configure(args.original, args.output)
    if args.action == 'prepare':
        prepare(args)
    else:
        if not args.token:
            raise ValueError('An explicit coordination token is required')
        collect(args.token)
