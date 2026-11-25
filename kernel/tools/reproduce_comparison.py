"""Recompute complete-operation studies, or explicitly collect a new native study.

Replay reads every retained CSV shard. Collect is opt-in and runs only on the
platform named in the acquisition plan. All paths in plans are relative to the
plan directory; no host or laboratory directory is embedded in this tool.
"""
from pathlib import Path, PurePosixPath
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
import argparse, csv, hashlib, record_io as json, math, os, platform, signal, subprocess, sys
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'analysis'))
import mean_tail_statistics as stats
import pooled_statistics as shared
from publicschemas.pooled_block_model import token


def need(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    return shared.read(path)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, data):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2, allow_nan=False)
        f.write('\n')


def keys(value, expected):
    need(type(value) is dict and set(value) == set(expected.split()), 'Unexpected plan fields')


def relative(base, value):
    need(type(value) is str and value and '\\' not in value and ':' not in value,
         'Use a relative POSIX path')
    p = PurePosixPath(value)
    need(not p.is_absolute() and p.as_posix() == value, 'Noncanonical relative path')
    return (base / p).resolve()


def artifact(base, record):
    keys(record, 'path sha256')
    p = relative(base, record['path'])
    need(p.is_file() and sha(p) == record['sha256'], 'Missing or changed input: ' + record['path'])
    return p


def ci(x):
    return np.quantile(x, [.025, .975], method='linear').tolist()


def ratio_summary(points, replicates, indices):
    need(indices and len(set(indices)) == len(indices), 'Empty or duplicate contrast cells')
    return dict(cells=[list(stats.model.CELLS[i]) for i in indices],
                mean_ratio_geomean=float(np.exp(np.log(points[indices]).mean())),
                ci95=ci(np.exp(np.log(replicates[indices]).mean(axis=0))))


def verify_numerical_summary(expected, actual):
    """Keep sample/method identities exact and audit floating-point rounding."""
    report = dict(relative_tolerance=3e-13, absolute_tolerance=1e-9,
                  float_fields=0, unequal_float_fields=0,
                  maximum_absolute_difference=0.0, maximum_relative_difference=0.0,
                  archived_replicate_values_sha256=expected['method']['replicate_values_sha256'],
                  recomputed_replicate_values_sha256=actual['method']['replicate_values_sha256'],
                  archived_runtime=expected['runtime'], recomputed_runtime=actual['runtime'])

    def compare(left, right, path=()):
        if path == ('runtime',):
            return
        if path == ('method', 'replicate_values_sha256'):
            # This checksum binds the local binary64 array. Its bytes may vary
            # across instruction sets even when published estimates agree.
            stats.model.digest(left); stats.model.digest(right)
            return
        need(type(left) is type(right), 'Reconstruction type differs: ' + '/'.join(path))
        if isinstance(left, dict):
            need(left.keys() == right.keys(), 'Reconstruction fields differ: ' + '/'.join(path))
            for key in left:
                compare(left[key], right[key], path + (key,))
        elif isinstance(left, list):
            need(len(left) == len(right), 'Reconstruction length differs: ' + '/'.join(path))
            for index, (x, y) in enumerate(zip(left, right)):
                compare(x, y, path + (str(index),))
        elif isinstance(left, float):
            need(math.isfinite(left) and math.isfinite(right), 'Nonfinite reconstructed value')
            need(math.isclose(left, right, rel_tol=report['relative_tolerance'],
                              abs_tol=report['absolute_tolerance']),
                 'Numerical reconstruction differs: ' + '/'.join(path))
            delta = abs(left - right)
            report['float_fields'] += 1
            report['unequal_float_fields'] += left != right
            report['maximum_absolute_difference'] = max(report['maximum_absolute_difference'], delta)
            relative_delta = delta / max(abs(left), abs(right)) if left or right else 0.0
            report['maximum_relative_difference'] = max(report['maximum_relative_difference'], relative_delta)
        else:
            need(left == right, 'Exact reconstruction differs: ' + '/'.join(path))

    compare(expected, actual)
    report['replicate_bytes_equal'] = (report['archived_replicate_values_sha256'] ==
                                        report['recomputed_replicate_values_sha256'])
    report['scope'] = 'Exact raw samples, source identities, methods and block draws; numerical comparison of every published floating-point field.'
    return report


def replay(input_path, output):
    plan = read(input_path)
    keys(plan, 'schema studies')
    need(plan['schema'] == 'lattice.comparison_replay.v1' and plan['studies'], 'Unknown replay schema')
    need(not output.exists(), 'Fresh output required')
    output.mkdir(parents=True)
    records = []; resource_points = []; cell_table = []; ratio_table = []
    for entry in plan['studies']:
        keys(entry, 'id observations summary design resources')
        token(entry['id'])
        paths = {k: artifact(input_path.parent, entry[k]) for k in ('observations', 'summary', 'design', 'resources')}
        obs = shared.read_observations(paths['observations'])
        expected = read(paths['summary'])
        stats.model.validate(expected, obs)
        need(expected['source_code_hashes'] == stats.sources(), 'Statistical source differs')
        need(expected['observations_sha256'] == sha(paths['observations']), 'Observation identity differs')
        pairs = [{k: x[k] for k in ('id', 'candidate', 'reference')} for x in expected['comparisons']]
        actual, raw = stats.analyze(obs, pairs, sha(paths['observations']), expected['method']['resamples'],
                                    expected['method']['bootstrap_seed'], paths['observations'].parent)
        numerical_validation = verify_numerical_summary(expected, actual)
        actual_path = output / (entry['id'] + '.recomputed-summary.xml')
        write(actual_path, actual)
        for row in actual['cells']:
            flat = dict(dataset_id=obs['dataset_id'], platform=obs['platform'], configuration=row['configuration'],
                        parameter=row['parameter'], operation=row['operation'], minimum_ns=row['minimum_ns'], maximum_ns=row['maximum_ns'])
            for name, estimate in row['statistics'].items():
                flat[name+'_ns'] = estimate['ns']; flat[name+'_ci_low_ns'], flat[name+'_ci_high_ns'] = estimate['ci95_ns']
            cell_table.append(flat)
        for pair in actual['comparisons']:
            for row in pair['cells']:
                flat = dict(dataset_id=obs['dataset_id'], platform=obs['platform'], candidate=pair['candidate'], reference=pair['reference'],
                            parameter=row['parameter'], operation=row['operation'])
                for name, estimate in row['ratios'].items():
                    flat[name+'_ratio'] = estimate['value']; flat[name+'_ci_low'], flat[name+'_ci_high'] = estimate['ci95']
                ratio_table.append(flat)
        labels = actual['configuration_order']
        design = read(paths['design'])
        keys(design, 'schema primary_cells interactions compilation_policy scope')
        need(design['schema'] == 'lattice.comparison_design.v1', 'Unknown design schema')
        need(set(design['primary_cells']) == {x['id'] for x in pairs}, 'Incomplete primary-cell map')
        rep = raw['mean_tail_replicates_ns'][:, :, 0, :]
        point = np.array([x['statistics']['mean']['ns'] for x in actual['cells']]).reshape(len(labels), 18)
        contrasts = []
        for pair in pairs:
            a, b = labels.index(pair['candidate']), labels.index(pair['reference'])
            cells = [tuple(x) for x in design['primary_cells'][pair['id']]]
            indices = [stats.model.CELLS.index(x) for x in cells]
            contrasts.append(dict(**pair, **ratio_summary(point[a] / point[b], rep[a] / rep[b], indices)))
        interactions = []
        for row in design['interactions']:
            keys(row, 'id numerator denominator cells')
            need(len(row['numerator']) == len(row['denominator']) == 2, 'A 2 by 2 interaction requires four arms')
            a, b = [labels.index(x) for x in row['numerator']]
            c, d = [labels.index(x) for x in row['denominator']]
            pt = (point[a] / point[b]) / (point[c] / point[d])
            bs = (rep[a] / rep[b]) / (rep[c] / rep[d])
            indices = [stats.model.CELLS.index(tuple(x)) for x in row['cells']]
            interactions.append({**row, **ratio_summary(pt, bs, indices),
                                 'per_cell':[dict(parameter=p, operation=o, ratio_of_ratios=float(pt[i]), ci95=ci(bs[i]))
                                             for i, (p, o) in enumerate(stats.model.CELLS)]})
        resources = read(paths['resources'])
        need(resources['schema'] == 'lattice.comparison_resources.v1', 'Unknown resource schema')
        images = {x['id']: x['library_sha256'] for x in obs['configurations']}
        need({x['configuration'] for x in resources['configurations']} == set(labels), 'Incomplete resource rows')
        pareto = []
        for row in resources['configurations']:
            need(row['library_sha256'] == images[row['configuration']], 'Resource image differs from timed image')
            screen = row['common']
            if screen is None:
                continue
            need(all(type(screen[k]) is int and screen[k] >= 0 for k in ('P', 'W', 'S', 'C', 'G', 'H', 'R')), 'Invalid resource count')
            need(screen['R'] == sum(screen[k] for k in ('W', 'S', 'C', 'G', 'H')), 'Resource sum differs')
            li = labels.index(row['configuration'])
            resource_points.append(dict(dataset_id=obs['dataset_id'], platform=obs['platform'], configuration=row['configuration'],
                                         binary_sha256=row['library_sha256'], ram_bytes=screen['R'], program_bytes=screen['P'],
                                         equal_weight_18_mean_ns=math.fsum(map(float,point[li]))/18, core_components=screen,
                                         resource_source_sha256=row['source_record_sha256'], statistics_sha256=sha(paths['summary']),
                                         role='signature-order-control' if row['configuration']=='lattice-early-low-check' else
                                              'preserved-deployment' if row['configuration']=='lattice-mixed-sampling-reference' else 'configuration-or-reference'))
            pareto.append(dict(configuration=row['configuration'], library_sha256=row['library_sha256'], **screen,
                               cells=[dict(parameter=p, operation=o, mean_ns=float(point[li, i])) for i, (p, o) in enumerate(stats.model.CELLS)],
                               mean_ns_geomean=float(np.exp(np.log(point[li]).mean())),
                               fits_16k=screen['R'] <= 16384, fits_32k=screen['R'] <= 32768))
        result = dict(schema='lattice.comparison_derived.v1', dataset_id=obs['dataset_id'], platform=obs['platform'],
                      source_sha256=sha(__file__), observations_sha256=sha(paths['observations']), summary_sha256=sha(paths['summary']),
                      design_sha256=sha(paths['design']), resources_sha256=sha(paths['resources']), counts=actual['counts'],
                      block_draws_sha256=actual['method']['block_draws_sha256'], ratio_direction='numerator_over_denominator',
                      interval_scope='pointwise; shared whole-block bootstrap; all measured samples retained',
                      compilation_policy=design['compilation_policy'], scope=design['scope'], primary_contrasts=contrasts,
                      interactions=interactions, resource_rows=resources['configurations'], pareto_points=pareto,
                      numerical_validation=numerical_validation,
                      recomputed_summary=dict(path=actual_path.name, sha256=sha(actual_path)))
        dest = output / (entry['id'] + '.xml')
        write(dest, result)
        records.append(dict(id=entry['id'], path=dest.name, sha256=sha(dest), status='RAW_AND_NUMERICAL_REPLAY'))
        print(entry['id'], 'RAW_AND_NUMERICAL_REPLAY', flush=True)
    write(output/'resource_points.xml', dict(schema='lattice.comparison_resource_points.v1', points=resource_points))
    for name, rows in [('operation_cells.csv', cell_table), ('paired_operation_ratios.csv', ratio_table)]:
        with (output/name).open('x', encoding='utf-8', newline='') as f:
            writer=csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    write(output / 'result.xml', dict(schema='lattice.comparison_replay_result.v1', status='PASS', input_sha256=sha(input_path),
                                      source_sha256=sha(__file__), studies=records, target_execution=False,
                                      tables={name:sha(output/name) for name in ('resource_points.xml','operation_cells.csv','paired_operation_ratios.csv')}))


def acquisition_plan(path):
    data = read(path)
    keys(data, 'schema platform dataset_id compiler crypto_library crypto_prefix preparation_library cpu blocks samples warmups seed bootstrap_seed resamples message_bytes context_bytes configurations comparisons')
    need(data['schema'] == 'lattice.comparison_acquisition.v1', 'Unknown acquisition schema')
    current = ('windows_x86_64' if os.name == 'nt' and platform.machine().lower() in ('amd64', 'x86_64') else
               'linux_aarch64' if sys.platform.startswith('linux') and platform.machine().lower() in ('aarch64', 'arm64') else None)
    need(data['platform'] == current, 'This acquisition must run natively on the named platform')
    for name, lower, upper in [('cpu', 0, 1023), ('blocks', 2, 50), ('samples', 10, 10000), ('warmups', 0, 1000),
                                ('seed', 1, 2**63-1), ('bootstrap_seed', 0, 2**63-1), ('resamples', 1, 100000),
                                ('message_bytes', 0, 16384), ('context_bytes', 0, 255)]:
        need(type(data[name]) is int and lower <= data[name] <= upper, 'Invalid ' + name)
    token(data['dataset_id'])
    artifact(path.parent, data['crypto_library'])
    need((relative(path.parent, data['crypto_prefix']) / 'include/openssl/evp.h').is_file(), 'OpenSSL headers missing')
    labels = []
    for row in data['configurations']:
        keys(row, 'id library workspace')
        token(row['id']); labels.append(row['id']); artifact(path.parent, row['library'])
        need(type(row['workspace']) is int and 32 <= row['workspace'] <= 262144, 'Invalid workspace')
    need(2 <= len(labels) <= 30 and len(labels) == len(set(labels)), 'Unique arms required')
    need(data['preparation_library'] in labels, 'Preparation library not in comparison')
    stats.model.comparisons(data['comparisons'], labels)
    return data


def collect(input_path, output, check_only=False):
    data = acquisition_plan(input_path)
    need(not output.exists(), 'Fresh output required'); output.mkdir(parents=True)
    record = dict(schema='lattice.comparison_collection.v1', status='READY', input_sha256=sha(input_path),
                  source_sha256=sha(__file__), records=[], planned_tasks=data['blocks'] * 18 * len(data['configurations']),
                  target_execution=False)
    def save():
        (output / 'execution.xml').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    save()
    if check_only:
        record['status'] = 'PLAN_VALIDATED_NO_TARGET_EXECUTION'; save(); return
    def run(label, argv, timeout):
        command = [sys.executable, '-B', *map(str, argv)]
        item = dict(label=label, command=command, status='STARTED'); record['records'].append(item); save()
        worker = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0,
                                  start_new_session=os.name != 'nt')
        item['pid'] = worker.pid; save()
        try:
            stdout, stderr = worker.communicate(timeout=timeout)
            code = worker.returncode
        except subprocess.TimeoutExpired as error:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(worker.pid), '/T', '/F'], capture_output=True, timeout=30)
            else:
                os.killpg(worker.pid, signal.SIGTERM)
                try: worker.wait(timeout=5)
                except subprocess.TimeoutExpired: os.killpg(worker.pid, signal.SIGKILL)
            stdout, stderr = worker.communicate(timeout=30)
            code = None
        (output / (label + '.stdout')).write_bytes(json.capture_bytes(stdout)); (output / (label + '.stderr')).write_bytes(stderr)
        item.update(exit_code=code, status='PASS' if code == 0 else 'FAILED',
                    stdout_sha256=sha(output / (label + '.stdout')), stderr_sha256=sha(output / (label + '.stderr'))); save()
        need(code == 0, label + ' failed; original outputs retained')
    try:
        record['target_execution'] = True; save()
        rows = data['configurations']; chosen = next(x for x in rows if x['id'] == data['preparation_library'])
        run('prepare', [ROOT/'bench/complete_operations/prepare.py', '--boundary', 'serialized', '--library', artifact(input_path.parent, chosen['library']),
                        '--crypto-library', artifact(input_path.parent, data['crypto_library']), '--crypto-prefix', relative(input_path.parent, data['crypto_prefix']),
                        '--expected-version', '3.6.4', '--cpu', data['cpu'], '--count', 20, '--workspace', chosen['workspace'],
                        '--message-bytes', data['message_bytes'], '--context-bytes', data['context_bytes'], '--cc', data['compiler'], '--output', output/'prepared'], 900)
        cfg = {k: data[k] for k in ('cpu', 'blocks', 'samples', 'warmups', 'seed', 'message_bytes', 'context_bytes')}
        cfg.update(driver=str(output/'prepared'/('driver.exe' if os.name == 'nt' else 'driver')), prepared=str(output/'prepared/prepared.xml'),
                   crypto_library=str(artifact(input_path.parent, data['crypto_library'])), boundary='serialized', expected_version='3.6.4',
                   configurations=[dict(label=x['id'], library=str(artifact(input_path.parent, x['library'])), provider='lattice', pct='none', workspace=x['workspace']) for x in rows])
        write(output/'configuration.xml', cfg); write(output/'labels.xml', {x['id']: x['id'] for x in rows}); write(output/'comparisons.xml', data['comparisons'])
        run('collect', [ROOT/'bench/complete_operations/collect.py', '--configuration', output/'configuration.xml', '--output', output/'acquisition'], 7200)
        run('project', [ROOT/'tools/import_complete_operations.py', '--input', output/'acquisition', '--configuration', output/'configuration.xml',
                        '--labels', output/'labels.xml', '--dataset-id', data['dataset_id'], '--platform', data['platform'], '--output', output/'observations', '--audit', output/'import_audit.xml'], 1800)
        run('statistics', [ROOT/'analysis/mean_tail_statistics.py', 'derive', '--observations', output/'observations/observations.xml',
                           '--comparisons', output/'comparisons.xml', '--seed', data['bootstrap_seed'], '--resamples', data['resamples'], '--output', output/'observations/mean_tail_summary.xml'], 1800)
        record['status'] = 'PASS'
    except BaseException as error:
        record.update(status='FAILED_OR_INCOMPLETE', error=repr(error)); raise
    finally:
        save()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=['replay', 'collect', 'check'], default='replay')
    p.add_argument('--input', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    a = p.parse_args(); input_path = a.input.resolve(); output = a.output.resolve()
    need(not output.is_relative_to(ROOT), 'Keep generated outputs outside source')
    if a.mode == 'replay': replay(input_path, output)
    else: collect(input_path, output, check_only=a.mode == 'check')


if __name__ == '__main__':
    main()
