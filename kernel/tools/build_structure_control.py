"""Rebuild an explicit storage or operation-schedule control.

The separated32 control uses the original pipeline schedule with a 32-bit matrix,
an independent transformed-mask vector, and stack-owned sampling temporaries.
Use --source with an archived source tree to reproduce its historical build;
the default rebuild uses the current source with the recorded control settings.
"""
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
import argparse, contextlib, hashlib, record_io as json, sys, traceback

FEATURES = ('borrow_sig_y', 'natural_sig_y', 'checked_sparse',
            'defer_challenge_ntt', 'parameter_a32', 'early_low_44')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--backend', choices=['x86_64', 'aarch64'], required=True)
    ap.add_argument('--method', choices=['separated32', 'operation-schedule'], default='separated32')
    ap.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    ap.add_argument('--compiler', default='gcc')
    ap.add_argument('--ar', default='gcc-ar')
    ap.add_argument('--nm', default='nm')
    ap.add_argument('--size', default='size')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--plan-only', action='store_true')
    args = ap.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError('Use a fresh output outside the selected source tree')
    catalog = json.loads((source/'configs/recipes.xml').read_text(encoding='utf-8'))['recipes']
    prefix = 'native-' + ('x86' if args.backend == 'x86_64' else 'arm') + '-sign-pipeline'
    recipe = prefix + '-base' if prefix + '-base' in catalog else prefix
    base = catalog[recipe]
    if any(base['algorithm'].get(key, 0) for key in FEATURES):
        raise ValueError('The control requires the original pipeline schedule')
    overrides = {key: 0 for key in FEATURES}
    native = dict(base['defaults']['native_options'])
    if args.method == 'separated32':
        overrides.update(matrix_cache_bits=32, a_planes24=0, inplace_ay=0,
                         keygen_eta_arena=0, matrix4_arena=0, kem_matrix4_arena=0)
    else:
        overrides.update(keygen_eta4=0, fused_keygen_pack=0, verify_hash_batch=0,
                         keygen_eta_arena=0)
        if args.backend == 'aarch64':
            overrides.update(keyverify_dense=0, native_matrix_rows=0,
                             keygen_retain_s2=0, pack_verify_cp=1, matrix4_arena=0)
            native['verify_t1_centered_neon'] = True
    effective = dict(base['algorithm'], **overrides)
    sys.path.insert(0, str(source/'tools'))
    import public_recipes
    from configuration_capabilities import validate_pruned_configuration
    from build_variants import main as build_main
    validate_pruned_configuration(recipe, effective, backend=args.backend)
    child = ['--config', recipe, '--backend', args.backend, '--opt', 'O3', '--lto',
             '--probe-count', '100', '--cc', args.compiler, '--ar', args.ar,
             '--nm', args.nm, '--size', args.size, '--output', str(output/'artifacts')]
    if args.backend == 'aarch64':
        from native_options import arm_argv
        child += arm_argv(native)
    inventory = source/'configs/source_files.xml'
    paths = json.loads(inventory.read_text(encoding='utf-8'))['paths']
    files = [dict(path=p, sha256=hashlib.sha256((source/p).read_bytes()).hexdigest()) for p in paths]
    identity = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    plan = dict(schema='lattice.explicit_feature_control.v2', method=args.method,
                configuration=recipe, optimization='O3', lto=True, backend=args.backend,
                source=str(source), source_files=files, source_identity_sha256=identity,
                source_inventory_sha256=hashlib.sha256(inventory.read_bytes()).hexdigest(),
                base_recipe=base, recipe_value_overrides=overrides,
                effective_algorithm=effective, native_options=native,
                effective_builder_arguments=child)
    output.mkdir(parents=True)
    (output/'plan.xml').write_text(json.dumps(plan, indent=2)+'\n', encoding='utf-8')
    if args.plan_only:
        print(json.dumps(dict(status='PLAN_ONLY', method=args.method, configuration=recipe,
                              source_identity_sha256=identity)))
        return
    previous = public_recipes.CONFIGS[recipe]
    old_argv = sys.argv
    public_recipes.CONFIGS[recipe] = effective
    sys.argv = [str(source/'tools/build_variants.py'), *child]
    code = 0
    try:
        with (output/'build.log').open('w', encoding='utf8') as log, contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            try:
                build_main()
            except BaseException:
                traceback.print_exc()
                code = 1
    finally:
        sys.argv = old_argv
        public_recipes.CONFIGS[recipe] = previous
    record = dict(method=args.method, source_identity_sha256=identity,
                  effective_builder_arguments=child, recipe_value_overrides=overrides, exit_code=code)
    (output/'command.xml').write_text(json.dumps(record, indent=2)+'\n', encoding='utf-8')
    if code:
        raise RuntimeError('Control build failed; inspect build.log')
    print(json.dumps(dict(status='PASS', method=args.method, configuration=recipe,
                          artifacts=str(output/'artifacts'))))


if __name__ == '__main__':
    main()
