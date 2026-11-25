"""Explicit algorithm recipes and supported platform defaults."""
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
import record_io as json

ROOT = Path(__file__).resolve().parents[1]
CATALOG = json.loads((ROOT / 'configs/recipes.xml').read_text(encoding='utf-8'))
if CATALOG.get('schema') != 'lattice.build_recipes.v1':
    raise ValueError('Unsupported recipe schema')
RECIPES = CATALOG['recipes']
CONFIGS = {name: dict(recipe['algorithm']) for name, recipe in RECIPES.items()}

def validate_backend(name, backend):
    if name not in RECIPES or backend not in RECIPES[name]['backends']:
        raise ValueError('Configuration and backend combination is unsupported')

def apply_plan_defaults(args):
    from native_options import ARM_OPTION_NAMES
    if args.configuration == 'canonical':
        defaults = dict(backend='portable', optimization='O3', lto=False,
                        native_options=dict(linker='default', raw_y_prefix='none'))
    else:
        if args.configuration not in RECIPES:
            raise ValueError('Unknown algorithm configuration')
        defaults = RECIPES[args.configuration]['defaults']
    for attr, key in [('backend', 'backend'), ('opt', 'optimization'), ('lto', 'lto')]:
        if getattr(args, attr) is None:
            setattr(args, attr, defaults[key])
    for name in ARM_OPTION_NAMES:
        if getattr(args, name) is None:
            setattr(args, name, defaults['native_options'].get(name, False))
    return args
