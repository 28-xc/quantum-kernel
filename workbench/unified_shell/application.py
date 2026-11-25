"""Load data and configure test providers."""
import importlib.util
from pathlib import Path
import sys


def optional_providers(platform_config, ssh_provider, arm_path, board_path, *, packaged_board=None, records_directory=None):
    providers, unavailable = {}, {}
    for platform, path in (('arm', arm_path), ('ch32', board_path)):
        if path is None: continue
        try:
            providers[platform] = (ssh_provider(platform_config.arm_config(path)) if platform == 'arm'
                                   else platform_config.board_provider(path))
        except (ValueError, OSError, KeyError, TypeError, ImportError) as error:
            unavailable[platform] = dict(error_type=type(error).__name__, error=str(error))
    if board_path is None and packaged_board is not None and packaged_board.is_file():
        try:
            providers['ch32'] = platform_config.board_provider(packaged_board, records_directory=records_directory)
        except (ValueError, OSError, KeyError, TypeError, ImportError) as error:
            unavailable['ch32'] = dict(error_type=type(error).__name__, error=str(error))
    return providers, unavailable


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def build(args, address):
    source, adapter = args.source.resolve(strict=True), args.archive_adapter.resolve(strict=True)
    sys.path.insert(0, str(source)); sys.path.insert(0, str(adapter))
    from demo import server, platform_config, platform_server
    from demo.platform_providers import SshProvider
    if Path(server.__file__).resolve() != source/'demo/server.py':
        raise ValueError('Unexpected source module origin')
    import tempfile
    providers, unavailable = optional_providers(platform_config, SshProvider, args.arm_config, args.board_config,
        packaged_board=platform_config.default_board(source.parents[1]),
        records_directory=Path(tempfile.gettempdir()) / 'CACR2026LatticeDemo' / 'ch32')
    live = platform_server.UnifiedApplication(server.Application(args.config), providers,
                                             f407=platform_server.F407Provider(package=source.parents[1],
                                                    records_directory=Path(tempfile.gettempdir())/'CACR2026LatticeDemo'/'stm32f407'))

    sessions_module = module(adapter/'launch.py', '_session_adapter')
    bridge = module(adapter/'statistics_bridge.py', '_statistics_bridge')
    numerical = bridge.install(source, source.parent, adapter/'statistics-bridge.xml')
    archive = server.Application(args.archive_config)
    if numerical['status'] != 'CROSS_RUNTIME_NUMERICAL_EQUIVALENCE_VERIFIED':
        raise ValueError('Registered archive numerical verification was not completed')
    sessions = sessions_module.Configuration(args.session_config); sessions.runs = {}
    old_title = server.presentation.configuration_title
    names = {'lattice-whole-row-native': '整行缓存配置',
             'lattice-whole-row-separate-y': '整行缓存·独立向量对照',
             'native-a24': '成熟原生·24项矩阵缓存', 'native-a40': '成熟原生·40项矩阵缓存'}
    server.presentation.configuration_title = lambda name: names.get(name, old_title(name))
    # Serialize local calls. Remote providers have their own locks.
    archive.lock = live.lock
    from unified_shell.router import compose
    handler = compose(platform_server.handler(server, live, address),
                      sessions_module.overlay(server, archive, address, sessions, source, numerical), unavailable)
    return handler, live, archive, unavailable
