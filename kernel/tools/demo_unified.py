"""Unified loopback UI; optional ARM SSH config is external to the package."""
from pathlib import Path
import argparse
from http.server import ThreadingHTTPServer
import sys
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo import server
from demo.platform_providers import SshProvider
from demo.platform_server import UnifiedApplication, handler
from demo.f407_provider import F407Provider
from demo import platform_config


def create_application(config, *, arm_config=None, board_provider=None, board_config=None):
    providers = {}
    if arm_config is not None:
        providers['arm'] = SshProvider(platform_config.arm_config(arm_config))
    if board_config is not None:
        if board_provider is not None:
            raise ValueError('Choose either board configuration or injected provider')
        board_provider = platform_config.board_provider(board_config)
    if board_provider is not None:
        providers['ch32'] = board_provider
    if 'ch32' not in providers:
        preset = platform_config.default_board(ROOT.parents[1])
        if preset.is_file():
            import tempfile
            providers['ch32'] = platform_config.board_provider(preset, records_directory=Path(tempfile.gettempdir())/'CACR2026LatticeDemo'/'ch32')
    return UnifiedApplication(server.Application(config), providers, f407=F407Provider())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path)
    board = p.add_mutually_exclusive_group()
    board.add_argument('--stm32-probe', action='store_true')
    board.add_argument('--ch32-probe', action='store_true')
    board.add_argument('--ch32-run', metavar='PARAM', type=int, choices=(512, 768, 1024, 44, 65, 87))
    board.add_argument('--stm32-run', metavar='PARAM', type=int, choices=(512, 768, 1024, 44, 65, 87))
    p.add_argument('--strategy')
    p.add_argument('--mode', choices=('normal', 'insufficient'), default='normal')
    p.add_argument('--message-bytes', type=int, default=0)
    p.add_argument('--context-bytes', type=int, default=0)
    p.add_argument('--output-xlsx', type=Path)
    p.add_argument('--arm-config', type=Path)
    p.add_argument('--board-config', type=Path)
    p.add_argument('--check-connections', action='store_true', help='Validate external files only; no service or device access')
    p.add_argument('--port', type=int, default=0)
    p.add_argument('--no-browser', action='store_true')
    a = p.parse_args()
    if a.ch32_probe or a.ch32_run is not None:
        import tempfile
        from demo.platform_providers import ProviderError
        from demo.platform_server import ERROR_MESSAGES
        config = a.board_config or platform_config.default_board(ROOT.parents[1])
        records = Path(tempfile.gettempdir()) / 'CACR2026LatticeDemo' / 'ch32'
        provider = platform_config.board_provider(config, records_directory=None if a.board_config else records)
        try:
            rows = provider.catalog()['libraries']
            if a.ch32_probe:
                print('CH32V307', rows[0]['title'])
                return
            if not a.output_xlsx or a.output_xlsx.suffix.lower() != '.xlsx' or a.output_xlsx.exists():
                p.error('--ch32-run 需要尚未使用的 --output-xlsx 路径')
            result = provider.run(dict(library=rows[0]['id'], parameter=a.ch32_run,
                                       message_bytes=a.message_bytes, context_bytes=a.context_bytes, mode=a.mode))
            from demo.spreadsheet_export import functional_workbook
            with a.output_xlsx.open('xb') as stream:
                stream.write(functional_workbook(result))
            print('CH32V307', result['algorithm'], result['parameter'], '通过' if result['functional_checks_passed'] else '失败')
            if not result['functional_checks_passed']:
                raise SystemExit(1)
        except ProviderError as error:
            print(ERROR_MESSAGES.get(error.code, '设备未完成请求') + ' (' + error.code + ')', file=sys.stderr)
            raise SystemExit(2)
        return
    if a.stm32_probe or a.stm32_run is not None:
        from demo.platform_providers import ProviderError
        from demo.platform_server import ERROR_MESSAGES
        result_folder = (a.output_xlsx.parent / (a.output_xlsx.stem + '-原始记录')) if a.output_xlsx else None
        provider = F407Provider(records_directory=result_folder)
        try:
            rows = provider.catalog()['libraries']
            if a.stm32_probe:
                print('STM32F407', provider.mode.upper(), ', '.join(row['configuration'] for row in rows))
                return
            if not a.output_xlsx or not a.strategy:
                p.error('--stm32-run 需要 --strategy 和 --output-xlsx')
            if a.output_xlsx.suffix.lower() != '.xlsx' or a.output_xlsx.exists():
                p.error('结果文件需要尚未使用的 .xlsx 路径')
            result = provider.run(dict(library=provider.prefix + a.strategy, parameter=a.stm32_run,
                                       message_bytes=a.message_bytes, context_bytes=a.context_bytes, mode=a.mode))
            from demo.spreadsheet_export import functional_workbook
            with a.output_xlsx.open('xb') as stream:
                stream.write(functional_workbook(result))
            print(result['platform'], result['algorithm'], result['parameter'], '通过' if result['functional_checks_passed'] else '失败')
            if not result['functional_checks_passed']:
                raise SystemExit(1)
        except ProviderError as error:
            print(ERROR_MESSAGES.get(error.code, '设备未完成请求') + ' (' + error.code + ')', file=sys.stderr)
            raise SystemExit(2)
        return
    if not a.config and not a.check_connections:
        p.error('需要 --config')
    if a.port != 0 and not 1024 <= a.port <= 65535:
        raise ValueError('Use an automatic or unprivileged port')
    if a.check_connections:
        if a.arm_config: SshProvider(platform_config.arm_config(a.arm_config))
        if a.board_config: platform_config.board_provider(a.board_config)
        print('连接文件校验通过；尚未连接远端或开发板。', flush=True)
        return
    print('正在校验本机程序与资料，首次启动请等待。', flush=True)
    app = create_application(a.config, arm_config=a.arm_config, board_config=a.board_config)
    httpd = ThreadingHTTPServer(('127.0.0.1', a.port), handler(server, app, 'pending'))
    address = '127.0.0.1:' + str(httpd.server_port)
    httpd.RequestHandlerClass = handler(server, app, address)
    print('http://' + address, flush=True)
    print('选择运行平台后连接设备。设备未连接时仍可使用 Windows；按 Ctrl+C 结束服务。', flush=True)
    if not a.no_browser:
        webbrowser.open('http://' + address)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, ImportError):
        print('启动未完成：请检查本机程序、连接文件和离线依赖。未自动连接或重发设备操作。', file=sys.stderr)
        raise SystemExit(2)
