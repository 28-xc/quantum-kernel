"""Start the packaged local demonstration with its bundled interpreter."""
from pathlib import Path
import argparse
import sys
import threading
import webbrowser
from http.server import ThreadingHTTPServer

# The official embeddable interpreter isolates sys.path using python313._pth.
# Only this published source directory is added; the runtime remains unchanged.
SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
sys.path.insert(0, str(SOURCE / 'demo'))
from server import Application, handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    if args.port != 0 and not 1024 <= args.port <= 65535:
        raise ValueError('Use an automatic or unprivileged local port')
    app = Application(args.config.resolve())
    with ThreadingHTTPServer(('127.0.0.1', args.port), handler(app, 'pending')) as server:
        server.daemon_threads = True
        address = f'127.0.0.1:{server.server_address[1]}'
        server.RequestHandlerClass = handler(app, address)
        print(f'DEMO_URL=http://{address}', flush=True)
        print('本地演示已启动。关闭此窗口或按 Ctrl+C 结束服务。', flush=True)
        if not args.no_browser:
            opener = threading.Timer(0.25, webbrowser.open, args=(f'http://{address}',))
            opener.daemon = True
            opener.start()
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
