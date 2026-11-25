"""Unified interface for live operations and validated experimental results."""
import argparse
import datetime
import hashlib
import platform
from http.server import ThreadingHTTPServer
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
from pathlib import Path
import secrets
import sys
import threading
from types import SimpleNamespace
import webbrowser

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def stamp(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(path, value):
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2); f.write('\n')


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=ROOT.parents[2]/'01_源代码/可参数化格运算内核')
    p.add_argument('--config', type=Path)
    p.add_argument('--archive-config', type=Path, default=ROOT/'history/frozen-demo.xml')
    p.add_argument('--archive-adapter', type=Path, default=ROOT/'session-demo')
    p.add_argument('--session-config', type=Path, default=ROOT/'session-demo/session.xml')
    p.add_argument('--arm-config', type=Path)
    p.add_argument('--board-config', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--port', type=int, default=8134)
    p.add_argument('--no-browser', action='store_true')
    p.add_argument('--stop-file', type=Path, help='包外关闭请求文件')
    p.add_argument('--history', action='store_true', help='打开实验与应用页面')
    p.add_argument('--arm', action='store_true', help='在 AArch64 主机本地运行两策略页面')
    a = p.parse_args(argv)
    if not 1024 <= a.port <= 65535: p.error('端口须位于1024至65535')
    if a.config is None:
        a.config = ROOT/'live-demo'/('arm.xml' if a.arm else 'windows.xml')
    # User-owned optional files; none are shipped with credentials or addresses.
    for field, name in (('arm_config', 'arm.xml'), ('board_config', 'board.xml')):
        candidate = Path.home()/'.lattice-live'/name
        if getattr(a, field) is None and candidate.is_file(): setattr(a, field, candidate)
    if a.arm_config is None:
        legacy_arm = Path.home()/'.lattice-live/arm.json'
        if legacy_arm.is_file(): a.arm_config = legacy_arm
    a.output = (a.output or Path.home()/'.lattice-live'/(datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))).resolve()
    if a.output.exists() or a.output == ROOT or ROOT in a.output.parents or a.source.resolve() in a.output.parents:
        p.error('运行记录必须位于程序与源码之外的全新目录')
    if a.stop_file:
        a.stop_file = a.stop_file.resolve()
        if a.stop_file == ROOT or ROOT in a.stop_file.parents or a.source.resolve() in a.stop_file.parents:
            p.error('关闭请求文件必须位于运行资料之外')
    return a


def serve_arm(a):
    if not sys.platform.startswith('linux') or platform.machine().lower() not in ('aarch64', 'arm64'):
        raise SystemExit('请在 Linux AArch64 上使用 --arm。')
    source = a.source.resolve(strict=True)
    sys.path.insert(0, str(source))
    from demo import server
    from unified_workbench.web import wrap

    app = server.Application(a.config)
    names = {'low-memory': 'arm-low-memory', 'performance': 'arm-performance'}
    libs = {profile: app.libs[name] for profile, name in names.items() if name in app.libs}
    if not libs:
        raise SystemExit('没有可运行的 AArch64 运行库。')
    current = SimpleNamespace(token=app.token, libs=libs,
                              descriptors={profile: app.descriptors[name] for profile, name in names.items()
                                           if name in app.descriptors})
    live = SimpleNamespace(providers={}, remote_rows={})
    address = f'127.0.0.1:{a.port}'
    a.output.mkdir(parents=True)
    handler = wrap(server.handler(app, address), current, live, None, source, ROOT.parents[2], a.output,
                   address, local_platform='arm')
    with ThreadingHTTPServer(('127.0.0.1', a.port), handler) as httpd:
        finished = threading.Event()
        if a.stop_file:
            def watch_close():
                while not finished.wait(.25):
                    if a.stop_file.is_file():
                        httpd.shutdown()
                        return
            threading.Thread(target=watch_close, daemon=True).start()
        url = f'http://{address}'
        print('DEMO_URL='+url, flush=True)
        if not a.no_browser:
            opener = threading.Timer(.25, webbrowser.open, args=(url,))
            opener.daemon = True
            opener.start()
        try:
            httpd.serve_forever(poll_interval=.25)
        except KeyboardInterrupt:
            pass
        finally:
            finished.set()


def main(argv=None):
    a = arguments(argv)
    if a.arm:
        return serve_arm(a)
    a.output.mkdir(parents=True)
    receipt = dict(status='STARTING', started_utc=stamp(), argv=sys.argv,
                   controller_sha256=sha(__file__), source=str(a.source.resolve()),
                   policy='No automatic device connect, retry or simulated fallback; one loopback listener')
    httpd = None; opener = None
    finished = threading.Event(); watcher = None
    try:
        print('正在校验本机程序与实验资料，首次启动可能需要等待。', flush=True)
        from unified_shell.application import build
        address = '127.0.0.1:'+str(a.port)
        handler, live, archive, unavailable = build(a, address)
        receipt['unavailable_optional_connections'] = unavailable
        receipt['input_sha256'] = {str(p.resolve()): sha(p) for p in (a.config, a.archive_config, a.session_config)}
        receipt['shell_sha256'] = {p.relative_to(ROOT).as_posix(): sha(p) for p in (ROOT/'unified_shell').glob('*') if p.is_file()}
        for scope, app in (('live', live), ('archive', archive)):
            original = app.run
            def recorded(request, _run=original, _scope=scope):
                result = dict(status='FAILED', scope=_scope, request=request, started_utc=stamp())
                try:
                    value = _run(request); result.update(status='RETURNED', result=value); return value
                except Exception as error:
                    result.update(error_type=type(error).__name__, error=str(error)); raise
                finally:
                    result['finished_utc'] = stamp()
                    save(a.output/('flow-'+secrets.token_hex(16)+'.xml'), result)
            app.run = recorded
        httpd = ThreadingHTTPServer(('127.0.0.1', a.port), handler)
        httpd.daemon_threads = False  # bounded active calls drain before NORMAL_STOP
        receipt['status'] = 'READY_NO_AUTOMATIC_CONNECTION'
        save(a.output/'startup.xml', receipt)
        print('DEMO_URL=http://'+address+('/history/' if a.history else '/'), flush=True)
        print('Windows 密码功能在本机执行；实验结果与实板证据由顶部导航进入。关闭启动窗口可结束服务。', flush=True)
        if not a.no_browser:
            opener = threading.Timer(.25, webbrowser.open, args=('http://'+address+('/history/' if a.history else '/'),)); opener.daemon = True; opener.start()
        if a.stop_file:
            def watch_close():
                while not finished.wait(.2):
                    if a.stop_file.is_file():
                        httpd.shutdown(); return
            watcher = threading.Thread(target=watch_close, daemon=True); watcher.start()
        try: httpd.serve_forever(poll_interval=.25)
        except KeyboardInterrupt: pass
        receipt['status'] = 'NORMAL_STOP'
    except BaseException as error:
        receipt.update(status='FAILED', error_type=type(error).__name__, error=str(error)); raise
    finally:
        finished.set()
        if watcher: watcher.join(timeout=2)
        if opener: opener.cancel()
        if httpd: httpd.server_close()
        receipt['finished_utc'] = stamp(); save(a.output/'stop.xml', receipt)


if __name__ == '__main__': main()
