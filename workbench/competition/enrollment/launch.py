"""Optional session demonstration overlay; the published core source is unchanged."""
from pathlib import Path
import argparse
import hashlib
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
import os
import secrets
import subprocess
import sys
import threading
from urllib.parse import urlsplit
import webbrowser
from session_runtime import Configuration, check

HERE = Path(__file__).resolve().parent

def overlay(base, app, address, sessions, source, numerical):
    class Handler(base.handler(app, address)):
        def do_GET(self):
            if not self.valid_host(): return self.send(403, {'error': '仅接受本地访问'})
            url = urlsplit(self.path)
            try:
                if url.path == '/' and not url.query:
                    page = (Path(base.__file__).parent/'index.html').read_text(encoding='utf-8')
                    check(page.count('</nav>') == 1 and page.count('</main>') == 1, 'Unsupported base layout')
                    page = page.replace('</nav>', '<button data-page="session">连续接入</button></nav>')
                    page = page.replace('<small>功能入口</small>', '<small>基础功能入口</small>')
                    page = page.replace('</main>', (HERE/'session.html').read_text(encoding='utf-8') + '</main>')
                    page = page.replace('</body>', '<script src="/session.js"></script></body>')
                    page = page.replace('<div id="science-exports"></div>', '<div id="science-exports"></div>')
                    return self.send(200, page.replace('__CSRF__', app.token), 'text/html')
                if url.path == '/export/numerical-verification.xml' and not url.query:
                    return self.send(200, numerical)
                if url.path == '/session.js' and not url.query:
                    return self.send(200, (HERE/'session.js').read_bytes(), 'text/javascript')
                if url.path == '/api/session/catalog' and not url.query:
                    from publicschemas.cpu_features import availability
                    catalog = sessions.catalog()
                    for row in catalog['configurations']:
                        available = availability(sessions.entries[row['id']]['execution'], app.host)
                        row.update(execution_available=available['available'], execution_reason=available['reason'])
                    return self.send(200, catalog)
                if url.path.startswith('/export/session/run/') and not url.query:
                    ident = url.path.removeprefix('/export/session/run/').removesuffix('.xml').removesuffix('.xlsx')
                    check(ident in sessions.runs, 'No such session observation')
                    return self.send(200, sessions.runs[ident])
                if url.path.startswith('/export/session/study/') and not url.query:
                    key = url.path.removeprefix('/export/session/study/').removesuffix('.xml').removesuffix('.xlsx')
                    check(key in sessions.downloads, 'No such session study')
                    path, digest = sessions.downloads[key]; data = path.read_bytes()
                    check(hashlib.sha256(data).hexdigest() == digest, 'Study artifact changed')
                    return self.send(200, data, 'text/csv' if path.suffix.lower() == '.csv' else 'application/json')
                return super().do_GET()
            except (ValueError, KeyError, TypeError):
                return self.send(400, {'error': '会话资料与已登记记录不一致'})

        def do_POST(self):
            if self.path != '/api/session/run': return super().do_POST()
            valid = (self.valid_host() and self.headers.get('X-Demo-Token') == app.token
                     and self.headers.get('Origin') in (None, 'http://' + address))
            if not valid:
                try:
                    count = int(self.headers.get('Content-Length', '0'))
                    if 0 < count <= 2048:
                        self.connection.settimeout(.25); self.rfile.read(count)
                except (ValueError, OSError): pass
                return self.send(403, {'error': '本地请求来源或令牌不匹配'})
            try:
                check(self.headers.get('Content-Type', '').split(';')[0] == 'application/json', 'JSON required')
                count = int(self.headers.get('Content-Length', '0')); check(0 < count <= 2048, 'Request too large')
                request = base.strict_json(self.rfile.read(count))
                check(type(request) is dict and set(request) == {'library', 'dsa', 'mode'}, 'Unknown session fields')
                check(type(request['library']) is str and request['library'] in sessions.entries, 'Unknown library')
                check(type(request['dsa']) is int and request['dsa'] in (44, 65, 87), 'Unknown parameter')
                check(request['mode'] in ('cold1', 'reuse200', 'fresh200'), 'Unknown lifecycle')
                from publicschemas.cpu_features import availability
                supported = availability(sessions.entries[request['library']]['execution'], app.host)
                if not supported['available']: return self.send(409, {'error': supported['reason']})
                # Serialize all actual cryptographic demonstration calls with the old UI.
                with app.lock:
                    command = [sys.executable, str(HERE/'session_runtime.py'), '--source', str(source),
                               '--config', str(sessions.path), '--library', request['library'],
                               '--dsa', str(request['dsa']), '--mode', request['mode']]
                    options = dict(capture_output=True, text=True, encoding='utf-8', timeout=60,
                                   env=dict(os.environ, PYTHONIOENCODING='utf-8', PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1'))
                    if sys.platform == 'win32': options['creationflags'] = subprocess.CREATE_NO_WINDOW
                    completed = subprocess.run(command, **options)
                    check(completed.returncode == 0 and not completed.stderr, 'Actual session worker failed')
                    result = base.strict_json(completed.stdout)
                    check(result.get('functional_checks_passed') is True, 'Application checks failed')
                    ident = secrets.token_hex(8); result['run_id'] = ident
                    sessions.runs[ident] = result
                    if len(sessions.runs) > 50: sessions.runs.pop(next(iter(sessions.runs)))
                    return self.send(200, result)
            except (ValueError, TypeError, KeyError):
                return self.send(400, {'error': '会话操作未完成，请检查配置与运行记录'})
            except (OSError, subprocess.SubprocessError):
                return self.send(500, {'error': '会话执行未完成；未生成成功记录'})
    return Handler

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--session-config', type=Path, required=True)
    p.add_argument('--port', type=int, default=0); p.add_argument('--no-browser', action='store_true')
    a = p.parse_args(); source = a.source.resolve()
    check(a.port == 0 or 1024 <= a.port <= 65535, 'Use an automatic or unprivileged port')
    sys.path.insert(0, str(source)); from demo import server as base
    # Presentation-only additions for the newly published recipes. Scientific
    # identifiers, measurements and the frozen source files remain unchanged.
    old_title = base.presentation.configuration_title
    display_names = {'lattice-whole-row-native': '整行缓存配置',
                     'lattice-whole-row-separate-y': '整行缓存·独立向量对照',
                     'native-a24': '成熟原生·24项矩阵缓存',
                     'native-a40': '成熟原生·40项矩阵缓存'}
    base.presentation.configuration_title = lambda name: display_names.get(name, old_title(name))
    from statistics_bridge import install as install_numerical_replay
    workspace = a.config.resolve().parent
    if not (workspace/'report_tools').is_dir() and (source.parent/'report_tools').is_dir():
        workspace = source.parent
    numerical = install_numerical_replay(source, workspace, HERE/'statistics-bridge.xml')
    app = base.Application(a.config.resolve())
    check(numerical['status'] == 'CROSS_RUNTIME_NUMERICAL_EQUIVALENCE_VERIFIED', 'Registered ARM numerical reconstruction was not checked')
    sessions = Configuration(a.session_config); sessions.runs = {}
    with ThreadingHTTPServer(('127.0.0.1', a.port), base.handler(app, 'pending')) as server:
        server.daemon_threads = True
        address = f'127.0.0.1:{server.server_address[1]}'
        server.RequestHandlerClass = overlay(base, app, address, sessions, source, numerical)
        print(f'DEMO_URL=http://{address}', flush=True)
        if not a.no_browser:
            opener = threading.Timer(.25, webbrowser.open, args=(f'http://{address}',)); opener.daemon = True; opener.start()
        try: server.serve_forever(poll_interval=.25)
        except KeyboardInterrupt: pass

if __name__ == '__main__': main()
