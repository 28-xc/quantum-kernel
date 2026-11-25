"""Start the local Quantum Kernel service."""
from pathlib import Path
import sys as _record_sys
from pathlib import Path as _RecordPath
for _record_parent in _RecordPath(__file__).resolve().parents:
    _record_candidate = _record_parent / 'record_io.py'
    if not _record_candidate.is_file():
        _record_candidate = _record_parent / '01_源代码/可参数化格运算内核/record_io.py'
    if _record_candidate.is_file():
        _record_sys.path.insert(0, str(_record_candidate.parent))
        break
import argparse, copy, datetime, gzip, hashlib, importlib.util, record_io as json, os, secrets, sys, threading, time, types
from http.server import ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parents[2]
EXPECTED_MANIFEST='27378e40f834d39f5c1fbb78523ad7a2f5ac276241eb3c520cb0e8fec7d38dcc'

def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8'))
def save(path,value):
    with Path(path).open('x',encoding='utf-8') as f:json.dump(value,f,ensure_ascii=False,indent=2)
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def bound(value):
    from package_layout import bound as resolve_package_path
    return resolve_package_path(PACKAGE, value)
def config(name,output):
    def resolve(value):
        if isinstance(value,dict):
            out={k:resolve(v) for k,v in value.items()}
            if isinstance(value.get('path'),str) and isinstance(value.get('sha256'),str):out['path']=str(bound(value['path']))
            return out
        if isinstance(value,list):return [resolve(v) for v in value]
        return value
    target=output/(name+'.xml');save(target,resolve(read(HERE/'prepared'/ (name+'.xml'))));return target
def state(name):
    def hook(value):
        if set(value)=={'__package_path__'}:return bound(value['__package_path__'])
        if set(value)=={'__tuple__'}:return tuple(value['__tuple__'])
        if set(value)=={'__mapping__'}:return dict(value['__mapping__'])
        return value
    return json.loads(gzip.decompress((HERE/'prepared'/(name+'-state.xml.gz')).read_bytes()),object_hook=hook)
def restore(app,name):
    value=state(name);views=value.pop('prepared_science_views')
    for key,item in value.items():setattr(app,key,item)
    for entry in app.upgrades.values():entry['base']=PACKAGE
    def science_views(self,library=None):
        key=library or ''
        if key not in views:raise ValueError('Unknown library')
        return copy.deepcopy(views[key])
    app.science_views=types.MethodType(science_views,app)
    return app

def main():
    started=time.perf_counter();phases={}
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',type=Path,default=PACKAGE);p.add_argument('--cache-root',type=Path)
    p.add_argument('--output',type=Path);p.add_argument('--stop-file',type=Path)
    p.add_argument('--port',type=int,default=8134);p.add_argument('--no-browser',action='store_true')
    p.add_argument('--history',action='store_true')
    a=p.parse_args()
    if a.package.resolve()!=PACKAGE or not 1024<=a.port<=65535:p.error('材料位置或本机端口无效')
    output=(a.output or Path(os.environ.get('LOCALAPPDATA',str(Path.home())))/'CACR2026LatticeDemo'/'runs'/(datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(4))).resolve()
    if output.exists() or output.is_relative_to(PACKAGE):p.error('请选择支撑材料之外的全新运行目录')
    if a.stop_file and a.stop_file.resolve().is_relative_to(PACKAGE):p.error('关闭文件须在支撑材料之外')
    output.mkdir(parents=True)
    manifest_path=HERE/'prepared/manifest.xml'
    if sha(manifest_path)!=EXPECTED_MANIFEST:raise ValueError('展示配置清单不匹配，请从完整支撑材料恢复启动文件')
    manifest=read(manifest_path)
    def verify(row):
        path=bound(row['path'])
        if not path.is_file() or path.stat().st_size!=row['bytes'] or sha(path)!=row['sha256']:
            raise ValueError('运行依赖不完整或已改变：'+row['path'])
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(verify,manifest['startup_files']))
    phases['dependencies_verified']=time.perf_counter()-started
    source=PACKAGE/'01_源代码/可参数化格运算内核'
    adapter=PACKAGE/'03_复现环境与运行程序/完整设备接入应用/连续接入'
    sys.path[:0]=[str(HERE),str(source),str(adapter)]
    from demo import server,platform_server,platform_config
    from demo.platform_providers import SshProvider
    from unified_shell.application import optional_providers
    from unified_shell.router import compose
    from session_runtime import Configuration
    current=restore(server.Application(config('current',output)),'current')
    archive=restore(server.Application(config('experiments',output)),'experiments')
    phases['applications_ready']=time.perf_counter()-started
    user=Path.home()/'.lattice-live'
    arm=user/'arm.xml';board=user/'board.xml'
    if not arm.is_file(): arm=user/'arm.json'
    providers,unavailable=optional_providers(platform_config,SshProvider,arm if arm.is_file() else None,board if board.is_file() else None,
        packaged_board=platform_config.default_board(PACKAGE), records_directory=output/'ch32')
    live=platform_server.UnifiedApplication(current,providers,f407=platform_server.F407Provider(package=PACKAGE,records_directory=output/'stm32f407'))
    from demo.ch32_strategy import StrategyController
    live.ch32_strategy=StrategyController(PACKAGE,output/'ch32')
    live.ch32_external_config=board.is_file()
    archive.lock=live.lock
    for label,app in [('current',current),('experiments',archive)]:
        app._deployment_builds=server.DeploymentBuilds(output/'deployment-runs'/label,app.host)
    sessions=Configuration(config('session',output));sessions.runs={}
    numerical=read(HERE/'prepared/numerical-verification.xml')
    sessions_module=module(adapter/'launch.py','_prepared_session_adapter')
    address='127.0.0.1:'+str(a.port)
    handler=compose(platform_server.handler(server,live,address),sessions_module.overlay(server,archive,address,sessions,source,numerical),unavailable)
    from unified_workbench.web import wrap
    handler=wrap(handler, current, live, sessions, source, PACKAGE, output, address)
    for scope,app in [('live',live),('archive',archive)]:
        original=app.run
        def recorded(request,_run=original,_scope=scope):
            result=dict(status='FAILED',scope=_scope,request=request,started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
            try:
                value=_run(request);result.update(status='RETURNED',result=value);return value
            except Exception as error:
                result.update(error_type=type(error).__name__,error=str(error));raise
            finally:
                result['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
                save(output/('flow-'+secrets.token_hex(16)+'.xml'),result)
        app.run=recorded
    httpd=ThreadingHTTPServer(('127.0.0.1',a.port),handler);httpd.daemon_threads=False
    finished=threading.Event()
    if a.stop_file:
        def close_watch():
            while not finished.wait(.1):
                if a.stop_file.is_file():httpd.shutdown();return
        threading.Thread(target=close_watch,daemon=True).start()
    receipt=dict(status='READY_NO_AUTOMATIC_CONNECTION',startup_seconds=time.perf_counter()-started,phases=phases,
        presentation='Prepared from hash-bound original results at package preparation; no raw statistics recomputed at ordinary startup',
        live_crypto='Original algorithm libraries; image identities and CPU capabilities checked',
        snapshot_manifest_sha256=EXPECTED_MANIFEST,output=str(output),unavailable_optional_connections=unavailable)
    save(output/'startup.xml',receipt)
    url='http://'+address+('/history/' if a.history else '/')
    print('DEMO_URL='+url,flush=True)
    print('密码功能已就绪；实验页面展示已核验结果。',flush=True)
    # The desktop window opens this URL.
    try:httpd.serve_forever(poll_interval=.1)
    except KeyboardInterrupt:pass
    finally:
        finished.set();httpd.server_close();save(output/'stop.xml',dict(status='NORMAL_STOP'))

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('ERROR: '+str(error),file=sys.stderr,flush=True)
        raise SystemExit(1)
