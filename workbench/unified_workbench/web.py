"""Serve the local interface and run tests."""
from collections import deque
import hmac
import re
import threading
import json
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from demo import platform_protocol as wire
from .runtime import Workbench

HERE = Path(__file__).resolve().parent
XLSX = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
FILE_TYPES = {'.xlsx':XLSX, '.json':'application/json', '.xml':'application/xml',
              '.md':'text/markdown', '.tsv':'text/tab-separated-values'}
ASSETS = {'/':('index.html','text/html'), '/wb/style.css':('style.css','text/css'),
          '/wb/app.js':('app.js','text/javascript'), '/wb/views.js':('views.js','text/javascript'),
          '/wb/quantum-kernel.png':('quantum-kernel.png','image/png')}


def wrap(parent,current,live,sessions,source,root,output,address,*,local_platform='windows'):
    work=Workbench(current,live,sessions,source,root,output,local_platform=local_platform)
    token=current.token
    progress = {}
    traffic = {}
    progress_lock = threading.Lock()
    class Routes(parent):
        def reply(self,status,value,mime='application/json',name=None):
            if not isinstance(value,bytes):
                text=value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,allow_nan=False)
                value=text.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type',mime + ('; charset=utf-8' if mime.startswith('text/') or mime=='application/json' else ''))
            self.send_header('Content-Length',str(len(value)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            if name: self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+quote(name))
            self.end_headers()
            try: self.wfile.write(value)
            except (ConnectionError,OSError): pass

        def do_GET(self):
            if not self.valid_host(): return self.reply(403,{'error':'仅接受本地访问'})
            url=urlsplit(self.path); path=url.path
            try:
                if path in ASSETS and not url.query:
                    file,mime=ASSETS[path]
                    body=(HERE/file).read_bytes()
                    if path=='/': body=body.replace(b'__CSRF__',token.encode('ascii'))
                    return self.reply(200,body,mime)
                if path.startswith('/wb/performance/') and path.endswith('/samples') and not url.query:
                    return self.reply(200,work.performance_samples(path.split('/')[3]))
                if path.startswith('/wb/performance/') and path.endswith('.xlsx'):
                    options=parse_qs(url.query)
                    data,name=work.performance_archive(path[16:-5],options.get('view',['operations'])[0])
                    return self.reply(200,data,XLSX,name)
                if path=='/wb/catalog' and not url.query: return self.reply(200,work.catalog())
                if path.startswith('/wb/download/') and path.endswith('.bin') and not url.query:
                    raw, name = work.material_download(path[13:-4])
                    return self.reply(200,raw,'application/octet-stream',name)
                if path.startswith('/wb/records/'):
                    ident=path.removeprefix('/wb/records/')
                    if '/' in ident and not url.query:
                        request, artifact = ident.split('/', 1)
                        if artifact == 'traffic.txt':
                            log, name = work.traffic_file(request)
                            return self.reply(200,log,'text/plain',name)
                        if artifact == 'board.json':
                            raw, name = work.board_file(request)
                            return self.reply(200,raw,name=name)
                        if artifact.endswith('.bin'):
                            raw, name = work.public_file(request,artifact[:-4])
                            return self.reply(200,raw,'application/octet-stream',name)
                        raise ValueError('文件未找到。')
                    if ident.endswith('.xlsx'):
                        rec=work.get_record(ident[:-5])
                        folder=rec.get('export_folder','correctness')
                        if url.query and parse_qs(url.query,strict_parsing=True)!={'folder':[folder]}:
                            raise ValueError('结果目录不匹配。')
                        return self.reply(200,work.export(ident[:-5]),XLSX,work.export_name(rec))
                    if url.query: raise ValueError('记录不存在。')
                    return self.reply(200,work.get_record(ident))
                if path.startswith('/wb/progress/') and not url.query:
                    if not hmac.compare_digest(self.headers.get('X-Workbench-Token',''), token):
                        return self.reply(403,{'error':'请求被拒绝'})
                    with progress_lock:
                        entries = list(progress.get(path.rsplit('/',1)[-1], ()))
                    return self.reply(200,entries)
                if path.startswith('/wb/traffic/'):
                    if not hmac.compare_digest(self.headers.get('X-Workbench-Token',''), token):
                        return self.reply(403,{'error':'请求被拒绝'})
                    ident = path.rsplit('/',1)[-1]
                    if not re.fullmatch(r'[0-9a-f]{20}|[0-9a-f]{32}',ident):
                        raise ValueError('运行日志编号无效。')
                    start = int(parse_qs(url.query).get('from',['0'])[0])
                    if not 0 <= start <= 1024:
                        raise ValueError('通信日志位置无效。')
                    with progress_lock:
                        recorder = traffic.get(ident)
                    log = recorder.snapshot(start) if recorder is not None else work.job_traffic(ident,start)
                    return self.reply(200,log)
                if path.startswith('/wb/job/') and not url.query: return self.reply(200,work.job(path.rsplit('/',1)[-1]))
                if path=='/wb/file':
                    query=parse_qs(url.query,strict_parsing=True)
                    if set(query)!={'p'} or len(query['p'])!=1: raise ValueError('材料标识无效')
                    file=work.files.get(query['p'][0])
                    if file is None: raise ValueError('文件未找到。')
                    mime=FILE_TYPES.get(file.suffix.lower(),'text/plain')
                    return self.reply(200,file.read_bytes(),mime,file.name)
                if path in ('/history/','/evidence/','/history','/evidence'):
                    self.send_response(302); self.send_header('Location','/#resources')
                    self.end_headers(); return
                return self.reply(404,{'error':'无此入口'})
            except (ValueError,OSError,KeyError) as exc:
                return self.reply(400,{'error':str(exc)})

        def do_POST(self):
            if not self.valid_host() or self.headers.get('Origin')!='http://'+address or not hmac.compare_digest(
                    self.headers.get('X-Workbench-Token',''),token):
                return self.reply(403,{'error':'请求被拒绝'})
            progress_id = self.headers.get('X-Workbench-Progress')
            entries = None
            trace_token = None
            def report(message):
                with progress_lock:
                    entries.append(message)
            try:
                if self.headers.get_content_type()!='application/json': raise ValueError('请求格式无效')
                length=int(self.headers.get('Content-Length','0'))
                if not 1<=length<=256*1024: raise ValueError('请求长度无效')
                q=json.loads(self.rfile.read(length))
                if type(q) is not dict: raise ValueError('参数对象无效')
                url=urlsplit(self.path)
                if url.query or not url.path.startswith('/wb/'): raise ValueError('请求路径无效')
                action=url.path[4:]
                general_actions = ('crypto','onboarding','arithmetic','security','board-suite')
                logged_actions = (*general_actions,'board-vectors','performance')
                if progress_id and action in logged_actions:
                    if not re.fullmatch(r'[0-9a-f]{32}', progress_id):
                        raise ValueError('运行日志编号无效。')
                    with progress_lock:
                        if progress_id in progress or len(progress) >= 16:
                            raise ValueError('已有操作正在运行。')
                        entries = progress[progress_id] = deque(maxlen=64)
                        if q.get('platform') in ('stm32f407','ch32v307','arm'):
                            recorder = traffic[progress_id] = wire.Traffic(public=action in ('arithmetic','board-vectors'))
                            trace_token = wire.RUN_TRAFFIC.set(recorder)
                log_options = {'report':report} if entries is not None else {}
                if action in general_actions: value=work.act(action,q,**log_options)
                elif action=='performance': value=work.run_performance(q,**log_options)
                elif action in ('import-material','clear-materials','show-material','save-material'):
                    value=work.material(action,q)
                elif action=='connect': value=work.connect(q)
                elif action=='deploy-stm32': value=work.deploy_stm32(q)
                elif action=='deploy-ch32': value=work.deploy_ch32(q)
                elif action=='batch': value=work.start_job(q)
                elif action=='cases': value=work.case_list(q)
                elif action=='vector-inputs': value=work.vector_inputs(q)
                elif action=='board-vectors': value=work.run_board_vectors(q,**log_options)
                elif action=='board-archive': value=work.board_archive(q)
                elif action=='board-vector-detail': value=work.board_case_detail(q)
                elif action=='cancel': value=work.job(q.get('request_id'),stop=True)
                elif action=='check':
                    family,p,t,profile=work.validate(q,live=False)
                    value=dict(available=work.available(t,profile),platform=t,profile=profile,parameter=p,
                               fields=work.parameters[str(p)],source_kind=q.get('source_kind'))
                else: return self.reply(404,{'error':'无此操作'})
                if entries is not None:
                    value = dict(value, run_log=list(entries))
                return self.reply(200,value)
            except (ValueError,KeyError,TypeError,OSError) as exc:
                value = {'error':str(exc)}
                if entries is not None: value['run_log'] = list(entries)
                return self.reply(400,value)
            except Exception:
                value = {'error':'操作未完成。'}
                if entries is not None: value['run_log'] = list(entries)
                return self.reply(500,value)
            finally:
                if trace_token is not None:
                    wire.RUN_TRAFFIC.reset(trace_token)
                    with progress_lock:
                        traffic.pop(progress_id,None)
                if entries is not None:
                    with progress_lock:
                        progress.pop(progress_id, None)
    return Routes
