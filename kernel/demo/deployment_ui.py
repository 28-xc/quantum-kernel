"""Local bounded deployment builds through the same public command-line tool."""
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
import hashlib, record_io as json, os, platform, re, secrets, shutil, signal, subprocess, sys, threading, zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import deploy as deployment_cli
from kernel import HOST_RECIPES
from publicschemas.cpu_features import availability
from demo.resource_scopes import verifier_resources

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf-8'))

def recipe_availability(name,host):
    recipe=deployment_cli.RECIPES[name];backend=recipe['defaults']['backend']
    features=[];xcr0=0
    if backend=='x86_64':
        features=['avx','avx2','bmi2'];xcr0=6
        if recipe['algorithm'].get('kem_vnni_dot'):features.append('avxvnni')
    elif backend=='aarch64':features=['fp','asimd']
    return availability(dict(backend=backend,required_features=features,required_xcr0=xcr0),host)

class DeploymentBuilds:
    def __init__(self,folder,host=None):
        self.folder=Path(folder).resolve();self.host=dict(host or {})
        if self.folder==ROOT or self.folder.is_relative_to(ROOT):raise ValueError('Build output must be outside the source')
        self.jobs={};self.lock=threading.Lock();self.active=None

    def catalog(self):
        host='windows-x86_64' if sys.platform=='win32' and platform.machine().lower() in ('amd64','x86_64') else 'linux-aarch64' if sys.platform.startswith('linux') and platform.machine().lower() in ('aarch64','arm64') else None
        rows=[]
        for name,title,required in ((host,'本机程序',('gcc','ar','nm','objdump','size')),
            ('m4','Cortex-M4 仿真验证',('arm-none-eabi-gcc','arm-none-eabi-nm','arm-none-eabi-size','qemu-system-arm')),
            ('rv32','RV32 仿真验证',('riscv64-unknown-elf-gcc','riscv64-unknown-elf-nm','riscv64-unknown-elf-size','qemu-system-riscv32'))):
            if name is None:continue
            missing=[x for x in required if shutil.which(x) is None]
            emulated=name in ('m4','rv32');strategies=[]
            for strategy,label,workspace in (('low-memory','低内存',12288),('performance','性能',65536)):
                if emulated and strategy!='low-memory':continue
                recipe='compact-rate' if emulated else HOST_RECIPES[(name,strategy)]
                check=dict(available=True) if emulated else recipe_availability(recipe,self.host)
                strategies.append(dict(id=strategy,title=label,recipe=recipe,workspace_bytes=workspace,
                    available=bool(check['available']),cpu_availability=check))
            rows.append(dict(id=name,title=title,available=not missing and any(x['available'] for x in strategies),
                missing_tools=missing,emulated=emulated,strategies=strategies))
        return dict(schema='lattice.deployment_build_catalog.v2',platforms=rows,parameters=[512,768,1024,44,65,87],
            maximum_seconds=600,scope='默认保留六组参数的18项完整操作；按所选策略实际编译、核验资源并运行固定标准向量。Cortex-M4与RV32仅进行指令仿真验证。程序包附完整构建记录。')

    def validate(self,value):
        allowed={'schema','platform','parameters','operations','budgets','workspace_bytes','strategy'}
        if type(value) is not dict or set(value)-allowed:raise ValueError('Unsupported deployment request fields')
        if value.get('schema')!='lattice.deployment_strategy_request.v1':raise ValueError('Unsupported deployment strategy request schema')
        entry=next((p for p in self.catalog()['platforms'] if p['id']==value.get('platform')),None)
        if entry is None or not entry['available']:raise ValueError('所选平台当前不可用，请检查工具链与处理器支持')
        strategy=next((s for s in entry['strategies'] if s['id']==value.get('strategy')),None)
        if strategy is None or not strategy['available']:raise ValueError('所选平台或处理器不支持该策略')
        request=dict(value);request.pop('strategy');request['schema']='lattice.deployment_request.v1'
        request['recipes']=[strategy['recipe']]
        request.setdefault('workspace_bytes',strategy['workspace_bytes'])
        request=deployment_cli.validate(request)
        if any(v>4194304 for v in request['budgets'].values()):raise ValueError('请选择不超过4 MiB的预算')
        return request

    def start(self,value):
        request=self.validate(value)
        with self.lock:
            if self.active is not None:raise ValueError('已有程序正在生成，请等待完成')
            ident=secrets.token_hex(8);self.folder.mkdir(parents=True,exist_ok=True)
            folder=self.folder/ident;folder.mkdir()
            request_path=folder/'request.xml';request_path.write_text(json.dumps(request,indent=2)+'\n')
            self.jobs[ident]=dict(build_id=ident,status='BUILDING',strategy=value['strategy'],request=request);self.active=ident
        threading.Thread(target=self._run,args=(ident,folder),daemon=True).start()
        return self.status(ident)

    def _run(self,ident,folder):
        process=None
        try:
            from demo.build_environment import prepare
            executable,build_source=prepare(ROOT,folder)
            argv=[str(executable),'-B',str(build_source/'tools/deploy.py'),'--request',str(folder/'request.xml'),'--output',str(folder/'build')]
            options=dict(creationflags=subprocess.CREATE_NO_WINDOW) if os.name=='nt' else dict(start_new_session=True)
            with (folder/'compile.log').open('wb') as log:
                process=subprocess.Popen(argv,cwd=build_source,stdout=log,stderr=subprocess.STDOUT,**options)
                try:rc=process.wait(timeout=600)
                except subprocess.TimeoutExpired:
                    if os.name=='nt':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
                    else:os.killpg(process.pid,signal.SIGTERM)
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        if os.name!='nt':os.killpg(process.pid,signal.SIGKILL)
                        process.wait(timeout=10)
                    raise RuntimeError('程序生成超过本次运行时限')
            if rc:
                failed=folder/'build/failure.xml';d=read(failed) if failed.exists() else {}
                budget_failed=d.get('attempts') and all(x.get('accepted') is False for x in d['attempts'])
                raise RuntimeError('保留全部必需功能后，给定预算不足' if budget_failed else '编译或功能核验未完成，已保留本次记录')
            result=read(folder/'build/result.xml');selected=result['selected'];artifacts=[]
            for item in result['deployment_files']:
                path=(folder/'build'/item['path']).resolve()
                if not path.is_relative_to(folder/'build/deployment') or path.is_symlink() or sha(path)!=item['sha256']:raise ValueError('Artifact identity changed')
                artifacts.append(dict(name=path.name,bytes=path.stat().st_size,sha256=sha(path)))
            archive=folder/'program.zip'
            with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
                # Complete build records allow independent local inspection.
                for path in sorted((folder/'build').rglob('*')):
                    rel=path.relative_to(folder/'build')
                    if path.is_file() and not path.is_symlink() and 'tmp' not in rel.parts:z.write(path,rel.as_posix())
            self.jobs[ident].update(status='READY',configuration=selected['recipe'],resources=selected['resources'],
                resource_object=verifier_resources(selected['resources']),
                image_sha256=selected['image']['sha256'],artifacts=artifacts,archive_sha256=sha(archive),
                download='/export/deployment/'+ident+'.zip',result_download='/export/deployment/'+ident+'.xml')
        except Exception as error:self.jobs[ident].update(status='FAILED',error=str(error))
        finally:
            (folder/'status.xml').write_text(json.dumps(self.jobs[ident],ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            with self.lock:self.active=None

    def status(self,ident):
        if not isinstance(ident,str) or not re.fullmatch('[0-9a-f]{16}',ident) or ident not in self.jobs:raise ValueError('Unknown build')
        return json.loads(json.dumps(self.jobs[ident]))

    def export(self,ident,kind):
        result=self.status(ident)
        if result['status']!='READY' or kind not in ('zip','json'):raise ValueError('Build not ready')
        if kind=='xml':return json.dumps(result,ensure_ascii=False,indent=2).encode()
        path=self.folder/ident/'program.zip'
        if sha(path)!=result['archive_sha256']:raise ValueError('Build archive changed')
        return path.read_bytes()
