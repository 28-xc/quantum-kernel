"""Route local requests to the test and archive handlers."""
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
ASSETS = {'/unified-shell.css': ('shell.css', 'text/css'),
          '/history-routing.js': ('archive-routing.js', 'text/javascript')}


PACKAGE = HERE.parents[3]
EVIDENCE = {
    'stm32-board.jpg': '05_设备与运行记录/STM32F407/开发板正面.jpg',
    'stm32-kem.png': '05_设备与运行记录/STM32F407/统一演示/ML-KEM-512.png',
    'stm32-dsa.png': '05_设备与运行记录/STM32F407/统一演示/ML-DSA-44.png',
    'stm32-recovery.png': '05_设备与运行记录/STM32F407/统一演示/容量不足与恢复.png',
    'stm32.xlsx': '05_设备与运行记录/STM32F407/统一演示/ML-DSA-44运行结果.xlsx',
    'ch32-board.jpg': '05_设备与运行记录/CH32V307/开发板实物照片.jpg',
    'ch32-kem.png': '05_设备与运行记录/CH32V307/实板运行截图/统一演示-ML-KEM-512.png',
    'ch32-dsa.png': '05_设备与运行记录/CH32V307/实板运行截图/统一演示-ML-DSA-44.png',
    'ch32-cycles.png': '05_设备与运行记录/CH32V307/实板运行截图/统一演示-周期与栈.png',
    'windows-kem.png': '05_设备与运行记录/软件运行与测试截图/统一演示/ML-KEM-768.png',
    'windows-dsa.png': '05_设备与运行记录/软件运行与测试截图/统一演示/ML-DSA-87.png',
    'arm-dsa.png': '05_设备与运行记录/软件运行与测试截图/AArch64签名功能运行.png',
    'qemu-m4.png': '05_设备与运行记录/Cortex-M4_QEMU/功能验证截图/QEMU终端运行截图.png',
    'qemu-rv.png': '05_设备与运行记录/RV32IM_QEMU/功能验证截图/QEMU终端运行截图.png',
    'index.xlsx': '04_实验结果与验证材料/performance/实验结果索引.xlsx',
}


ASSETS["/evidence-results.js"]=("evidence-results.js","text/javascript")
EVIDENCE.update({'full-replay.mp4': '演示视频.mp4', 'video-chapters.tsv': '03_复现环境与运行程序/软件演示程序/入口/history/当次双板演示/剪辑来源.tsv', 'stm32f407-low-result.png': '05_设备与运行记录/STM32F407/现场演示/24KiB/运行结果.png', 'stm32f407-low-source.xml': '05_设备与运行记录/STM32F407/现场演示/24KiB/窗口与固件.xml', 'stm32f407-low-operations.tsv': '05_设备与运行记录/STM32F407/现场演示/24KiB/逐项运行.tsv', 'stm32f407-high-result.png': '05_设备与运行记录/STM32F407/现场演示/32KiB/运行结果.png', 'stm32f407-high-source.xml': '05_设备与运行记录/STM32F407/现场演示/32KiB/窗口与固件.xml', 'stm32f407-high-operations.tsv': '05_设备与运行记录/STM32F407/现场演示/32KiB/逐项运行.tsv', 'ch32-low-result.png': '05_设备与运行记录/CH32V307/现场演示/28KiB/运行结果.png', 'ch32-low-source.xml': '05_设备与运行记录/CH32V307/现场演示/28KiB/窗口与固件.xml', 'ch32-low-operations.tsv': '05_设备与运行记录/CH32V307/现场演示/28KiB/逐项运行.tsv', 'ch32-high-result.png': '05_设备与运行记录/CH32V307/现场演示/80KiB/运行结果.png', 'ch32-high-source.xml': '05_设备与运行记录/CH32V307/现场演示/80KiB/窗口与固件.xml', 'ch32-high-operations.tsv': '05_设备与运行记录/CH32V307/现场演示/80KiB/逐项运行.tsv'})

def decorate(page, archive, unavailable=()):
    if page.count('</header>') != 1 or page.count('</head>') != 1:
        raise ValueError('Unregistered page layout')
    evidence = '<title>实板与仿真证据</title>' in page
    nav = '<nav class="unified-navigation" aria-label="演示范围">'
    for target, title, selected in (('/', '本机与设备运行', not archive and not evidence),
                                    ('/history/', '实验与应用', archive),
                                    ('/evidence/', '实板与仿真证据', evidence)):
        nav += '<a href="'+target+'"'+(' aria-current="page"' if selected else '')+'>'+title+'</a>'
    nav += '</nav>'
    if archive:
        nav += '<p class="unified-configuration-note">历史测量数据 · 设备接入在本机运行</p>'
    elif unavailable:
        labels = {'arm': 'ARM', 'ch32': 'CH32V307'}
        # Show a short status without exposing connection details.
        if any(x not in labels for x in unavailable): raise ValueError('Unknown optional platform')
        nav += '<p class="unified-configuration-note">'+ '、'.join(labels[x] for x in unavailable) +'连接配置无效。</p>'
    page = page.replace('ARM原始摘要保持不变，本机重算结果已核对。', '')
    scripts = '<link rel="stylesheet" href="/unified-shell.css">'
    if archive: scripts += '<script src="/history-routing.js"></script>'
    page = page.replace('</head>', scripts+'</head>')
    page = page.replace('</header>', '</header>'+nav)
    if archive: page = page.replace('src="/session.js"', 'src="/history/session.js"')
    return page


def compose(live_handler, archive_handler, unavailable=()):
    """Keep each handler bound to its app and token."""
    class UnifiedRoutes(live_handler, archive_handler):
        def setup(self):
            super().setup()
            # Let shutdown finish even if a local HTTP request stalls.
            self.connection.settimeout(15)

        def send(self, status, data, mime='application/json'):
            if status == 200 and mime == 'text/html':
                page = data.decode('utf-8') if isinstance(data, bytes) else data
                data = decorate(page, getattr(self, '_archive_request', False), unavailable)
            return super().send(status, data, mime)

        def dispatch(self, method):
            url = urlsplit(self.path)
            if method == 'GET' and url.path in ASSETS:
                if not self.valid_host(): return self.send(403, {'error': '仅接受本地访问'})
                if url.query: return self.send(400, {'error': '静态资源不接受参数'})
                name, mime = ASSETS[url.path]
                return self.send(200, (HERE/name).read_bytes(), mime)
            if method == 'GET' and url.path.startswith('/evidence/media/'):
                if not self.valid_host(): return self.send(403, {'error': '仅接受本地访问'})
                name = url.path.removeprefix('/evidence/media/')
                if url.query or name not in EVIDENCE:
                    return self.send(404, {'error': '无此记录'})
                path = PACKAGE / EVIDENCE[name]
                media = {'.png': 'image/png', '.jpg': 'image/jpeg', '.mp4': 'video/mp4', '.tsv': 'text/tab-separated-values; charset=utf-8', '.xml':'application/xml',
                         '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
                try:
                    if path.suffix=='.mp4':
                        return self.send_movie(path)
                    return self.send(200, path.read_bytes(), media[path.suffix])
                except OSError:
                    return self.send(404, {'error': '记录文件缺失'})
            if method == 'GET' and url.path == '/evidence/':
                if not self.valid_host(): return self.send(403, {'error': '仅接受本地访问'})
                if url.query: return self.send(400, {'error': '证据说明不接受参数'})
                self._archive_request = False
                page = (HERE/'evidence.html').read_text(encoding='utf-8')
                return self.send(200, page, 'text/html')
            old_path = self.path
            archive = url.path == '/history' or url.path.startswith('/history/')
            self._archive_request = archive
            if archive:
                self.path = (url.path[len('/history'):] or '/') + ('?'+url.query if url.query else '')
            try:
                parent = archive_handler if archive else live_handler
                return getattr(parent, 'do_'+method)(self)
            finally:
                self.path = old_path
                self._archive_request = False

        def send_movie(self,path):
            # WebView uses single HTTP byte ranges to seek to chapter offsets.
            import re
            size=path.stat().st_size
            first,last,status=0,size-1,200
            header=self.headers.get('Range')
            if header:
                bounds=re.fullmatch(r'bytes=(\d*)-(\d*)',header)
                if bounds and any(bounds.groups()):
                    left,right=bounds.groups()
                    if left:
                        first=int(left);last=min(int(right),size-1) if right else size-1
                    else:
                        first=max(0,size-int(right))
                    status=206 if first<=last and first<size else 416
                else:status=416
            if status==416:
                self.send_response(status);self.send_header('Content-Range','bytes */'+str(size))
                self.send_header('Content-Length','0');self.end_headers();return
            self.send_response(status);self.send_header('Content-Type','video/mp4')
            self.send_header('X-Content-Type-Options','nosniff');self.send_header('Accept-Ranges','bytes')
            self.send_header('Content-Length',str(last-first+1))
            if status==206:self.send_header('Content-Range',f'bytes {first}-{last}/{size}')
            self.end_headers()
            with path.open('rb')as src:
                src.seek(first);remaining=last-first+1
                try:
                    while remaining:
                        part=src.read(min(65536,remaining))
                        if not part:break
                        self.wfile.write(part);remaining-=len(part)
                except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):
                    pass

        def do_GET(self): return self.dispatch('GET')
        def do_POST(self): return self.dispatch('POST')
    return UnifiedRoutes
