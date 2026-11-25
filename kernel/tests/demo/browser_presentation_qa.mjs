/* Actual Edge/HTTP/ABI state checks; optional screenshots use the rendered page. */
import {spawn,execFileSync} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const config=path.resolve(process.argv[2]||''),out=path.resolve(process.argv[3]||'');
let pythonArgument=null,captureScreenshots=false,deploymentScreenshots=false,allowEmptyResults=false,unified=false;
for(let i=4;i<process.argv.length;i++){
 if(process.argv[i]==='--python'&&!pythonArgument&&process.argv[i+1])pythonArgument=path.resolve(process.argv[++i]);
 else if(process.argv[i]==='--screenshots'&&!captureScreenshots)captureScreenshots=true;
 else if(process.argv[i]==='--deployment-screenshots'&&!deploymentScreenshots)deploymentScreenshots=true;
 else if(process.argv[i]==='--allow-empty-results'&&!allowEmptyResults)allowEmptyResults=true;
 else if(process.argv[i]==='--unified'&&!unified)unified=true;
 else throw Error('Unknown or duplicate browser QA option');
}
if(process.argv.length<4||!out.toUpperCase().startsWith('D:\\'))throw Error('Usage: node browser_qa.mjs explicit-config new-D-output [--python explicit-interpreter] [--screenshots]');
await fs.mkdir(out,{recursive:false});
const profile=path.join(out,'edge_profile');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function freePort(){const server=net.createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));const p=server.address().port;await new Promise(r=>server.close(r));return p;}
const serverPort=await freePort(),cdpPort=await freePort();
const rejectedQueries=[];
const env={...process.env,TEMP:out,TMP:out,PYTHONDONTWRITEBYTECODE:'1',PYTHONUTF8:'1'};
const python=pythonArgument||execFileSync('py',['-3.13','-c','import sys;print(sys.executable)'],{windowsHide:true,encoding:'utf8',env}).trim();
// Keep browser protocol JSON in memory. Persist evidence with the package's XML codec.
function saveQaOutput(interpreter,sourceRoot,folder,name,value,log=false){
 const program=[
  'import sys,json',
  'from decimal import Decimal',
  'from pathlib import Path',
  'sys.path.insert(0,sys.argv[1])',
  'import record_io',
  'target=Path(sys.argv[2])',
  "text=sys.stdin.buffer.read().decode('utf-8')",
  "if sys.argv[3]=='record':",
  " record_io.write(target,json.loads(text,parse_float=Decimal))",
  'else:',
  ' saved=record_io.capture_text(text)',
  " if saved!=text and saved.lstrip().startswith('<record'):target=target.with_suffix(target.suffix+'.xml')",
  " target.write_bytes(saved.encode('utf-8'))",
 ].join('\n');
 execFileSync(interpreter,['-B','-c',program,sourceRoot,path.join(folder,name),log?'log':'record'],
              {input:log?value:JSON.stringify(value),windowsHide:true,stdio:['pipe','pipe','pipe']});
}
const platformCode="import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from demo import server,platform_server;from http.server import ThreadingHTTPServer;app=platform_server.UnifiedApplication(server.Application(Path(sys.argv[2])));port=int(sys.argv[3]);httpd=ThreadingHTTPServer(('127.0.0.1',port),platform_server.handler(server,app,'127.0.0.1:'+str(port)));httpd.serve_forever()";
const command=unified?['-B','-c',platformCode,root,config,String(serverPort)]:['-B',path.join(root,'demo/server.py'),'--config',config,'--port',String(serverPort)];
const py=spawn(python,command,{windowsHide:true,stdio:['ignore','pipe','pipe'],env});
let serverLog='',edgeLog='',edge,ws,failed;
py.stdout.on('data',b=>serverLog+=b);py.stderr.on('data',b=>serverLog+=b);
const checks=[],events=[],requests=[],screenshots=[],exports=[];
let cdp;
try{
 let ready=false;for(let i=0;i<4800;i++){try{const r=await fetch(`http://127.0.0.1:${serverPort}/api/catalog`);if(r.ok){ready=true;break;}}catch{}if(py.exitCode!==null)throw Error('Local server exited: '+serverLog);await delay(100);}if(!ready)throw Error('Local server did not start');
 const binary='C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
 edge=spawn(binary,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-sync',`--user-data-dir=${profile}`,`--disk-cache-dir=${profile}/cache`,`--remote-debugging-port=${cdpPort}`,'about:blank'],{windowsHide:true,stdio:['ignore','ignore','pipe'],env});edge.stderr.on('data',b=>edgeLog+=b);
 let targets;for(let i=0;i<100;i++){try{targets=await(await fetch(`http://127.0.0.1:${cdpPort}/json/list`)).json();if(targets.some(t=>t.type==='page'))break;}catch{}await delay(100);}if(!targets)throw Error('Browser debug endpoint absent');
 ws=new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j;});let seq=0;const pending=new Map();
 ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);if(p){pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result);}}else if(m.method==='Runtime.exceptionThrown'||m.method==='Log.entryAdded')events.push(m);else if(m.method==='Network.requestWillBeSent')requests.push(m.params.request.url);};
 cdp=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;const timer=setTimeout(()=>{pending.delete(id);reject(Error('CDP timeout '+method));},20000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));});
 async function evaluate(expression){const r=await cdp('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));return r.result.value;}
 function must(ok,message){if(!ok)throw Error(message);}
 async function capture(width,height,name,selector){
  if(!captureScreenshots&&!(deploymentScreenshots&&['deployment_strategies','workspace_choices','upgrade_measurements','upgrade_resources'].includes(name)))return;
  if(selector)await evaluate(`document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block:'start'});window.scrollBy(0,-24)`);
  const image=await cdp('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
  const file=`${width}x${height}_${name}.png`,bytes=Buffer.from(image.data,'base64');
  await fs.writeFile(path.join(out,file),bytes);screenshots.push({path:file,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length,width,height,page:name});
 }
 await cdp('Page.enable');await cdp('Runtime.enable');await cdp('Log.enable');await cdp('Network.enable');
 for(const [width,height] of [[1280,720],[1920,1080]]){
  await cdp('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});await cdp('Page.navigate',{url:`http://127.0.0.1:${serverPort}/`});
  let loaded=false;for(let i=0;i<100;i++){if(await evaluate(unified?'Boolean(window.__platformReady)':'Boolean(window.__ready)')){loaded=true;break;}await delay(100);}must(loaded,'Application did not initialize');
  if(unified){must(await evaluate("$('live-platform').value==='windows'&&$('run-library').options.length===2"),'Unified Windows page must expose only its two strategies');checks.push({width,height,unified_platform_windows:true,visible_strategies:2});}
  for(const name of ['overview','run','resources','measurements','data']){
   await evaluate(`page('${name}')`);
   const result=await evaluate(`({page:'${name}',width:innerWidth,height:innerHeight,documentWidth:document.documentElement.scrollWidth,visible:!document.querySelector('#page-${name}').hidden,title:document.querySelector('#page-${name} h1').textContent})`);
   must(result.visible&&result.documentWidth<=width,'Layout visibility or horizontal overflow');checks.push(result);
   await capture(width,height,name);
  }
  const deployment=await evaluate(`(async()=>{
   const catalog=await(await fetch('/api/deployment-builds')).json();
   for(let i=0;i<100&&!document.querySelector('#deploy-strategy').options.length;i++)await new Promise(r=>setTimeout(r,20));
   const current=catalog.platforms.find(p=>p.id===document.querySelector('#deploy-platform').value);
   const selector=document.querySelector('#deploy-strategy'),previous=selector.value,workspaces={};
   for(const option of selector.options){if(option.disabled)continue;selector.value=option.value;selector.dispatchEvent(new Event('change'));workspaces[option.value]=Number(document.querySelector('#deploy-workspace').value)*1024;}
   selector.value=previous;selector.dispatchEvent(new Event('change'));
   return {current,choices:[...document.querySelector('#deploy-strategy').options].map(x=>x.value),
    workspaces,
    operation_count:document.querySelectorAll('#deploy-operations input:checked').length,
    removed_recipe_selector:document.querySelector('#deploy-recipe')===null};
  })()`);
  must(deployment.current&&deployment.operation_count===18&&deployment.removed_recipe_selector,'Deployment must initially retain all 18 operations');
  must(deployment.current.strategies.filter(s=>s.available).every(s=>deployment.workspaces[s.id]===s.workspace_bytes),'Strategy change must apply its workspace capacity');
  if(deployment.current&&!deployment.current.emulated)must(JSON.stringify(deployment.choices)==='["low-memory","performance"]','Host deployment exposes extra strategies');
  if(deployment.current?.emulated)must(deployment.choices.length===1&&deployment.choices[0]==='low-memory'&&deployment.current.title.includes('仿真'),'Emulated targets must identify their scope');
  checks.push({width,height,deployment});
  await evaluate("page('resources')");
  await capture(width,height,'deployment_strategies','#deployment-builder');
  const allScience=await evaluate("get('/api/results').then(x=>x.views)");
  must(allScience.length>0||allowEmptyResults,'Technical data absent');
  must(await evaluate("!document.querySelector('#measurement-scope').textContent.includes('开发')"),'Internal role exposed');
  await evaluate("document.querySelector('#measurement-scope').value='all';measurements()");
  if(allScience.length)must(await evaluate("document.querySelector('#measurement-result').textContent.includes('μs') && document.querySelector('#measurement-result').textContent.includes('95%')"),'Time units or intervals absent');
  else {
   must(await evaluate("document.querySelector('#measurement-result').textContent.includes('此配置暂无性能统计') && document.querySelector('#measurement-result table')===null"),'Empty result state contains unexpected measurements');
   must(await evaluate("document.querySelector('#science-exports a[href]')===null"),'Unregistered scientific export exposed');
  }
  const labels=await evaluate("[...document.querySelectorAll('#science-exports .dataset-item h3')].map(x=>x.textContent)");
  must(labels.every(x=>!x.includes('r2-')&&!x.includes('confirm')&&!x.includes('develop')),'Opaque workflow labels exposed');
  checks.push({width,height,technical_views:allScience.length,result_labels:labels});
  if(allScience.some(v=>v.kind==='upgrade_paired')){
   await evaluate("page('measurements');$('measurement-scope').value='current';$('measurement-library').value='performance';measurements()");
   must(await evaluate("$('measurement-result').textContent.includes('42,944')&&$('measurement-result').textContent.includes('57,024')&&$('measurement-result').textContent.includes('逐项 95%')"),'Paired workspace or interval scope missing');
   await capture(width,height,'upgrade_measurements','#page-measurements h1');
   await evaluate("page('resources');$('resource-library').value='performance';resources()");
   must(await evaluate("$('resource-result').textContent.includes('R = W + S + C + G + H')"),'Algorithm memory components missing');
   await capture(width,height,'upgrade_resources','#resource-result');
  }
  const exportResults=await evaluate(`(async()=>{
   const urls=[...new Set([...document.querySelectorAll('#science-exports a[href]')].map(a=>a.getAttribute('href')))];
   const result=[];
   for(const url of urls){
    const r=await fetch(url);if(!r.ok)throw Error('Export HTTP '+r.status);
    const bytes=new Uint8Array(await r.arrayBuffer());
    result.push({url,bytes:bytes.length,sha256:[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(v=>v.toString(16).padStart(2,'0')).join(''),type:r.headers.get('content-type')});
    if(url.startsWith('/export/observations-manifest.xml')){
     const doc=new DOMParser().parseFromString(new TextDecoder('utf-8',{fatal:true}).decode(bytes),'application/xml');
     const root=doc.documentElement;
     if(root.tagName!=='record'||root.getAttribute('format')!=='typed-xml-v1'||root.children.length!==1)throw Error('Invalid observation XML');
     const fieldText=n=>{
      if(!n.hasAttribute('encoding'))return n.textContent;
      if(n.getAttribute('encoding')!=='base64-utf8-surrogatepass')throw Error('Invalid text encoding');
      return new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(n.textContent),c=>c.charCodeAt(0)));
     };
     function readNode(n){
      switch(n.tagName){
       case 'object':{
        const obj=Object.create(null);
        for(const field of n.children){
         const [name,value]=field.children;
         if(field.tagName!=='field'||field.children.length!==2||name.tagName!=='name')throw Error('Invalid observation field');
         const key=fieldText(name);if(Object.hasOwn(obj,key))throw Error('Duplicate observation field');
         obj[key]=readNode(value);
        }
        return obj;
       }
       case 'list':return Array.from(n.children,readNode);
       case 'string':return fieldText(n);
       case 'integer':return BigInt(n.textContent);
       case 'number':return Number(n.textContent);
       case 'boolean':if(n.textContent==='true')return true;if(n.textContent==='false')return false;break;
       case 'null':return null;
      }
      throw Error('Invalid typed observation');
     }
     const manifest=readNode(root.firstElementChild);
     const shards=observationFiles(manifest);
     for(const ordinal of [...new Set([0,shards.length-1])]){
      const rawName=shards[ordinal].path||shards[ordinal].file;const ext=rawName.endsWith('.records.xml')?'records.xml':rawName.endsWith('.xml')?'xml':rawName.endsWith('.csv')?'csv':'bin';
      const rawUrl='/export/raw.'+ext+'?dataset='+encodeURIComponent(new URL(url,location.href).searchParams.get('dataset'))+'&ordinal='+ordinal;
      const raw=await fetch(rawUrl);if(!raw.ok)throw Error('Raw export HTTP '+raw.status);
      const rawBytes=new Uint8Array(await raw.arrayBuffer());
      const digest=[...new Uint8Array(await crypto.subtle.digest('SHA-256',rawBytes))].map(v=>v.toString(16).padStart(2,'0')).join('');
      if(digest!==shards[ordinal].sha256 || (shards[ordinal].bytes!=null && BigInt(rawBytes.length)!==BigInt(shards[ordinal].bytes)))throw Error('Raw export identity mismatch');
      result.push({url:rawUrl,bytes:rawBytes.length,sha256:digest,type:raw.headers.get('content-type'),manifest_bound:true});
     }
    }
   }
   return result;
  })()`);
  must(exportResults.every(x=>x.bytes>0||(x.manifest_bound&&x.bytes===0)),'Empty scientific export');exports.push({width,height,records:exportResults});
  if(allScience.some(v=>v.kind==='verification'))must(await evaluate("document.querySelector('#verification-result').textContent.includes('标准向量')"),'Verification counts absent');
  const budgetReady=await evaluate("!document.querySelector('#budget-query').disabled");
  if(budgetReady){await evaluate("page('resources');document.querySelector('#budget-ram').value='64';document.querySelector('#budget-program').value='512';queryBudget()");must(await evaluate("window.__lastBudget && ['MATCHES_AVAILABLE','NO_MEASURED_CONFIGURATION_FITS'].includes(window.__lastBudget.outcome)"),'Budget result absent');await capture(width,height,'budget_result','#page-resources h1');}
  if(budgetReady){
   const weighted=await evaluate(`(async()=>{
    $('budget-workload').value='sign';setWorkloadPreset();await queryBudget();
    const d=window.__lastBudget;
    if(d.schema!=='lattice.workload_budget_query.v1'||d.total_calls!==303||workloadCounts().length!==6)throw Error('Signing preset or API workload identity');
    if(d.candidates.some(c=>Math.abs(c.workload_total_service_ns-c.workload_mean_ns*303)>1e-5))throw Error('Weighted service normalization');
    const custom=document.querySelector('[data-workload-parameter="87"][data-workload-operation="1"]');custom.value=500;custom.dispatchEvent(new Event('input',{bubbles:true}));await queryBudget();
    if($('budget-workload').value!=='custom'||window.__lastBudget.total_calls!==703)throw Error('Custom counts did not reach the API');
    $('budget-workload').value='equal';setWorkloadPreset();await queryBudget();
    if(window.__lastBudget.schema==='lattice.workload_budget_query.v1')throw Error('Equal-frequency choice did not reset');
    return d;
   })()`);
   saveQaOutput(python,root,out,`weighted-selection-${width}.xml`,weighted);
   checks.push({width,explicit_operation_counts:true,custom_counts:true,equal_frequency_restored:true});
  }
  if(allScience.some(v=>v.kind==='application_owner')){
   const application=await evaluate(`(async()=>{
    page('resources');$('application-ram').value='64';$('application-program').value='512';await queryApplicationBudget();
    const d=window.__lastApplicationBudget;
    if(d.schema!=='lattice.application_selection.v1'||d.request.kem!==1024||d.request.dsa!==87||d.request.flows!==200)throw Error('Application request identity');
    if(d.candidates.some(c=>c.application_ram_bytes>65536||c.application_program_bytes>524288||c.resource.charged_bytes!==c.application_ram_bytes))throw Error('Complete application resource scope');
    if(!document.querySelector('#application-selection button'))throw Error('Application export absent');
    return d;
   })()`);
   saveQaOutput(python,root,out,`application-selection-${width}.xml`,application);
   checks.push({width,complete_application_budget:true,application_mean_and_interval_preserved:true});
  }

  await evaluate("page('run');document.querySelector('#run-parameter').value='768';runParameter();run('normal')");
  must(await evaluate('window.__lastRun.functional_checks_passed && window.__lastRun.checks.implicit_rejection'),'KEM roundtrip and implicit rejection');
  await capture(width,height,'kem_result','#run-result');
  await evaluate("document.querySelector('#run-parameter').value='65';runParameter();document.querySelector('#run-message').value='32';document.querySelector('#run-context').value='255';run('normal')");
  must(await evaluate('window.__lastRun.functional_checks_passed && window.__lastRun.operations.at(-1).return_code===-6'),'DSA modified signature rejected');
  must(await evaluate("document.querySelector('#run-result').textContent.includes('修改签名被拒绝')"),'Normal technical rejection hidden');
  await capture(width,height,'dsa_result','#run-result');
  await evaluate("run('insufficient')");
  must(await evaluate('window.__lastRun.operations.some(x=>x.return_code===-5) && window.__lastRun.failure_output_zero && window.__lastRun.recovery.functional_checks_passed'),'Capacity return and ordinary recovery');
  await capture(width,height,'capacity_result','#run-result');
  const adjustable=await evaluate("catalog.libraries.find(x=>x.workspace_options)?.id");
  if(adjustable){
   const choices=await evaluate(`(async()=>{
    $('run-library').value=${JSON.stringify(adjustable)};parameters();
    const options=[...$('run-workspace').options].map(x=>Number(x.value));
    if($('run-workspace-label').hidden||JSON.stringify(options)!=='[42944,57024]')throw Error('Discrete workspace selector absent');
    $('run-parameter').value='87';runParameter();const results=[];
    for(const capacity of options){$('run-workspace').value=String(capacity);await run('normal');const d=window.__lastRun;if(d.requested_workspace_bytes!==capacity||d.workspace_bytes!==capacity||!d.functional_checks_passed||!d.canaries_ok)throw Error('Selected capacity did not reach the kernel');results.push(d);}
    if(results[0].binary_sha256!==results[1].binary_sha256||results[0].observed_arena_high_water_bytes>42944||results[1].observed_arena_high_water_bytes<=42944)throw Error('Different image or unexercised capacity choice');
    return results;
   })()`);
   checks.push({width,height,same_image_workspace_choices:choices.map(x=>({capacity:x.workspace_bytes,high_water:x.observed_arena_high_water_bytes,binary_sha256:x.binary_sha256,functional_checks_passed:x.functional_checks_passed}))});
   await capture(width,height,'workspace_choices','#page-run h1');
   const fixed=await evaluate("catalog.libraries.find(x=>!x.workspace_options&&x.execution_available)?.id");
   if(fixed){await evaluate(`$('run-library').value=${JSON.stringify(fixed)};parameters()`);must(await evaluate("$('run-workspace-label').hidden"),'Fixed strategy exposes capacity choices');}
  }
  const shared=await evaluate("catalog.libraries.find(x=>x.configuration==='portable-shared')?.id");
  if(shared){await evaluate("document.querySelector('#run-library').value="+JSON.stringify(shared)+";parameters();document.querySelector('#run-parameter').value='87';runParameter();run('normal')");must(await evaluate('window.__lastRun.functional_checks_passed && window.__lastRun.parameter===87'),'Shared-program-space operation');await capture(width,height,'shared_result','#run-result');}
  must(await evaluate("localStorage.length===0 && sessionStorage.length===0"),'Unexpected browser storage');
  checks.push({width,height,kem_roundtrip:true,dsa_reject:true,capacity_return_and_recovery:true,shared_image_exercised:Boolean(shared),scientific_views:allScience.length,budget_query_exercised:budgetReady,scientific_export_count:exportResults.length});

 }
 if(captureScreenshots){
  const width=1100,height=1100;
  await cdp('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
  await cdp('Page.navigate',{url:`http://127.0.0.1:${serverPort}/`});
  let loaded=false;for(let i=0;i<100;i++){if(await evaluate('Boolean(window.__ready)')){loaded=true;break;}await delay(100);}must(loaded,'Print-width application did not initialize');
  async function clip(name,expression){
   const bounds=await evaluate(expression);must(bounds.width>0&&bounds.height>0,'Empty screenshot bounds');
   const image=await cdp('Page.captureScreenshot',{format:'png',captureBeyondViewport:true,clip:{...bounds,scale:1}});
   const file='report_'+name+'.png',bytes=Buffer.from(image.data,'base64');await fs.writeFile(path.join(out,file),bytes);
   screenshots.push({path:file,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length,width:bounds.width,height:bounds.height,viewport_width:width,viewport_height:height,page:name,clip:bounds,method:'browser-rendered element bounds; no image post-processing'});
  }
  const runBounds=`(()=>{const a=document.querySelector('#run-result > article.panel').getBoundingClientRect();return {x:Math.floor(a.left+scrollX),y:Math.floor(a.top+scrollY),width:Math.ceil(a.width),height:Math.ceil(a.height)}})()`;
  await evaluate("page('run');document.querySelector('#run-parameter').value='768';runParameter();run('normal')");
  must(await evaluate('window.__lastRun.functional_checks_passed && window.__lastRun.checks.implicit_rejection'),'Print KEM observation');
  const kem=await evaluate('window.__lastRun');saveQaOutput(python,root,out,'report_kem_observation.xml',kem);await clip('kem',runBounds);
  await evaluate("document.querySelector('#run-parameter').value='65';runParameter();document.querySelector('#run-message').value='32';document.querySelector('#run-context').value='255';run('normal')");
  must(await evaluate('window.__lastRun.functional_checks_passed && window.__lastRun.operations.at(-1).return_code===-6'),'Print DSA observation');
  const dsa=await evaluate('window.__lastRun');saveQaOutput(python,root,out,'report_dsa_observation.xml',dsa);await clip('dsa',runBounds);
  await evaluate("page('resources');document.querySelector('#budget-ram').value='64';document.querySelector('#budget-program').value='512';queryBudget()");
  const budget=await evaluate('window.__lastBudget');saveQaOutput(python,root,out,'report_budget_observation.xml',budget);
  await clip('budget',`(()=>{const a=document.querySelector('#budget-result').getBoundingClientRect(),rows=document.querySelectorAll('#budget-result table tbody tr'),b=rows.length?rows[Math.min(2,rows.length-1)].getBoundingClientRect():a;return {x:Math.floor(a.left+scrollX-12),y:Math.floor(a.top+scrollY-12),width:Math.ceil(a.width+24),height:Math.ceil(b.bottom-a.top+24)}})()`);
  await evaluate("$('application-platform').value='windows_x86_64';$('application-parameters').value='1024,87';$('application-flows').value='200';$('application-ram').value='64';$('application-program').value='512';queryApplicationBudget()");
  const applicationBudget=await evaluate('window.__lastApplicationBudget');
  saveQaOutput(python,root,out,'report_application_budget_observation.xml',applicationBudget);
  await clip('application_budget',`(()=>{const a=document.querySelector('#application-selection').getBoundingClientRect(),p=[...document.querySelectorAll('#application-selection > p')].at(-1).getBoundingClientRect();return {x:Math.floor(a.left+scrollX-2),y:Math.floor(a.top+scrollY-2),width:Math.ceil(a.width+4),height:Math.ceil(p.bottom-a.top+4)}})()`);
  await evaluate("page('data')");
  await clip('exports',`(()=>{const a=document.querySelector('#science-exports').getBoundingClientRect(),b=document.querySelectorAll('#science-exports .dataset-item')[1].getBoundingClientRect();return {x:Math.floor(a.left+scrollX-12),y:Math.floor(a.top+scrollY-12),width:Math.ceil(a.width+24),height:Math.ceil(b.bottom-a.top+24)}})()`);
  checks.push({report_element_screenshots:5,viewport_width:width,viewport_height:height,kem_parameters:[768,0,0],dsa_parameters:[65,32,255],budget_kib:[64,512],application_parameters:[1024,87,200]});
 }
 const registered=await evaluate('catalog.libraries');
 const functionalMatrix=[];
 for(const lib of registered){
  if(!lib.execution_available)continue;
  for(const parameter of [512,768,1024,44,65,87]){
   const request={library:lib.id,parameter,message_bytes:parameter>100?0:32,context_bytes:parameter>100?0:1,mode:'normal'};
   const observed=await evaluate(`(async()=>{const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Token':document.querySelector('meta[name=demo-token]').content},body:JSON.stringify(${JSON.stringify(request)})});if(!r.ok)throw Error('Functional matrix HTTP '+r.status);return r.json();})()`);
   must(observed.functional_checks_passed && observed.binary_sha256===lib.binary_sha256 && observed.parameter===parameter,'Functional matrix image and parameter binding');
   must(observed.canaries_ok && (parameter>100?observed.checks.implicit_rejection:observed.operations.at(-1).return_code===-6),'Functional matrix modified-result check');
   functionalMatrix.push(observed);
  }
 }
 const expectedFlows=registered.filter(x=>x.execution_available).length*6;
 must(expectedFlows>0&&functionalMatrix.length===expectedFlows,'Complete six-parameter image sets required');
 saveQaOutput(python,root,out,'functional_matrix.xml',{schema:'latticecore.demo_functional_matrix.v1',status:'PASS',request_count:expectedFlows,configuration_sha256:crypto.createHash('sha256').update(await fs.readFile(config)).digest('hex'),observations:functionalMatrix});
 checks.push({http_functional_flows:expectedFlows,libraries:registered.filter(x=>x.execution_available).map(x=>({id:x.id,configuration:x.configuration,binary_sha256:x.binary_sha256})),parameters:[512,768,1024,44,65,87],dsa_message_bytes:32,dsa_context_bytes:1});
 const external=requests.filter(value=>{const u=new URL(value);return !['about:','data:'].includes(u.protocol)&&!['127.0.0.1','localhost','[::1]'].includes(u.hostname);});
 must(!external.length,'Unexpected external page request');
 const expectedNetworkRejection=e=>e.method==='Log.entryAdded'&&e.params?.entry?.source==='network'&&
  rejectedQueries.some(q=>e.params.entry.url===`http://127.0.0.1:${serverPort}${q}`)&&
  e.params.entry.text==='Failed to load resource: the server responded with a status of 400 (Bad Request)';
 const faults=events.filter(e=>(e.method==='Runtime.exceptionThrown'||e.params?.entry?.level==='error')&&!expectedNetworkRejection(e));
 must(!faults.length,'Browser exception or unexpected console error');
}catch(e){failed=String(e.stack||e);}finally{
 if(cdp)try{await cdp('Browser.close');}catch{}
 if(ws)ws.close();
 if(edge&&edge.exitCode===null){edge.kill();}
 if(py.exitCode===null)py.kill();
 for(let i=0;i<50&&py.exitCode===null;i++)await delay(50);
 const sources={};for(const file of ['demo/deployment_ui.py','demo/deployment_ui.js','demo/presentation.py','demo/server.py','demo/app.js','demo/scientific_ui.js','demo/app.css','demo/index.html','publicschemas/demo.py','publicschemas/observations.py','publicschemas/science.py','publicschemas/block_model.py','publicschemas/verification_model.py','publicschemas/verification_v2.py','publicschemas/resources.py','publicschemas/pooled_model.py','publicschemas/pooled_conditions.py','publicschemas/pooled_shards.py','publicschemas/workload_selection.py','publicschemas/application_selection.py','publicschemas/application_owner_v1.py'])sources[file]=crypto.createHash('sha256').update(await fs.readFile(path.join(root,file))).digest('hex');
 let stillListening=false;try{await fetch(`http://127.0.0.1:${serverPort}/api/catalog`,{signal:AbortSignal.timeout(1000)});stillListening=true;}catch{}
 if(stillListening&&!failed)failed='Owned server still listening after cleanup';
 saveQaOutput(python,root,out,'qa.xml',{status:failed?'FAIL':'PASS',registered_science_required:!allowEmptyResults,checks,events,requests,exports,error:failed||null,controller_sha256:crypto.createHash('sha256').update(await fs.readFile(fileURLToPath(import.meta.url))).digest('hex'),base_browser_qa_sha256:'649b8fa81074cc913c50fbcd9921b2f4f74d4702d987d72ca9b5e16843575922',configuration_sha256:crypto.createHash('sha256').update(await fs.readFile(config)).digest('hex'),sources,screenshots_created:screenshots.length,screenshots,scope:'Registered technical results, fixed normal KEM/DSA inputs, documented capacity/recovery preset, optional shared-program-space execution, five-page browsing and registered exports at two viewports. Functional interface validation; no performance measurement.',server_stopped:!stillListening});
 saveQaOutput(python,root,out,'server.log',serverLog,true);saveQaOutput(python,root,out,'edge.log',edgeLog,true);
}
if(failed)throw Error(failed);console.log('PASS: ten page/viewport states, real KEM/DSA, scientific exports and page-request scope');
