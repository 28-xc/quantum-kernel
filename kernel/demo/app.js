'use strict';
function recordXML(value){
 const text=value=>String(value).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])).replace(/\r/g,'&#13;');
 const node=value=>{
  if(value===null)return '<null />';
  if(typeof value==='boolean')return '<boolean>'+value+'</boolean>';
  if(typeof value==='number'){if(!Number.isFinite(value))throw Error('结果包含非有限数值');const t=Number.isInteger(value)?'integer':'number';return '<'+t+'>'+String(value)+'</'+t+'>';}
  if(typeof value==='string')return '<string>'+text(value)+'</string>';
  if(Array.isArray(value))return '<list>'+value.map(node).join('')+'</list>';
  if(typeof value==='object')return '<object>'+Object.entries(value).map(([k,v])=>'<field><name>'+text(k)+'</name>'+node(v)+'</field>').join('')+'</object>';
  throw Error('结果包含不支持的字段类型');
 };
 return '<record format="typed-xml-v1">'+node(value)+'</record>\n';
}

let catalog, displayCatalog, lastRun=null, applicationPlatforms=[];
const $=id=>document.getElementById(id);
const escapeHTML=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const empty=(title,detail)=>`<div class="empty"><span>${escapeHTML(title)}</span><p>${escapeHTML(detail)}</p></div>`;
function error(e){$('notice').hidden=false;$('notice').textContent=e.message||String(e);}
async function get(url){const r=await fetch(url);if(!r.ok)throw Error('技术数据读取失败');return r.json();}
function page(name){if(!['overview','run','resources','measurements','data'].includes(name))return;for(const s of document.querySelectorAll('main>section'))s.hidden=s.id!=='page-'+name;for(const b of document.querySelectorAll('nav button')){if(b.dataset.page===name){b.setAttribute('aria-current','page');$('crumb').textContent=b.textContent.slice(2);}else b.removeAttribute('aria-current');}window.scrollTo(0,0);}
function libraryOptions(execution=false){return catalog.libraries.map(l=>`<option value="${escapeHTML(l.id)}"${execution&&!l.execution_available?' disabled':''}>${escapeHTML(l.title)}${execution&&!l.execution_available?'（本机不支持）':''}</option>`).join('');}
function parameters(){const l=catalog.libraries.find(l=>l.id===$('run-library').value);if(!l||!l.execution_available){$('run-normal').disabled=true;$('run-insufficient').disabled=true;return;}$('run-normal').disabled=false;$('run-insufficient').disabled=false;$('run-parameter').innerHTML=l.parameters.map(p=>`<option>${p}</option>`).join('');const capacities=l.workspace_options||[l.workspace_bytes];$('run-workspace-label').hidden=capacities.length===1;$('run-workspace').innerHTML=capacities.map(n=>`<option value="${n}">${n.toLocaleString()} B</option>`).join('');$('run-workspace').value=l.workspace_bytes;runParameter();}
function runParameter(){const kem=Number($('run-parameter').value)>100;$('run-context').disabled=kem;$('run-message').disabled=kem;if(kem){$('run-message').value='0';$('run-context').value='0';}}
function table(headers,rows){return `<div class="table-wrap"><table><thead><tr>${headers.map(s=>`<th>${escapeHTML(s)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>'<tr>'+r.map(s=>`<td>${escapeHTML(s)}</td>`).join('')+'</tr>').join('')}</tbody></table></div>`;}
function resultBlock(r,title){
 const expected=r.canaries_ok&&r.failure_output_zero===true&&r.operations.some(e=>e.return_code===-5);
 const codes=r.operations.map(e=>[e.operation_title||displayCatalog.operations[e.operation]||e.operation,e.result_description||e.outcome,e.return_code]);
 const checks=Object.entries(r.checks).map(([k,v])=>`${displayCatalog.checks[k]||k}：${v?'通过':'失败'}`).join('；');
 const lib=catalog.libraries.find(l=>l.id===r.library);
 const inputs=r.algorithm?`<p class="muted">${escapeHTML(lib?lib.title:r.library)}${r.parameter<100?` · 消息 ${r.message_bytes} B；上下文 ${r.context_bytes} B`:''}</p>`:'';
 return `<article class="panel"><div class="result-head"><h2>${escapeHTML(title)}</h2><span class="${r.functional_checks_passed?'good':expected?'expected':'bad'}">${r.functional_checks_passed?'PASS':expected?'容量不足':'FAIL'}</span></div>${inputs}${table(['操作','运行结果','返回码'],codes)}<p class="muted">工作区 ${r.workspace_bytes.toLocaleString()} B；边界${r.canaries_ok?'保持完整':'发生改写'}${r.failure_output_zero===null?'':'；失败输出'+(r.failure_output_zero?'已清零':'清零检查失败')}。</p><details><summary>完整检查与工作区记录</summary><p>${escapeHTML(checks)}</p>${table(['操作编号','返回码','状态','工作区峰值 B'],r.operations.map(e=>[e.operation,e.return_code,e.outcome,e.arena_high_water_bytes]))}<p class="muted">工作区峰值表示本次调用使用量，算法预留内存见资源配置。</p></details></article>`;
}
async function run(mode='normal'){const buttons=[$('run-normal'),$('run-insufficient')];buttons.forEach(b=>b.disabled=true);$('notice').hidden=true;try{const p=Number($('run-parameter').value);const request={library:$('run-library').value,parameter:p,message_bytes:p>100?0:Number($('run-message').value),context_bytes:p>100?0:Number($('run-context').value),mode};const lib=catalog.libraries.find(l=>l.id===request.library);if(lib.workspace_options)request.workspace_bytes=Number($('run-workspace').value);const response=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Token':document.querySelector('meta[name=demo-token]').content},body:JSON.stringify(request)});if(!response.ok)throw Error('本地算法调用未完成');const r=await response.json();lastRun=r;window.__lastRun=r;$('run-result').innerHTML=resultBlock(r,r.algorithm+'-'+r.parameter)+(r.recovery?resultBlock(r.recovery,'恢复容量后重新执行'):'')+`<a class="link" href="/export/run/${r.run_id}.xlsx" download="functional_observation.xlsx">下载本次结果 XLSX →</a>`;}catch(e){error(e);}finally{buttons.forEach(b=>b.disabled=false);}}
async function resources(){
 const id=$('resource-library').value;
 const scientific=await get('/api/results?library='+encodeURIComponent(id));
 const points=scientific.views.filter(v=>['deployment_resources','comparison_resources'].includes(v.kind)).flatMap(v=>v.points);
 const applications=scientific.views.filter(v=>v.kind==='application_owner');
 const upgraded=scientific.views.filter(v=>v.kind==='upgrade_paired'&&v.resources.length);
 $('resource-result').innerHTML=points.length?points.map(renderResourcePoint).join(''):upgraded.length?'':empty('当前配置的资源记录为空','请选择已登记的配置。');
 $('resource-result').innerHTML+=upgraded.map(renderUpgradeResources).join('');
 $('resource-result').innerHTML+=applications.map(renderApplicationOwnerResources).join('');
}
function median(values){const a=[...values].sort((a,b)=>a-b);return a.length%2?a[(a.length-1)/2]:(a[a.length/2-1]+a[a.length/2])/2;}
function isOperationTiming(v){return ['pooled_measurements','mean_tail_measurements'].includes(v.kind);}
async function measurements(){
 const scope=$('measurement-scope').value;
 $('measurement-library').disabled=scope==='all';
 const data=await get('/api/results'+(scope==='current'?'?library='+encodeURIComponent($('measurement-library').value):''));
 const views=data.views.filter(isOperationTiming);
 const upgraded=data.views.filter(v=>v.kind==='upgrade_paired');
 $('measurement-result').innerHTML=views.length?views.map(v=>v.kind==='mean_tail_measurements'?renderMeanTail(v):renderPooled(v)).join(''):upgraded.length?'':empty('此配置暂无性能统计','可在功能页执行密码操作，或选择全部性能结果。');
 $('measurement-result').innerHTML+=upgraded.map(renderUpgrade).join('');
 $('measurement-result').innerHTML+=data.views.filter(v=>v.kind==='resource_limits').map(renderLimits).join('');
 $('measurement-result').innerHTML+=data.views.filter(v=>v.kind==='process_footprint').map(renderFootprint).join('');
 $('measurement-result').innerHTML+=data.views.filter(v=>v.kind==='shared_keccak').map(renderShared).join('');
 $('measurement-result').innerHTML+=data.views.filter(v=>v.kind==='application_owner').map(renderApplicationOwnerTiming).join('');
 $('measurement-result').innerHTML+=data.views.filter(v=>v.kind==='application_latency').map(renderApplicationLatency).join('');
 $('measurement-result').innerHTML+=data.views.filter(v=>v.kind==='primitive_samples').map(renderPrimitiveSamples).join('');
 $('measurement-result').innerHTML+=data.views.filter(v=>v.kind==='instruction_samples').map(renderInstructionSamples).join('');
 $('measurement-result').innerHTML+=data.views.filter(v=>v.measurement_binding).map(renderMeasurementBinding).join('');
}
function exports(){const scope=$('export-scope').value;$('export-json').href='/export/observations.xml?scope='+scope;$('export-csv').href='/export/samples.xlsx?scope='+scope;$('export-note').textContent=scope==='all'?'导出已保存的实验记录，保留程序版本、样本和返回结果。':'导出当前所选程序版本与工作区的实验记录；空集合表示暂无对应记录。';}
async function scienceExports(){
 const data=await get('/api/results'); const views=data.views.filter(v=>v.kind!=='upgrade_paired');
 applicationPlatforms=[...new Set(views.filter(v=>v.kind==='application_owner').map(v=>v.platform))];
 $('science-exports').innerHTML='<h2>实验数据</h2>'+views.map(v=>'<article class="dataset-item"><h3>'+escapeHTML(v.title||datasetTitle(v))+'</h3><p><a class="link" href="/export/results.xml?dataset='+encodeURIComponent(v.dataset_id)+'">结果 XML</a>'+(isOperationTiming(v)?' · <a class="link" href="/export/results.xlsx?dataset='+encodeURIComponent(v.dataset_id)+'">完整耗时表 XLSX</a>':['resource_limits','process_footprint','application_resources','application_owner','application_latency','primitive_samples','shared_keccak','comparison_resources'].includes(v.kind)?' · <a class="link" href="/export/science.xlsx?dataset='+encodeURIComponent(v.dataset_id)+'">逐项实验统计 XLSX</a>':'')+'</p><details><summary>原始数据与核验信息</summary><p class="hash">数据标识：'+escapeHTML(v.dataset_id)+'</p><a class="link" href="/export/science.xml?dataset='+encodeURIComponent(v.dataset_id)+'">科学数据原文件 XML</a>'+(['pooled_measurements','mean_tail_measurements','timing_distributions','resource_limits','process_footprint','application_resources','application_owner','application_latency','primitive_samples','shared_keccak','timing_attribution','instruction_samples','verification_records'].includes(v.kind)?' · <a class="link" href="/export/observations-manifest.xml?dataset='+encodeURIComponent(v.dataset_id)+'">原始样本文件索引</a>':'')+'</details></article>').join('');
 $('verification-result').innerHTML=views.filter(v=>v.kind==='verification').map(renderVerification).join('');
 $('verification-result').innerHTML+=views.filter(v=>v.kind==='verification_records').map(renderVerificationRecords).join('');
 $('verification-result').innerHTML+=views.filter(v=>v.kind==='verification_profiles').map(renderVerificationProfiles).join('');
 const timing=views.filter(v=>v.kind==='timing_distributions');
 $('verification-result').innerHTML+=timing.map(renderTiming).join('');
 $('verification-result').innerHTML+=views.filter(v=>v.kind==='timing_attribution').map(renderAttribution).join('');
 const rawViews=views.filter(v=>['pooled_measurements','mean_tail_measurements','timing_distributions','resource_limits','process_footprint','application_resources','application_owner','application_latency','primitive_samples','shared_keccak','timing_attribution','instruction_samples','verification_records'].includes(v.kind));
 $('science-exports').insertAdjacentHTML('beforeend','<details><summary>按运行序号下载原始样本</summary>'+rawViews.map((v,i)=>{const limit=isOperationTiming(v)?v.counts.measured_rows/v.counts.samples_per_run:v.raw_files_checked;return '<div class="panel"><h3>'+escapeHTML(v.title||datasetTitle(v))+'</h3><label>序号（0 至 '+(limit-1)+'）<input id="raw-ordinal-'+i+'" type="number" min="0" max="'+(limit-1)+'" value="0" step="1"></label><button class="secondary raw-download" data-index="'+i+'">下载原始样本</button></div>';}).join('')+'</details>');
 for(const b of document.querySelectorAll('.raw-download')){b.textContent='下载原始记录';b.addEventListener('click',async()=>{try{const i=Number(b.dataset.index),v=rawViews[i],n=Number($('raw-ordinal-'+i).value),limit=isOperationTiming(v)?v.counts.measured_rows/v.counts.samples_per_run:v.raw_files_checked;if(!Number.isInteger(n)||n<0||n>=limit)throw Error('请选择索引范围内的运行序号');let ext='csv';if(['resource_limits','process_footprint','application_resources','application_owner','application_latency','primitive_samples','shared_keccak','timing_attribution','instruction_samples','verification_records'].includes(v.kind)){const manifest=await get('/api/observations-manifest?dataset='+encodeURIComponent(v.dataset_id));const item=observationFiles(manifest)[n],name=item.path||item.file;ext=name.endsWith('.records.xml')?'records.xml':name.endsWith('.xml')?'xml':name.endsWith('.csv')?'csv':'bin';}const a=document.createElement('a');a.href='/export/raw.'+ext+'?dataset='+encodeURIComponent(v.dataset_id)+'&ordinal='+n;a.download=v.dataset_id+'-'+n+'.'+ext;a.click();}catch(e){error(e);}});}
 $('science-exports').insertAdjacentHTML('beforeend',data.views.filter(v=>v.kind==='upgrade_paired').map(upgradeExports).join(''));
 for(const b of document.querySelectorAll('.upgrade-raw'))b.addEventListener('click',()=>{const n=Number($('upgrade-ordinal-'+b.dataset.dataset).value);if(!Number.isInteger(n)||n<0||n>=Number(b.dataset.count))return error(Error('请选择索引范围内的运行序号'));const a=document.createElement('a');a.href='/export/upgrade/raw.csv?dataset='+encodeURIComponent(b.dataset.dataset)+'&ordinal='+n;a.download=b.dataset.dataset+'-'+n+'.csv';a.click();});
}
async function init(){
 [catalog,displayCatalog]=await Promise.all([get('/api/catalog'),get('/api/presentation')]);window.__catalog=catalog;
 $('libraries').innerHTML=catalog.libraries.map(l=>`<article class="card"><span class="tag">${escapeHTML(platformTitle(l.platform))}</span><h3>${escapeHTML(l.title.replace('构建','配置'))}</h3><p>${l.parameters.join(' / ')}</p><p>工作区 ${memoryText(l.workspace_bytes)}</p><p class="muted">${l.execution_available?'本机可运行':'本机指令条件不满足；可查看测量结果'}</p><details><summary>实现信息</summary><p>${escapeHTML(configTitle(l.configuration))}</p><div class="hash">SHA256 ${escapeHTML(l.binary_sha256)}</div></details></article>`).join('');
 for(const id of ['run-library','resource-library','measurement-library'])$(id).innerHTML=libraryOptions(id==='run-library');
 const firstAvailable=catalog.libraries.find(l=>l.execution_available);if(firstAvailable)$('run-library').value=firstAvailable.id;
 if($('ordinary-exports'))$('ordinary-exports').hidden=!catalog.archived_records;
 parameters();exports();await Promise.all([resources(),measurements(),scienceExports(),initBudget()]);
 $('budget-query').closest('.panel').hidden=$('budget-query').disabled;
 $('application-query').disabled=!applicationPlatforms.length;$('application-query').closest('.panel').hidden=$('application-query').disabled;
 window.__ready=true;
}
for(const b of document.querySelectorAll('nav button'))b.addEventListener('click',()=>page(b.dataset.page));$('run-library').addEventListener('change',parameters);$('run-parameter').addEventListener('change',runParameter);$('run-normal').addEventListener('click',()=>run('normal'));$('run-insufficient').addEventListener('click',()=>run('insufficient'));$('resource-library').addEventListener('change',()=>resources().catch(error));$('measurement-library').addEventListener('change',()=>measurements().catch(error));$('measurement-scope').addEventListener('change',()=>measurements().catch(error));$('export-scope').addEventListener('change',exports);init().catch(error);
$('budget-query').addEventListener('click',()=>queryBudget().catch(error));

$('application-query').addEventListener('click',()=>queryApplicationBudget().catch(error));
