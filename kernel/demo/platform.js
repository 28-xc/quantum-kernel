/* One selector. Unsupported presets remain absent, including board 16KiB/negative mode. */
'use strict';
let activePlatform='windows',platformStates=null;
const platformLabels={windows:'Windows',arm:'Linux AArch64',ch32:'CH32V307',stm32f407:'STM32F407'};
const originalParameters=parameters,originalRun=run,originalResultBlock=resultBlock;
resultBlock=function(r,title){
 if(r.kind==='stm32f407_live_observation') return boardResult(r,title);
 let html=originalResultBlock(r,title);
 if(r.device_metrics){
  const m=r.device_metrics,clock=m.timer.frequency_hz,mem=m.resources;
  html+=`<article class="panel"><h2>本次设备观测</h2><p class="muted">时钟 ${(clock/1000000).toLocaleString()} MHz。计时包含接口内部清理；外层清理、摘要与串口传输另计。</p>${table(['操作','设备 tick','时间 ms','观测栈 B'],m.operations.map(x=>[displayCatalog.operations[x.operation]||x.operation,x.return_code===-127?'未运行':x.ticks.toLocaleString(),x.return_code===-127?'—':(x.ticks*1000/clock).toFixed(3),x.return_code===-127?'—':x.observed_stack_bytes.toLocaleString()]))}<p>固件 Flash ${mem.flash_bytes.toLocaleString()} B；固定 RAM ${mem.static_ram_bytes.toLocaleString()} B。</p><p class="muted">固定 RAM 已含工作区、输入输出和保留栈。</p></article>`;
 }
 if(r.device_metrics?.verified_profile){
   const p=r.device_metrics.verified_profile;
   html+=`<p class="muted">本参数工作区容量 ${p.active_workspace_bytes.toLocaleString()} B。</p><details><summary>固件身份</summary><div class="hash">ELF SHA-256 ${escapeHTML(p.elf_sha256)}</div></details>`;
 }
 return html;
};
const boardOps={keygen:'密钥生成',encaps:'封装',decaps:'解封装',sign:'签名',verify:'验签'};
const boardImplementations={release:'作品实现',reference:'参考实现',compact:'低内存',cached:'高性能',speed:'高性能'};
let boardHistory=[],boardMemory=[],boardDataErrors={},runInProgress=false,selecting=0;
function boardResult(r,title){
 const status=r.functional_checks_passed?'通过':'未通过';
 const unit=x=>Number.isFinite(x)?x.toLocaleString('zh-CN',{maximumFractionDigits:3}):'—';
 const withPlan=r.operations.every(o=>Number.isFinite(o.workspace_bound_bytes));
 const rows=r.operations.map(o=>[o.operation_title,o.return_code,o.cycles===null?'—':unit(o.cycles),
     unit(o.microseconds),...(withPlan?[unit(o.workspace_bound_bytes)]:[]),unit(o.arena_high_water_bytes),unit(o.stack_bytes)]);
 const checks=Object.entries(r.checks).map(([label,value])=>[label,value?'通过':'失败']);
 const negative=checks.find(([name])=>name.includes('篡改'));
 return `<article class="panel"><div class="result-head"><h2>${escapeHTML(title)}</h2><span class="${r.functional_checks_passed?'good':'bad'}">${status}</span></div>
 ${r.mode==='insufficient'?`<p>容量不足返回 ${escapeHTML(r.insufficient_code)}　恢复后返回 ${escapeHTML(r.recovery_code)}</p>`:''}
 <p>本次实板运行 · STM32F407 · ${escapeHTML(boardImplementations[r.strategy]||r.strategy)} · ${unit(r.clock_hz/1000000)} MHz</p>
 ${table(['操作','返回码','时钟周期','耗时 μs',...(withPlan?['工作区上界 B']:[]),'工作区峰值 B','栈峰值 B'],rows)}
 ${negative?`<p>${escapeHTML(negative[0])}　${escapeHTML(negative[1])}</p>`:''}
 <p>${r.image_storage==='flash'?'Flash':'SRAM'} 固件 ${unit(r.image_bytes)} B　固定 RAM ${unit(r.static_ram_bytes)} B　预留栈 ${unit(r.stack_capacity)} B　观测栈峰值 ${unit(r.stack_peak)} B</p>
 <details><summary>功能检查（${checks.length} 项）</summary>${table(['检查','结果'],checks)}</details>
 <details><summary>设备与固件</summary>${table(['项目','值'],[['芯片系列 ID',r.device_id],['芯片 UID',r.uid],['CPU ID',r.cpuid],['随机源',r.entropy_source],['构建标识',r.build_tag],['固件 SHA-256',r.firmware_sha256],['请求编号',r.request_id]])}
 ${r.response_file?`<a class="link" href="/export/stm32f407/response/${encodeURIComponent(r.run_id)}.bin" download="板端应答.bin">导出原始应答</a>`:''}</details></article>`;
}
function boardHistoryTable(resourcesOnly){
 if(resourcesOnly&&boardMemory.length){
   const flash=boardMemory.every(x=>x.image_storage==='flash');
   const labels=['参数','实现',flash?'Flash 程序 B':'SRAM 镜像 B','主 SRAM B','CCM B','RAM 合计 B','工作区 B','预留栈 B'];
   const rows=boardMemory.map(x=>[(x.param>100?'ML-KEM-':'ML-DSA-')+x.param,boardImplementations[x.implementation]||x.implementation,
      x.image_bytes,x.main_sram_bytes,x.ccm_bytes,x.total_ram_bytes,x.arena_capacity,x.stack_capacity]);
   return '<h2>STM32F407 · 32 KiB 默认部署 · '+(flash?'Flash':'SRAM')+'</h2>'+table(labels,rows);
 }
 if(boardDataErrors[resourcesOnly?'memory':'rows'])return empty('历史数据读取失败','');
 if(!boardHistory.length)return empty('暂无历史实板测量','');
 const headers=resourcesOnly?['参数','操作','实现','工作区峰值 B','观测栈峰值 B']:
    ['参数','操作','实现','样本数','周期中位数','耗时中位数 μs','时钟 Hz'];
 const rows=boardHistory.map(x=>[(Number(x.param)>100?'ML-KEM-':'ML-DSA-')+x.param,
     boardOps[x.operation],boardImplementations[x.implementation]||x.implementation,
     ...(resourcesOnly?[x.arena_bytes??'—',x.stack_bytes??'—']:[x.samples,x.median_cycles,x.median_us,x.clock_hz])]);
 return '<h2>历史实板测量 · STM32F407 · 32 KiB 默认部署</h2>'+table(headers,rows);
}
function selectedPlatformRows(){return catalog.libraries.filter(x=>x.platform_id===activePlatform);}
libraryOptions=function(execution=false){return selectedPlatformRows().map(l=>`<option value="${escapeHTML(l.id)}"${execution&&!l.execution_available?' disabled':''}>${escapeHTML(l.title)}${execution&&!l.execution_available?'（未连接）':''}</option>`).join('');};
parameters=function(){
 const priorParameter=$('run-parameter').value;
 const priorInputs={message:$('run-message').value,context:$('run-context').value,workspace:$('run-workspace').value};
 const row=catalog.libraries.find(x=>x.id===$('run-library').value);
 const cap=row?.run_presets||{message_lengths:[],context_lengths:[],modes:[]};
 for(const [id,values] of [['run-message',cap.message_lengths],['run-context',cap.context_lengths]]){
  const prior=$(id).value;$(id).innerHTML=values.map(x=>`<option>${x}</option>`).join('');if(values.map(String).includes(prior))$(id).value=prior;
 }
 originalParameters();
 if(row?.workspace_options?.map(String).includes(priorInputs.workspace))$('run-workspace').value=priorInputs.workspace;
 if(row?.parameters.map(String).includes(priorParameter)){$('run-parameter').value=priorParameter;runParameter();}
 if(Number($('run-parameter').value)<100){if(cap.message_lengths.map(String).includes(priorInputs.message))$('run-message').value=priorInputs.message;if(cap.context_lengths.map(String).includes(priorInputs.context))$('run-context').value=priorInputs.context;}
 if(!row)$('run-parameter').innerHTML='';
 $('run-normal').hidden=!cap.modes.includes('normal');
 $('run-insufficient').hidden=!cap.modes.includes('insufficient');
 $('run-insufficient').closest('.panel').querySelector('p.muted').hidden=!row;
 if(!row){$('run-workspace-label').hidden=true;$('run-message').disabled=true;$('run-context').disabled=true;}
};
const ch32Selector=document.createElement('label');
ch32Selector.hidden=true;ch32Selector.id='ch32-strategy-controls';
ch32Selector.append(document.createTextNode('板端策略 '));
const ch32Choice=document.createElement('select');ch32Choice.id='ch32-strategy';
for(const [value,label] of [['low','低内存 · 28 KiB'],['high','高性能 · 80 KiB'],['original','恢复原现场']]){
  const option=document.createElement('option');option.value=value;option.textContent=label;ch32Choice.append(option);
}
ch32Selector.append(ch32Choice);$('live-connect').before(ch32Selector);
ch32Choice.addEventListener('change',()=>platformStatus());
async function platformStatus(){
 const states=await get('/api/platforms'), state=states.platforms.find(x=>x.id===activePlatform);
 platformStates=states;
 const connected=state?.state==='connected', busy=runInProgress||state?.state==='busy';
 $('live-state').textContent=busy?'正在运行':activePlatform==='windows'?'本机已就绪':
   !state?.configured?'未配置':!connected?'未连接':activePlatform==='stm32f407'?
   (state.mode==='dfu'?'已发现 · DFU 下载':'已连接 · 应用串口'):'上次连接成功';
 $('live-help').textContent=activePlatform==='stm32f407'&&connected&&state.mode==='dfu'?
    '运行时连接至应用串口。':'';
 $('live-help').hidden=!$('live-help').textContent;
 $('live-connect').textContent=connected?'重新检测':'连接';
 $('live-connect').hidden=activePlatform==='windows';
 $('live-connect').disabled=busy||!state?.configured;
 ch32Selector.hidden=activePlatform!=='ch32';ch32Choice.disabled=busy;
 if(activePlatform==='ch32'){
   $('live-connect').textContent=ch32Choice.value==='original'?'恢复并核验':'写入并连接';
   $('live-help').hidden=false;
   $('live-help').textContent='切换策略时会备份并核验当前板卡，写入固件并重启。可在这里恢复原现场。';
 }
 document.querySelector('.sidebar-foot').innerHTML=`<i></i>${escapeHTML(platformLabels[activePlatform])}<br><span>ML-KEM / ML-DSA</span>`;
 return state;
}
let representativeView=null;
function renderBoardRepresentatives(models){
   const deploymentRows=models.deployments.map(x=>[(x.role==='low'?'低档':'高档')+' · '+x.budget_kib+' KiB',x.ram,x.flash]);
   const boardSource='/export/representatives/'+models.deployments[0].board+'.tsv';
   $('resource-result').innerHTML=table(['部署','完整 RAM（B）','Flash（B）'],deploymentRows)+'<p><a href="'+boardSource+'" download>固件与实测来源</a></p>';
   const timed=models.rows.map(x=>[x.budget_kib+' KiB',(x.parameter>100?'ML-KEM-':'ML-DSA-')+x.parameter,boardOps[x.operation],x.strategy==='compact'?'低内存':x.strategy==='cached'?'高性能':x.role==='low'?'低档':'高档',x.samples,x.median_cycles,(x.median_cycles*1000000/x.clock_hz).toFixed(2)]);
   $('measurement-result').innerHTML=timed.length?table(['部署','参数','操作','策略','样本数','周期中位数','时间中位数（μs）'],timed):empty('暂无入选实板测量','');
}
const previousResourceQuery=resources,previousTimingQuery=measurements;
resources=async function(...args){
 if(['stm32f407','ch32'].includes(activePlatform)){
   if(representativeView)renderBoardRepresentatives(representativeView);
   return;
 }
 return previousResourceQuery.apply(this,args);
};
measurements=async function(...args){
 if(['stm32f407','ch32'].includes(activePlatform)){
   if(representativeView)renderBoardRepresentatives(representativeView);
   return;
 }
 return previousTimingQuery.apply(this,args);
};
async function selectPlatform(){
 representativeView=null;
 const selection=++selecting, platform=activePlatform;
 const [nextCatalog, history, models]=await Promise.all([get('/api/catalog'),platform==='stm32f407'?get('/api/platforms/stm32f407/history'):Promise.resolve(null),['ch32','stm32f407'].includes(platform)?get('/api/representatives/'+platform):Promise.resolve(null)]);
 if(selection!==selecting||platform!==activePlatform)return;
 catalog=nextCatalog;window.__catalog=catalog;
 boardHistory=history?.rows||[];boardMemory=history?.memory||[];boardDataErrors=history?.errors||{};
 lastRun=null;window.__lastRun=null;$('notice').hidden=true;
 const rows=selectedPlatformRows();
 if(models){$('libraries').innerHTML=models.deployments.map(d=>'<article class="card"><h3>'+d.budget_kib+' KiB · '+({compact:'低内存',cached:'高性能',low:'低内存',high:'高性能'}[d.strategy])+'</h3><p>ML-KEM 512 / 768 / 1024 · ML-DSA 44 / 65 / 87</p></article>').join('');}else{$('libraries').innerHTML=rows.length?rows.map(l=>`<article class="card"><h3>${escapeHTML(l.title)}</h3><p>${l.parameters.join(' / ')}</p>${Number.isInteger(l.workspace_bytes)&&!l.workspace_by_parameter?`<p>工作区 ${memoryText(l.workspace_bytes)}</p>`:''}<p class="muted">${l.execution_available?'可实时运行':'未连接'}</p></article>`).join(''):empty('未连接','');}
 for(const id of ['run-library','resource-library','measurement-library'])$(id).innerHTML=libraryOptions(id==='run-library');
 const measured=rows.find(x=>x.technical_result_sets>0);if(measured)$('measurement-library').value=measured.id;
 const first=rows.find(x=>x.execution_available && x.representative_strategy)||rows.find(x=>x.execution_available);if(first)$('run-library').value=first.id;
 parameters();$('run-result').innerHTML=empty('等待运行','');
 $('measurement-scope').value='current';$('measurement-scope').querySelector('option[value="all"]').hidden=true;
 const applicationValue=activePlatform==='windows'?'windows_x86_64':activePlatform==='arm'?'linux_aarch64':null;
 $('application-query').disabled=applicationValue===null||!applicationPlatforms.includes(applicationValue);
 if(applicationValue)$('application-platform').value=applicationValue;
 $('application-platform').disabled=true;
 $('application-query').closest('.panel').hidden=$('application-query').disabled;
 $('resource-objects').hidden=activePlatform!=='windows';$('host-resource').hidden=activePlatform!=='windows';
 $('verification-result').hidden=['ch32','stm32f407'].includes(activePlatform);
 const board=activePlatform==='stm32f407';
 $('resource-library').closest('label').hidden=Boolean(models);
 $('measurement-scope').closest('.form-grid').hidden=Boolean(models);
 $('science-exports').hidden=Boolean(models);
 $('ordinary-exports').hidden=Boolean(models)||!catalog.archived_records;
 let data=$('board-exports');
 if(!data){data=document.createElement('div');data.id='board-exports';$('science-exports').after(data);}
 data.hidden=!models;
 if(models){
   data.innerHTML='<p><a class="link" href="/export/representatives/'+platform+'.tsv" download="代表策略逐操作.tsv">代表策略逐操作 TSV</a></p>';
 }
 $('page-data').querySelector('p.lead').textContent=models?'代表策略实板测量':'历史实验数据';
 if($('deployment-builder'))$('deployment-builder').hidden=activePlatform!=='windows';
 if(resourceCatalog){
  const studies=resourceCatalog.timing_studies.filter(x=>x.platform===applicationValue);
  const datasets=resourceCatalog.datasets.filter(x=>x.platform===applicationValue);
  $('budget-study').innerHTML=studies.map(x=>`<option value="${escapeHTML(x.dataset_id)}">${escapeHTML(datasetTitle(x))}</option>`).join('');
  $('budget-resources').innerHTML=datasets.map(x=>`<option value="${escapeHTML(x.dataset_id)}">${escapeHTML(datasetTitle(x))}</option>`).join('');
  $('budget-query').disabled=!studies.length||!datasets.length;
  $('budget-query').closest('.panel').hidden=activePlatform==='ch32'||$('budget-query').disabled;
  $('budget-result').innerHTML='';$('application-selection').innerHTML='';
 }
 // No other platform's archived resource/performance values substitute for a new board.
 if(models){representativeView=models;renderBoardRepresentatives(models);}
 else if(rows.length){await Promise.all([resources(),measurements()]);}
 else{$('resource-result').innerHTML=empty('暂无资源记录','');$('measurement-result').innerHTML=empty('暂无测量记录','');}
 await platformStatus();
}
run=async function(mode='normal'){
 runInProgress=true;$('live-platform').disabled=true;$('live-connect').disabled=true;$('live-state').textContent='正在运行';
 const buttons=[$('run-normal'),$('run-insufficient')];
 for(const control of document.querySelectorAll('#page-run .form-grid select'))control.disabled=true;
 buttons.forEach(b=>b.disabled=true);$('notice').hidden=true;
 window.__lastRun=null;lastRun=null;
 $('run-result').innerHTML=empty('正在执行','等待所选平台返回结果。');
 try{
  const p=Number($('run-parameter').value),request={library:$('run-library').value,parameter:p,message_bytes:p>100?0:Number($('run-message').value),context_bytes:p>100?0:Number($('run-context').value),mode};
  const selected=catalog.libraries.find(x=>x.id===request.library);if(selected?.workspace_options)request.workspace_bytes=Number($('run-workspace').value);
  const response=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Token':document.querySelector('meta[name=demo-token]').content},body:JSON.stringify(request)});
  const r=await response.json();if(!response.ok)throw Error(r.error||'设备调用未完成');
  lastRun=r;window.__lastRun=r;$('run-result').innerHTML=resultBlock(r,r.algorithm+'-'+r.parameter)+(r.recovery?resultBlock(r.recovery,'恢复容量后重新执行'):'')+`<a class="link" href="/export/run/${encodeURIComponent(r.run_id)}.xlsx" download="functional_observation.xlsx">导出本次结果 XLSX</a>`;
 }catch(e){
   $('run-result').innerHTML=empty('本次未完成','');error(e);
   if(activePlatform!=='windows'){catalog=await get('/api/catalog');window.__catalog=catalog;}
 }finally{
   runInProgress=false;$('live-platform').disabled=false;
   for(const control of document.querySelectorAll('#page-run .form-grid select'))control.disabled=false;
   await platformStatus();parameters();
 }
};
$('live-platform').addEventListener('change',()=>{activePlatform=$('live-platform').value;selectPlatform().catch(error);});
$('run-library').addEventListener('change',parameters);
$('live-connect').addEventListener('click',async()=>{
 $('live-connect').disabled=true;$('live-platform').disabled=true;$('live-state').textContent=activePlatform==='ch32'?'正在核验板端映像':'连接中';
 if(activePlatform==='ch32'){ch32Choice.disabled=true;$('run-normal').disabled=true;}
 try{const r=await fetch('/api/platforms/connect',{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Token':document.querySelector('meta[name=demo-token]').content},body:JSON.stringify(activePlatform==='ch32'?{platform_id:'ch32',strategy:ch32Choice.value}:{platform_id:activePlatform})});const body=await r.json();if(!r.ok)throw Error(body.error||'连接未完成');await selectPlatform();if(body.ch32_switch){
      const target=body.ch32_switch.strategy==='original'?'ch32-partial64':'ch32-finals-'+body.ch32_switch.strategy;
      const select=$('run-library');
      if(Array.from(select.options).some(o=>o.value===target&&!o.disabled)){select.value=target;parameters();}
    }}catch(e){await selectPlatform();error(e);}finally{$('live-platform').disabled=false;ch32Choice.disabled=false;parameters();}
});
(async()=>{for(let n=0;n<600&&!window.__ready;n++)await new Promise(r=>setTimeout(r,100));if(!window.__ready)throw Error('基础界面尚未就绪');await selectPlatform();window.__platformReady=true;})().catch(error);

setInterval(async()=>{
 if(activePlatform!=='stm32f407'||runInProgress||$('live-platform').disabled||document.hidden)return;
 const prior=platformStates?.platforms.find(x=>x.id==='stm32f407');
 if(prior?.state!=='connected')return;
 try{
   const state=await platformStatus();
   if(activePlatform==='stm32f407'&&state?.state==='disconnected'){
     await selectPlatform();
     $('run-result').innerHTML=empty('实板已断开','');
   }
 }catch(e){error(e);}
},3500);
