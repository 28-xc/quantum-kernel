"use strict";
const pages={parameters:"参数与接口",crypto:"密码功能",arithmetic:"核心算术",resources:"性能与资源",security:"安全检查"};
const opNames={keygen:"生成密钥",encaps:"封装",decaps:"解封装",sign:"签名",verify:"验签",
 "decaps-modified":"修改密文再试","verify-modified":"修改消息再试",
 decaps_modified_ciphertext:"修改密文后解封装",verify_modified_signature:"修改签名后验签"};
const profileNames={"low-memory":"低内存",performance:"高性能",saved:"记录"};
const cases={capacity:"工作区不足与恢复",length:"错误长度",encoding:"非法编码",random:"随机数异常与恢复",signature:"签名篡改测试",message:"消息篡改测试",ciphertext:"密文篡改测试"};
const fieldNames={public_key:"公钥",secret_key:"私钥",ciphertext:"密文",shared_secret:"共享秘密",signature:"签名",secret_key_length:"私钥长度",shared_secret_length:"共享秘密长度"};
function E(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function B(action,label,variant="",disabled=false){return '<button type="button" data-act="'+E(action)+'" class="'+E(variant)+'"'+(disabled?" disabled":"")+'>'+E(label)+'</button>';}
function details(title,body){return '<details class="secondary-info"><summary>'+E(title)+'</summary>'+body+'</details>';}
function opt(id,label,selected){return '<option value="'+E(id)+'"'+(String(id)===String(selected)?" selected":"")+'>'+E(label)+'</option>';}
function sel(id,title,items,value,disabled=false){return '<label class="field"><span>'+E(title)+'</span><select id="'+E(id)+'"'+(disabled?' disabled':'')+'>'+items.map(x=>opt(x[0],x[1],value)).join("")+'</select></label>';}
function panel(name,body){return '<section class="panel"><div class="section-head"><h2>'+E(name)+'</h2></div>'+body+'</section>';}
function badge(v,ok){return '<span class="badge '+(ok===true?"good":ok===false?"bad":"")+'">'+E(v)+'</span>';}
function table(head,rows,empty="暂无记录"){return rows.length?'<div class="grid-scroll"><table><thead><tr>'+head.map(x=>'<th scope="col">'+E(x)+'</th>').join("")+'</tr></thead><tbody>'+rows.map(r=>'<tr>'+r.map(v=>'<td>'+v+'</td>').join("")+'</tr>').join("")+'</tbody></table></div>':'<p class="empty">'+E(empty)+'</p>';}
function pairs(items){return '<dl class="pairs">'+items.map(([k,v])=>'<dt>'+E(k)+'</dt><dd>'+v+'</dd>').join("")+'</dl>';}
function metrics(items){return '<div class="cards">'+items.map(([k,v])=>'<div class="metric"><span>'+E(k)+'</span><strong>'+E(v)+'</strong></div>').join("")+'</div>';}
function actions(...items){return '<div class="actions">'+items.filter(Boolean).join("")+'</div>';}
function tabs(view,choices){return '<div class="tabs">'+choices.map(([id,title])=>B('tab:'+id,title,S.tabs[view]===id?'active':'')).join("")+'</div>';}
function download(p,label){return p&&S.data.files.includes(p)?'<a class="button" href="/wb/file?p='+encodeURIComponent(p)+'" download>'+E(label)+'</a>':'';}
function exportLink(rec,label='保存结果'){
 return '<a class="button" href="/wb/records/'+E(rec.request_id)+'.xlsx?folder='+encodeURIComponent(rec.export_folder||'correctness')+'" download>'+E(label)+'</a>';
}
const publicLabels={public_key:'公钥',ciphertext:'密文',signature:'签名'};
const materialLabels={...publicLabels,secret_key:'私钥',shared_secret:'共享秘密 K',decapsulated_secret:'共享秘密 K′',modified_shared_secret:'共享秘密 K″'};
function outputLink(rec,key){
 return '<a class="button" href="/wb/records/'+E(rec.request_id)+'/'+E(key)+'.bin" download>保存'+E(publicLabels[key])+'</a>';
}
function sourceButton(path,label){
 return path&&S.data.files.includes(path)?B('view-source:'+encodeURIComponent(path),label):'';
}
function codeLinks(rec,kind=rec.kind){
 const source='01_源代码/可参数化格运算内核/';
 const app='03_复现环境与运行程序/软件演示程序/入口/unified_workbench/';
 const ring='02_测试代码与数据/performance/多项式运算/完整环乘实板测量/';
 const board=rec.source_kind==='live_board';
 let impl=rec.result.source_path||source+'src/common/public_api.c';
 let check=app+({vectors:'vectors',arithmetic:'arithmetic',onboarding:'onboarding',security:'crypto'}[kind]||'runtime')+'.py';
 if(board){
  if(kind==='security')check=app+(rec.result.raw_response?'runtime.py':'security_checks.py');
  impl=source+'demo/'+(rec.platform==='stm32f407'?'f407_provider':'ch32_strategy')+'.py';
  if(kind==='vectors'&&rec.platform==='stm32f407')impl=app+'arithmetic/stm32-acvp.c';
  if(kind==='arithmetic'){
   if(rec.operation==='mul')impl=ring+(rec.platform==='stm32f407'?'stm32/'+rec.profile+'KiB/ring_driver.c':'ch32/measure_ring.c');
   else {
    const driver=['add','sub','reduce','ntt','intt'].includes(rec.operation)?'transform':'primitive';
    impl=app+'arithmetic/'+driver+'-'+(rec.platform==='stm32f407'?'stm32':'ch32')+'.c';
   }
  }
 }else if(rec.platform==='arm'&&kind!=='arithmetic'){
  impl=source+'demo/platform_providers.py';
 }
 if(kind==='onboarding')impl=source+'examples/public_a_session/application.c';
 return actions(sourceButton(impl,'调用代码'),sourceButton(check,'核验代码'));
}
function recordDownloads(rec){
 if(rec.source_kind==='live_board'&&(rec.result.raw_response||rec.result.raw_responses))
  return ['<a class="button" href="/wb/records/'+E(rec.request_id)+'/board.json" download>保存板端应答</a>'];
 if(rec.kind!=='crypto')return [];
 const rows=rec.result.rows||[rec.result];
 return Object.keys(publicLabels).filter(key=>rows.some(r=>r.verified&&r.public_outputs?.[key]?.hex))
  .map(key=>outputLink(rec,key));
}
function num(n,d=0){return n==null?'未记录':Number(n).toLocaleString('zh-CN',{minimumFractionDigits:d,maximumFractionDigits:d});}
function pName(v){return profileNames[v]||(/^\d+$/.test(v)?v+' KiB':v);}
function selectedTarget(){return S.data.platforms.find(x=>x.id===S.platform);}
function selectedProfile(){return selectedTarget().profiles.find(x=>x.id===S.profile);}
function isHost(){return S.platform===S.data.local_platform;}
function isBoard(platform=S.platform){return ['stm32f407','ch32v307'].includes(platform);}
function isLive(){return !!selectedProfile()?.available;}
function hostControls(){return isLive()&&isHost()&&!S.busy;}
function cfg(){return {algorithm:S.alg,parameter:S.param,platform:S.platform,profile:S.profile,source_kind:isBoard()?'live_board':'live_host'};}
function remoteInputs(){
 const p=selectedProfile()?.presets;
 if(!p?.message_lengths?.length||!p.context_lengths?.length)return {};
 const message=p.message_lengths.includes(32)?32:p.message_lengths[0];
 return {message_bytes:p.message_lengths.includes(S.remoteMessage)?S.remoteMessage:message,
  context_bytes:p.context_lengths.includes(S.remoteContext)?S.remoteContext:p.context_lengths[0]};
}
function remoteInputFields(){
 const p=selectedProfile()?.presets, input=remoteInputs();
 if(input.message_bytes==null)return '';
 const lengths=list=>list.map(n=>[n,n+' B']);
 return '<div class="controls">'+
  sel('remoteMessage','消息大小',lengths(p.message_lengths),input.message_bytes,S.busy)+
  sel('remoteContext','上下文大小',lengths(p.context_lengths),input.context_bytes,S.busy)+'</div>';
}
function connectionInstructions(platform=S.platform){
 const base='03_复现环境与运行程序/';
 const paths={arm:'host/AArch64/README.md',stm32f407:'firmware/STM32F407/运行.txt',ch32v307:'firmware/CH32V307/运行说明.md'};
 return download(base+paths[platform],'连接说明');
}
function platformLabel(rec){return S.data.platforms.find(p=>p.id===rec.platform)?.title||rec.platform;}
function renderGlobal(){
 const params=Object.keys(S.data.parameters).filter(n=>S.data.parameters[n].algorithm===S.alg).sort((a,b)=>a-b);
 const target=selectedTarget(), algorithmSettings=['parameters','crypto','arithmetic','security'].includes(S.view);
 const settings=algorithmSettings;
 const status=isHost()?(isLive()?'':'当前配置无法运行'):(isLive()?'已连接':target.configured?'未连接':'未配置');
 document.querySelector('#heading').innerHTML='<div class="title-line"><h1>'+E(pages[S.view])+'</h1></div>';
 const actual=isBoard()?target.profiles.find(profile=>profile.available):null;
 const deploying=S.deploying===S.platform;
 const deviceStatus=deploying?'部署中':isBoard()?(actual?'已连接':status):status;
 const mismatch=actual&&actual.id!==S.profile, showDeviceControls=S.view!=='parameters';
 const boardAction=showDeviceControls&&target.can_deploy&&(mismatch||S.platform==='stm32f407')?
  B('deploy-board','部署所选固件','',S.busy||!mismatch):'';
 const boardNote=showDeviceControls&&mismatch&&!deploying?'<p class="muted" role="status">已选 '+E(pName(S.profile))+
  (target.can_deploy?'。部署并核验后可运行。':'。连接同档固件后可运行。')+'</p>':'';
 document.querySelector('#top-state').innerHTML=(settings||isBoard())?E(target.title)+
  (actual&&!deploying?' · '+E(pName(actual.id))+' 固件':'')+
  (deviceStatus?' '+badge(deviceStatus,!deploying&&(!!actual||isLive())?true:undefined):''):'';
 document.querySelector('#config').innerHTML=settings?'<div class="configuration">'+
  (algorithmSettings?sel('alg','算法',[['ML-KEM','ML-KEM'],['ML-DSA','ML-DSA']],S.alg,S.busy)+
  sel('param','参数',params.map(p=>[p,p]),S.param,S.busy):'')+
  sel('platform','平台',S.data.platforms.map(p=>[p.id,p.title]),S.platform,S.busy||S.data.platforms.length===1)+
  (showDeviceControls?sel('profile',isBoard()?'RAM 档位':'配置',target.profiles.map(p=>[p.id,pName(p.id)]),S.profile,S.busy):'')+
  (showDeviceControls&&!isHost()?(target.configured?B('connect',actual||isLive()?'重新连接':'连接设备','',S.busy):connectionInstructions()):'')+
  boardAction+'</div>'+boardNote:'';
 document.querySelectorAll('nav a').forEach(a=>{if(a.dataset.view===S.view)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
}
function parameters(){
 const z=S.data.parameters[S.param];
 const values=Object.entries(fieldNames).filter(([key])=>z[key]>0).map(([k,l])=>[l,num(z[k])+' B']);
 const support=table(['算法','参数集','操作'],[
  ['ML-KEM','512 / 768 / 1024','生成密钥、封装、解封装'],
  ['ML-DSA','44 / 65 / 87','生成密钥、签名、验签']
 ]);
 const api=table(['操作','函数'],z.operations.map(op=>[E(opNames[op]),'<code>'+E(op==='keygen'?'lc_keypair':'lc_'+op)+'</code>']));
 return panel('六组参数 · 18 项操作',support+actions(B('nav:crypto','运行密码操作','primary'),B('nav:arithmetic','核心算术')))+
  panel(S.alg+'-'+S.param,metrics(values)+details('接口',api+actions(download('01_源代码/可参数化格运算内核/include/latticecore.h','查看接口代码'))));
}
function recordLabel(r){return r.operation==='板上正确性测试'?'ACVP 测试':opNames[r.operation]||r.operation;}
function vectorInputFields(row, values={}){
 const inputNames={...fieldNames,seed:'种子',message:'消息',context:'上下文',randomness:'随机输入'};
 return Object.entries(row.input_lengths||{}).map(([field,size])=>{
  const label=inputNames[field]||field, hex=values[field];
  let value='';
  if(typeof hex==='string'){
   if(!hex)value='<span class="muted">（空）</span>';
   else if(size<=24){
    let display=hex;
    if(field==='message'||field==='context'){
     try{
      const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Uint8Array.from(hex.match(/../g),b=>parseInt(b,16)));
      if(!/[\u0000-\u001f\u007f-\u009f]/.test(text))display=JSON.stringify(text);
     }catch{}
    }
    value='<code aria-label="'+E(label)+'内容">'+E(display)+'</code>';
   }else{
    value='<details class="vector-input-detail"><summary><span>查看</span><span>收起</span></summary>'+
     '<pre class="material-hex" tabindex="0" aria-label="'+E(label)+'十六进制">'+hexLines(hex)+'</pre></details>';
   }
  }
  return '<div class="vector-field" data-input-field="'+E(field)+'"><span>'+E(label)+' <small>'+E(num(size))+' B</small></span>'+value+'</div>';
 }).join('');
}
const vectorKeyChecks=['encapsulationKeyCheck','decapsulationKeyCheck'];
function vectorOperationKey(row){return row.tested_category||row.tested_operation||'incomplete';}
function vectorOperation(row){
 const key=vectorOperationKey(row);
 return ({encapsulationKeyCheck:'封装密钥检查',decapsulationKeyCheck:'解封装密钥检查'})[key]||opNames[key]||'未完成';
}
function vectorOutcome(row,value){
 return typeof value!=='boolean'?'—':row.tested_operation==='verify'?(value?'验签通过':'验签失败'):(value?'接受':'拒绝');
}
function vectorActual(row){
 return [0,-1,-2,-6].includes(row.return_code)?vectorOutcome(row,row.actual_accept):'运行出错';
}
function vectorOutputName(field){return field==='secret'?'共享秘密':fieldNames[field]||field;}
function vectorChecks(row){
 const checks=Object.entries(row.output_checks||{});
 if(row.return_code===0&&!checks.length&&!row.verified&&Object.keys(row.output_lengths||{}).length)return '输出核验未通过';
 if(row.return_code!==0||!checks.length)return vectorActual(row);
 return [true,false].map(ok=>{
  const names=checks.filter(([,value])=>value===ok).map(([field])=>vectorOutputName(field));
  return names.length?names.join('、')+(ok?'与预期一致':'与预期不一致'):'';
 }).filter(Boolean).join('，');
}
function vectorOutputs(row, values=[]){
 const lengths=row.output_lengths||{};
 const rows=Object.entries(row.output_checks||{}).map(([key,ok])=>{
  const label=vectorOutputName(key), length=lengths[key]??row.public_outputs?.[key]?.length;
  const comparisons=values.filter(value=>value.field===key);
  const compare=comparisons.length?'<details class="vector-input-detail"><summary><span>查看</span><span>收起</span></summary>'+
   comparisons.map(({actual,expected})=>'<span>预期'+E(label)+'</span><pre class="material-hex" tabindex="0" aria-label="预期'+E(label)+'十六进制">'+hexLines(expected)+'</pre>'+
     '<span>实际'+E(label)+'</span><pre class="material-hex" tabindex="0" aria-label="实际'+E(label)+'十六进制">'+hexLines(actual)+'</pre>').join('')+'</details>':'';
  return [E(label),length==null?'—':E(num(length)+' B'),badge(ok?'与预期逐字节一致':'与预期不一致',ok),compare];
 });
 return rows.length?table(['输出','长度','检查结果',''],rows):'';
}
function boardVectorTable(rows, scope){
 return '<div class="board-vector-results">'+vectorFilters(rows,scope)+
  '<div id="vector-filtered-'+scope+'">'+boardVectorRows(rows,scope)+'</div></div>';
}
function boardVectorRows(rows, scope){
 const parameters=new Set(rows.map(row=>row.parameter)).size>1;
 const filter=scope==='saved'?S.savedVectorFilter:S.vectorOperationFilter;
 const failuresOnly=scope==='saved'?S.savedVectorFailures:S.vectorFailuresOnly;
 const filtered=rows.map((row,index)=>({row,index})).filter(({row})=>vectorMatches(row,filter,failuresOnly));
 const listing=table([...(parameters?['算法参数']:[]),'用例','操作','检查结果','状态',''],filtered.map(({row,index})=>{
  const action='board-case:'+scope+':'+index;
  return [ ...(parameters?[E((row.parameter>100?'ML-KEM':'ML-DSA')+'-'+row.parameter)]:[]),
   B(action,'tc'+row.tc_id,'vector-case'),E(vectorOperation(row)),E(vectorChecks(row)),
   badge(row.verified?'通过':'失败',row.verified),B(action,'详情')];
 }),failuresOnly?'没有失败用例':'没有符合筛选条件的用例');
 const count=filtered.length<rows.length?'<p class="muted vector-filter-count">显示 '+num(filtered.length)+' / '+num(rows.length)+' 条</p>':'';
 return count+(rows.length>5?'<div class="vector-rows" role="region" aria-label="逐项结果" tabindex="0">'+listing+'</div>':listing);
}
function boardVectorDetail(row, data){
 const facts=pairs([['算法参数',E((row.parameter>100?'ML-KEM':'ML-DSA')+'-'+row.parameter)],
  ['用例',E(row.case_id)],['操作',E(vectorOperation(row))],
  ['预期结果',E(vectorOutcome(row,row.expected_accept))],['实际结果',E(vectorActual(row))],
  ['返回码',E(row.return_code??'—')],['检查结果',E(vectorChecks(row))],
  ['状态',badge(row.verified?'通过':'失败',row.verified)]]);
 const outputs=data.outputs.map(({field,actual,expected})=>{
  const label=vectorOutputName(field);
  const bytes=(name,value)=>'<span>'+E(name)+'</span><pre class="material-hex" tabindex="0" aria-label="'+E(name)+'">'+hexLines(value)+'</pre>';
  return details(label,bytes('预期'+label,expected)+(typeof actual==='string'?bytes('实际'+label,actual):''));
 });
 return facts+(Object.keys(row.input_lengths).length?'<h3 class="vector-detail-heading">测试输入</h3>'+
  '<div class="vector-inputs">'+vectorInputFields(row,data.inputs)+'</div>':'')+
  (outputs.length?'<h3 class="vector-detail-heading">输出核验</h3>'+outputs.join(''):'');
}
function vectorComparison(row,rec){
 const check=value=>typeof value==='boolean'?badge(value?'通过':'失败',value):'—';
 const length=Object.keys(row.input_lengths||{}).length;
 return pairs([['算法参数',E(rec.algorithm+'-'+rec.parameter)],['操作',E(vectorOperation(row))],
  ['完整编号',E(row.case_id||row.operation)],['状态',check(row.verified)],
  ['预期结果',E(vectorOutcome(row,row.expected_accept))],['实际结果',E(vectorActual(row))],
  ['返回码',E(row.return_code??'—')],['检查结果',E(vectorChecks(row))],
  ['缓冲区保护',check(row.canaries_ok)],['工作区清理',check(row.used_workspace_erased)],
  ['工作区使用量',E(row.workspace_used_bytes==null?'—':num(row.workspace_used_bytes)+' B')]])+
  (length?'<h3 class="vector-detail-heading">测试输入</h3>':'')+
  (row.case_description?'<div class="muted">'+E(row.case_description)+'</div>':'')+
  '<div class="vector-inputs" id="vector-case-inputs">'+vectorInputFields(row)+'</div>'+
  '<div id="vector-case-outputs">'+vectorOutputs(row)+'</div>';
}
function vectorMatches(row,filter,onlyFailures){
 const key=vectorOperationKey(row);
 return (!onlyFailures||!row.verified)&&(filter==='all'||filter===key||(filter==='key-checks'&&vectorKeyChecks.includes(key)));
}
function vectorFilters(rows,scope='host'){
 const options=new Map(rows.map(row=>[vectorOperationKey(row),vectorOperation(row)]));
 const keyChecks=vectorKeyChecks.every(key=>options.has(key))?[['key-checks','密钥检查']]:[];
 const saved=scope==='saved', suffix=scope==='host'?'':'-'+scope;
 const filter=saved?S.savedVectorFilter:S.vectorOperationFilter;
 const failed=saved?S.savedVectorFailures:S.vectorFailuresOnly;
 return '<div class="vector-filters">'+sel('vector-operation-filter'+suffix,'操作',[['all','全部操作'],...keyChecks,...options],filter)+
  '<label class="vector-failures"><input type="checkbox" id="vector-failures-only'+suffix+'"'+(failed?' checked':'')+'>只看失败</label></div>';
}
function vectorCoverage(rows){
 const operations=new Map();
 for(const row of rows){
  const key=vectorOperationKey(row), count=operations.get(key)||[vectorOperation(row),0,0];
  count[1]++;count[2]+=Number(row.verified===true);
  operations.set(key,count);
 }
 return operations.size?'<h4>测试覆盖范围</h4>'+table(['测试项目','用例数量','通过数量'],
  [...operations.values()].map(([title,count,passed])=>[E(title),num(count),num(passed)])):'';
}
function vectorResultRows(rows){
 const filter=S.vectorOperationFilter;
 const items=rows.flatMap((row,i)=>{
  if(!vectorMatches(row,filter,S.vectorFailuresOnly))return [];
  const action='vector-detail:'+i;
  return [[B(action,row.tc_id==null?row.case_id||row.operation:'tc'+row.tc_id,'vector-case'),
   E(vectorOperation(row)),E(vectorChecks(row)),badge(row.verified?'通过':'失败',row.verified),B(action,'详情')]];
 });
 const count=items.length<rows.length&&items.length>0?'<p class="muted vector-filter-count">显示 '+num(items.length)+' / '+num(rows.length)+' 条</p>':'';
 const empty=S.vectorFailuresOnly?'没有失败用例':'没有符合筛选条件的用例';
 return count+'<div class="vector-rows" role="region" aria-label="逐项结果" tabindex="0">'+
  table(['用例','操作','检查结果','状态',''],items,empty)+'</div>';
}
function vectorResults(rec){
 if(!rec)return '';
 const x=rec.result;
 const summary=Number.isInteger(x.executed)?(x.status==='已取消'?'已取消 · ':'')+x.passed+'/'+x.executed+' 项通过':x.summary||x.status||rec.status;
 const rows=x.rows||[];
 const listing=x.board_vectors?boardVectorTable(rows,'live'):
  rows.length?'<details class="secondary-info" open><summary>逐项结果</summary>'+vectorFilters(rows)+
   '<div id="vector-filtered-rows">'+vectorResultRows(rows)+'</div></details>':'';
 const totals=Number.isInteger(x.executed)?'<p class="result-meta">已执行 '+num(x.executed)+' · 通过 '+num(x.passed)+' · 失败 '+num(x.failed)+'</p>':'';
 return '<section class="vector-results"><h3>测试结果</h3><div class="vector-summary'+
  (rec.verification?' vector-success':rec.verification===false&&x.status!=='已取消'?' vector-failure':'')+'">'+E(summary)+'</div>'+
  totals+(rows.length?vectorCoverage(rows)+listing+actions(exportLink(rec)):'')+'</section>';
}
function boardResults(raw){
 const rows=raw.operations, readings=raw.device_metrics?.operations||[];
 const data=rows.map(r=>{
  const ticks=r.cycles??readings.find(m=>m.operation===r.operation&&m.return_code===r.return_code)?.ticks;
  let result=r.return_code===0?'成功':r.return_code===-6?'已拒绝':'失败';
  if(r.operation==='decaps_modified_ciphertext'&&r.return_code===0)
   result=raw.checks?.implicit_rejection===true||raw.functional_checks_passed?'已生成替代共享秘密':'比较未通过';
  if(r.operation==='decaps'&&r.return_code===0&&raw.checks?.shared_secret_equal===false)result='共享秘密不一致';
  return [E(r.operation_title||opNames[r.operation]||r.operation||r.name),E(result),ticks];
 });
 const cycles=data.some(([, ,ticks])=>Number.isInteger(ticks));
 return table(cycles?['操作','结果','板端周期']:['操作','结果'],
  data.map(([op,result,ticks])=>cycles?[op,result,Number.isInteger(ticks)?E(num(ticks)):'']: [op,result]));
}
function resultCard(rec){
 if(!rec)return '';
 const x=rec.result, pub=x.public_outputs||{};
 if(x.steps||x.findings)return panel('运行结果',remoteResult(rec)+actions(
  B('test-detail:'+(rec.kind==='security'?'security':rec.kind==='performance'?'performance':'crypto'),'详情'),
  exportLink(rec),...recordDownloads(rec)));
 const profile=platformLabel(rec);
 const platform=rec.source_kind==='live_board'?profile+' · '+pName(rec.profile):profile;
 const input=rec.algorithm+' '+rec.parameter;
 const brief={
  '修改签名':'修改签名后，验签失败',
  '修改消息':'修改消息后，验签失败',
  '修改密文':'已生成替代共享秘密',
  '工作区不足与恢复':'工作区不足，恢复后通过',
  '随机数异常与恢复':'随机数异常，恢复后运行成功',
  '使用错误长度':'已拒绝错误长度',
  '错误长度':'已拒绝错误长度',
  '使用非法编码':'已拒绝非法编码',
  '非法编码':'已拒绝非法编码',
 };
 const batch=Number.isInteger(x.total);
 const boardRows=x.raw_response?.operations;
 const summary=batch?(x.status==='已取消'?'已取消 · '+x.executed+'/'+x.total+' 项已运行':x.passed+'/'+x.total+' 项通过'):
  (rec.verification?brief[rec.operation]:'')||(rec.export_folder==='performance'&&rec.operation==='设备接入'&&x.return_code===-6?'验签失败，接入已停止':'')||x.summary||x.status||rec.status;
 const trace=Object.keys(pub).length?table(['输出','长度（B）'],Object.entries(pub).map(([k,v])=>[E(fieldNames[k]||k),E(typeof v==='object'?v.length:v)])):'';
 const rows=Array.isArray(x.rows)?x.rows:null;
 let outcomes='';
 if(rows&&rows.length&&x.total<=18)outcomes=table(['参数','操作或用例','结果',''],rows.map((r,i)=>[
  E(r.parameter),E(opNames[r.operation]||r.operation),badge(x.remote_batch?r.summary:r.verified?'通过':'失败',r.verified),
  B('test-detail:batch:'+i,'详情')]));
 else if(Array.isArray(boardRows)&&boardRows.length)outcomes=boardResults(x.raw_response);
 else if(rows?.length)outcomes=details('逐项结果',table(['用例','结果'],rows.map(r=>[E(r.operation),badge(r.verified?'通过':'失败',r.verified)])));
 const t=x.duration_ms==null?'':' · '+num(x.duration_ms,3)+' ms';
 const header='<div class="result-head'+(rec.verification===false?' result-error':'')+'"><strong>'+E(summary)+'</strong></div><p class="result-meta">'+E(platform+(batch?'':' · '+input)+t)+'</p>';
 return panel('结果',header+(x.remote_batch&&x.summary?'<p class="muted">'+E(x.summary)+'</p>':'')+outcomes+
   (trace?details('输出长度',trace):'')+actions(
    rec.kind==='security'?B('test-detail:security','详情'):'',exportLink(rec),...recordDownloads(rec)));
}
function msgFields(){
 const disabled=S.busy?' disabled':'';
 const modes=[['text','手动输入'],['file','导入文件']].map(([mode,label])=>
  '<label><input type="radio" name="message-mode" id="message-mode-'+mode+'" value="'+mode+'"'+
  (S.messageMode===mode?' checked':'')+disabled+'>'+label+'</label>').join('');
 const message=S.messageMode==='text'
  ?'<textarea id="message" aria-label="消息" rows="2"'+disabled+'>'+E(S.msg)+'</textarea>'
  :'<div class="message-file">'+B('pick-message','选择文件','',S.busy)+
   '<input id="msgfile" type="file" hidden'+disabled+'><span class="muted" role="status">'+
   E(S.file?.name||(S.messageRequest?'正在读取…':'未选择文件'))+'</span></div>';
 return '<fieldset class="message-input"><legend>消息</legend><div class="message-modes">'+modes+'</div>'+
  message+'<p class="inline-note" id="msgcounts">'+E(messageSizeText())+'</p></fieldset>'+
  '<label class="field"><span>上下文（选填，最多 255 字节）</span><input id="context" value="'+E(S.ctx)+'"'+disabled+'></label>';
}
function cryptoStep(rec){
 const r=rec.result;
 const title=opNames[rec.operation]||rec.operation;
 const compared=rec.operation==='decaps'&&r.return_code===0?r.checks?.shared_secret_equal:undefined;
 const status=compared===true&&rec.verification?'K = K′':compared===false?'K ≠ K′':r.summary||(rec.verification?'通过':'失败');
 return '<div class="crypto-step"><div class="crypto-step-head"><strong>'+E(title)+'</strong>'+
  '<div class="crypto-step-status">'+badge(status,rec.verification)+
  B('test-detail:flow:'+rec.operation,'详情')+'</div></div></div>';
}
function hexLines(hex){return E((hex.match(/.{1,48}/g)||[]).join('\n'));}
function hexPreview(label,hex,buttons=''){
 return '<div class="material-preview"><div class="material-title"><strong>'+E(label)+'（十六进制）</strong>'+buttons+
  '</div><pre class="material-hex" tabindex="0" aria-label="'+E(label)+'十六进制">'+
  hexLines(hex)+'</pre></div>';
}
function materialsView(){
 const lengths=activeMaterials()?.lengths||{};
 const entries=Object.entries(lengths);
 const gridClass=entries.length===5?'material-grid five-columns':'material-grid';
 const selected=lengths[S.expanded?.field]?S.expanded:null;
 const cards=entries.map(([field,length])=>{
  const label=materialLabels[field], open=selected?.field===field;
  return '<div class="material-row'+(open?' material-selected':'')+'"><div class="material-title"><strong>'+E(label)+'</strong>'+
   '<span>'+E(num(length))+' B</span></div>'+
   actions(B('show-material:'+field,(open?'隐藏':'查看')+label,'',S.busy),
    field==='shared_secret'||field==='decapsulated_secret'?'':B('save-material:'+field,'保存'+label,'',S.busy))+'</div>';
 }).join('');
 let preview='';
 if(selected){
  const {field,hex}=selected, label=materialLabels[field];
  const copy=field==='public_key'||field==='secret_key'?B('copy-material:'+field,'复制'+label,'',S.busy):'';
  preview=hexPreview(label,hex,copy);
 }
 return '<section class="panel material-panel"><div class="section-head"><h2>密钥与输出</h2>'+
  B('import-bin','导入 .bin','',!hostControls())+'</div>'+
  '<input id="material-file" type="file" accept=".bin,application/octet-stream" hidden>'+
  (cards?'<div class="'+gridClass+'">'+cards+'</div>':'')+preview+'</section>';
}
function cryptoResults(){
 const latest=S.last.crypto;
 const ops=S.data.parameters[S.param].operations;
 const rows=ops.map(op=>S.flow[op]).filter(Boolean);
 if(!rows.length)return resultCard(latest);
 const calls=rows.filter(x=>x.result.function);
 const tech=calls.length?details('运行详情',
  pairs([['平台',E(platformLabel(calls[0]))],['配置',E(pName(calls[0].profile))],['库文件',E(calls[0].result.library)]])+
  table(['操作','C 函数','耗时（ms）'],calls.map(r=>[
   E(opNames[r.operation]),'<code>'+E(r.result.function)+'</code>',E(num(r.result.duration_ms,3))]))):'';
 const cancelled=latest?.result.status==='已取消'?'<p class="muted">已取消</p>':'';
 return panel('运行结果',cancelled+rows.map(cryptoStep).join('')+
  tech+(latest?actions(exportLink(latest)):''));
}
function cryptoView(){
 if(!isHost())return remoteCryptoView();
 const out=tabs('crypto',[['operations','密码操作'],['vectors','测试']]);
 if(S.tabs.crypto==='vectors')return out+vectorTestPanel();
 const ref=activeMaterials(), lengths=ref?.lengths||{}, ops=S.data.parameters[S.param].operations;
 const needsFile=S.alg==='ML-DSA'&&S.messageMode==='file'&&!S.file;
 const has={keygen:true,encaps:!!lengths.public_key,decaps:!!(lengths.secret_key&&lengths.ciphertext),
  sign:!!lengths.secret_key&&!needsFile,verify:!!(lengths.public_key&&lengths.signature)&&!needsFile};
 return out+panel(S.alg+'-'+S.param,(S.alg==='ML-DSA'?msgFields():'')+
  '<div class="crypto-actions">'+ops.map(op=>B('op:'+op,opNames[op],'',!hostControls()||!has[op])).join('')+
  B('batch:parameter','运行完整流程','primary',!hostControls()||needsFile)+'</div>')+runLog('crypto')+
  '<div id="crypto-materials">'+materialsView()+'</div>'+
  panel('批量测试',actions(B('batch:all','运行全部 18 项','',!hostControls())))+
  runLog('batch')+resultCard(S.last.batch)+'<div id="crypto-results">'+cryptoResults()+'</div>';
}
function remoteCryptoView(){
 const key=S.alg+'-'+S.param;
 const out=tabs('crypto',[['operations','密码操作'],['vectors','测试']]);
 if(S.tabs.crypto==='vectors')return out+vectorTestPanel();
 const disabled=!isLive()||S.busy;
 return out+panel(key,(S.alg==='ML-DSA'?remoteInputFields():'')+
  actions(B('board-suite','运行完整流程','primary',disabled)))+runLog('crypto')+
  panel('批量测试',actions(B('batch:all','运行全部 18 项','',disabled)))+
  runLog('batch')+resultCard(S.last.batch)+resultCard(S.last.crypto);
}
function vectorTestPanel(){
 const host=isHost(), acvp=S.suite==='acvp', subset=S.casePick==='subset';
 const parameter=S.alg+'-'+S.param;
 const cases=S.data.acvp_cases[String(S.param)]||[];
 const scopes=[];
 if(acvp)scopes.push(['subset','全部 21 条']);
 if(host){
  const available=S.caseIds.length;
  const range=available?'当前参数全部 '+available+' 条':S.caseError?'未能载入用例':'正在载入…';
  scopes.push(['all',range],...S.caseIds.map(id=>[id,id]));
 }else{
  scopes.push(['all','当前参数 '+cases.length+' 条']);
  for(const row of cases){
   const label=opNames[row.operation]+(row.accepted===false?'（预期拒绝）':'');
   scopes.push([row.id,label+' · tc'+row.tc]);
  }
 }
 const ready=host?(subset?isLive():isLive()&&S.caseIds.length>0):!!selectedProfile()?.board_vectors;
 let message='';
 if(!host&&!ready){
  message=!isLive()?(isBoard()?'连接开发板后可运行测试。':'连接 Linux 主机后可运行测试。'):
   S.platform==='arm'?'请更新 Linux 端运行程序。':'当前固件未提供 ACVP 测试。';
 }
 const suite=sel('suite','测试集',host?[['acvp','NIST ACVP'],['wycheproof','Wycheproof']]:[['acvp','NIST ACVP']],S.suite,S.busy);
 const meta=[selectedTarget().title,pName(S.profile),subset?'6 组参数':parameter].join(' · ');
 let retry='';
 if(host&&S.caseError)retry=actions(B('retry-cases','重新载入用例','',S.busy));
 return panel('标准测试向量','<p class="result-meta">'+E(meta)+'</p>'+
  '<div class="vector-controls">'+suite+sel('casepick','测试范围',scopes,S.casePick,S.busy)+'</div>'+
  B('run-vectors','运行测试','primary vector-run',!ready||S.busy)+
  (message?'<p class="muted">'+E(message)+'</p>':'')+retry+
  runLog('vectors')+vectorResults(S.last.boardVectors||S.last.vectors));
}
function remoteResult(rec,key=rec.kind==='performance'?'performance':'crypto'){
 const x=rec.result;
 const meta=E(platformLabel(rec)+' · '+rec.algorithm+'-'+rec.parameter+' · '+pName(rec.profile));
 const steps=x.steps||[], findings=x.findings||[];
 const cycles=steps.some(row=>Number.isInteger(row.cycles));
 const ops=steps.length?table(cycles?['操作','结果','周期','']:['操作','结果',''],steps.map((row,index)=>{
  const cells=[E(opNames[row.operation]),badge(row.summary,row.return_code==null?undefined:row.verified)];
  if(cycles)cells.push(row.cycles==null?'—':num(row.cycles));
  return [...cells,B('test-detail:'+key+':'+index,'详情')];
 })):'';
 return '<p class="result-meta">'+meta+'</p>'+ops+
  (findings.length?pairs(findings.map(row=>[row.label,badge(row.value,row.verified)])):'');
}
function runLogEntries(log){
 return log.entries.map(line=>'<li>'+E(line)+'</li>').join('');
}
function trafficRows(frames,key,offset=0){
 return frames.map((frame,index)=>'<li><strong>'+E(frame.direction)+'</strong> '+E(frame.link)+' · '+
  E(frame.description)+(frame.bytes?' · '+num(frame.bytes)+' B':'')+
  (frame.hex?' '+B('traffic-frame:'+key+':'+(index+offset),'查看报文'):'')+'</li>').join('');
}
function trafficSave(id){
 return '<a class="button" download href="/wb/records/'+E(id)+'/traffic.txt">保存日志</a>';
}
function runLogBody(key,log){
 const raw=log.mode==='traffic';
 const switching=log.remote?'<div class="tabs log-tabs">'+
  B('log-view:'+key+':progress','运行进度',raw?'':'active')+
  B('log-view:'+key+':traffic','原始收发',raw?'active':'')+'</div>':'';
 return '<div id="run-log-'+E(key)+'-body">'+switching+
  '<ol class="run-log-list" role="log" aria-label="运行日志" id="run-log-'+E(key)+'-entries"'+(raw?' hidden':'')+'>'+
  runLogEntries(log)+'</ol>'+
  (raw?'<ol class="run-log-list traffic-list" role="log" aria-label="原始收发" id="run-log-'+E(key)+'-traffic">'+
   trafficRows(log.traffic.frames,key)+'</ol>'+
   (log.traffic.frames.length?'':'<p class="muted" id="run-log-'+E(key)+'-empty">'+(log.running?'正在等待设备收发记录。':'本次未记录到设备收发。')+'</p>')+
   (log.traffic.omitted?'<p class="muted">另有 '+num(log.traffic.omitted)+' 条超出记录上限。</p>':'')+
   (log.recordId&&log.traffic.frames.length?actions(trafficSave(log.recordId)):''):'')+'</div>';
}
function runLog(key){
 const log=S.logs[key];
 if(!log)return '';
 const status=log.running?'正在运行':log.status;
 const open=key==='security'||log.running||log.status==='运行失败';
 const job=S.job?.key===key&&log.running?S.job:null;
 return '<details class="panel run-log"'+(open?' open':'')+'><summary>'+
  '<strong data-state="'+E(status)+'">'+E(status)+' · '+E(log.title)+'</strong>'+
  '<span class="run-log-toggle">查看运行日志</span></summary>'+
  runLogBody(key,log)+
  (job?actions(B('cancel','取消剩余操作','',!!job.cancelling)):'')+'</details>';
}
function arithmeticResult(rec){
 if(!rec)return '';
 const x=rec.result, inputs=x.inputs||{}, operation=rec.operation;
 const descriptor=S.data.arithmetic.operations.find(item=>item.id===operation);
 const pair=descriptor?.input==='pair';
 const inputLabel=pair?'输入多项式 A':operation==='ntt'?'输入多项式':operation==='intt'?'输入变换系数':'输入系数';
 const outputs={ntt:'变换结果',intt:'变换结果',encode:'编码结果',decode:'解码结果',compress:'压缩结果',decompress:'解压结果',reduce:'约减结果'};
 const outputLabel=pair?'计算结果 C':outputs[operation]||'采样结果';
 const data=[
  [inputLabel,inputs.a,pair||operation==='ntt'],['输入多项式 B',inputs.b,true],
  [operation==='decompress'?'输入压缩字节':'输入编码',inputs.data_hex],['公开种子',inputs.public_seed_hex],
  [outputLabel,x.output??x.output_hex]
 ].filter(([,value])=>value!=null);
 const indexFields=[['行索引',inputs.row],['列索引',inputs.column],['采样索引',inputs.index],['位宽',inputs.width]]
  .filter(([,value])=>value!=null);
 const rows=data.map(([label,value,polynomial])=>{
  const isArray=Array.isArray(value);
  const count=isArray?value.length:value.length/2;
  const text=isArray?value.slice(0,8).join(', '):(value.slice(0,16).match(/../g)||[]).join(' ');
  const power=polynomial?value.findIndex(n=>n!==0):-1;
  const term=power>0&&power===value.findLastIndex(n=>n!==0)?' · '+(value[power]===1?'':value[power])+(power===1?'x':'x^'+power):'';
  return '<div class="arithmetic-value"><strong>'+E(label)+'</strong><code>'+E(text+(count>8?' …':'')+term)+'</code></div>';
 }).join('');
 const long=data.filter(([,value])=>Array.isArray(value)?value.length>8:value.length>16);
 const kind=long.every(([,value])=>Array.isArray(value))?'查看全部系数':long.every(([,value])=>!Array.isArray(value))?'查看全部字节':'查看全部数据';
 const content=long.map(([label,value])=>'<h3>'+E(label)+'</h3><pre aria-label="'+E(label)+'完整数据">'+
  (Array.isArray(value)?E(Array.from({length:Math.ceil(value.length/16)},(_,i)=>value.slice(i*16,i*16+16).join(', ')).join('\n')):hexLines(value))+'</pre>').join('');
 const meta=[descriptor?.title,rec.algorithm+'-'+rec.parameter,
  rec.source_kind==='live_board'?platformLabel(rec)+' '+pName(rec.profile):'',
  x.modulus==null?'':'q = '+x.modulus,x.cycles==null?'':num(x.cycles)+' 周期'].filter(Boolean).join(' · ');
 const status=x.verified?'校验通过':x.status_code!=null&&x.status_code===0?'校验失败':'计算失败';
 return '<section class="panel arithmetic-result"><div class="section-head"><h2>计算结果</h2>'+badge(status,!!x.verified)+'</div>'+
  '<p class="result-meta">'+E(meta)+'</p>'+(indexFields.length?pairs(indexFields.map(([label,n])=>[label,E(n)])):'')+
  '<div class="arithmetic-values">'+rows+'</div><p class="arithmetic-check"><strong>'+E(x.summary||rec.status)+'</strong></p>'+
  (long.length?details(kind,'<div class="arithmetic-full" tabindex="0" role="region" aria-label="'+E(kind)+'">'+content+'</div>'):'')+
  actions(B('test-detail:'+(S.view==='resources'?'performance':'arithmetic'),'详情'),exportLink(rec))+'</section>';
}
function arithmeticView(){
 const board=isBoard(), linux=S.platform==='arm';
 const operations=linux?selectedProfile()?.linux_operations:board?selectedProfile()?.board_operations:null;
 const a=S.data.arithmetic, available=a.operations.filter(o=>o.algorithms.includes(S.alg));
 if(!available.find(o=>o.id===S.arith))S.arith=available[0].id;
 const ready=linux||board?!!operations?.includes(S.arith):isHost()&&a.available;
 const op=available.find(o=>o.id===S.arith), requestImport=S.preset==='import', input=op.input;
 const presets=input==='seed'?[['monomial','默认种子'],['random','随机种子'],['import','导入测试数据']]:
  [['monomial','单项式'],['zero','全零'],['unit','单位多项式'],['boundary','极值系数'],['random','随机输入'],['import','导入测试数据']];
 if(!presets.some(([key])=>key===S.preset))S.preset='monomial';
 let controls='<div class="controls arithmetic-toolbar">'+sel('arithop','运算',available.map(o=>[o.id,o.title]),S.arith,S.busy)+sel('preset','测试输入',presets,S.preset,S.busy);
 if(op.widths)controls+=sel('width','量化位宽',op.widths[S.param].map(w=>[w,w+' 位']),S.width,S.busy);
 controls+=actions(B('arithmetic','开始计算','primary',!ready||!isLive()||S.busy),B('reset-input','重置输入','',S.busy));
 controls+='</div>';
 const disabled=S.busy?' disabled':'';
 const area=(id,n,v)=>{
  const text='<textarea id="'+id+'" rows="2"'+disabled+'>'+E(v||'')+'</textarea>';
  if(id!=='a'&&id!=='b')return '<label class="field grow"><span>'+E(n)+'</span>'+text+'</label>';
  return '<div class="field grow"><div class="coefficient-field-header"><label class="label" for="'+id+'">'+E(n)+'</label>'+
   B('pick-coefficients:'+id,'导入 .txt','',S.busy)+'</div>'+text+'</div>';
 };
 if(input==='seed'&&(requestImport||op.id!=='challenge')){
  const n=typeof op.seed_bytes==='object'?op.seed_bytes[S.param]:op.seed_bytes;
  const number=(id,label)=>'<label class="field arithmetic-index"><span>'+E(label)+'</span><input type="number" min="0" id="'+id+'" value="'+E(S.arInputs[id]??'0')+'"'+disabled+'></label>';
  controls+='<div class="controls arithmetic-extra">'+(requestImport?area('seedhex','公开种子（十六进制，'+n+' B）',S.arInputs.seedhex):'');
  if(op.id==='matrix')controls+=number('row','行索引')+number('column','列索引');
  else if(op.id!=='challenge')controls+=number('index','采样索引');
  controls+='</div>';
 }else if(requestImport){
  controls+='<div class="controls arithmetic-extra">'+(input==='bytes'?area('datahex','编码字节（十六进制）',S.arInputs.datahex):area('a',input==='scalar'?'系数（1 或 256 个整数）':'多项式 A（256 个整数）',S.arInputs.a))+(input==='pair'?area('b','多项式 B（256 个整数）',S.arInputs.b):'')+'</div>';
  if(input!=='bytes')controls+='<input id="arithmetic-file" type="file" accept=".txt,text/plain" hidden'+disabled+'>';
 }
 if((board||linux)&&!ready){
  const message=isLive()?'当前设备尚未提供此运算。':board?'连接正式部署固件后可运行。':'连接 Linux AArch64 后可运行。';
  controls+='<p class="muted">'+E(message)+'</p>';
 }
 return panel(board?'板上计算':'运算',controls)+runLog('arithmetic')+'<div id="arithmetic-result">'+arithmeticResult(S.last.arithmetic)+'</div>';
}
function performanceRows(rec,key='performance'){
 const steps=rec.result.steps||[];
 const board=rec.source_kind==='live_board';
 return table(['参数','操作','耗时（ms）',...(board?['周期']:[]),'检查结果',''],steps.map((row,index)=>{
  const parameter=S.data.parameters[row.parameter];
  const timing=row.duration_ms??rec.result.duration_ms;
  return [E(parameter?parameter.algorithm+'-'+row.parameter:row.parameter),E(opNames[row.operation]),
   timing==null?'—':num(timing,3),...(board?[row.cycles==null?'—':num(row.cycles)]:[]),
   badge(row.summary,row.return_code==null?undefined:row.verified),
   B('test-detail:'+key+':'+index,'详情')];
 }),'暂无已执行项目');
}
function performanceResult(rec){
 if(!rec)return '<p class="empty">尚未运行密码操作。</p>';
 const x=rec.result, steps=x.steps||[], single=steps[0];
 const counts=x.total?[
  ['实际执行',num(x.executed)+' / '+num(x.total)],
  ['通过',num(x.passed)],
  ['总耗时',num(x.elapsed_ms,3)+' ms']
 ]:[
  ...(x.duration_ms!=null?[['耗时',num(x.duration_ms,3)+' ms']]:[]),
  ...(single?.cycles!=null?[['周期',num(single.cycles)]]:[])
 ];
 return metrics([...counts,['运行状态',E(rec.status)]])+
  (!rec.verification&&x.summary?'<p class="muted">'+E(x.summary)+'</p>':'')+
  performanceRows(rec)+actions(exportLink(rec,'保存测试结果'),...recordDownloads(rec));
}
function performanceArithmeticResult(rec){
 if(!rec)return '<p class="empty">尚未运行算术测试。</p>';
 const x=rec.result, descriptor=S.data.arithmetic.operations.find(item=>item.id===rec.operation);
 return table(['参数','运算','周期','耗时（ms）','检查结果',''],[[
  E(rec.algorithm+'-'+rec.parameter),E(descriptor?.title),
  x.cycles==null?'—':num(x.cycles),x.duration_ns==null?'—':num(x.duration_ns/1e6,3),
  badge(x.summary||rec.status,rec.verification),B('test-detail:performanceArithmetic','详情')
 ]])+actions(exportLink(rec,'保存测试结果'));
}
function performanceResourceResult(rec){
 const usage=rec?.result.resource_usage;
 if(!rec)return '<p class="empty">运行密码操作后可在此查看本次工作区峰值。</p>';
 const rows=rec.result.steps||[];
 const measured=rows.filter(row=>row.return_code!=null&&Number.isInteger(row.workspace_used_bytes));
 const total=rec.result.total??1;
 const rowsFor=labels=>Object.entries(labels).filter(([key])=>Number.isInteger(usage?.[key]))
  .map(([key,label])=>[label,num(usage[key])+' B']);
 const live=rowsFor({workspace_bytes:'临时缓冲区容量最大值（工作区）',
  workspace_used_bytes:'临时缓冲区实测峰值（工作区）'});
 if(measured.length)live.push(['峰值采样项数',num(measured.length)+' / '+num(total)]);
 const build=rowsFor({ram_budget_bytes:'RAM 预算',static_ram_bytes:'完整 RAM',
  firmware_workspace_bytes:'临时缓冲区预留（固件工作区）',flash_bytes:'Flash 占用',
  code_bytes:'代码段（.text）',library_bytes:'算法库文件大小'});
 const missing=measured.length?'':'<p class="empty">本次运行未取得工作区峰值。请查看运行日志后重试。</p>';
 return '<h3>本次运行</h3>'+(live.length?pairs(live):'')+missing+
  (build.length?'<h3>'+(isBoard(rec.platform)?'当前固件':'当前算法库')+'</h3>'+pairs(build):'')+
  actions(exportLink(rec,'保存测试结果'));
}
function livePerformanceResults(){
 const {performance,performanceArithmetic}=S.last;
 if(!performance&&!performanceArithmetic)return '';
 const choices=[['crypto','密码耗时'],['arithmetic','算术性能'],['memory','资源占用']];
 const body={crypto:()=>performanceResult(performance),
  arithmetic:()=>performanceArithmeticResult(performanceArithmetic),
  memory:()=>performanceResourceResult(performance)
 }[S.perfResult]();
 return panel('运行结果','<div class="tabs">'+choices.map(([id,label])=>
  B('performance-result:'+id,label,S.perfResult===id?'active':'')).join('')+'</div>'+body);
}
function resources(){
 const logKey=S.perfResult==='arithmetic'?'performanceArithmetic':'performance';
 return livePerformanceControls()+runLog(logKey)+livePerformanceResults();
}
function performanceSelection(){
 const {platforms,local_platform}=S.data;
 const target=platforms.find(item=>item.id===(S.perfPlatform||S.platform))||
  platforms.find(item=>item.id===local_platform);
 const profile=target.profiles.find(item=>item.id===S.perfProfiles[target.id])||
  target.profiles.find(item=>item.available)||target.profiles[0];
 return {target,profile};
}
function performanceArithmeticOperations(target,profile,family){
 const catalog=S.data.arithmetic;
 const supported=isBoard(target.id)?profile.board_operations:target.id==='arm'?profile.linux_operations:
  catalog.available?catalog.operations.map(item=>item.id):[];
 return catalog.operations.filter(item=>item.algorithms.includes(family)&&supported?.includes(item.id));
}
function livePerformanceControls(){
 const {target,profile}=performanceSelection();
 const ready=profile.operation_timing;
 const local=target.id===S.data.local_platform;
 const other=target.profiles.find(item=>item.available);
 const settings=Object.entries(S.data.parameters).map(([key,value])=>[key,value.algorithm+'-'+key]);
 const selected=S.data.parameters[S.perfParam];
 if(!selected.operations.includes(S.perfOperation))S.perfOperation=selected.operations[0];
 const arithmetic=performanceArithmeticOperations(target,profile,selected.algorithm);
 if(arithmetic.length&&!arithmetic.some(item=>item.id===S.perfArithmetic))
  S.perfArithmetic=arithmetic[0].id;
 const board=isBoard(target.id);
 const connection=local?'':target.configured?
  B('performance-connect',profile.available||board&&other?'重新连接':'连接设备','',S.busy):
  connectionInstructions(target.id);
 let status='';
 if(local){
  if(!ready)status='当前配置不可用';
 }else if(profile.available){
  status=ready?(board?'已连接 · '+pName(profile.id)+' 固件':'已连接'):'Linux 端运行程序需更新';
 }else if(!target.configured){
  status='设备未配置';
 }else{
  status=board&&other?'板上当前运行 '+pName(other.id)+' 固件':'设备未连接';
 }
 const shared='<div class="controls">'+
  sel('perfPlatform','设备',S.data.platforms.map(item=>[item.id,item.title]),target.id,S.busy)+
  sel('perfProfile',board?'RAM 档位':'配置',target.profiles.map(item=>[item.id,pName(item.id)]),profile.id,S.busy)+
  sel('perfParam','参数',settings,S.perfParam,S.busy)+connection+'</div>'+
  (status?'<p class="muted" role="status">'+E(status)+'</p>':'');
 const cryptoTest='<section class="performance-test-group"><h3>密码操作</h3><div class="controls">'+
  sel('perfOperation','操作',selected.operations.map(op=>[op,opNames[op]]),S.perfOperation,S.busy)+
  B('performance-current','运行所选操作','primary',S.busy||!ready)+
  B('performance-batch','运行全部 18 项','',S.busy||!ready)+'</div></section>';
 const arithmeticTest='<section class="performance-test-group"><h3>算术运算</h3><div class="controls">'+
  sel('perfArithmetic','运算',arithmetic.length?arithmetic.map(item=>[item.id,item.title]):[['','当前设备不可运行']],
   arithmetic.length?S.perfArithmetic:'',S.busy||!arithmetic.length)+
  B('performance-arithmetic','运行算术测试','',S.busy||!arithmetic.length)+'</div></section>';
 return panel('当前设备测试',shared+'<div class="cols performance-test-columns">'+cryptoTest+arithmeticTest+'</div>');
}
function securityEvidence(result){
 const input=result?.security_input;
 if(!input)return '';
 const {field,before,after,source,reference}=input;
 const fields={ciphertext:'密文',signature:'签名',message:'消息',public_key:'公钥',
  workspace_bytes:'工作区容量',entropy_bytes:'测试随机源'};
 const sources={current:'当前密码流程',fresh:'本次生成',fixture:'公开测试向量',firmware:'当前板上固件'};
 let content=pairs([['检查对象',E(fields[field])],['输入来源',E(sources[source]+(reference?' · '+reference:''))],
  ...[['调用 API',result.function],['原始返回码',result.original_return_code],
      ['本次返回码',result.return_code],['预期返回码',result.expected_return_code],
      ['恢复后返回码',result.recovery_return_code]].filter(([,value])=>value!=null).map(([label,value])=>[label,E(value)])]);
 if(typeof before==='number'){
  const workspace=field==='workspace_bytes';
  const requested=source==='fixture'?'正常向量提供':'回调请求字节数';
  content+=pairs([[workspace?'正常工作区容量':requested,E(num(before)+' B')],
   [workspace?'本次提供容量':'本次提供随机数据',E(num(after)+' B')]]);
  return content;
 }
 const originalHex=before.toUpperCase(),actualHex=after.toUpperCase();
 content+=pairs([['原始长度',E(num(originalHex.length/2)+' B')],['本次传入长度',E(num(actualHex.length/2)+' B')]]);
 const changed=value=>'<span class="hex-change">'+E(value)+'</span>';
 const differences=[];
 for(let offset=0;offset<Math.max(originalHex.length,actualHex.length)&&differences.length<8;offset+=2){
  const original=originalHex.slice(offset,offset+2),actual=actualHex.slice(offset,offset+2);
  if(original!==actual)differences.push([num(offset/2),changed(original||'—'),changed(actual||'—')]);
 }
 if(differences.length)content+=table(['字节偏移（从 0 开始）','原始字节（HEX）','本次字节（HEX）'],differences);
 const preview=(hex,other)=>{
  const lines=[];
  for(let start=0;start<hex.length;start+=48){
   let line='';
   for(let offset=start;offset<Math.min(start+48,hex.length);offset+=2){
    const byte=hex.slice(offset,offset+2);
    line+=byte===other.slice(offset,offset+2)?E(byte):changed(byte);
   }
   lines.push(line);
  }
  return '<pre class="material-hex">'+(lines.join('\n')||'空输入')+'</pre>';
 };
 return content+details('查看原始'+fields[field]+'（HEX）',preview(originalHex,actualHex))+
  details('查看本次传入'+fields[field]+'（HEX）',preview(actualHex,originalHex));
}

function ciphertextCheck(rec){
 const x=rec?.result, test=x?.ciphertext_test;
 if(!test)return resultCard(rec);
 const originalCode=test.original_return_code??0;
 const equal=x.checks.original_shared_secret_equal??true;
 const original=originalCode!==0?'解封装出错':equal?'K = K′':'K ≠ K′';
 const modified=x.return_code!==0?'解封装出错':x.checks.differs_from_original?'K ≠ K″':'K = K″';
 const field='modified_shared_secret', label=materialLabels[field], open=S.expanded?.field===field;
 const show=test.modified_secret_available?B('show-material:'+field,(open?'隐藏':'查看')+label,'',S.busy):'';
 return panel('ML-KEM 密文篡改测试',
  pairs([['原始解封装',badge(original,originalCode===0&&equal)],
   ['修改字节数',E(num(test.changed_bytes)+' 字节')],
   ['修改后解封装',badge(modified,rec.verification)]])+actions(show,B('test-detail:security','详情'),exportLink(rec))+
  (open?hexPreview(label,S.expanded.hex):''));
}
function signatureTamperResult(rec){
 const x=rec.result, test=x.signature_test||x.message_test;
 const title=x.signature_test?cases.signature:cases.message;
 const originalCode=test.original_return_code??0;
 const label=code=>code===0?'验签通过':code===-6?'验签失败':'验签出错';
 return panel('ML-DSA '+title,
  pairs([['原始验签',badge(label(originalCode),originalCode===0)],
   ['修改字节数',E(num(test.changed_bytes??1)+' 字节')],
   ['修改后验签',badge(label(x.return_code),rec.verification)]])+actions(B('test-detail:security','详情'),exportLink(rec)));
}
function securityView(){
 const list=S.alg==='ML-KEM'?['ciphertext','length','encoding','capacity','random']:['message','signature','length','encoding','capacity','random'];
 const profile=selectedProfile(), complete=isHost()||profile?.security_checks===true;
 const capacity=profile?.presets?.modes?.includes('insufficient')===true;
 const supported=k=>complete||k==='ciphertext'||k==='signature'||k==='capacity'&&capacity;
 const hint=isLive()&&!complete?'<p class="muted" role="status">'+
  (S.platform==='arm'?'更新 Linux 端运行程序后可运行全部检查。':'当前固件仅开放部分检查。')+'</p>':'';
 const result=S.last.security;
 const renderResult=result?.result.signature_test||result?.result.message_test?signatureTamperResult:ciphertextCheck;
 return panel(S.alg+'-'+S.param,(!isHost()&&S.alg==='ML-DSA'&& !complete?remoteInputFields():'')+
  actions(...list.map((k,i)=>B('sec:'+k,cases[k],i===0?'primary':'',S.busy||!isLive()||!supported(k))))+hint)+
  runLog('security')+(result?.result.security_input?panel('本次输入与变更',securityEvidence(result.result)):'')+
  renderResult(result);
}
