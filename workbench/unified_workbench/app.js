"use strict";
const S={data:null,view:'parameters',alg:'ML-KEM',param:768,platform:'windows',profile:'low-memory',boardProfiles:{},revision:0,
 tabs:{crypto:'operations'},perfPlatform:null,perfProfiles:{},perfParam:768,perfOperation:'keygen',perfArithmetic:'mul',perfResult:'crypto',last:{},refs:{},flow:{},expanded:null,materialViewRequest:null,busy:false,deploying:null,job:null,logs:{},
 messageMode:'text',msg:'This is a test message.',ctx:'',file:null,messageRequest:null,remoteMessage:32,remoteContext:0,arith:'mul',preset:'monomial',width:4,arInputs:{},suite:'acvp',caseIds:[],casePick:'subset',caseError:false,caseRequest:null,
 notice:'',vectorOperationFilter:'all',vectorFailuresOnly:false,savedVectorFilter:'all',savedVectorFailures:false};
const $=id=>document.getElementById(id);
const token=document.querySelector('meta[name=workbench-token]').content;
const coefficientReads=new WeakMap();
let nativeCoefficientTarget=null;
const previousDetails=[];
let activeDetail=null;
const renderers={parameters,crypto:cryptoView,arithmetic:arithmeticView,resources,security:securityView};
function currentView(){return Object.hasOwn(pages,location.hash.slice(1))?location.hash.slice(1):'parameters';}
function fitScrollRoom(top){
 const scroller=document.scrollingElement, room=$('scroll-room');
 const contentHeight=scroller.scrollHeight-room.offsetHeight;
 // Keep the current offset when closing a result makes the document shorter.
 const height=Math.max(0,Math.ceil(top+scroller.clientHeight-contentHeight));
 if(room.offsetHeight!==height)room.style.height=height+'px';
}
function keepScroll(update){
 const scroller=document.scrollingElement, top=scroller.scrollTop;
 try{update();}finally{
  fitScrollRoom(top);
  scroller.scrollTop=top;
 }
}
function notify(text){
 S.notice=text||'';
 const notice=$('notice');
 if(notice.textContent!==S.notice)keepScroll(()=>{notice.textContent=S.notice;});
}
async function api(path,body,progressId){
 const headers=/^(progress|traffic)\//.test(path)||body!==undefined?{'X-Workbench-Token':token}:{};
 const options=body===undefined?{headers}:{method:'POST',headers,body:JSON.stringify(body)};
 if(body!==undefined)headers['Content-Type']='application/json';
 if(progressId)headers['X-Workbench-Progress']=progressId;
 const timeout=new AbortController();
 const deadline=path==='deploy-stm32'?1500000:195000;
 const timer=setTimeout(()=>timeout.abort(),deadline);
 let value;
 try{
  const response=await fetch('/wb/'+path,{...options,cache:'no-store',signal:timeout.signal});
  try{value=await response.json();}catch{throw new Error('未收到完整结果。');}
  if(!response.ok){
   const error=new Error(value.error||'操作未完成');
   error.runLog=value.run_log;
   throw error;
  }
 }catch(err){
  if(err.name==='AbortError')throw new Error('等待响应超时。');
  if(err.name==='TypeError')throw new Error('连接中断。');
  throw err;
 }finally{clearTimeout(timer);}
 return value;
}
function draw(){
 if(!S.data)return;
 keepScroll(()=>{
  S.view=currentView();renderGlobal();$('content').innerHTML=renderers[S.view]();
  $('notice').textContent=S.notice;
  for(const [key,log] of Object.entries(S.logs)){
   if(log.running||log.status==='运行失败')scrollRunLog(key);
  }
 });
 loadVectors();
}
function messageSizeText(){
 const bytes=S.messageMode==='text'?new TextEncoder().encode(S.msg).length:S.file?.hex.length/2;
 return Number.isFinite(bytes)?'消息大小 '+num(bytes)+' B':'';
}
function msgPayload(){
 return S.messageMode==='file'&&S.file?{message_hex:S.file.hex,context:S.ctx}:{message:S.msg,context:S.ctx};
}
function renderDetail(frame){
 $('dialog-title').textContent=frame.title;
 $('dialog-body').replaceChildren(frame.body);
}
function showDialog(title,html,record=null){
 const body=document.createElement('div'), dialog=$('detail');
 const opener=document.activeElement;
 body.innerHTML=html;
 const frame={title,body,record,opener};
 keepScroll(()=>{
  if(activeDetail){
   activeDetail.scroll=dialog.scrollTop;
   previousDetails.push(activeDetail);
  }
  activeDetail=frame;
  renderDetail(frame);
  if(!dialog.open)dialog.showModal();
  $('dialog-close').focus({preventScroll:true});
  dialog.scrollTop=0;
 });
 return frame;
}
function closeAllDialogs(){
 const dialog=$('detail');
 if(!dialog.open)return;
 const root=previousDetails[0]||activeDetail;
 keepScroll(()=>{
  previousDetails.length=0;
  activeDetail=null;
  dialog.close();
  $('dialog-body').replaceChildren();
  root?.opener?.focus({preventScroll:true});
 });
}
function closeDialog(){
 if(!previousDetails.length){closeAllDialogs();return;}
 const child=activeDetail;
 keepScroll(()=>{
  activeDetail=previousDetails.pop();
  renderDetail(activeDetail);
  const opener=activeDetail.body.contains(child.opener)?child.opener:$('dialog-close');
  opener.focus({preventScroll:true});
  $('detail').scrollTop=activeDetail.scroll;
 });
}
function refKey(){return S.alg+'-'+S.param+'-'+S.profile;}
function activeMaterials(){return S.refs[refKey()];}
function rememberMaterials(value){
 if(value?.id)S.refs[refKey()]={...value,configuration:cfg()};
}
function releaseMaterials(ref){
 if(ref?.id)api('clear-materials',{...ref.configuration,object_ref:ref.id}).catch(()=>{});
}
function materialRequest(field){
 const ref=activeMaterials();
 return {...cfg(),object_ref:ref?.id,field};
}
function modifiedSecretRequest(record){
 const {algorithm,parameter,platform,profile,source_kind,request_id}=record;
 return {algorithm,parameter,platform,profile,source_kind,request_id,field:'modified_shared_secret'};
}
function clearMaterialView(field){
 if(!field||S.expanded?.field===field)S.expanded=null;
 S.materialViewRequest=null;
}
function redrawMaterials(field){
 if(field==='modified_shared_secret'){
  draw();document.querySelector('[data-act="show-material:modified_shared_secret"]')?.focus({preventScroll:true});return;
 }
 const panel=$('crypto-materials');
 if(!panel)return;
 keepScroll(()=>{
  panel.innerHTML=materialsView();
  if(field)panel.querySelector('[data-act="show-material:'+field+'"]')?.focus({preventScroll:true});
 });
}
async function copyMaterial(field){
 if(S.expanded?.field!==field)return;
 const {hex}=S.expanded;
 try{await navigator.clipboard.writeText(hex);}
 catch{
  keepScroll(()=>{
   const input=document.createElement('textarea'), previous=document.activeElement;
   input.className='clipboard-text';input.value=hex;input.setAttribute('aria-hidden','true');
   document.body.append(input);input.focus({preventScroll:true});input.select();
   try{if(!document.execCommand('copy'))throw new Error('复制失败。');}
   finally{input.remove();previous?.focus({preventScroll:true});}
  });
 }
 notify('已复制'+materialLabels[field]+'。');
}
async function saveMaterial(field){
 const ref=activeMaterials(), version=S.revision;
 const {url}=await api('save-material',materialRequest(field));
 if(S.revision!==version||ref!==activeMaterials()||currentView()!=='crypto'||S.tabs.crypto!=='operations')return;
 const link=document.createElement('a');
 link.href=url;link.download='';document.body.append(link);
 try{link.click();}finally{link.remove();}
}
function showTestDetail(rec,row){
 const operation=rec.kind==='arithmetic'?S.data.arithmetic.operations.find(v=>v.id===rec.operation)?.title:
  opNames[row.operation||rec.operation]||recordLabel(rec);
 const fields=[['设备',E(platformLabel(rec)+' · '+pName(rec.profile))],
  ['参数',E(row.parameter??rec.parameter)],['结果',E(row.summary||rec.status)]];
 if(rec.kind==='performance'){
  fields.push(['操作核验',badge(row.verified?'通过':'失败',row.verified)]);
  if(rec.result.clock_hz)fields.push(['处理器频率',num(rec.result.clock_hz/1e6)+' MHz']);
  if(rec.result.timing_method)fields.push(['计时方式',E(rec.result.timing_method)]);
  if(rec.build_id)fields.push(['构建标识','<code>'+E(rec.build_id)+'</code>']);
  if(Number.isInteger(row.workspace_bytes))fields.push(['临时缓冲区容量（工作区）',num(row.workspace_bytes)+' B']);
  if(Number.isInteger(row.workspace_used_bytes))fields.push(['临时缓冲区实测峰值（工作区）',num(row.workspace_used_bytes)+' B']);
 }
 for(const [key,label] of [['return_code','返回码'],['expected_return_code','预期返回码'],
                           ['status_code','返回码'],['cycles','周期'],
                           ['duration_ms','耗时（ms）'],['duration_ns','耗时（ns）'],['function','调用函数']]){
  if(row[key]!=null)fields.push([label,E(row[key])]);
 }
 const names={...fieldNames,message:'消息',context:'上下文'};
 const materials=(entries,direction)=>Object.entries(entries||{}).filter(([,value])=>
  Number.isInteger(value?.length)||Number.isInteger(value)).map(([key,value])=>{
   const length=num(value.length??value)+' B', title=direction+' · '+(names[key]||key);
   return typeof value.hex==='string'&&value.hex.length?
    details(title+' · '+length,'<pre class="material-hex">'+hexLines(value.hex.toUpperCase())+'</pre>'):
    pairs([[title,E(length)]]);
  }).join('');
 const inputs=materials(row.inputs,'输入'), outputs=materials(row.public_outputs,'输出');
 const checks=Object.entries(row.checks||{}).filter(([,value])=>typeof value==='boolean').map(([key,value])=>
  [({shared_secret_equal:'共享秘密一致',signature_verified:'验签结果',modified_signature_rejected:'篡改签名被拒绝',
     operation_verified:'操作核验',canaries_ok:'缓冲区保护',used_workspace_erased:'工作区清理',
     failure_output_zero:'失败输出清零',original_shared_secret_equal:'原始共享秘密一致',
     replacement_matches_fips203:'替代共享秘密独立核验',differs_from_original:'替代共享秘密与原值不同',
     original_signature_verified:'原始验签通过',modified_message_rejected:'修改消息后拒绝验签',
     modified_signature_rejected:'修改签名后拒绝验签'})[key]||key,
   badge(value?'通过':'失败',value)]);
 if(row.input_fixture)fields.push(['公开向量',E(row.input_fixture)]);
 let body=(inputs||outputs?details('输入与输出',inputs+outputs):
   rec.kind==='performance'&&row.return_code!=null&&rec.source_kind==='live_board'?
    '<p class="muted">板载完整流程回传了周期与核验结果。「公开向量 · 可查看字节」可查看同次计时的输入输出。</p>':'')+
  (checks.length?details('检查结果',pairs(checks)):'')+
  (row.findings?.length?pairs(row.findings.map(item=>[E(item.label),E(item.value)])):'');
 if(rec.kind==='arithmetic'&&row.output)body=details('输入与输出',
  Object.entries({...row.inputs,expected_output:row.expected_output,output:row.output,native_output:row.native_output})
  .filter(([,values])=>Array.isArray(values)).map(([key,values])=>
   '<h3>'+E({a:'多项式 A',b:'多项式 B',output:'实际结果',expected_output:'独立预期值',native_output:'板端原始代表元'}[key]||key)+
   '</h3><pre>'+E(values.join(', '))+'</pre>').join(''));
 if(rec.kind==='arithmetic'&&row.output_hex)body=details('输入与输出',
  '<h3>独立预期值</h3><pre class="material-hex">'+hexLines(row.expected_output_hex||'')+'</pre>'+
  '<h3>实际结果</h3><pre class="material-hex">'+hexLines(row.output_hex)+'</pre>');
 const log=rec.kind==='security'&&row.log?.length?details('运行日志',
  '<ol class="run-log-list">'+runLogEntries({entries:row.log})+'</ol>'):'';
 const comm=rec.traffic?details('原始收发','<ol class="run-log-list">'+trafficRows(rec.traffic.frames,'record')+'</ol>'+
  actions(trafficSave(rec.request_id))):'';
 showDialog(operation||'测试详情',pairs(fields)+(rec.kind==='security'&&row.security_input?
  details('本次输入与变更',securityEvidence(row)):'')+body+codeLinks(rec)+log+comm,rec);
}
function resetVectors(){
 S.caseIds=[];S.casePick=S.suite==='acvp'?'subset':'all';S.caseError=false;S.caseRequest=null;
}
async function loadVectors(){
 if(S.view!=='crypto'||S.tabs.crypto!=='vectors'||!isHost()||S.caseRequest||S.caseIds.length||S.caseError)return;
 const request={};
 S.caseRequest=request;
 try{
  const ids=await api('cases',{...cfg(),suite:S.suite});
  if(S.caseRequest===request){S.caseIds=ids;S.caseError=!ids.length;}
 }catch{
  if(S.caseRequest===request)S.caseError=true;
 }finally{
  if(S.caseRequest===request){S.caseRequest=null;draw();}
 }
}
function coefficientList(text){return String(text||'').trim().split(/[\s,，]+/).filter(Boolean).map(v=>{if(!/^[+-]?\d+$/.test(v)||!Number.isSafeInteger(Number(v)))throw new Error('每个系数均须为整数');return Number(v);});}
function setArithmeticInput(field,value){
 S.arInputs[field]=value;
 if(S.last.arithmetic){
  delete S.last.arithmetic;
  keepScroll(()=>$('arithmetic-result')?.replaceChildren());
 }
}
async function loadCoefficients(area,name,readBytes){
 const request={};coefficientReads.set(area,request);
 const current=()=>area.isConnected&&!S.busy&&coefficientReads.get(area)===request;
 try{
  if(!/\.txt$/i.test(name))throw new Error('请选择 .txt 文件。');
  let text;
  try{
   const bytes=new Uint8Array(await readBytes());
   const encoding=bytes[0]===255&&bytes[1]===254?'utf-16le':bytes[0]===254&&bytes[1]===255?'utf-16be':'utf-8';
   text=new TextDecoder(encoding,{fatal:true}).decode(bytes).trim();
  }catch{throw new Error('无法读取文本，请检查文件编码。');}
  if(!current())return;
  const count=coefficientList(text).length;
  const scalar=S.data.arithmetic.operations.find(op=>op.id===S.arith)?.input==='scalar';
  if(count!==256&&!(scalar&&count===1))throw new Error('需要 '+(scalar?'1 或 256':'256')+' 个整数，文件中有 '+count+' 个。');
  area.value=text;setArithmeticInput(area.id,text);notify('');
  area.focus({preventScroll:true});
 }catch(error){
  if(current())notify(error.message);
 }finally{
  if(coefficientReads.get(area)===request)coefficientReads.delete(area);
 }
}
function acceptNativeCoefficients(value){
 const area=nativeCoefficientTarget;
 if(!area)return;
 const prefix='coefficients-'+area.id+'-file';
 if(!value.startsWith(prefix))return;
 nativeCoefficientTarget=null;
 if(!area.isConnected||S.busy||value===prefix+'-cancelled')return;
 const newline=value.indexOf('\n',prefix.length+1);
 if(value.startsWith(prefix+':')&&newline>=0){
  const hex=value.slice(prefix.length+1,newline);
  loadCoefficients(area,value.slice(newline+1),()=>Uint8Array.from(hex.match(/../g)||[],part=>parseInt(part,16)));
 }else notify(value===prefix+'-too-large'?'文件太大，无法读取。':'文件读取失败。');
}
function beginCryptoStep(op){
 const ops=S.data.parameters[S.param].operations, start=ops.indexOf(op), key=refKey();
 if(start>=0){
  for(const later of ops.slice(start))delete S.flow[later];
 }else delete S.flow[op];
 if(start===0){
  releaseMaterials(S.refs[key]);delete S.refs[key];clearMaterialView();
 }else if(start===1 && S.refs[key]){
  const field=op==='encaps'?'ciphertext':'signature';
  delete S.refs[key].lengths[field];clearMaterialView(field);
  if(op==='encaps'){
   delete S.refs[key].lengths.shared_secret;
   clearMaterialView('shared_secret');
  }
  S.refs[key].can_retest=false;
 }
 if((op==='encaps'||op==='decaps')&&S.refs[key]){
  delete S.refs[key].lengths.decapsulated_secret;
  S.refs[key].can_retest=false;
  clearMaterialView('decapsulated_secret');
 }
}
function saveCryptoStep(rec){
 S.flow[rec.operation]=rec;
 rememberMaterials(rec.result.materials);
}
function applyFullFlow(record){
 for(const row of record.result.rows||[]){
  if(!Object.hasOwn(opNames,row.operation))continue;
  S.flow[row.operation]={...record,operation:row.operation,result:row,verification:row.verified};
 }
 rememberMaterials(record.result.materials);
}
function clearSignatureCheck(){
 if(S.alg!=='ML-DSA')return;
 delete S.flow.verify;
 if(['完整流程','verify'].includes(S.last.crypto?.operation))delete S.last.crypto;
 if($('crypto-results'))keepScroll(()=>{$('crypto-results').innerHTML=cryptoResults();});
}
function beginRunLog(key,title,remote=false){
 const log={title,entries:[],running:true,status:'',remote,traffic:{frames:[],omitted:0},mode:'progress'};
 S.logs[key]=log;
 return log;
}
function scrollRunLog(key){
 const entries=$('run-log-'+key+'-entries');
 if(entries)entries.scrollTop=entries.scrollHeight;
}
function updateRunLog(key,log,entries){
 if(!entries?.length||entries.length===log.entries.length&&entries.every((line,i)=>line===log.entries[i]))return;
 log.entries=entries;
 const list=$('run-log-'+key+'-entries');
 if(list&&S.logs[key]===log){
  list.innerHTML=runLogEntries(log);
  scrollRunLog(key);
 }
}
function finishRunLog(log,record,error){
 const result=record?.result;
 if(record?.traffic)log.traffic=record.traffic;
 log.recordId=record?.request_id;
 log.running=false;
 log.status=record?.status==='已取消'?'已取消':record?.verification?'运行完成':'运行失败';
 const last=error?.message||result?.summary||record?.status;
 if(last&&!(record?.kind==='security'&&result?.log?.length)&&log.entries.at(-1)!==last)
  log.entries=[...log.entries.slice(-63),last];
}
async function pollTraffic(key,log,id){
 if(log.mode!=='traffic')return;
 try{
  const next=await api('traffic/'+id+'?from='+log.traffic.frames.length);
  if(!log.running||S.logs[key]!==log)return;
  const from=log.traffic.frames.length;
  log.traffic.frames.push(...next.frames);
  log.traffic.omitted=next.omitted;
  const list=$('run-log-'+key+'-traffic');
  if(list&&next.frames.length){
   $('run-log-'+key+'-empty')?.remove();
   list.insertAdjacentHTML('beforeend',trafficRows(next.frames,key,from));
   list.scrollTop=list.scrollHeight;
  }
 }catch{}
}
async function watchRunLog(key,log,id){
 while(log.running){
  await new Promise(resolve=>setTimeout(resolve,180));
  if(!log.running)return;
  try{
   const entries=await api('progress/'+id);
   if(log.running)updateRunLog(key,log,entries);
  }catch{}
  await pollTraffic(key,log,id);
 }
}
function progressTitle(action,body){
 const parameter=body.algorithm+'-'+body.parameter;
 if(action==='arithmetic')return parameter+' '+S.data.arithmetic.operations.find(row=>row.id===body.operation).title;
 if(action==='performance')return parameter+' '+opNames[body.operation];
 if(action==='board-vectors')return 'NIST ACVP';
 if(action==='board-suite')return parameter+' '+(cases[body.test]||'完整流程');
 if(action==='security')return cases[body.case];
 return parameter+' '+opNames[body.operation];
}
async function perform(action,body,key){
 if(S.busy)return;
 const revision=S.revision;
 delete S.last[key];
 if(action==='crypto')beginCryptoStep(body.operation);
 const logKey=key==='boardVectors'?'vectors':key;
 const log=beginRunLog(logKey,progressTitle(action,body),body.platform!==S.data.local_platform);
 const id=window.crypto.randomUUID().replaceAll('-','');
 S.busy=true;notify('');draw();
 watchRunLog(logKey,log,id);
 try{
  const r=await api(action,body,id);
  updateRunLog(logKey,log,r.run_log||r.result?.log);
  delete r.run_log;
  finishRunLog(log,r);
  if(S.revision===revision){
   S.last[key]=r;
   if(action==='crypto')saveCryptoStep(r);
  }
 }catch(error){
  updateRunLog(logKey,log,error.runLog);
  finishRunLog(log,null,error);
 }finally{
  if(action==='board-suite'||action==='board-vectors'||
      (['arithmetic','performance','security'].includes(action)&&body.platform!==S.data.local_platform))await refreshPlatforms();
  S.busy=false;draw();
 }
}
async function refreshPlatforms(){
 try{S.data.platforms=(await api('catalog')).platforms;}catch{}
}
async function batch(mode,config=cfg()){
 if(S.busy)return;S.busy=true;
 const outputKey={parameter:'crypto',vectors:'vectors',all:'batch',performance:'performance'}[mode], revision=S.revision;
 const remote=config.platform!==S.data.local_platform;
 delete S.last[outputKey];
 if(mode==='vectors'){S.vectorOperationFilter='all';S.vectorFailuresOnly=false;}
 if(mode==='parameter'){
  releaseMaterials(activeMaterials());delete S.refs[refKey()];S.flow={};clearMaterialView();
 }
 const title={parameter:S.alg+'-'+S.param+' 完整流程',all:'全部 18 项',performance:'18 项性能测试',
              vectors:S.suite==='acvp'?'NIST ACVP':'Wycheproof'}[mode];
 const log=beginRunLog(outputKey,title,remote);
 notify('');draw();
 try{
  const q={...config,mode};
  if(mode==='vectors')Object.assign(q,{suite:S.suite,case_id:S.casePick});
  if(mode==='all'&&!isHost())Object.assign(q,remoteInputs());
  else if(mode==='all'||(mode==='parameter'&&S.alg==='ML-DSA'))Object.assign(q,msgPayload());
  const {request_id}=await api('batch',q);
  S.job={id:request_id,key:outputKey};draw();
  for(;;){
   const next=await api('job/'+request_id);
   const counts='已执行 '+next.done+'/'+next.total+' · 通过 '+next.passed+' · 失败 '+(next.done-next.passed);
   const entries=mode==='vectors'&&next.result?[...next.log.slice(-63),counts]:next.log;
   updateRunLog(outputKey,log,entries);
   if(!next.result)await pollTraffic(outputKey,log,request_id);
   if(next.result){
    finishRunLog(log,next.result);
    if(S.revision===revision){
     S.last[outputKey]=next.result;
     if(mode==='parameter')applyFullFlow(next.result);
    }
    break;
   }
   await new Promise(resolve=>setTimeout(resolve,140));
  }
 }catch(error){
  finishRunLog(log,null,error);
 }finally{
  if(remote)await refreshPlatforms();
  S.busy=false;S.job=null;draw();
 }
}
function clearPerformanceResults(){
 for(const key of ['performance','performanceArithmetic']){
  delete S.last[key];delete S.logs[key];
 }
}
function switchConfig(){
 S.revision++;
 S.messageRequest=null;
 Object.values(S.refs).forEach(releaseMaterials);
 const security=S.last.security;
 if(security?.result.ciphertext_test?.modified_secret_available)
  api('clear-materials',modifiedSecretRequest(security)).catch(()=>{});
 S.refs={};S.flow={};clearMaterialView();resetVectors();S.last={};S.logs={};S.notice='';
 closeAllDialogs();
 if(S.data.arithmetic.operations.find(o=>o.id===S.arith)?.widths)S.width=S.param===1024?5:4;
 draw();
}
async function dispatch(action){
 const [name,a,b]=action.split(':');
 const parentDetail=activeDetail, view=currentView();
 if(name==='nav'){location.hash=a;return;}
 if(name==='log-view'){
  const log=S.logs[a], before=$('run-log-'+a+'-body');
  if(!log||!before||log.mode===b)return;
  log.mode=b;
  keepScroll(()=>{before.outerHTML=runLogBody(a,log);});
  const list=$('run-log-'+a+'-traffic');
  if(list)list.scrollTop=list.scrollHeight;
  return;
 }
 if(name==='traffic-frame'){
  const frame=(a==='record'?activeDetail?.record?.traffic:S.logs[a]?.traffic)?.frames[Number(b)];
  if(frame?.hex)showDialog(frame.direction+' '+frame.link,pairs([
   ['操作',E(frame.description)],['长度',num(frame.bytes)+' B']
  ])+'<pre>'+hexLines(frame.hex)+'</pre>');
  return;
 }
 if(name==='tab'){S.tabs[S.view]=a;S.notice='';clearMaterialView();draw();return;}
 if(name==='view-source'){
  const path=decodeURIComponent(a);
  if(!S.data.files.includes(path))return;
  const response=await fetch('/wb/file?p='+encodeURIComponent(path));
  if(!response.ok)throw new Error('读取代码失败。');
  const code=await response.text();
  if(activeDetail===parentDetail&&currentView()===view)showDialog(path.split('/').at(-1),'<pre>'+E(code)+'</pre>');
  return;
 }
 if(name==='test-detail'){
  const [key,index]=[a,b];
  const record=key==='flow'?S.flow[index]:key==='record'?activeDetail?.record:S.last[key];
  if(!record)return;
  const row=index!=null&&key!=='flow'?(record.result.steps||record.result.rows)?.[Number(index)]:record.result;
  if(row)showTestDetail(record,row);
  return;
 }
 if(name==='performance-connect'){
  const {target,profile}=performanceSelection();
  if(S.busy||target.id===S.data.local_platform||!target.configured)return;
  S.perfPlatform=target.id;
  const parameter=S.perfParam, algorithm=S.data.parameters[parameter].algorithm;
  S.busy=true;notify('正在连接 '+target.title+'…');draw();
  try{
   S.data=await api('connect',{platform:target.id,profile:profile.id,parameter,algorithm});
   const connected=performanceSelection();
   if(connected.profile.id!==profile.id)clearPerformanceResults();
   if(!connected.target.profiles.some(item=>item.available))notify('连接失败，请检查设备。');
   else notify('');
  }catch(error){await refreshPlatforms();throw error;}
  finally{S.busy=false;draw();}
  return;
 }
 if(name==='performance-result'){S.perfResult=a;draw();return;}
 if(['performance-current','performance-batch','performance-arithmetic'].includes(name)){
  const {target,profile}=performanceSelection(), arithmetic=name==='performance-arithmetic';
  const algorithm=S.data.parameters[S.perfParam].algorithm;
  if(S.busy||(arithmetic?
   !performanceArithmeticOperations(target,profile,algorithm).some(item=>item.id===S.perfArithmetic):
   !profile.operation_timing))return;
  S.perfProfiles[target.id]=profile.id;
  S.perfResult=arithmetic?'arithmetic':'crypto';
  const q={platform:target.id,profile:profile.id,algorithm,parameter:S.perfParam,
   operation:arithmetic?S.perfArithmetic:S.perfOperation,source_kind:isBoard(target.id)?'live_board':'live_host'};
  if(!arithmetic&&isBoard(target.id))q.performance_input=profile.board_vectors?'vector':'flow';
  if(arithmetic)await perform('arithmetic',{...q,preset:'random'},'performanceArithmetic');
  else if(name==='performance-batch')await batch('performance',q);
  else await perform('performance',q,'performance');
  return;
 }
 if(name==='deploy-board'){
  const platform=S.platform, profile=S.profile, target=selectedTarget();
  if(S.busy||!target?.can_deploy)return;
  if(!window.confirm('将连接的 '+target.title+' 部署为 '+pName(profile)+' 正式固件？'))return;
  S.busy=true;S.deploying=platform;notify('正在部署和核验固件…');draw();
  try{
   S.data=await api(platform==='stm32f407'?'deploy-stm32':'deploy-ch32',{platform,profile});
   S.platform=platform;S.profile=profile;S.boardProfiles[platform]=profile;switchConfig();
   notify('已核验 '+pName(profile)+' 固件。');
  }catch(error){await refreshPlatforms();throw error;}
  finally{S.busy=false;S.deploying=null;draw();}
  return;
 }
 if(name==='connect'){
  S.last={};S.logs={};S.busy=true;notify('正在连接…');draw();
  try{
   S.data=await api('connect',cfg());
   const detected=selectedTarget().profiles.find(p=>p.available);
   if(!isLive()&&detected&&isBoard()&&!S.boardProfiles[S.platform]){
    S.profile=detected.id;switchConfig();
   }
   notify(isLive()||isBoard()&&detected?'':'连接失败。');
  }catch(error){await refreshPlatforms();throw error;}
  finally{S.busy=false;draw();}return;
 }
 if(name==='retry-cases'){resetVectors();draw();return;}
 if(name==='run-vectors'){
  if(isHost()&&S.casePick!=='subset'){
   delete S.last.boardVectors;
   await batch('vectors');
  }else{
   delete S.last.vectors;
   S.vectorOperationFilter='all';S.vectorFailuresOnly=false;
   const pick=S.casePick;
   await perform('board-vectors',{...cfg(),all_cases:pick==='subset',
    case_id:['subset','all'].includes(pick)?undefined:pick},'boardVectors');
  }
  return;
 }
 if(name==='board-case'){
  const record=a==='live'?S.last.boardVectors:a==='saved'?activeDetail?.record:null;
  const row=record?.result.rows?.[b];
  if(!row)return;
  const frame=showDialog('测试用例 tc'+row.tc_id,'<p id="board-case-loading">正在载入…</p>');
  const loading=frame.body.querySelector('#board-case-loading');
  try{
   const detail=await api('board-vector-detail',{case_id:row.case_id,request_id:record.request_id});
   keepScroll(()=>{loading.outerHTML=boardVectorDetail(row,detail)+codeLinks(record,'vectors');});
  }catch(error){
   loading.textContent=error.message;
  }
  return;
 }
 if(name==='vector-detail'){
  const record=S.last.vectors, row=record?.result.rows?.[a];
  if(!row)return;
  const frame=showDialog(row.tc_id==null?row.case_id||row.operation:'测试用例 '+row.tc_id,
   vectorComparison(row,record)+codeLinks(record,'vectors'));
  if(!Object.keys(row.input_lengths||{}).length&&!Object.keys(row.output_checks||{}).length)return;
  const fields=frame.body.querySelector('#vector-case-inputs'), outputs=frame.body.querySelector('#vector-case-outputs');
  try{
   const values=await api('vector-inputs',{request_id:record.request_id,case_id:row.case_id,include_outputs:true});
   keepScroll(()=>{
    fields.innerHTML=vectorInputFields(row,values.inputs);
    outputs.innerHTML=vectorOutputs(row,values.outputs);
   });
  }catch(error){
   keepScroll(()=>{fields.insertAdjacentHTML('beforeend','<p class="muted">'+E(error.message)+'</p>');});
  }
  return;
 }
 if(name==='batch'){await batch(a);return;}
 if(name==='cancel'&&S.job){
  const job=S.job;
  job.cancelling=true;
  const cancelButton=document.querySelector('[data-act="cancel"]');
  if(cancelButton)cancelButton.disabled=true;
  try{await api('cancel',{request_id:job.id});}
  catch(error){job.cancelling=false;if(cancelButton)cancelButton.disabled=false;throw error;}
  return;
 }
 if(name==='show-material'){
  const modified=a==='modified_shared_secret';
  const ref=modified?S.last.security:activeMaterials();
  if(modified&&!ref?.result.ciphertext_test?.modified_secret_available)return;
  const closing=S.expanded?.field===a;
  clearMaterialView();redrawMaterials(a);
  if(closing)return;
  const request={};
  S.materialViewRequest=request;
  try{
   const {hex}=await api('show-material',modified?modifiedSecretRequest(ref):materialRequest(a));
   const current=modified?ref===S.last.security&&currentView()==='security':
    ref===activeMaterials()&&currentView()==='crypto'&&S.tabs.crypto==='operations';
   if(S.materialViewRequest===request&&current&&!S.busy){
    S.expanded={field:a,hex};redrawMaterials(a);
   }
  }catch(err){
   if(S.materialViewRequest===request)throw err;
  }finally{
   if(S.materialViewRequest===request)S.materialViewRequest=null;
  }
  return;
 }
 if(name==='copy-material'){await copyMaterial(a);return;}
 if(name==='save-material'){
  if(a==='secret_key'){
   showDialog('保存私钥','<p>私钥文件未加密。</p>'+actions(B('confirm-save-key','继续保存','primary'),B('close-detail','取消')));
  }else await saveMaterial(a);
  return;
 }
 if(name==='close-detail'){closeDialog();return;}
 if(name==='confirm-save-key'){closeDialog();await saveMaterial('secret_key');return;}
 if(name==='import-bin'){
  const payload=S.alg==='ML-KEM'?'ciphertext':'signature';
  showDialog('导入 .bin',actions(...['public_key','secret_key',payload].map(field=>
   B('pick-material:'+field,'导入'+materialLabels[field])),
   activeMaterials()?B('clear-materials','清除当前数据'):''));
  return;
 }
 if(name==='pick-material'){
  const file=$('material-file');file.dataset.field=a;file.click();return;
 }
 if(name==='clear-materials'){
  closeDialog();S.busy=true;draw();
  try{
   await api(name,materialRequest());delete S.refs[refKey()];S.flow={};clearMaterialView();delete S.last.crypto;notify('');
  }finally{S.busy=false;draw();}
  return;
 }
 if(name==='pick-message'){
  if(window.__nativeMessagePicker&&window.chrome?.webview)window.chrome.webview.postMessage('pick-message-file');
  else $('msgfile').click();
  return;
 }
 if(name==='op'){
  const input=a==='sign'||a==='verify'?msgPayload():{};
  await perform('crypto',{...cfg(),...input,operation:a,object_ref:activeMaterials()?.id},'crypto');return;
 }
 if(name==='board-suite'||name==='remote-test'){
  await perform('board-suite',{...cfg(),...remoteInputs(),test:a},name==='remote-test'?'security':'crypto');return;
 }
 if(name==='sec'){
  clearMaterialView('modified_shared_secret');
  const ref=activeMaterials();
  const useCurrent=a==='ciphertext'||((a==='message'||a==='signature')&&S.flow.verify?.verification);
  const object_ref=useCurrent&&ref?.can_retest?ref.id:undefined;
  await perform('security',{...cfg(),...remoteInputs(),case:a,operation:cases[a],object_ref},'security');return;
 }
 if(name==='reset-input'){S.arInputs={};S.preset='monomial';delete S.last.arithmetic;delete S.logs.arithmetic;draw();return;}
 if(name==='pick-coefficients'){
  if(window.__nativeCoefficientPicker&&window.chrome?.webview){
   if(nativeCoefficientTarget)return;
   nativeCoefficientTarget=$(a);window.chrome.webview.postMessage('pick-coefficients-'+a);
  }else{
   const input=$('arithmetic-file');input.dataset.field=a;input.click();
  }
  return;
 }
 if(name==='arithmetic'){
  if(coefficientReads.has($('a'))||coefficientReads.has($('b'))){notify('正在读取系数文件。');return;}
  const op=S.data.arithmetic.operations.find(o=>o.id===S.arith),q={...cfg(),operation:S.arith,preset:S.preset};
  if(op.widths)q.width=Number(S.width);
  if(op.input==='seed'){
   if(S.arInputs.seedhex)q.seed_hex=S.arInputs.seedhex.trim();
   for(const f of ['row','column','index'])if(S.arInputs[f]!==undefined)q[f]=Number(S.arInputs[f]);
  }else if(S.preset==='import'){
   if(op.input==='bytes')q.data_hex=(S.arInputs.datahex||'').trim();
   else {q.a=coefficientList(S.arInputs.a);if(op.input==='pair')q.b=coefficientList(S.arInputs.b);}
  }
  await perform('arithmetic',q,'arithmetic');return;
 }

}
document.addEventListener('click',e=>{
 const summary=e.target.closest('summary');
 if(summary&&summary.parentElement instanceof HTMLDetailsElement&&!e.defaultPrevented){
  const details=summary.parentElement;
  e.preventDefault();
  keepScroll(()=>{details.open=!details.open;});
  return;
 }
 const button=e.target.closest('[data-act]');if(!button||button.disabled)return;
 dispatch(button.dataset.act).catch(err=>{notify(err.message||'操作未完成');});
});
document.addEventListener('input',e=>{
 const el=e.target;
 if(el.id==='message'){S.msg=el.value;$('msgcounts').textContent=messageSizeText();clearSignatureCheck();}
 if(el.id==='context'){S.ctx=el.value;clearSignatureCheck();}
 if(['a','b','datahex','seedhex','row','column','index'].includes(el.id)){
  coefficientReads.delete(el);setArithmeticInput(el.id,el.value);
 }
});
document.addEventListener('change',async e=>{
 const el=e.target,v=el.value;
 const boardFilter=el.id?.match(/^vector-(operation-filter|failures-only)-(live|saved)$/);
 if(boardFilter){
  const [,kind,scope]=boardFilter, saved=scope==='saved';
  if(kind==='operation-filter')S[saved?'savedVectorFilter':'vectorOperationFilter']=v;
  else S[saved?'savedVectorFailures':'vectorFailuresOnly']=el.checked;
  const rows=(saved?activeDetail?.record:S.last.boardVectors)?.result.rows;
  if(rows)keepScroll(()=>{$('vector-filtered-'+scope).innerHTML=boardVectorRows(rows,scope);});
  return;
 }
 if(el.id==='vector-operation-filter'||el.id==='vector-failures-only'){
  if(el.id==='vector-operation-filter')S.vectorOperationFilter=v;
  else S.vectorFailuresOnly=el.checked;
  const container=$('vector-filtered-rows'),rows=S.last.vectors?.result.rows;
  if(container&&rows)keepScroll(()=>{container.innerHTML=vectorResultRows(rows);});
  return;
 }
 if(S.busy)return;
 if(el.id==='arithmetic-file'){
  const file=el.files[0],area=$(el.dataset.field);el.value='';
  if(file&&area)await loadCoefficients(area,file.name,()=>file.arrayBuffer());
  return;
 }
 if(el.name==='message-mode'){
  S.messageMode=v;S.messageRequest=null;S.notice='';
  clearSignatureCheck();draw();$(el.id)?.focus({preventScroll:true});return;
 }
 if(el.id==='material-file'){
  const file=el.files[0], field=el.dataset.field;
  el.value='';
  if(!file)return;
  closeDialog();
  const length=S.data.parameters[S.param][field];
  if(file.size!==length){notify(materialLabels[field]+'应为 '+length+' 字节，请检查文件和参数。');return;}
  S.busy=true;draw();
  try{
   const bytes=new Uint8Array(await file.arrayBuffer());
   const hex=Array.from(bytes,n=>n.toString(16).padStart(2,'0')).join('');
   rememberMaterials(await api('import-material',{...materialRequest(field),hex}));
   clearMaterialView();S.flow={};delete S.last.crypto;
   notify('已导入'+materialLabels[field]+'。');
  }catch(err){notify(err.message||'导入失败。');}
  finally{S.busy=false;draw();}
  return;
 }
 if(['perfPlatform','perfProfile','perfParam','perfOperation','perfArithmetic'].includes(el.id)){
  if(el.id==='perfProfile')S.perfProfiles[performanceSelection().target.id]=v;
  else S[el.id]=el.id==='perfParam'?Number(v):v;
  if(['perfPlatform','perfProfile'].includes(el.id)){
   clearPerformanceResults();S.notice='';
  }
  draw();
  $(el.id)?.focus({preventScroll:true});
  return;
 }
 if(el.id==='alg'){S.alg=v;S.param=v==='ML-KEM'?768:65;switchConfig();}
 if(el.id==='param'){S.param=Number(v);switchConfig();}
 if(el.id==='platform'){
  S.platform=v;
  if(!isHost())S.suite='acvp';
  const profiles=selectedTarget().profiles;
  S.profile=S.boardProfiles[v]||profiles.find(p=>p.available)?.id||profiles[0].id;
  switchConfig();
 }
 if(el.id==='profile'){
  S.profile=v;
  if(isBoard())S.boardProfiles[S.platform]=v;
  switchConfig();
  $('profile')?.focus({preventScroll:true});
 }
 if(el.id==='remoteMessage'||el.id==='remoteContext'){
  S[el.id]=Number(v);S.last={};draw();return;
 }
 if(el.id==='suite'){S.suite=v;resetVectors();delete S.last.vectors;delete S.last.boardVectors;delete S.logs.vectors;draw();}
 if(el.id==='casepick'){S.casePick=v;delete S.last.vectors;delete S.last.boardVectors;delete S.logs.vectors;draw();}
 if(el.id==='arithop'){S.arith=v;S.arInputs={};S.width=S.param===1024?5:4;delete S.last.arithmetic;delete S.logs.arithmetic;draw();}
 if(el.id==='preset'){S.preset=v;S.arInputs={};delete S.last.arithmetic;delete S.logs.arithmetic;draw();}
 if(el.id==='width'){S.width=Number(v);delete S.last.arithmetic;delete S.logs.arithmetic;draw();}
 if(el.id==='msgfile'){
  const f=el.files[0];if(!f||S.messageMode!=='file')return;
  S.file=null;S.messageRequest=null;clearSignatureCheck();
  if(f.size>65536){S.notice='文件超过 65,536 字节。';draw();return;}
  const request={};S.messageRequest=request;S.notice='';draw();
  try{
   const data=new Uint8Array(await f.arrayBuffer());
   if(S.messageRequest!==request)return;
   S.file={name:f.name,hex:Array.from(data,v=>v.toString(16).padStart(2,'0')).join('')};
  }catch{
   if(S.messageRequest===request)S.notice='文件读取失败。';
  }finally{
   if(S.messageRequest===request){S.messageRequest=null;draw();}
  }
 }
});
$('detail').setAttribute('aria-labelledby','dialog-title');
$('dialog-close').addEventListener('click',closeDialog);
$('detail').addEventListener('cancel',event=>{event.preventDefault();closeDialog();});
window.chrome?.webview?.addEventListener('message',event=>{
 const value=event.data;
 if(value==='export-saved'){notify('已保存。');return;}
 if(value==='export-failed'){notify('保存失败，请重试。');return;}
 if(typeof value!=='string')return;
 if(value.startsWith('coefficients-')){acceptNativeCoefficients(value);return;}
 if(!value.startsWith('message-file')||S.busy||S.messageMode!=='file'||!$('msgfile'))return;
 const prefix='message-file:';
 if(value.startsWith(prefix)){
  const newline=value.indexOf('\n',prefix.length);
  if(newline<0)return;
  S.file={name:value.slice(newline+1),hex:value.slice(prefix.length,newline)};
  S.notice='';
 }else if(value==='message-file-too-large'||value==='message-file-error'){
  S.file=null;
  S.notice=value==='message-file-too-large'?'文件超过 65,536 字节。':'文件读取失败。';
 }else return;
 S.messageRequest=null;clearSignatureCheck();draw();
});
window.addEventListener('scroll',()=>{
 if($('scroll-room').offsetHeight)fitScrollRoom(document.scrollingElement.scrollTop);
},{passive:true});
window.addEventListener('hashchange',()=>{
 S.notice='';clearMaterialView();closeAllDialogs();
 window.scrollTo(0,0);$('scroll-room').style.height='';draw();
 if(!matchMedia('(prefers-reduced-motion: reduce)').matches&&
    getComputedStyle(document.documentElement).getPropertyValue('--view-enter').trim()==='1'){
  for(const animation of $('content').getAnimations())animation.cancel();
  $('content').animate([{opacity:.65,transform:'translateY(4px)'},{opacity:1,transform:'translateY(0)'}],
   {duration:190,easing:'cubic-bezier(.2,.75,.28,1)'});
 }
});
(async()=>{
 try{S.data=await api('catalog');S.platform=S.data.local_platform;S.profile=selectedTarget().profiles.find(x=>x.available)?.id||'low-memory';draw();window.__platformReady=true;window.__ready=true;window.chrome?.webview?.postMessage('desktop-ready');}
 catch(err){notify('无法启动。'+err.message);}
})();
