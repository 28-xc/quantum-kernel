'use strict';
(() => {
 const panel=document.createElement('article');panel.className='panel';panel.id='deployment-builder';
 panel.innerHTML=`<h2>导出验证程序</h2>
 <div class="form-grid"><label>目标平台<select id="deploy-platform"></select></label><label>部署策略<select id="deploy-strategy"></select></label><label>常用功能<select id="deploy-preset"><option value="all">六组参数全部操作</option><option value="pair">768 / 65 全部操作</option><option value="client">封装与验签</option></select></label><label>工作区容量（KiB）<input id="deploy-workspace" type="number" min="1" max="1024" value="12"></label></div>
 <div id="deploy-operations" class="deploy-operations"></div>
 <div class="form-grid"><label>验证程序大小上限（KiB）<input id="deploy-program" type="number" min="1" max="4096" value="512"></label><label>验证程序内存上限（KiB）<input id="deploy-ram" type="number" min="1" max="4096" value="256"></label><label id="deploy-writable-label" hidden>可写区上限（KiB）<input id="deploy-writable" type="number" min="1" max="1024" value="64"></label></div>
 <p id="deploy-scope" class="muted"></p><div class="actions"><button id="deploy-start" class="primary" disabled>编译并验证</button><button id="deploy-request" class="secondary" disabled>下载功能与预算</button></div><div id="deploy-result" aria-live="polite"></div>`;
 document.querySelector('#page-resources article.panel').after(panel);
 const get=id=>document.getElementById(id),esc=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const parameters=[512,768,1024,44,65,87],names=p=>p>100?['keypair','encaps','decaps']:['keypair','sign','verify'];
 const titles={keypair:'密钥生成',encaps:'封装',decaps:'解封装',sign:'签名',verify:'验签'},strategyTitles={'low-memory':'低内存','performance':'性能'};
 get('deploy-operations').innerHTML=parameters.map(p=>`<fieldset><legend>${p>100?'ML-KEM':'ML-DSA'}-${p}</legend>${names(p).map(n=>`<label><input type="checkbox" data-parameter="${p}" value="${n}"> ${titles[n]}</label>`).join('')}</fieldset>`).join('');
 let catalog,building=false;
 const entry=()=>catalog?.platforms.find(x=>x.id===get('deploy-platform').value);
 const selectedStrategy=()=>entry()?.strategies.find(x=>x.id===get('deploy-strategy').value);
 function enabled(){const usable=entry()?.available&&selectedStrategy()?.available;get('deploy-start').disabled=building||!usable;get('deploy-request').disabled=!usable;}
 function preset(){const mode=get('deploy-preset').value;for(const x of panel.querySelectorAll('input[type=checkbox]')){const p=Number(x.dataset.parameter);x.checked=mode==='all'||mode==='pair'&&[768,65].includes(p)||mode==='client'&&(p===768&&x.value==='encaps'||p===65&&x.value==='verify');}}
 function strategy(){const chosen=selectedStrategy();if(chosen)get('deploy-workspace').value=chosen.workspace_bytes/1024;enabled();}
 function platform(){
  const current=entry(),previous=get('deploy-strategy').value;
  get('deploy-strategy').innerHTML=(current?.strategies||[]).map(x=>`<option value="${esc(x.id)}" ${x.available?'':'disabled'}>${esc(x.title)}${x.available?'':'（处理器不支持）'}</option>`).join('');
  const chosen=current?.strategies.find(x=>x.id===previous&&x.available)||current?.strategies.find(x=>x.available);
  if(chosen)get('deploy-strategy').value=chosen.id;
  get('deploy-writable-label').hidden=!current?.emulated;
  get('deploy-scope').textContent=!current?.available?'当前没有可用的构建目标，请检查本地工具链与处理器支持。':current.emulated?'此处进行指令仿真中的功能与资源验证。程序内存包含代码、向量常量、可写区、工作池及两类栈，堆为零；可写区另设上限。':'两种策略默认均保留六组参数的18项完整操作，可按需要明确裁剪功能。验证程序内存包含工作区、输入输出及64 KiB调用栈；核心资源另列。';
  strategy();
 }
 function request(){
  if(!entry()?.available||!selectedStrategy()?.available)throw Error('所选平台或处理器当前不支持该策略');
  const operations={};for(const x of panel.querySelectorAll('input[type=checkbox]:checked'))(operations[x.dataset.parameter]??=[]).push(x.value);
  const p=parameters.filter(x=>operations[x]);if(!p.length)throw Error('请至少选择一个密码操作');
  const integer=id=>{const n=Number(get(id).value);if(!Number.isInteger(n)||n<=0)throw Error('容量必须为正整数 KiB');return n*1024;};
  const target=get('deploy-platform').value,budgets={program_bytes:integer('deploy-program'),ram_bytes:integer('deploy-ram')};
  if(entry().emulated)budgets.writable_ram_bytes=integer('deploy-writable');
  return {schema:'lattice.deployment_strategy_request.v1',platform:target,strategy:get('deploy-strategy').value,parameters:p,operations,budgets,workspace_bytes:integer('deploy-workspace')};
 }
 function display(r){
  const out=get('deploy-result');
  if(r.status==='BUILDING'){out.textContent='正在编译并运行标准向量与接口检查……';return;}
  if(r.status==='FAILED'){out.innerHTML=`<p class="bad">${esc(r.error)}</p>`;return;}
  const target=['m4','rv32'].includes(r.request.platform),c=r.resource_object.included_components;
  out.innerHTML=`<p class="good">${target?'仿真验证程序已生成，功能与资源检查通过。':'程序已生成，功能与资源检查通过。'}</p><table><thead><tr><th>验证程序大小</th><th>${target?'验证程序 RAM':'验证程序可写区'}</th><th>部署策略</th></tr></thead><tbody><tr><td>${r.resources.program_bytes.toLocaleString()} B</td><td>${r.resources.ram_bytes.toLocaleString()} B</td><td>${esc(strategyTitles[r.strategy]||r.strategy)}</td></tr></tbody></table>${c?`<p class="muted">可写区已包含：调用栈 ${c.call_stack_reserved_bytes.toLocaleString()} B，工作区 ${c.workspace_reserved_bytes.toLocaleString()} B，其余 ${c.other_writable_bytes.toLocaleString()} B。</p>`:''}<p><a class="link" href="${r.download}" download="deployment.zip">下载程序及构建记录</a> · <a class="link" href="${r.result_download}" download="deployment-result.xml">下载本次资源结果</a></p><details><summary>程序信息</summary><div class="hash">SHA-256 ${esc(r.image_sha256)}</div></details>`;
 }
 function failed(e,finished=false){get('deploy-result').textContent=e.message||'程序生成未完成';if(finished)building=false;enabled();}
 async function poll(id){const response=await fetch('/api/deployment-build?id='+id);if(!response.ok)throw Error('构建结果读取失败');const r=await response.json();display(r);if(r.status==='BUILDING')setTimeout(()=>poll(id).catch(e=>failed(e,true)),1200);else{building=false;enabled();if(r.status==='READY')await refreshResourceObjects();}}
 get('deploy-start').addEventListener('click',async()=>{try{const body=request();building=true;enabled();const response=await fetch('/api/deployment-build',{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Token':document.querySelector('meta[name=demo-token]').content},body:JSON.stringify(body)});const r=await response.json();if(!response.ok)throw Error(r.error||'策略无法执行');display(r);poll(r.build_id).catch(e=>failed(e,true));}catch(e){failed(e,true);}});
 get('deploy-request').addEventListener('click',()=>{try{const value=request();delete value.strategy;value.schema='lattice.deployment_request.v1';value.recipes=[selectedStrategy().recipe];const blob=new Blob([recordXML(value)],{type:'application/xml'}),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='deployment-request.xml';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){failed(e);}});
 get('deploy-preset').addEventListener('change',preset);get('deploy-platform').addEventListener('change',platform);get('deploy-strategy').addEventListener('change',strategy);preset();
 fetch('/api/deployment-builds').then(r=>{if(!r.ok)throw Error('构建目标读取失败');return r.json();}).then(r=>{catalog=r;get('deploy-platform').innerHTML=r.platforms.map(x=>`<option value="${esc(x.id)}" ${x.available?'':'disabled'}>${esc(x.title)}${x.available?'':'（当前不可用）'}</option>`).join('');const usable=r.platforms.find(x=>x.available);if(usable)get('deploy-platform').value=usable.id;platform();}).catch(e=>failed(e));
})();
