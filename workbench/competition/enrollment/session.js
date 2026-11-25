'use strict';
(() => {
  const el = id => document.getElementById(id);
  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const tab = document.querySelector('button[data-page="session"]');
  document.querySelector('main>footer').before(el('page-session'));
  const actions = ['session-cold', 'session-reuse', 'session-fresh'].map(el);
  let data;
  tab.addEventListener('click', () => {
    for (const section of document.querySelectorAll('main>section')) section.hidden = section.id !== 'page-session';
    for (const button of document.querySelectorAll('nav button')) button.removeAttribute('aria-current');
    tab.setAttribute('aria-current', 'page'); el('crumb').textContent = '连续接入'; window.scrollTo(0, 0);
  });
  function rows(headings, values) {
    return '<div class="table-wrap"><table><thead><tr>' + headings.map(s=>'<th>'+esc(s)+'</th>').join('') + '</tr></thead><tbody>' + values.map(row=>'<tr>'+row.map(s=>'<td>'+esc(s)+'</td>').join('')+'</tr>').join('') + '</tbody></table></div>';
  }
  function selected() {
    const choice = data.configurations.find(r=>r.id === el('session-library').value);
    actions.forEach(b=>b.disabled = !choice || !choice.execution_available);
    if (!choice) return;
    const p = el('session-pair').value, r = choice.resources[p];
    el('session-scope').textContent = choice.execution_available ? '实际调用本机密码库，随机数来自操作系统。' : choice.execution_reason;
    el('session-resources').innerHTML = rows(['预留部分', '字节'], [['完整对象池（含公开矩阵）', r.pool_bytes], ['完整流程栈', r.stack_reserved_bytes], ['算法库与应用全局区', r.library_globals_tls_bytes+r.application_globals_bytes+r.application_module_globals_bytes], ['本参数合计', r.charged_bytes], ['六参数共同最大值', choice.maximum_charged_bytes], ['预算', data.budget_bytes]]);
  }
  async function run(mode) {
    actions.forEach(b=>b.disabled=true); el('session-result').innerHTML='<article class="panel"><h2>正在执行完整接入流程…</h2><p class="muted">身份生成、准备、签发和密钥建立均由本机库执行。</p></article>';
    try {
      const response = await fetch('/api/session/run', {method:'POST', headers:{'Content-Type':'application/json','X-Demo-Token':document.querySelector('meta[name=demo-token]').content}, body:JSON.stringify({library:el('session-library').value,dsa:Number(el('session-pair').value),mode})});
      const r = await response.json(); if (!response.ok) throw Error(r.error || '完整流程未完成');
      window.__lastSessionRun=r;
      const o=r.operation_counts, title={cold1:'首次接入完成',reuse200:'连续接入完成',fresh200:'更换身份接入完成'}[mode];
      el('session-result').innerHTML='<article class="panel"><div class="result-head"><h2>'+title+'</h2><span class="good">全部通过</span></div>'+rows(['实际操作','完成次数'],[['身份生成 / 矩阵准备',o.identity_keygen+' / '+o.prepare_public_matrix],['设备密钥生成',o.kem_keygen],['完整签名 / 验签',o.sign+' / '+o.verify],['封装 / 解封装',o.encaps+' / '+o.decaps],['共享秘密一致的完整接入',r.completed_flows]])+'<p class="muted">临时秘密已擦除；会话已关闭；完整对象池已清零；前后边界保持完整。</p><a class="link" href="/export/session/run/'+esc(r.run_id)+'.xlsx" download="session-observation.xlsx">下载本次运行记录 →</a></article>';
    } catch (e) {el('session-result').innerHTML='<article class="panel"><h2>本次运行未完成</h2><p>'+esc(e.message)+'</p></article>';}
    finally {selected();}
  }
  el('session-cold').addEventListener('click',()=>run('cold1')); el('session-reuse').addEventListener('click',()=>run('reuse200')); el('session-fresh').addEventListener('click',()=>run('fresh200'));
  el('session-library').addEventListener('change',selected); el('session-pair').addEventListener('change',selected);
  actions.forEach(b=>b.disabled=true);
  fetch('/api/session/catalog').then(r=>{if(!r.ok)throw Error('会话配置加载失败');return r.json();}).then(r=>{
    data=r; el('session-library').innerHTML=r.configurations.map(c=>'<option value="'+esc(c.id)+'"'+(c.execution_available?'':' disabled')+'>'+esc(c.title)+'</option>').join('');
    const available=r.configurations.find(c=>c.execution_available); if(available)el('session-library').value=available.id;
    selected(); el('session-studies').innerHTML=r.studies.length?r.studies.map(s=>'<div class="dataset-item"><h3>'+esc(s.title)+'</h3><a class="link" href="/export/session/study/'+s.id+'-summary.xml">统计结果</a> · <a class="link" href="/export/session/study/'+s.id+'-plan.xml">实验条件</a> · <a class="link" href="/export/session/study/'+s.id+'-raw.xml">完整原始记录</a></div>').join(''):'<p>尚未绑定与当前演示版本一致的归档测量。</p>';
    window.__sessionReady=true;
  }).catch(e=>{el('session-result').textContent=e.message;});
})();
