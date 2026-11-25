'use strict';
function renderUpgrade(v){
 const title=x=>v.label_titles[x]||x;
 const rows=v.comparisons.map(c=>[title(c.candidate)+' / '+title(c.reference),c.equal_frequency.candidate_sum_18_us.toFixed(3),c.equal_frequency.reference_sum_18_us.toFixed(3),c.equal_frequency.time_change_percent.toFixed(2)+'%',c.equal_frequency.time_change_percent_ci95.map(x=>x.toFixed(2)+'%').join(' 至 ')]);
 const cells=v.comparisons.map(c=>'<h3>'+escapeHTML(title(c.candidate)+' / '+title(c.reference))+'</h3>'+table(['参数','操作','本策略 μs','参考 μs','耗时变化','95%区间'],c.cells.map(r=>[r.parameter,operationName(r.parameter,r.operation),r.candidate_mean_us.toFixed(3),r.reference_mean_us.toFixed(3),r.time_change_percent.toFixed(2)+'%',r.time_change_percent_ci95.map(x=>x.toFixed(2)+'%').join(' 至 ')]))).join('');
 return '<article class="dataset-item"><h2>'+escapeHTML(v.title)+'</h2>'+table(['比较与实际工作区','18项总耗时 μs','参考总耗时 μs','耗时变化','95%区间'],rows)+'<p class="muted">负值表示耗时降低。每项操作各调用一次，累加十八项均值后计算耗时比。'+v.method.blocks+' 个完整配对区组，每项每区组 '+v.method.samples_per_cell_per_block+' 个样本；保留全部慢样本。按完整区组重采样 '+v.method.resamples+' 次，区间为逐项 95% 百分位区间。</p><p class="muted">消息 '+v.message_bytes+' B，上下文 '+v.context_bytes+' B。完整调用包含序列化密钥处理、操作、编码及调用清理。工作区容量仅包含内核工作区。</p><details><summary>六参数十八项操作明细</summary>'+cells+'</details></article>';
}
function renderUpgradeResources(v){
 if(!v.resources.length)return '';
 return '<article class="dataset-item"><h2>'+escapeHTML(v.title)+' · 资源</h2>'+table(['策略','工作区 W','预留栈 S','上下文 C','可写全局 G','额外堆 H','算法内存 R','程序空间 P'],v.resources.map(r=>[r.title,...['W','S','C','G','H','R','P'].map(k=>Number(r[k]).toLocaleString()+' B')]))+'<p class="muted">R = W + S + C + G + H。算法内存不包含调用方密钥、签名、密文、应用状态；完整应用 RAM 另行核算。栈预留按测得峰值增加 256 B 后向上对齐至 256 B。</p></article>';
}
function upgradeExports(v){
 const query='?dataset='+encodeURIComponent(v.dataset_id);
 const resourceLinks=v.resources.map((r,i)=>'<p>'+escapeHTML(r.title+' · '+r.W+' B 工作区')+'：'+['result','observations','commands'].map((key,j)=>'<a class="link" href="/export/upgrade/resource-'+key+'.xml'+query+'&ordinal='+i+'">'+['资源结果','逐次资源记录','资源测量命令'][j]+'</a>').join(' · ')+'</p>').join('');
 return '<article class="dataset-item"><h3>'+escapeHTML(v.title)+'</h3><p><a class="link" href="/export/upgrade/summary.xml'+query+'">原始统计 XML</a> · <a class="link" href="/export/upgrade/manifest.xml'+query+'">实验与映像清单</a> · <a class="link" href="/export/upgrade/commands.xml'+query+'">配对区组与样本索引</a></p>'+resourceLinks+'<details><summary>下载原始样本（0 至 '+(v.raw_files_checked-1)+'）</summary><label>运行序号<input id="upgrade-ordinal-'+escapeHTML(v.dataset_id)+'" type="number" min="0" max="'+(v.raw_files_checked-1)+'" value="0"></label><button class="secondary upgrade-raw" data-dataset="'+escapeHTML(v.dataset_id)+'" data-count="'+v.raw_files_checked+'">下载原始样本</button></details></article>';
}
function renderVerificationProfiles(v){
 const rows=v.profiles.map(p=>[p.platform==='windows'?'Windows x86-64':'Linux AArch64',configTitle(p.configuration),
  p.applicable_standard_vectors,p.complete_sequences,p.complete_signature_pairs,p.openssl_cross_comparisons,
  p.capacity_and_recovery==='PASS'?'通过':p.capacity_and_recovery]);
 return '<h2>标准与功能验证</h2>'+table(['平台','配置','标准向量','完整流程','签名字节对','OpenSSL操作','容量恢复'],rows)+'<p class="muted">各配置分别验证645条适用标准向量、完整输出与随机请求；原始记录保留程序标识和测试条件。</p>';
}
function renderVerificationRecords(v){
 const kinds={acvp:'NIST 标准向量',complete:'完整操作字节对照',signatures:'签名字节对照',capacity:'容量与接口恢复',wycheproof:'Wycheproof 固定向量',go:'Go 互操作',liboqs:'liboqs 互操作',boringssl:'BoringSSL 互操作',openssl:'OpenSSL 互操作','key-encoding':'秘密密钥编码检查','native-codec':'原生编码边界','native-bitmap':'原生提示位图',vector24:'24 位系数表示',cbmc:'有界模型检查',lifetimes:'缓冲区生命周期','common-context':'共同上下文交错调用'};
 const count=r=>r.kind==='acvp'?(r.statistics.observed_status_counts?.PASS??r.statistics.records):r.kind==='complete'?r.statistics.complete_sequences:r.kind==='signatures'?r.statistics.complete_signature_pairs:r.statistics.records;
 const build=r=>({ 'ordinary-pqclean':'普通构建 · PQClean 对照',ordinary:'普通构建',strict:'ASan / UBSan', 'strict-pqclean':'ASan / UBSan · PQClean 对照' }[r.conditions.build]||r.conditions.build||'固定功能案例');
 return '<article class="dataset-item"><h3>'+escapeHTML(v.title||'标准、互操作与接口验证')+'</h3><p>每组结果关联实际程序 SHA-256、测试条件和原始记录，页面加载时校验文件并重新计算数量。</p><div class="table-scroll"><table><thead><tr><th>平台</th><th>验证项目</th><th>条件</th><th>记录 / 对照数</th></tr></thead><tbody>'+v.runs.map(r=>'<tr><td>'+escapeHTML(r.platform==='windows-x86_64'?'Windows x86-64':r.platform==='linux-aarch64'?'Linux AArch64':r.platform)+'</td><td>'+escapeHTML(kinds[r.kind]||r.kind)+'</td><td>'+escapeHTML(build(r))+'</td><td>'+Number(count(r)).toLocaleString()+'</td></tr>').join('')+'</tbody></table></div></article>';
}
let resourceCatalog=null;
function observationFiles(m){
 if(m.schema==='lattice.signing_pipeline_qualification.v1')return m.files;
 if(m.schema==='latticecore.verification_observations.v1')return m.runs.map(x=>x.records);
 if(m.schema==='lattice.application_pool_observations.v1')return [m.raw];
 if(m.schema==='lattice.application_latency_observations.v1')return m.jobs.map(j=>j.raw);
 if(m.schema==='lattice.primitive_samples_observations.v1')return m.processes.map(j=>j.raw);
 if(m.schema==='lattice.block_observation_shards.v2')return m.runs.map(x=>x.sample_shard);
 if(m.schema==='lattice.instruction_samples.windows.v1')return [...m.cells.map(x=>x.raw),...m.libraries.map(x=>x.mapping)];
 if(m.raw_files)return m.raw_files;
 if(m.schema==='latticecore.shared_keccak.v1')return m.measurements.jobs.map(j=>j.raw);
 if(m.schema==='latticecore.timing_attribution.v1')return m.studies.flatMap(s=>s.jobs.flatMap(j=>j.files?Object.values(j.files):[j.raw]));
 return m.studies.flatMap(s=>s.records.map(x=>x.raw));
}
function operationName(p,o){return o===0?'密钥生成':p>100?(o===1?'封装':'解封装'):(o===1?'签名':'验签');}
function platformTitle(v){return displayCatalog?.platforms[v]||v;}
function datasetTitle(v){return v.title||displayCatalog?.datasets[v.dataset_id]||'实验结果';}
function configTitle(v){return displayCatalog?.configurations[v]||v;}
function memoryText(v){return Number(v).toLocaleString('en-US')+' B（'+(v/1024).toFixed(2)+' KiB）';}
function timeText(v){return (v/1000).toFixed(3);}
function renderEqualFrequency(v){
 if(!v.equal_frequency)return '';
 const rows=v.equal_frequency.comparisons.map(c=>[configTitle(c.reference)+' → '+configTitle(c.candidate),c.sum_mean_time_ratio.toFixed(4),((1-c.sum_mean_time_ratio)*100).toFixed(2)+'%',c.ci95.map(x=>x.toFixed(4)).join(' – ')]);
 return '<h3>十八项操作等频总耗时</h3>'+table(['参考实现 → 本方案','总耗时比','耗时下降','95%区间'],rows)+'<p class="muted">每项操作各调用一次，先累加十八项平均耗时，再计算本方案与参考实现之比。</p><a class="link" href="/export/equal-frequency.xml?dataset='+encodeURIComponent(v.dataset_id)+'">下载等频总耗时与原始数据身份</a>';
}
function renderMeanTail(v){
 const range=a=>a.map(x=>x.toFixed(4)).join(' – ');
 const estimate=s=>timeText(s.ns)+' ['+s.ci95_ns.map(timeText).join(', ')+']';
 const capacities=[...new Set(v.configurations.map(c=>c.workspace_reserved))];
 const capacityText='<p class="muted">比较驱动传入工作区：'+capacities.map(memoryText).join('、')+'。实际算法资源按各映像经验证的需求核算。</p>';
 const comparisons=v.comparisons.map(c=>[configTitle(c.reference)+' → '+configTitle(c.candidate),c.mean_time_ratio_geomean.toFixed(4),((1-c.mean_time_ratio_geomean)*100).toFixed(2)+'%',range(c.mean_time_ratio_geomean_ci95)]);
 const rows=v.cells.map(c=>[configTitle(c.configuration),c.parameter,operationName(c.parameter,c.operation),c.pooled_samples,...['mean','median','p95','p99'].map(k=>estimate(c.statistics[k]))]);
 const details=v.comparisons.map(c=>'<details><summary>'+escapeHTML(configTitle(c.reference)+' → '+configTitle(c.candidate))+'：逐项耗时比</summary>'+table(['参数','操作','均值比 [95%区间]','P95比 [95%区间]','P99比 [95%区间]'],c.cells.map(r=>[r.parameter,operationName(r.parameter,r.operation),...['mean','p95','p99'].map(k=>r.ratios[k].value.toFixed(4)+' ['+range(r.ratios[k].ci95)+']')]))+'</details>').join('');
 const scope=v.boundary==='openssl_retained_key_lattice_serialized_key_service'?'OpenSSL 在批次内复用已导入密钥并逐次创建操作上下文；本作逐次接收序列化密钥。密钥生成包含编码。':'逐次调用接收序列化密钥，包含准备、密码运算、编码与清理。';
 return '<h2>'+escapeHTML(datasetTitle(v))+'</h2>'+capacityText+'<p class="muted">'+escapeHTML(platformTitle(v.platform))+'；'+v.counts.blocks+' 轮配对测量，每项 '+(v.counts.blocks*v.counts.samples_per_run).toLocaleString()+' 次调用。</p>'+table(['参考实现 → 本方案','几何平均耗时比','耗时下降','95%区间'],comparisons)+'<p class="muted">耗时比为本方案除以参考实现，小于 1 表示耗时更短；综合值为十八项平均耗时比的几何平均。负的下降率表示耗时增加。</p>'+renderEqualFrequency(v)+'<details><summary>六参数十八项完整操作耗时与区间（μs）</summary><p class="muted">P95 表示 95% 的调用耗时不超过该值，P99 对应 99% 的调用。</p>'+table(['配置','参数','操作','样本数','均值 [95%区间]','中位数 [95%区间]','P95 [95%区间]','P99 [95%区间]'],rows)+'</details>'+details+'<p class="muted">'+scope+' 95%区间按完整配对轮次进行 '+v.method.resamples.toLocaleString()+' 次重采样，逐项计算。全部较慢调用均计入统计。</p>';
}
function renderPooled(v){
 const rows=v.cells.map(x=>[configTitle(x.configuration),x.parameter,operationName(x.parameter,x.operation),x.pooled_samples,timeText(x.pooled_mean_ns),timeText(x.pooled_median_ns),timeText(x.pooled_p95_ns),timeText(x.pooled_p99_ns)]);
 const comparisons=v.comparisons.map(x=>[configTitle(x.reference)+' → '+configTitle(x.candidate),x.equal_weight_18_cell_median_ratio_geomean.toFixed(4),x.paired_complete_block_ci95.map(y=>y.toFixed(4)).join(' – '),timeText(x.reference_equal_weight_mean_ns),timeText(x.candidate_equal_weight_mean_ns)]);
 const scope='<p class="muted">'+(v.boundary==='openssl_retained_key_lattice_serialized_key_service'?'OpenSSL 在批次内复用已导入的密钥，每次调用重新创建并释放操作上下文；本作每次调用接收序列化密钥。密钥生成含编码。':'逐次调用接收序列化密钥，包含准备、密码运算、编码与清理。')+'</p>';
 return '<h2>'+escapeHTML(datasetTitle(v))+'</h2><p class="muted">'+escapeHTML(platformTitle(v.platform))+'；'+v.counts.blocks+' 轮配对测量，每项操作共 '+(v.counts.blocks*v.counts.samples_per_run).toLocaleString()+' 个测量样本。</p>'+table(['参考实现 → 本方案','综合加速比','95% 区间','参考平均耗时 μs','本方案平均耗时 μs'],comparisons)+'<details><summary>六参数十八项完整操作耗时</summary>'+table(['配置','参数','操作','样本数','均值 μs','中位数 μs','p95 μs','p99 μs'],rows)+'</details>'+scope+'<p class="muted">加速比为十八项操作中位数比的几何平均，大于 1 表示本方案更快；区间以完整配对测量轮次重采样。平均耗时为十八项操作均值的等权算术平均。</p>';
}
function renderResourcePoint(p){
 const r=p.reserved_components;
 if(p.statistics_dataset)return '<h3>'+escapeHTML(configTitle(p.configuration))+'</h3>'+table(['工作区','栈','上下文','全局可写区','额外堆','核心内存','核心程序大小'],[[r.workspace_bytes,r.stack_bytes,r.external_context_bytes,r.globals_bytes,r.outside_heap_bytes,p.core_reserved_bytes,p.program_bytes].map(memoryText)])+'<p class="muted">'+escapeHTML(platformTitle(p.platform))+'；计时传入工作区 '+memoryText(p.measurement_workspace_bytes)+'。算法预留按该映像的各项实际资源记录核算。</p>';
 return '<h3>'+escapeHTML(configTitle(p.configuration))+'</h3>'+table(['工作区','栈','上下文','全局可写区','额外堆','核心内存','核心程序大小'],[[r.workspace_bytes,r.stack_bytes,r.external_context_bytes,r.globals_bytes,r.outside_heap_bytes,p.core_reserved_bytes,p.program_bytes].map(memoryText)])+'<p class="muted">'+escapeHTML(platformTitle(p.platform))+' · '+escapeHTML(p.build.backend)+' · '+escapeHTML(p.build.optimization)+(p.build.lto?' / LTO':'')+'</p>';
}
async function refreshResourceObjects(){
 resourceCatalog=await get('/api/resources');
 const o=resourceCatalog.resource_objects,h=o.host,lib=catalog.libraries.find(x=>x.execution_available&&x.configuration==='lattice-sign-pipeline-native')||catalog.libraries.find(x=>x.execution_available),c=o.core.points.find(x=>x.binary_sha256===(lib?.measured_binary_sha256||lib?.binary_sha256)),v=o.exported_program.last_completed?.resource_object;
 const rows=[],opNames={keypair:'密钥生成',encaps:'封装',decaps:'解封装',sign:'签名',verify:'验签'};
 const completed=o.exported_program.last_completed;
 const functions=completed?Object.entries(completed.operations).flatMap(([p,ops])=>ops.map(op=>p+opNames[op])).join('、'):'编译后显示';
 if(c)rows.push(['密码核心',c.parameters.length===6?'六参数·'+c.operation_count+'项':c.parameters.join('/')+' · '+c.operation_count+'项',memoryText(c.ram_bytes),memoryText(c.program_bytes),'工作区、栈、上下文、全局区与堆']);
 if(v)rows.push(['导出验证程序',functions,memoryText(v.ram_bytes),memoryText(v.program_bytes),v.included_components?'含 '+v.included_components.call_stack_reserved_bytes.toLocaleString()+' B 调用栈、'+v.included_components.workspace_reserved_bytes.toLocaleString()+' B 工作区':'按目标实际装载布局核算']);
 else rows.push(['导出验证程序',functions,'编译后显示','编译后显示','含核心、输入输出与验证程序调用栈']);
 rows.push(['演示服务进程','当前页面服务',h.measured?memoryText(h.current_resident_bytes):'读取失败','—','当前工作集；Python 服务与已加载库']);
 $('resource-objects').innerHTML='<h2>资源对象</h2>'+table(['对象','功能','内存','程序大小','统计范围'],rows)+'<p class="muted">三个对象分别计量。界面进程由操作系统单独统计。</p><a class="link" href="/export/resource-scopes.xml" download="resource-scopes.xml">下载对应记录</a>';
 return resourceCatalog;
}
function workloadCounts(){
 return [...document.querySelectorAll('[data-workload-parameter]')].map(e=>({parameter:Number(e.dataset.workloadParameter),operation:Number(e.dataset.workloadOperation),calls:Number(e.value)})).filter(x=>x.calls!==0);
}
function setWorkloadPreset(){
 const choice=$('budget-workload').value;$('budget-counts-panel').hidden=choice==='equal';
 if(choice==='custom')return;
 document.querySelectorAll('[data-workload-parameter]').forEach(e=>{
  const p=Number(e.dataset.workloadParameter),o=Number(e.dataset.workloadOperation);
  let n=choice==='equal'?1:0;
  if(choice==='sign'&&p<100)n=o===0?1:o===1?100:0;
  if(choice==='verify'&&p<100)n=o===2?100:0;
  if(choice==='decaps'&&p>100)n=o===0?1:o===2?100:0;
  e.value=n;
 });
}
async function initBudget(){
 await refreshResourceObjects();const studies=resourceCatalog.timing_studies;
 const h=resourceCatalog.resource_objects.host;
 $('host-resource').innerHTML='<h2>演示宿主</h2>'+table(['测量对象','当前驻留内存','范围'],[['Python 服务进程',h.measured?memoryText(h.current_resident_bytes):'读取失败','包含运行时与已加载库；界面进程由系统单独统计']])+'<p><a class="link" href="/export/resource-scopes.xml" download="resource-scopes.xml">下载资源对象与进程记录</a></p>'; 
 $('budget-study').innerHTML=studies.map(x=>'<option value="'+escapeHTML(x.dataset_id)+'">'+escapeHTML(datasetTitle(x))+'</option>').join('');
 $('budget-resources').innerHTML=resourceCatalog.datasets.map(x=>'<option value="'+escapeHTML(x.dataset_id)+'">'+escapeHTML(datasetTitle(x))+'</option>').join('');
 $('budget-query').disabled=!studies.length||!resourceCatalog.datasets.length;
 $('budget-counts').innerHTML=table(['参数','密钥生成','封装 / 签名','解封装 / 验签'],[512,768,1024,44,65,87].map(p=>[(p>100?'ML-KEM-':'ML-DSA-')+p,...[0,1,2].map(o=>'<input type="number" min="0" max="1000000" step="1" value="1" aria-label="'+p+' '+o+' 调用次数" data-workload-parameter="'+p+'" data-workload-operation="'+o+'">')]));
 $('budget-counts').querySelectorAll('td').forEach(td=>{if(td.textContent.startsWith('<input type="number"'))td.innerHTML=td.textContent;});
 $('budget-workload').onchange=setWorkloadPreset;
 $('budget-counts').oninput=()=>{$('budget-workload').value='custom';};
 setWorkloadPreset();
 $('budget-result').innerHTML=empty('设置资源上限并查询','从已测配置中选择对应调用比例下平均耗时最低的方案。');
}
async function queryBudget(){
 const study=resourceCatalog.timing_studies.find(s=>s.dataset_id===$('budget-study').value);if(!study)return;
 const q=new URLSearchParams({resource_dataset:$('budget-resources').value,timing_dataset:study.dataset_id,platform:study.platform,ram_bytes:Number($('budget-ram').value)*1024,program_bytes:Number($('budget-program').value)*1024});
 if($('budget-workload').value!=='equal'){const counts=workloadCounts();if(!counts.length)throw new Error('请填写至少一项调用次数');q.set('operation_counts',JSON.stringify(counts));}
 const data=await get('/api/budget?'+q);window.__lastBudget=data;
 const limits='<p class="muted">核心预算：内存 '+$('budget-ram').value+' KiB；程序大小 '+$('budget-program').value+' KiB。部署范围内符合条件的配置 '+data.candidates.length+' 项。</p>';
 const unknown=data.unmeasured_configurations.length?'<details><summary>资源数据范围</summary><p>预算查询使用本作的部署配置。性能页同时提供以下参考实现的耗时：'+data.unmeasured_configurations.map(c=>escapeHTML(configTitle(c.configuration))).join('、')+'。</p></details>':'';
 if(!data.selected){$('budget-result').innerHTML=limits+empty('当前上限下可运行配置为 0 项','可增加资源上限，或选择其他平台的测量结果。')+unknown;return;}
 const x=data.selected,weighted=data.schema==='lattice.workload_budget_query.v1';
 const metric=weighted?'按调用比例平均耗时':'十八项平均耗时';
 const score=c=>weighted?c.workload_mean_ns:c.equal_weight_18_operation_mean_ns;
 $('budget-result').innerHTML='<div class="result-head"><h2>'+escapeHTML(configTitle(x.configuration))+'</h2><span class="good">平均耗时最低</span></div>'+limits+'<p>'+metric+' <strong>'+timeText(score(x))+' μs</strong>；核心内存 '+memoryText(x.core_reserved_bytes)+'；程序大小 '+memoryText(x.program_bytes)+'。</p>'+table(['配置','工作区','核心内存','核心程序大小',metric+' μs'],data.candidates.map(c=>[configTitle(c.configuration),memoryText(c.workspace_bytes),memoryText(c.core_reserved_bytes),memoryText(c.program_bytes),timeText(score(c))]))+unknown+'<details><summary>配置详情与来源</summary>'+table(['配置','代码编号','算法库 SHA256'],data.candidates.map(c=>[configTitle(c.configuration),c.configuration,c.binary_sha256||c.library_sha256||'见原始数据']))+'</details>';
 if(weighted)$('budget-result').innerHTML+='<p class="muted">共 '+data.total_calls+' 次调用的服务时间合计 '+timeText(x.workload_total_service_ns)+' μs，按各项完整操作均值与调用次数相乘后求和。</p>';
 const download=document.createElement('button');download.textContent='下载配置选择结果';download.onclick=()=>{const blob=new Blob([recordXML(data)],{type:'application/xml'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='configuration-selection.xml';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};$('budget-result').appendChild(download);
}
function renderVerification(v){
 const s=v.summary,standard=s.standard_case_id_counts.frozen_hosted,rows=[];
 if(standard)rows.push(['标准向量',standard.applicable_vector_ids+' 个适用用例',standard.mlkem_applicable_vector_ids+' 项 ML-KEM；'+standard.mldsa_applicable_vector_ids+' 项 ML-DSA']);
 rows.push(['标准向量执行',s.standard_record_counts['frozen_hosted/PASS']||0,'跨算法库重复执行'],['完整签名字节比较',s.signature_pair_executions,s.signature_design_case_ids+' 组输入，多个实现配对'],['完整输出与随机请求比较',s.differential_complete_sequence_pair_executions,'六参数完整操作序列'],['OpenSSL 互操作',s.interop_case_executions,'双向交叉检查']);
 if(s.normal_capacity_recovery_record_executions)rows.push(['正常容量下的错误恢复与并发',s.normal_capacity_recovery_record_executions,'顺序调用与四个独立上下文并发调用']);
 if(s.ordinary_parameter_seed_executions)rows.push(['连续调用与异常恢复',s.ordinary_parameter_seed_executions,'各参数与种子的测试记录']);
 if(s.detector_control_executions)rows.push(['检测器阳性对照',s.detector_controls_detected+' / '+s.detector_control_executions,'检出数 / 执行数']);
 if(s.emulated_case_executions)rows.push(['32 位指令仿真',s.emulated_case_executions,'目标程序功能检查']);
 return '<h2>功能验证</h2>'+table(['测试内容','数量','统计范围'],rows)+'<details><summary>各项验证记录</summary>'+table(['记录编号','类型','数量','结果'],v.suites.map(x=>[x.id,x.kind,x.record_count,x.status]))+'</details>';
}
function renderTiming(v){
 const rows=v.studies.map(s=>[s.study_id,platformTitle(s.platform),configTitle(s.configuration),({'registered_screen':'输入分组测试','repeat_screen':'独立重复测试','public_matrix_diagnostic':'公开矩阵对照','public_fields_diagnostic':'公开字段对照'}[s.phase]||s.phase),s.unit,
  s.target_differences_detected+' / '+s.target_records,
  s.positive_controls_detected+' / '+s.positive_controls]);
 const details=v.studies.map(s=>{const source=v.input_conditions.find(c=>c.study_id===s.study_id),c=source.conditions;
  return '<details><summary>'+escapeHTML(s.study_id)+' · '+s.records.length+' 组输入分布</summary>'+
  '<p class="muted">每组 '+c.samples_per_record+' 个样本；每 '+c.class_batch_size+' 个样本均衡随机分组；检查点 '+c.checkpoints.join(' / ')+'；原登记 |t| 阈值 '+c.threshold_abs_t+'。</p>'+
  table(['输入族','两类定义','测量范围','有效性','范围边界'],source.families.map(f=>[f.mode,f.class_definition,f.timed_region,f.input_validity,f.limits]))+
  table(['模式','参数','种子','阳性','检出分布差异','均值0','均值1','均值1−0','最大 |t|'],
   s.records.map(r=>[r.mode,r.parameter,r.seed,r.positive_control?'是':'否',r.detected?'是':'否',
    r.final_mean_class0.toFixed(3),r.final_mean_class1.toFixed(3),r.final_class1_minus_class0.toFixed(3),r.max_abs_t.toFixed(3)]))+
  (s.environment_events.length?'<p class="muted">环境记录：'+escapeHTML(JSON.stringify(s.environment_events))+'</p>':'')+'</details>';}).join('');
 return '<details><summary>时序检测结果</summary><h2>输入分组与时序检测</h2><p class="muted">'+v.raw_files_checked+' 份原始记录，共 '+v.raw_rows_checked.toLocaleString()+' 行。保留原试验、重复试验、公开输入诊断与全部检测阳性对照。</p>'+
  table(['研究','平台','配置','试验类型','单位','实际族检出 / 总数','阳性检出 / 总数'],rows)+details+
  '<p class="muted">Welch t 描述两类输入的样本分布差异；均值差保留各研究原始单位。公开输入诊断与原试验分别列示，签名保留自然拒绝过程。受测范围及实现检查共同用于解释检测结果。</p></details>';
}
function renderApplication(v){
 const status=r=>r.all_exchanges_passed?'完成六项操作（'+r.trials+'/'+r.trials+'）':Object.entries(r.status_counts).map(([k,n])=>({WORKSPACE_INSUFFICIENT:'工作区容量不足',POOL_TOO_SMALL:'应用内存池容量不足',PASS:'完成六项操作'}[k]||k)+' '+n+' 次').join('；');
 const budgetRows=v.configuration_budgets.map(r=>[configTitle(r.configuration),r.minimum_feasible_tested_budget_bytes===null?'当前测试容量下无完整成功记录':memoryText(r.minimum_feasible_tested_budget_bytes)]);
 const cells=v.cells.map(r=>[configTitle(r.configuration),r.kem+' / '+r.dsa,memoryText(r.budget_bytes),status(r),memoryText(r.serialized_object_bytes),memoryText(r.pool_bytes),memoryText(r.application_stack_bytes),memoryText(r.maximum_workspace_high_water_bytes)]);
 return '<h2>'+escapeHTML(datasetTitle(v))+'</h2><p>依次执行签名密钥生成、封装密钥生成、公钥签名、验签、封装和解封装。每种参数与容量组合使用 '+v.counts.repetitions_per_cell+' 组确定性输入，比较完整输出并检查清理结果。</p>'+table(['配置','三组参数共同可行的最小已测预算'],budgetRows)+'<p class="muted">预算包含固定内存池、整个应用调用的保护栈、算法库可写全局区与一份 TLS、应用分派指针。内存池容纳上下文、输入输出对象、对齐空间和复用工作区。</p><details><summary>逐参数、逐容量结果与内存组成</summary>'+table(['配置','ML-KEM / ML-DSA','总预算','运行结果','序列化对象','内存池','保护栈','应用池内工作区高水位'],cells)+'</details>';
}
function ownerLayout(n){return n===0?'独立序列化对象':'按生命周期复用存储';}
function renderApplicationOwnerResources(v){
 const rows=v.resources.map(r=>[configTitle(r.configuration),r.kem+' / '+r.dsa,ownerLayout(r.layout),memoryText(r.charged_bytes),memoryText(r.program_bytes),memoryText(r.pool_bytes),memoryText(r.workspace_bytes),memoryText(r.stack_reserved_bytes),memoryText(r.heap_reserved_bytes)]);
 const ids=v.configurations.filter(c=>!v.selected_configurations||v.selected_configurations.includes(c.id)).map(c=>'<p class="hash">'+escapeHTML(configTitle(c.id))+' · 核心 SHA256 '+escapeHTML(c.binary_sha256)+'<br>应用 SHA256 '+escapeHTML(c.application_sha256)+'</p>').join('');
 return '<h2>'+escapeHTML(datasetTitle(v))+'</h2><p>固定内存池包含应用状态、序列化输入输出、对齐空间和算法工作区。两种布局执行相同公钥签发、验签与密钥建立流程，关闭应用后清零整个池。</p>'+table(['配置','ML-KEM / ML-DSA','对象布局','应用运行内存 R','应用与核心程序 P','完整内存池','池内算法工作区','完整应用预留栈','外部堆预留'],rows)+'<p class="muted">R 还包含核心与应用的可写全局区、一份 TLS 和应用控制状态；池内工作区已包含在内存池中，不重复相加。P 包含实际应用模块与核心的非调试装载节。栈高水位仅描述已执行输入，保留安全余量。</p><details><summary>测量构建与资源边界</summary>'+ids+'<p>原始资源记录 '+v.counts.resource_processes+' 份，包含 '+v.counts.resource_flows+' 个正常流程和 '+v.counts.capacity_restorations+' 次容量恢复。完整原始记录保留在数据页。</p></details>';
}
function renderApplicationOwnerTiming(v){
 const rows=v.cells.map(r=>[configTitle(r.configuration),r.kem+' / '+r.dsa,ownerLayout(r.layout),r.fresh_identity?'每流程重建签发身份':'批内复用签发身份',r.flows,r.independent_batches,timeText(r.mean_batch_ns),timeText(r.ci95_batch_ns[0])+' – '+timeText(r.ci95_batch_ns[1]),r.complete_flows_per_second.toFixed(1)]);
 const ratios=v.comparisons.map(r=>[configTitle(r.numerator.configuration)+' · '+ownerLayout(r.numerator.layout),configTitle(r.denominator.configuration)+' · '+ownerLayout(r.denominator.layout),r.kem+' / '+r.dsa,r.fresh_identity,r.flows,r.mean_time_ratio.toFixed(4),r.ci95[0].toFixed(4)+' – '+r.ci95[1].toFixed(4)]);
 return '<details open><summary>'+escapeHTML(datasetTitle(v))+'</summary><p>从应用打开、上下文初始化开始，计入身份准备、全部流程、结束处理和最终关闭清理。每个进程测量一个含 1 或 200 个流程的完整批次；身份复用模式的初次签发密钥生成也在批次内。</p>'+table(['配置','参数','布局','身份生命周期','流程/批','独立批次','完整批次均值 μs','均值 95% 区间 μs','完整流程吞吐 次/s'],rows)+'<p class="muted">保留全部 '+v.counts.processes+' 个进程、'+v.counts.target_flows.toLocaleString()+' 个目标流程。置信区间以 '+v.method.blocks+' 个完整配对区组共同重采样 '+v.method.statistics.replicates.toLocaleString()+' 次（PCG64，种子 '+v.method.statistics.bootstrap_seed+'），使用百分位 95% 区间。吞吐为流程数除以完整批次均值。未记录单流程时延分布，因此不展示单流程 P95/P99。</p><p class="muted">模块加载、物理池分配/释放、同库宽工作区输出校验、计时后的清零和护栏检查在计时外。配对校验使用 64 位完整输出摘要。普通计时没有堆钩子或栈水位工具；预留资源来自相同应用与核心镜像的独立资源测量。</p><details><summary>全部配对耗时比（分子 / 分母，低于 1 表示分子更快）</summary>'+table(['分子','分母','参数','逐流程新身份','流程/批','均值耗时比','95% 区间'],ratios)+'</details></details>';
}
function renderApplicationLatency(v){
 const rows=v.cells.map(r=>[configTitle(r.configuration),r.kem+' / '+r.dsa,r.fresh_identity?'每次生成签发密钥':'复用签发密钥',r.samples,timeText(r.mean_ns),timeText(r.median_ns),timeText(r.p95_ns),timeText(r.p99_ns),r.aggregate_applications_per_second.toFixed(1)]);
 return '<details><summary>'+escapeHTML(datasetTitle(v))+'</summary><p>每项包含 '+v.counts.blocks+' 个配对区组，完整保留 '+v.counts.measured_calls.toLocaleString()+' 次应用调用。调用内计时包含公钥签发、验证、密钥建立与秘密清理。</p>'+table(['配置','参数组合','签发身份','样本数','均值 μs','中位数 μs','p95 μs','p99 μs','完整批次吞吐 次/s'],rows)+'<p class="muted">每次生成身份的配置把签发密钥生成计入应用调用；复用身份的配置在批次开始前生成签发密钥。完整批次吞吐还计入内存样本记录、校验和及循环开销。原始数据及配对区组区间可从数据页导出。</p></details>';
}
function renderPrimitiveSamples(v){
 const names={forward_ntt:'NTT',inverse_ntt_with_montgomery_scale:'逆NTT（Montgomery缩放）',pointwise_product_or_vector_dot_product:'变换域乘法／向量点积',negacyclic_polynomial_product:'负循环卷积'};
 const rows=v.cells.map(r=>[({'native-balanced':'原生算术后端','portable-compact':'可移植算术后端'}[r.configuration]||configTitle(r.configuration)),r.q,names[r.operation]||r.operation,r.rank,r.independent_processes,r.mean_batch_mean_ns.toFixed(1),r.mean_ci95_low.toFixed(1)+' – '+r.mean_ci95_high.toFixed(1),r.p95_batch_mean_ns.toFixed(1)]);
 return '<details><summary>'+escapeHTML(datasetTitle(v))+'</summary><p>从对应构建的静态库链接实际算术函数，每项采集 7 个独立进程，每进程 100 个测量批次，每批 100 次调用。数学结果由独立负循环卷积与排列转换检查核对。</p>'+table(['算术后端','模数','原语','向量维数','独立进程','批内单次均值 ns','均值95%区间 ns','批均值p95 ns'],rows)+'<p class="muted">分位数描述批均值分布；置信区间以完整独立进程重采样。原语采集程序单独链接，其静态库、实际符号和采集程序信息保存在原始索引中。</p></details>';
}
function renderLimits(v){
 const boundary=v.dataset_id==='aarch64_memory_boundary';
 const counts=v.counts,quota=v.cpu_quota_effects.map(r=>[configTitle(r.configuration),(r.cpu_fraction*100)+'%',r.gm_batch_wall_ratio.toFixed(3),r.batch_ci95_low.toFixed(3)+' – '+r.batch_ci95_high.toFixed(3),r.gm_mean_wall_ratio.toFixed(3),r.cpu_nr_throttled]);
 const conditions=v.operation_conditions.map(r=>[configTitle(r.configuration),r.parameter,operationName(r.parameter,r.operation),memoryText(r.memory_max_bytes),r.cpu_max,r.repetitions,r.samples,timeText(r.mean_wall_ns),timeText(r.p95_wall_ns)]);
 const failed=v.failed_jobs.map(r=>[r.ordinal,configTitle(r.configuration),r.parameter,operationName(r.parameter,r.operation),memoryText(r.memory_max_bytes),r.exit_code,r.status,r.cgroup_after.memory_events.oom_kill]);
 const experiment=boundary?'每个进程启动前丢弃项目文件缓存，固定 cgroup 内存上限 256 KiB。':'内存上限实验逐格改变 cgroup 容量；CPU 实验按四次独立进程重复比较 50%、25% 与 100% 配额。';
 const quotaText=quota.length?table(['配置','CPU 配额','完整批次耗时比','95% 区间','调用内平均耗时比','限流事件数'],quota)+'<p class="muted">完整批次包含 32 次预热、全部调用、校验和与计时。进程限流可发生在调用间隔，因此同时保留完整批次和调用内耗时。</p>':'';
 return '<h2>'+escapeHTML(datasetTitle(v))+'</h2><p>'+experiment+'</p><p>'+counts.jobs.toLocaleString()+' 次独立进程运行，成功进程含 '+counts.retained_samples.toLocaleString()+' 个完整操作样本；中止进程保留 '+counts.partial_process_samples+' 行已记录样本。另有 '+counts.functional_checks+' 项功能检查，共 '+v.raw_files_checked.toLocaleString()+' 份原始文件。</p>'+table(['进程结果','数量'],Object.entries(counts.status_counts))+quotaText+'<details><summary>各项资源条件及完整操作耗时</summary>'+table(['配置','参数','操作','cgroup 内存上限','CPU 配额/周期 μs','重复进程数','样本数','平均耗时 μs','p95 μs'],conditions)+'</details><details><summary>容量扫描中的实际返回结果（'+failed.length+' 项）</summary>'+table(['运行序号','配置','参数','操作','cgroup 内存上限','退出码','结果','内核 OOM 事件'],failed)+'<p class="muted">CGROUP_OOM 对应内核进程终止事件，CONTROLLER_TIMEOUT 对应固定 10 秒进程上限。每项保留实际文件缓存策略与内核计数；cgroup 记账内存与算法预留内存分别统计。</p></details>';
}
function renderFootprint(v){
 const range=v.configuration_ranges.map(r=>[configTitle(r.configuration),r.vmhwm_kib_minimum+' – '+r.vmhwm_kib_maximum,r.vmrss_after_cleanup_kib_minimum+' – '+r.vmrss_after_cleanup_kib_maximum,r.vmpeak_kib_minimum+' – '+r.vmpeak_kib_maximum]);
 return '<h2>'+escapeHTML(datasetTitle(v))+'</h2><p>'+v.counts.jobs+' 个实际目标进程，四配置各含十八项完整操作；每项进程 32 次预热后执行 64 次调用。</p>'+table(['配置','驻留高水位 KiB','清理后驻留量 KiB','虚拟地址峰值 KiB'],range)+'<p class="muted">从目标进程自身 /proc/self/status 读取 VmHWM、VmRSS 与 VmPeak；表中范围覆盖十八项操作，每项一个独立进程。进程加载器、标准库及输入输出缓冲区计入驻留量。</p><details><summary>逐操作进程内存</summary>'+table(['配置','参数','操作','VmHWM KiB','VmRSS KiB','VmPeak KiB'],v.operations.map(r=>[configTitle(r.configuration),r.parameter,operationName(r.parameter,r.operation),r.vmhwm_kib,r.vmrss_after_cleanup_kib,r.vmpeak_kib]))+'</details>';
}
function renderSharedResource(v){
 const r=v.common_context,p=v.resources.find(x=>x.dll_sha256===v.profile.library_sha256);
 return '<h3>紧凑·共享 Keccak（compact-shared）</h3>'+table(['工作区','栈','上下文','全局可写区','额外堆','核心内存','核心程序大小'],[[r.workspace_common_bytes,r.stack_common_bytes,r.external_context_bytes,r.globals_bytes,r.outside_heap_bytes,r.full_reserved_core_budget_bytes,p.program_bytes].map(memoryText)])+'<p class="muted">共享单轮 Keccak；可移植 C / GCC -Os / LTO。该配置的配对性能实验单独展示。</p>';
}
function renderShared(v){
 const m=v.measurements;
 return '<h2>'+escapeHTML(datasetTitle(v))+'</h2>'+renderSharedResource(v)+table(['共享方式','LTO','对照程序 B','本作配置程序 B','变化 B'],v.comparisons.map(r=>[r.provider,r.lto?'启用':'关闭',r.control_program_bytes,r.candidate_program_bytes,r.candidate_program_bytes-r.control_program_bytes]))+'<p>'+m.blocks+' 个配对轮次，每项每轮 '+m.samples_per_job+' 个样本，共 '+m.retained_samples.toLocaleString()+' 次完整操作。十八项对照/本作配置中位数比的几何平均为 '+m.geomean_control_over_candidate.toFixed(6)+'。</p><p class="muted">这组独立比较使用 1024 字节消息、空上下文，驱动预留 256 KiB 工作区；资源表采用另行验证的 10,720 B 统一工作区。各独立实验的测量条件和预算排序分别报告。</p><details><summary>共享程序空间配置的十八项配对结果</summary>'+table(['参数','操作','首配对区组对照中位数 μs','首配对区组本作配置中位数 μs','完整配对区组加速比'],m.cells.map(r=>[r.parameter,operationName(r.parameter,r.operation),timeText(r.control_median_ns),timeText(r.candidate_median_ns),r.geomean_paired_ratio.toFixed(6)]))+'</details>';
}
function renderAttribution(v){
 const names={'complete-key-factorial':'公开与秘密分量的交叉组合','portable-rho-factorial':'公开种子与固定公钥多项式','shared-screen':'共享程序空间配置的输入分组'};
 return '<details><summary>公开输入因素与时序分布</summary><p>共 '+v.retained_samples.toLocaleString()+' 个固定协议观察；原生速度研究、可移植配对因素实验和共享配置检查分别记录。</p>'+table(['实验','观察数','原始资料'],v.studies.map(s=>[names[s.id]||s.id,s.retained_samples.toLocaleString(),s.id]))+'<p class="muted">计时单位为 TSC ticks。交叉因素实验按完整 1000 组区块进行 20,000 次重采样，公开种子的 SHAKE 拒绝工作量逐项核验。各因素均值差、区间、阳性对照与全部实际样本由数据页导出。</p></details>';
}

function renderInstructionSamples(v){
 const names={encoding_and_representation:'编码与表示',shake_and_keccak:'SHAKE / Keccak',sampling:'采样',ntt_and_inverse:'NTT 与逆变换',cleanup_and_arena:'清理与工作区',polynomial_arithmetic:'多项式算术',protocol_and_other_inlined_code:'协议及其他内联代码',outside_core:'核心库以外'};
 const rows=v.cells.map(c=>{const parts=c.id.split('_');return [parts.at(-2),operationName(Number(parts.at(-2)),Number(parts.at(-1))),c.samples,c.core_samples,...Object.keys(names).map(k=>c.groups[k]||0)];});
 return '<h2>完整操作的指令采样分布</h2><p class="muted">每 1 ms 观察本地工作线程的指令位置，按该库实际反汇编标签归类。表中单位为采样次数，各项保留实际采样密度。</p><details><summary>六参数十八项操作的采样计数</summary>'+table(['参数','操作','总采样','库内采样',...Object.values(names)],rows)+'</details>';
}

async function queryApplicationBudget(){
 const [kem,dsa]=$('application-parameters').value.split(',').map(Number);
 const q=new URLSearchParams({platform:$('application-platform').value,kem,dsa,flows:Number($('application-flows').value),fresh_identity:Number($('application-identity').value),ram_bytes:Number($('application-ram').value)*1024,program_bytes:Number($('application-program').value)*1024});
 const data=await get('/api/application-budget?'+q);window.__lastApplicationBudget=data;
 const target=$('application-selection'),x=data.selected;
 target.innerHTML=x?'<div class="result-head"><h3>'+escapeHTML(configTitle(x.configuration))+'</h3><span class="good">完整批次均值最低</span></div><p>ML-KEM-'+kem+' / ML-DSA-'+dsa+'；应用内存上限 '+(data.request.ram_bytes/1024)+' KiB。</p>'+table(['配置','对象布局','应用内存 B','程序 B','批次均值 μs','95%区间 μs'],data.candidates.map(c=>[configTitle(c.configuration),ownerLayout(c.layout),c.application_ram_bytes.toLocaleString(),c.application_program_bytes.toLocaleString(),timeText(c.mean_batch_ns),c.ci95_batch_ns.map(timeText).join(' – ')])):'<p>当前预算与应用条件下，可用实测配置为0项。</p>';
 if(x)target.innerHTML+='<p class="muted">每批'+data.request.flows+'个完整流程；'+(data.request.fresh_identity?'每流程生成签发身份':'批内复用签发身份，初次密钥生成计入批次')+'。内存包含固定池、输入输出、栈、全局区及外部堆。</p>';
 const download=document.createElement('button');download.textContent='下载应用选择结果';download.onclick=()=>{const blob=new Blob([recordXML(data)],{type:'application/xml'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='application-selection.xml';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};target.appendChild(download);
}

function renderMeasurementBinding(v){
 const b=v.measurement_binding,query='dataset='+encodeURIComponent(v.dataset_id)+'&library='+encodeURIComponent(b.selected_library);
 const independent=b.mode==='independent_arithmetic_archive';
 const description=independent?'独立静态库原语测量':'原始测量程序与所选程序的装载视图一致';
 let identity='<p class="hash">所选程序 SHA256 '+escapeHTML(b.selected_binary_sha256)+'</p>';
 if(independent)identity+=b.measured_archives.map(x=>'<p class="hash">'+escapeHTML(configTitle(x.id))+' · 静态库 SHA256 '+escapeHTML(x.archive_sha256)+'<br>采集程序 SHA256 '+escapeHTML(x.driver_sha256)+'</p>').join('');
 else identity+='<p class="hash">原测量程序 SHA256 '+escapeHTML(b.measured_binary_sha256)+'<br>验证记录 SHA256 '+escapeHTML(b.equivalence_receipt_sha256)+'</p><a class="link" href="'+escapeHTML(b.equivalence_receipt_url)+'">验证记录 XML</a>';
 return '<details class="measurement-binding"><summary>'+escapeHTML(datasetTitle(v))+' · '+description+'</summary>'+identity+'<p><a class="link" href="/export/results.xml?'+query+'">关联结果 XML</a> · <a class="link" href="/export/results.xlsx?'+query+'">关联结果 CSV</a></p></details>';
}
