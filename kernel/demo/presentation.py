"""Public technical labels derived from scientific records, without changing observations."""
import copy
import csv
import io
import re

PLATFORMS={'windows_x86_64':'Windows x86-64','linux_aarch64':'Linux AArch64'}
OPERATIONS={'keygen':'密钥生成','encaps':'封装','decaps':'解封装',
            'decaps_modified_ciphertext':'修改密文后解封装','sign':'签名','verify':'验签',
            'verify_modified_signature':'修改签名后验签'}
CHECKS={'shared_secret_equal':'共享秘密一致','modified_ciphertext_changes_secret':'修改密文返回替代共享秘密',
        'implicit_rejection':'修改密文触发隐式拒绝',
        'signature_verified':'签名验证','modified_signature_rejected':'修改签名被拒绝'}

def configuration_title(name):
    special={'lattice-compact-standard-order':'本作紧凑实现',
             'lattice-dense-eta-decoding':'秘密系数展开对照',
             'lattice-retained-high-encoding':'高位编码保留对照',
             'lattice-dense-eta-retained-high':'秘密系数展开与高位保留对照',
             'lattice-wide-ntt-vectors':'NTT 向量展开对照',
             'lattice-staged-matrix-sampling':'矩阵分阶段采样对照','lattice-compact-native-os-lto':'本作原生紧凑实现（Os + LTO）',
             'lattice-compact-native-o3':'本作原生紧凑实现（O3）',
             'native-low-memory-os-lto':'成熟低内存实现（Os + LTO）',
             'native-low-memory-o3':'成熟低内存实现（O3）',
             'native-low-memory-reference':'成熟低内存实现',
             'portable-compact-rate':'可移植紧凑实现',
             'portable-row-recompute':'可移植逐行重算实现',
             'native-small-matrix-cache':'小矩阵缓存配置（本作）',
             'lattice-compact-native':'紧凑配置',
             'lattice-cache40-native':'部分矩阵缓存',
             'lattice-cache48-native':'48项矩阵缓存',
             'lattice-cache56-native':'完整矩阵缓存',
             'lattice-speed32-native':'32位矩阵缓存配置',
             'lattice-speed32-o3-control':'32位矩阵缓存（O3编译对照）',
             'lattice-sign-pipeline-native':'速度配置',
             'lattice-separated32-control':'32位矩阵与独立向量（结构对照）',
             'lattice-sign-pipeline-structure-control':'计算组织对照（O3 + LTO）',
             'lattice-compact-o3-control':'紧凑配置（O3 + LTO）',
             'native-full-lto':'成熟原生完整缓存（O3 + LTO）',
             'native-lowram-lto':'成熟原生低内存（O3 + LTO）',
             'native-lowram-os-lto':'成熟原生低内存（Os + LTO）',
             'lattice-early-low-check':'低位优先检查（方法对照）',
             'lattice-mixed-sampling-reference':'矩阵与噪声混合采样（方法对照）','baseline_clang':'原生优化对照（Clang）','speed':'速度优先配置',
             'lattice-shared-direct-message':'封装哈希融合 · 直接读取消息',
             'lattice-shared-copied-message':'封装哈希融合 · 复制消息',
             'lattice-shared-vnni':'向量点积实现',
             'lattice-expanded-secret-original-lowbits':'展开秘密系数 · 65/87 低位 19 位',
             'lattice-packed-secret-original-lowbits':'紧凑秘密系数 · 65/87 低位 19 位',
             'lattice-packed-secret-windows-unwind':'紧凑秘密系数 · Windows 栈回溯',
             'lattice-expanded-secret-polyz-lowbits':'展开秘密系数 · 65/87 低位 20 位',
             'lattice-packed-secret-polyz-lowbits':'紧凑秘密系数 · 65/87 低位 20 位',
             'lattice-packed-secret-aligned32':'紧凑秘密系数 · 32 字节函数对齐',
             'lattice-packed-secret-fused-sparse':'紧凑秘密系数 · 融合范数检查',
             'lattice-packed-secret-xof-reuse':'融合范数检查 · SHAKE 状态复用',
             'lattice-direct-matrix-sampling':'矩阵系数直接采样',
             'lattice-direct-matrix-sampling-xof-reuse':'矩阵直接采样 · SHAKE 状态复用',
             'lattice-native':'原生统一实现',
             'lattice-neon-mixed-sampling':'NEON 矩阵与噪声混合采样',
             'lattice-neon-base':'NEON 矩阵与噪声分别采样',
             'native-reference':'原生完整缓存对照',
             'pqclean-reference':'PQClean C 参考（GCC）',
             'native-full':'成熟原生完整缓存','native-low':'原生按需生成对照',
             'native-control':'原生缓存对照','native-fast':'大缓存实现','native-balanced':'小缓存实现',
             'portable-low':'可移植低内存对照','portable-control':'压缩存储对照',
             'portable-compact':'紧凑实现','portable-minimum':'逐行重算实现','portable-shared':'共享 Keccak 实现',
             'compact-rate':'紧凑实现','compact-recompute':'逐行重算实现','compact-rate-shared':'共享 Keccak 实现',
             'staged56-row4':'大缓存实现','joint28-adaptive':'小缓存实现',
             'pqclean-gcc':'PQClean C 参考（GCC）','pqclean-clang':'PQClean C 参考（Clang）',
             'openssl-serialized-none':'OpenSSL · 逐次导入密钥','openssl-serialized-random':'OpenSSL · 逐次导入与 PCT',
             'openssl-reused-none':'OpenSSL · 复用已导入密钥','openssl-reused-random':'OpenSSL · 复用密钥与导入 PCT',
             'compact-shared':'紧凑·共享 Keccak',
             'linux_aarch64-compact-fixed-portable-os-lto':'可移植紧凑配置',
             'linux_aarch64-reference-full-aarch64-o3-nolto':'原生全缓存对照',
             'linux_aarch64-reference-lowram-portable-os-lto':'可移植低内存对照',
             'linux_aarch64-staged56-s3-aarch64-o3-nolto':'原生矩阵与秘密缓存',
             'pqclean-gcc-O3':'PQClean C参考（GCC -O3）','pqclean-clang-O3':'PQClean C参考（Clang -O3）',
             'openssl-none':'OpenSSL（关闭附加导入检查）','openssl-random':'OpenSSL（随机导入检查）'}
    if name in special:return special[name]
    prefix='可移植' if name.startswith('portable-') else '原生' if name.startswith('native-') else ''
    core=re.sub(r'^(portable|native)-(Os-)?','',name)
    names={'reference-full':'全缓存对照','reference-lowram':'低内存对照','compact-fixed':'紧凑配置',
           'compact':'通用位流编码','compact-word24':'24位低位对照','compact-fullhigh':'完整高位对照',
           'compact-sign-only':'仅签名缓冲复用','staged56-s3':'缓存配置（矩阵56项、秘密3项）',
           'staged56-b1':'缓存配置（矩阵56项、四路生成）'}
    if core in names:return prefix+names[core]+('（Os）' if '-Os-' in name else '')
    m=re.fullmatch(r'cache(\d+)-(24|32)',core)
    if m:return f'{prefix}矩阵缓存{m[1]}项（{m[2]}位）'
    m=re.fullmatch(r'staged(\d+)-b([01])',core)
    if m:return f'{prefix}矩阵缓存{m[1]}项（'+('四路' if m[2]=='1' else '单路')+'生成）'
    m=re.fullmatch(r'stream(\d+)',core)
    if m:return f'{prefix}矩阵缓存{m[1]}项＋四路按需生成'+('（Os）' if '-Os-' in name else '')
    return name

def dataset_title(data):
    if data.get('schema')=='lattice.signing_pipeline_qualification_summary.v1':return '部署配置 · 标准与功能验证'
    ident=data.get('dataset_id')
    titles={'windows_native_resource_profiles_20blocks':'Windows x86-64 · 签名缓存与完整操作',
            'windows-layout-contribution-complete-operations':'Windows x86-64 · 紧凑表示消融',
            'windows-signing-pipeline-resource-budgets':'Windows x86-64 · 算法资源与预算',
            'arm-signing-pipeline-resource-budgets':'Linux AArch64 · 算法资源与预算',
            'windows-signing-speed-resource-profiles':'Windows x86-64 · 签名优化与完整操作',
            'windows-signing-speed-resource-budgets':'Windows x86-64 · 签名优化的算法资源与预算',
            'arm-signing-speed-resource-profiles':'Linux AArch64 · 签名优化与完整操作',
            'arm-speed32-final-operations':'Linux AArch64 · 签名优化与完整操作',
            'arm-signing-speed-resource-budgets':'Linux AArch64 · 签名优化的算法资源与预算',
            'windows-signing-resource-profiles':'Windows x86-64 · 签名缓存的算法资源与预算',
            'arm-cached-signing-final-operations':'Linux AArch64 · 签名缓存与完整操作',
            'arm-signing-resource-profiles':'Linux AArch64 · 签名缓存的算法资源与预算',
            'complete-operation-resources':'完整操作对应的算法资源与预算','standard-functional-verification':'标准、互操作与接口验证','windows-representation-operations':'Windows x86-64 · 紧凑表示的独立贡献',
            'windows-contribution-operations':'Windows x86-64 · NTT 表示与矩阵消费的独立贡献'}
    if ident in titles:return titles[ident]
    kind=data.get('kind','');schema=data.get('schema','');platform=PLATFORMS.get(data.get('platform'),data.get('platform',''))
    if kind=='verification' or 'verification_' in str(schema):return '标准与功能验证结果'
    if kind=='instruction_samples' or schema=='lattice.instruction_samples.recomputed.v1':return 'Windows x86-64 · 完整操作指令采样'
    if kind=='comparison_resources':return '完整操作对应的算法资源与预算'
    if kind=='deployment_resources' or 'deployment_resources' in str(schema):return '六参数资源统计'
    if kind=='application_owner' or schema in ('lattice.application_owner_summary.v1','lattice.application_owner_summary.v2'):return platform+' · 固定内存池应用资源与完整耗时'
    if kind=='application_resources' or schema=='lattice.application_pool_statistics.v1':return platform+' · 公钥签发与密钥建立的内存预算'
    if kind=='application_latency' or schema=='lattice.application_latency_statistics.v1':return platform+' · 公钥签发与密钥建立的完整耗时'
    if kind=='primitive_samples' or schema=='lattice.primitive_samples_statistics.v1':return platform+' · 实际算术后端的原语测量'
    if kind=='timing_distributions' or 'timing_statistics' in str(schema):return '输入分组与时序检测结果'
    if kind=='resource_limits' or 'resource_limit_statistics' in str(schema):
        return 'Linux AArch64 · '+('冷文件缓存下的内存边界' if data.get('dataset_id')=='aarch64_memory_boundary' else '系统资源约束实验')
    if kind=='process_footprint' or 'process_footprint_statistics' in str(schema):return 'Linux AArch64 · 实际进程内存'
    if kind=='shared_keccak' or schema=='latticecore.shared_keccak.v1':return '共享 Keccak · 程序空间与完整操作'
    if kind=='timing_attribution' or schema=='latticecore.timing_attribution.v1':return '公开输入因素与时序分布'
    if kind=='mean_tail_measurements' or schema=='lattice.mean_tail_statistics.v1':
        return platform+' · 完整操作耗时分布'
    if kind=='pooled_measurements' or 'pooled_median_statistics' in str(schema):
        n=data.get('counts',{}).get('samples_per_run')
        return platform+' · '+('完整操作性能对比' if n==1000 else '资源配置性能对比')
    if kind=='blocked_measurements':return platform+' · 分组性能测量'
    return '技术测量结果'

def public_view(view):
    result=copy.deepcopy(view)
    result['title']=dataset_title(view)
    result['platform_title']=PLATFORMS.get(view.get('platform'),view.get('platform',''))
    return result

def catalog(scientific):
    configs=set()
    for d in scientific.values():
        for c in d.get('configurations',[]):configs.add(c['id'] if isinstance(c,dict) else c)
        for p in d.get('points',[]):configs.add(p['configuration'])
    return {'schema':'lattice.result_presentation.v1','platforms':PLATFORMS,'operations':OPERATIONS,'checks':CHECKS,
            'configurations':{c:configuration_title(c) for c in sorted(configs)},
            'datasets':{k:dataset_title(v) for k,v in scientific.items()}}

def observed_operation(operation,code,checks):
    if operation=='decaps_modified_ciphertext' and code==0:
        changed=checks.get('implicit_rejection',checks.get('modified_ciphertext_changes_secret',checks.get('tampered_ciphertext_secret_differs')))
        return '触发隐式拒绝，返回替代共享秘密' if changed is True else '已返回解封装结果；共享秘密检查见下方'
    if operation in ('verify_modified_signature','verify_tampered') and code==-6:return '验证失败，修改签名被拒绝'
    return {0:'操作成功',-5:'工作区容量不足',-6:'验证失败',-8:'此构建未启用该参数'}.get(code,'调用返回错误')

def primitive_title(name):
    return {'native-balanced':'原生算术后端','portable-compact':'可移植算术后端'}.get(name,configuration_title(name))

def result_export(data):
    """Scientific source remains independently downloadable and byte-identical."""
    if data['schema']=='latticecore.verification_summary.v1':
        from publicschemas.science import summary
        view=public_view(summary(data))
    else:
        view=public_view(data)
    names={c['id'] for c in data.get('configurations',[]) if isinstance(c,dict)}
    primitive=data.get('schema')=='lattice.primitive_samples_statistics.v1'
    if primitive:names.update(c['configuration'] for c in data['cells'])
    return {'schema':'lattice.presented_scientific_result.v1','title':view['title'],
            'dataset_id':view['dataset_id'],'measurement':view,
            'configuration_titles':{c:(primitive_title(c) if primitive else configuration_title(c)) for c in sorted(names)}}

def result_csv(data):
    out=io.StringIO(newline='')
    fields=['平台','配置','配置编号','算法参数','操作','样本数','均值_ns','中位数_ns','p95_ns','p99_ns']
    mean_tail=data.get('schema')=='lattice.mean_tail_statistics.v1'
    if mean_tail:
        for name in ('均值','中位数','p95','p99'):fields.extend([name+'_95%下限_ns',name+'_95%上限_ns'])
    writer=csv.writer(out);writer.writerow(fields)
    for c in data.get('cells',[]):
        if 'pooled_median_ns' not in c and not mean_tail:continue
        p,o=c['parameter'],c['operation']
        operation=('密钥生成','封装','解封装')[o] if p>100 else ('密钥生成','签名','验签')[o]
        values=[PLATFORMS.get(data.get('platform'),data.get('platform')),configuration_title(c['configuration']),c['configuration'],p,operation,c['pooled_samples']]
        if mean_tail:
            values.extend(c['statistics'][name]['ns'] for name in ('mean','median','p95','p99'))
            for name in ('mean','median','p95','p99'):values.extend(c['statistics'][name]['ci95_ns'])
        else:values.extend(c[key] for key in ('pooled_mean_ns','pooled_median_ns','pooled_p95_ns','pooled_p99_ns'))
        writer.writerow(values)
    return out.getvalue()
