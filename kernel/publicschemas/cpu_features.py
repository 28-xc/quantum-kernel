"""Explicit host-ISA requirements for a separately identified native library."""
FEATURES = {
 'sse3':(1,0),'pclmul':(1,1),'ssse3':(1,9),'fma':(1,12),'cx16':(1,13),
 'sse4_1':(1,19),'sse4_2':(1,20),'movbe':(1,22),'popcnt':(1,23),'aes':(1,25),
 'xsave':(1,26),'avx':(1,28),'f16c':(1,29),'rdrnd':(1,30),
 'mmx':(2,23),'fxsr':(2,24),'sse':(2,25),'sse2':(2,26),
 'fsgsbase':(3,0),'bmi':(3,3),'avx2':(3,5),'bmi2':(3,8),'rdseed':(3,18),
 'adx':(3,19),'clflushopt':(3,23),'clwb':(3,24),'sha':(3,29),
 'pku':(4,3),'waitpkg':(4,5),'shstk':(4,7),'gfni':(4,8),'vaes':(4,9),'vpclmulqdq':(4,10),
 'rdpid':(4,22),'cldemote':(4,25),'movdiri':(4,27),'movdir64b':(4,28),'serialize':(5,14),'wbnoinvd':(5,9),'avxvnni':(6,4),'lzcnt':(7,5),
 'prfchw':(7,8),'sahf':(7,0),'xsaveopt':(10,0),'xsavec':(10,1),'xsaves':(10,3),
 'ptwrite':(12,4),
}
# Linux arm64 AT_HWCAP bit positions (uapi/asm/hwcap.h, Linux v6.8).
AARCH64_FEATURES={name:bit for bit,name in enumerate((
 'fp','asimd','evtstrm','aes','pmull','sha1','sha2','crc32','atomics','fphp',
 'asimdhp','cpuid','asimdrdm','jscvt','fcma','lrcpc','dcpop','sha3','sm3','sm4',
 'asimddp','sha512','sve','asimdfhm','dit','uscat','ilrcpc','flagm','ssbs','sb','paca','pacg'))}


def validate_execution(value):
    if type(value) is not dict or set(value)!={'backend','required_features','required_xcr0'}:
        raise ValueError('Explicit execution requirements required')
    if value['backend'] not in ('portable','x86_64','aarch64'):
        raise ValueError('Unknown execution backend')
    features=value['required_features']
    allowed=AARCH64_FEATURES if value['backend']=='aarch64' else FEATURES
    if type(features) is not list or len(features)!=len(set(features)) or any(x not in allowed for x in features):
        raise ValueError('Unknown/repeated CPU feature')
    if type(value['required_xcr0']) is not int or value['required_xcr0'] not in (0,6):
        raise ValueError('Unsupported OS state requirement')
    if value['backend']=='x86_64' and (not {'avx','avx2'}<=set(features) or value['required_xcr0']!=6):
        raise ValueError('Native AVX2 requires AVX, AVX2 and OS XMM/YMM state')
    if value['backend']=='portable' and (features or value['required_xcr0']):
        raise ValueError('Unexpected portable-path feature requirement')
    if value['backend']=='aarch64' and (not {'fp','asimd'}<=set(features) or value['required_xcr0']):
        raise ValueError('AArch64 native requires explicit FP/ASIMD and zero x86 state mask')
    return value


def availability(execution, host):
    validate_execution(execution)
    if execution['backend']=='portable':return dict(available=True,reason='可移植指令路径')
    if execution['backend']!=host.get('architecture'):
        return dict(available=False,reason='本机架构不支持该原生路径')
    if not host.get('query_succeeded'):
        return dict(available=False,reason='宿主能力尚未确认，使用可移植构建')
    missing=sorted(set(execution['required_features'])-set(host['features']))
    if missing:return dict(available=False,reason='缺少指令支持：'+', '.join(missing))
    if host['xcr0'] & execution['required_xcr0'] != execution['required_xcr0']:
        return dict(available=False,reason='操作系统未启用 XMM/YMM 状态保存')
    return dict(available=True,reason='CPU 指令与操作系统扩展状态支持已确认')
