"""Closed linked-image observations for parameter pruning and shared entities."""
from pathlib import PurePosixPath
import re

SCHEMA='lattice.program_space_observations.v1'
IMAGE_FIELDS={'format','bits','machine','file_bytes','sha256','sections','text_bytes','rodata_bytes','data_bytes','bss_bytes','readonly_allocated_bytes','all_allocated_section_bytes','image_virtual_span_bytes','load_segments','accounting'}
SECTION_FIELDS={'name','address','memory_bytes','file_bytes','file_offset','allocated','writable','executable','nobits','sha256'}
BAD=re.compile(r'(?i)(?:[a-z]:[\\/]|/(?:home|root|Users)/|[\\/]\.ssh[\\/]|BEGIN [A-Z ]*PRIVATE KEY)')

def need(ok,message):
    if not ok:raise ValueError(message)
def keys(v,names):need(type(v) is dict and set(v)==set(names),'Unexpected program-space fields')
def integer(v,minimum=0):need(type(v) is int and v>=minimum,'Invalid image integer')
def digest(v):need(type(v) is str and re.fullmatch('[0-9a-f]{64}',v),'Invalid content identity')
def clean(v):
    if isinstance(v,str):need(BAD.search(v) is None and '\x00' not in v,'Nonpublic path/text')
    elif isinstance(v,dict):
        for k,x in v.items():clean(k);clean(x)
    elif isinstance(v,list):
        for x in v:clean(x)
def descriptor(v):
    keys(v,('path','sha256'));digest(v['sha256']);p=PurePosixPath(v['path'])
    need(not p.is_absolute() and '\\' not in v['path'] and ':' not in v['path'] and
         p.as_posix()==v['path'] and all(x not in ('','.','..') for x in v['path'].split('/')),'Unsafe artifact path')
def image(v):
    keys(v,IMAGE_FIELDS);need(v['format'] in ('PE','ELF') and v['bits'] in (32,64),'Unknown image format');digest(v['sha256'])
    for k in IMAGE_FIELDS-{'format','sha256','sections','load_segments','accounting'}:integer(v[k])
    need(type(v['sections']) is list and v['sections'],'Section table missing')
    for s in v['sections']:
        keys(s,SECTION_FIELDS)
        for k in ('address','memory_bytes','file_bytes','file_offset'):integer(s[k])
        for k in ('allocated','writable','executable','nobits'):need(type(s[k]) is bool,'Wrong section flags')
        if s['sha256'] is not None:digest(s['sha256'])
        need((s['file_bytes']==0)==(s['sha256'] is None),'Section payload identity missing')
    selected=[s for s in v['sections'] if s['allocated']]
    totals={
      'text_bytes':sum(s['memory_bytes'] for s in selected if s['executable']),
      'rodata_bytes':sum(s['memory_bytes'] for s in selected if not s['executable'] and not s['writable']),
      'data_bytes':sum(s['memory_bytes'] for s in selected if s['writable'] and not s['nobits']),
      'bss_bytes':sum(s['memory_bytes'] for s in selected if s['writable'] and s['nobits']),
      'readonly_allocated_bytes':sum(s['memory_bytes'] for s in selected if not s['writable']),
      'all_allocated_section_bytes':sum(s['memory_bytes'] for s in selected)}
    need(all(v[k]==x for k,x in totals.items()),'Section accounting changed')
    for r in v['load_segments']:
        keys(r,('address','file_bytes','memory_bytes'))
        for x in r.values():integer(x)
def validate(data):
    keys(data,('schema','dataset_id','core_commit','images','pruning','sharing','technical_findings','scope'))
    need(data['schema']==SCHEMA,'Wrong program-space schema');clean(data)
    need(re.fullmatch('[a-zA-Z0-9_.-]+',data['dataset_id']),'Invalid dataset identifier')
    need(re.fullmatch('[0-9a-f]{40}',data['core_commit']),'Invalid core commit')
    images={}
    for x in data['images']:
        keys(x,('id','platform','role','binary','nm','disassembly','entities','image','dependencies','source_record_sha256','source_nm_sha256','source_disassembly_sha256'))
        need(x['id'] not in images,'Duplicate image');images[x['id']]=x
        need(x['platform'] in ('windows_x86_64','linux_aarch64'),'Unknown platform')
        need(x['role'] in ('shared_library','static_whole_image','shared_caller_image'),'Unknown link boundary')
        for k in ('binary','nm','disassembly','entities'):descriptor(x[k])
        for k in ('source_record_sha256','source_nm_sha256','source_disassembly_sha256'):digest(x[k])
        image(x['image']);need(x['binary']['sha256']==x['image']['sha256'],'Image identity mismatch')
        need(type(x['dependencies']) is list and all(isinstance(v,str) for v in x['dependencies']),'Invalid external dependencies')
    groups=set()
    for g in data['pruning']:
        keys(g,('id','platform','configuration','parameters','backend','compiler','optimization','lto','unsupported_status','exports','images','archive','checks','standard_counts','source_record_sha256'))
        need(g['id'] not in groups,'Duplicate pruning group');groups.add(g['id'])
        need(g['unsupported_status']==-8,'Changed unsupported-parameter contract')
        need(type(g['lto']) is bool and g['optimization'] in ('Os','O3'),'Unknown compiler conditions')
        need(g['parameters'] and len(set(g['parameters']))==len(g['parameters']) and set(g['parameters'])<={512,768,1024,44,65,87},'Invalid parameter selection')
        keys(g['images'],('shared_library','static_whole_image','shared_caller_image'))
        for role,identity in g['images'].items():need(identity in images and images[identity]['role']==role and images[identity]['platform']==g['platform'],'Wrong linked image')
        keys(g['archive'],('file_bytes','sha256','is_loaded_image'));integer(g['archive']['file_bytes']);digest(g['archive']['sha256']);need(g['archive']['is_loaded_image'] is False,'Archive is not a loaded-image metric')
        digest(g['source_record_sha256'])
        need(set(g['checks'])=={'shared','static'},'Both API linkage checks required')
        for c in g['checks'].values():
            keys(c,('exit_code','rows','sha256'));integer(c['exit_code'],-2147483648);digest(c['sha256'])
            need([r['parameter'] for r in c['rows']]==[512,768,1024,44,65,87],'Parameter boundary records omitted')
            for r in c['rows']:
                if r['status']=='UNSUPPORTED_AS_CONFIGURED':keys(r,('parameter','status','all_operation_entry_checks'))
                else:keys(r,('parameter','calls_per_operation','guard_bytes','random_failure','overlap_rejected','oom_recovery','initial_arena_highwater','status'))
        for v in g['standard_counts'].values():integer(v)
    for s in data['sharing']:
        keys(s,('id','platform','compiler','optimization','lto','reference','candidate','readonly_delta_bytes','provider_symbol','machine_paths','functional_checks','source_record_sha256','scope'))
        need(s['reference'] in images and s['candidate'] in images,'Missing shared comparison image')
        a,b=images[s['reference']],images[s['candidate']]
        need(a['platform']==b['platform']==s['platform'],'Cross-platform size comparison')
        need(s['readonly_delta_bytes']==b['image']['readonly_allocated_bytes']-a['image']['readonly_allocated_bytes'],'Program delta changed')
        need(s['provider_symbol']=='lc_shared_keccakf1600','Unknown provider');descriptor(s['machine_paths']);digest(s['source_record_sha256'])
        need(type(s['lto']) is bool,'Invalid LTO identity')
    for f in data['technical_findings']:
        keys(f,('platform','affected_group','original_record_sha256','observation','resolution','scope'));digest(f['original_record_sha256'])
    return data
