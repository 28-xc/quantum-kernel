"""Explicit local-library descriptor; filesystem fields never become API fields."""
from .observations import require, TOKEN, SHA
from .cpu_features import validate_execution

def descriptor(obj):
    require(type(obj) is dict and set(obj) == {'path', 'sha256'}, 'Explicit file identity required')
    require(type(obj['path']) is str and 0 < len(obj['path']) < 1024 and '\x00' not in obj['path'], 'Invalid file path')
    require(type(obj['sha256']) is str and SHA.fullmatch(obj['sha256']), 'Invalid file digest')

def validate_config(obj):
    require(type(obj) is dict and obj.get('schema') == 4, 'Unknown configuration schema')
    fields={'schema','kind','libraries','datasets','scientific_views','pooled_views','deployment_profiles'}
    optional={'host_probe','timing_views','resource_limit_views','process_footprint_views','application_views','application_latency_views','primitive_views','mean_tail_views','equal_frequency_views','application_owner_views','instruction_views','verification_record_views','qualification_views','upgrade_views'}
    require(fields<=set(obj)<=fields|optional, 'Unknown configuration field')
    require(obj['kind'] == 'local_lattice_demo', 'Unsupported configuration')
    require(type(obj['libraries']) is list and 0 < len(obj['libraries']) <= 16, 'Explicit library list required')
    seen = set()
    for lib in obj['libraries']:
        library_fields={'id','title','artifact','configuration','platform','parameters','workspace_bytes','execution'}
        require(type(lib) is dict and library_fields<=set(lib)<=library_fields|{'derivation','measurement_reuse','workspace_options'}, 'Explicit library and execution fields required')
        if 'derivation' in lib:descriptor(lib['derivation'])
        if 'measurement_reuse' in lib:
            from .measurement_reuse import validate_requests
            validate_requests(lib['measurement_reuse'])
        validate_execution(lib['execution'])
        for key in ('id','configuration','platform'):
            require(type(lib[key]) is str and TOKEN.fullmatch(lib[key]), 'Invalid library identity')
        require(lib['id'] not in seen, 'Duplicate library identity'); seen.add(lib['id'])
        require(type(lib['title']) is str and 0 < len(lib['title']) <= 64 and not any(ord(c)<32 for c in lib['title']), 'Invalid title')
        descriptor(lib['artifact'])
        require(type(lib['parameters']) is list and lib['parameters'] and len(set(lib['parameters'])) == len(lib['parameters']) and all(type(p) is int and p in (512,768,1024,44,65,87) for p in lib['parameters']), 'Invalid parameter list')
        require(type(lib['workspace_bytes']) is int and 32 <= lib['workspace_bytes'] <= 1048576 and lib['workspace_bytes'] % 32 == 0, 'Invalid demonstration workspace')
        if 'workspace_options' in lib:
            options=lib['workspace_options']
            require(type(options) is list and len(options)==2 and all(type(v) is int and 32<=v<=1048576 and v%32==0 for v in options)
                    and len(set(options))==2 and lib['workspace_bytes'] in options,'Two distinct qualified workspace capacities required')
    require(type(obj['datasets']) is list and len(obj['datasets']) <= 32, 'Explicit dataset list required')
    if 'host_probe' in obj:descriptor(obj['host_probe'])
    descriptor(obj['deployment_profiles'])
    for item in obj['datasets']: descriptor(item)
    require(type(obj.get('upgrade_views',[])) is list and len(obj.get('upgrade_views',[]))<=4,'Explicit upgrade views required')
    if obj.get('upgrade_views'):
        from .upgrade_views import validate_request
        for item in obj['upgrade_views']:validate_request(item)
    if obj['schema']>=2:
        require(type(obj['scientific_views']) is list and len(obj['scientific_views'])<=16, 'Explicit scientific file list required')
        for item in obj['scientific_views']: descriptor(item)
    if obj['schema']==4:
        require(type(obj['pooled_views']) is list and len(obj['pooled_views'])<=16,'Explicit paired statistics list required')
        for item in obj['pooled_views']:
            require(type(item) is dict and set(item)=={'summary','observations'},'Summary and ordered observations identities required')
            descriptor(item['summary']);descriptor(item['observations'])
        require(type(obj.get('timing_views',[])) is list and len(obj.get('timing_views',[]))<=4,
                'Explicit timing-screen file list required')
        for item in obj.get('timing_views',[]):
            require(type(item) is dict and set(item)=={'summary','observations'},'Timing summary and observations required')
            descriptor(item['summary']);descriptor(item['observations'])
        for field in ('resource_limit_views','process_footprint_views','application_views','application_latency_views','primitive_views','mean_tail_views','equal_frequency_views','application_owner_views','instruction_views','verification_record_views','qualification_views'):
            require(type(obj.get(field,[])) is list and len(obj.get(field,[]))<=8,'Explicit resource file list required')
            for item in obj.get(field,[]):
                require(type(item) is dict and set(item)=={'summary','observations'},'Resource summary and observations required')
                descriptor(item['summary']);descriptor(item['observations'])
    return obj
