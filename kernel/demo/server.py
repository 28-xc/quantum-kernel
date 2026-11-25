"""Local technical demonstrator. Inputs are explicit hashed libraries and observations."""
import argparse
import csv
import ctypes as C
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
# Shared typed XML persistence; transport JSON remains in memory.
import sys as _record_sys
from pathlib import Path as _RecordPath
for _record_parent in _RecordPath(__file__).resolve().parents:
    _record_candidate = _record_parent / 'record_io.py'
    if not _record_candidate.is_file():
        _record_candidate = _record_parent / '01_源代码/可参数化格运算内核/record_io.py'
    if _record_candidate.is_file():
        _record_sys.path.insert(0, str(_record_candidate.parent))
        break
import record_io as json
import json as wire_json
from pathlib import Path
import secrets
import sys
import threading
from urllib.parse import urlsplit, parse_qs

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from publicschemas.demo import validate_config
from publicschemas.observations import load as load_observations
from publicschemas import science
from publicschemas import resources as resource_model
from publicschemas import deployment
from publicschemas.cpu_features import availability
from demo import host_cpu, presentation
from demo.deployment_ui import DeploymentBuilds
from demo.resource_scopes import resource_objects

V, N, I = C.c_void_p, C.c_size_t, C.c_int
class Context(C.Structure):
    _fields_ = [('workspace',V),('workspace_bytes',N),('random',V),('random_user',V),
                ('arena_high_water',N),('allocations',N),('allocation_failures',N),('last_error',I)]
class Sizes(C.Structure):
    _fields_ = [(x,N) for x in ('public_key','secret_key','ciphertext','shared_secret','signature')]

def strict_json(blob):
    def pairs(items):
        obj={}
        for key,value in items:
            if key in obj:raise ValueError('Duplicate JSON field')
            obj[key]=value
        return obj
    return json.loads(blob,object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite scientific number')))

def read(path):
    return strict_json(Path(path).read_text(encoding='utf-8-sig'))

def checked_file(item, base):
    path = (base / item['path']).resolve()
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
        raise ValueError('Explicit input fingerprint does not match')
    return path

def bind(path):
    lib = C.CDLL(str(path))
    signatures = {'lc_get_sizes':[I,C.POINTER(Sizes)], 'lc_context_init':[C.POINTER(Context),V,N,V,V],
        'lc_keypair':[C.POINTER(Context),I,V,N,V,N], 'lc_encaps':[C.POINTER(Context),I,V,N,V,N,V,N],
        'lc_decaps':[C.POINTER(Context),I,V,N,V,N,V,N], 'lc_sign':[C.POINTER(Context),I,V,N,V,N,V,N,V,N],
        'lc_verify':[C.POINTER(Context),I,V,N,V,N,V,N,V,N]}
    for name,args in signatures.items():
        fn = getattr(lib,name); fn.argtypes=args; fn.restype=I
    return lib

def outcome(code):
    return 'SUCCESS' if code == 0 else 'CAPACITY_INSUFFICIENT' if code == -5 else 'REJECTED' if code == -6 else 'UNSUPPORTED' if code == -8 else 'ERROR'

class UnavailableLibraryError(ValueError):
    pass

class Application:
    def __init__(self, config_path):
        path = Path(config_path).resolve()
        config = validate_config(read(path))
        if config.get('application_latency_views') or config.get('primitive_views') or config.get('application_owner_views'):
            try:
                import numpy
            except ImportError:
                from tools.offline_analysis import numpy_site
                sys.path.insert(0, str(numpy_site(path.parent)))
                import numpy
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock(); self.libs = {}; self.descriptors = {}; self.runs = {}
        self.datasets = []
        self.scientific = {}
        self.pooled = {}
        self.equal_frequency = {}
        self.deployment = deployment.validate(read(checked_file(config['deployment_profiles'],path.parent)))
        self.host = host_cpu.query(checked_file(config['host_probe'],path.parent) if 'host_probe' in config else None)
        for item in config['libraries']:
            library = checked_file(item['artifact'], path.parent)
            measured_sha = item['artifact']['sha256']
            provenance = {}
            if 'derivation' in item:
                from publicschemas.deployment_image import load_deployment_image
                receipt = checked_file(item['derivation'], path.parent)
                verified = load_deployment_image(library, receipt, item['derivation']['sha256'],
                                                 binary_sha256=item['artifact']['sha256'])
                measured_sha = verified['measured_binary_sha256']
                provenance = {'measured_binary_sha256':measured_sha,
                              'deployment_derivation_sha256':verified['derivation_sha256']}
            if not deployment.permits(self.deployment,item['platform'],measured_sha,item['workspace_bytes']):
                raise ValueError('Algorithm image is outside the registered deployment profiles')
            if any(not deployment.permits(self.deployment,item['platform'],measured_sha,capacity)
                   for capacity in item.get('workspace_options',[])):
                raise ValueError('Selectable workspace is not registered for this exact algorithm image')
            execution=item['execution']
            state=availability(execution,self.host)
            if state['available']:self.libs[item['id']] = bind(library)
            self.descriptors[item['id']] = {k:v for k,v in item.items() if k not in ('artifact','derivation','measurement_reuse')} | {'binary_sha256':item['artifact']['sha256'],'execution':execution,'execution_available':state['available'],'execution_reason':state['reason']} | provenance
        names = set()
        from publicschemas import upgrade_views
        self.upgrades={}
        for item in config.get('upgrade_views',[]):
            if item['id'] in self.upgrades:raise ValueError('Duplicate upgrade dataset')
            self.upgrades[item['id']]=upgrade_views.load(item,path.parent,self.descriptors)
        for item in config['datasets']:
            data = load_observations(checked_file(item, path.parent))
            if data['dataset_id'] in names: raise ValueError('Duplicate dataset identity')
            names.add(data['dataset_id']); self.datasets.append(data)
        for item in config.get('scientific_views',[]):
            observation_path=checked_file(item,path.parent)
            data=science.load(observation_path)
            if data['dataset_id'] in names:raise ValueError('Duplicate dataset identity')
            names.add(data['dataset_id']);self.scientific[data['dataset_id']]=data
            if data['schema'] in (science.SHARED,science.ATTRIBUTION):
                self.pooled[data['dataset_id']]={'observations':data,'base':observation_path.parent,'manifest_path':observation_path,'manifest_sha256':item['sha256']}
        for item in config.get('pooled_views',[]):
            # These modules are the public scientific validators distributed
            # with this application, with import-only package adjustments.
            from publicschemas.pooled_model import validate as validate_pooled
            summary_path=checked_file(item['summary'],path.parent)
            observations_path=checked_file(item['observations'],path.parent)
            data=read(summary_path);observations=read(observations_path)
            if data.get('observations_sha256')!=item['observations']['sha256']:
                raise ValueError('Statistics refer to a different observation manifest')
            validate_pooled(data,observations)
            if data['dataset_id'] in names:raise ValueError('Duplicate dataset identity')
            names.add(data['dataset_id']);self.scientific[data['dataset_id']]=data
            self.pooled[data['dataset_id']]={'observations':observations,'base':observations_path.parent,'manifest_path':observations_path,
                                           'manifest_sha256':item['observations']['sha256']}
        for item in config.get('mean_tail_views',[]):
            from publicschemas.mean_tail_model import validate as validate_mean_tail
            summary_path=checked_file(item['summary'],path.parent)
            observations_path=checked_file(item['observations'],path.parent)
            data=read(summary_path);observations=read(observations_path)
            if data.get('observations_sha256')!=item['observations']['sha256']:
                raise ValueError('Mean/tail statistics refer to another observation manifest')
            validate_mean_tail(data,observations)
            for relative,digest in data['source_code_hashes'].items():
                if hashlib.sha256((ROOT/relative).read_bytes()).hexdigest()!=digest:
                    raise ValueError('Mean/tail statistical source identity changed')
            if data['dataset_id'] in names:raise ValueError('Duplicate dataset identity')
            names.add(data['dataset_id']);self.scientific[data['dataset_id']]=data
            self.pooled[data['dataset_id']]={'observations':observations,'base':observations_path.parent,'manifest_path':observations_path,
                                           'manifest_sha256':item['observations']['sha256']}
        for item in config.get('equal_frequency_views',[]):
            from analysis import equal_frequency_statistics as equal_frequency
            from tools.recompute_operation_statistics import compare as compare_statistics
            summary_path=checked_file(item['summary'],path.parent)
            observations_path=checked_file(item['observations'],path.parent)
            data=read(summary_path);observations=read(observations_path)
            equal_frequency.model.validate(data,observations)
            if data['observations_sha256']!=item['observations']['sha256']:
                raise ValueError('Equal-frequency observations changed')
            if data['source_code_hashes']!=equal_frequency.sources():
                raise ValueError('Equal-frequency statistical source changed')
            pairs=[{key:row[key] for key in ('id','candidate','reference')}
                   for row in data['comparisons']]
            reconstructed=equal_frequency.analyze(observations,pairs,
                item['observations']['sha256'],data['method']['resamples'],
                data['method']['bootstrap_seed'],observations_path.parent)
            compare_statistics(data,reconstructed)
            ident=data['dataset_id']
            if ident not in self.scientific or ident in self.equal_frequency:
                raise ValueError('Equal-frequency result requires one registered timing study')
            if self.scientific[ident]['observations_sha256']!=data['observations_sha256']:
                raise ValueError('Equal-frequency and operation statistics use different observations')
            self.equal_frequency[ident]=data
        for item in config.get('timing_views',[]):
            from publicschemas.timing_v1 import validate_summary
            summary_path=checked_file(item['summary'],path.parent)
            observations_path=checked_file(item['observations'],path.parent)
            data=read(summary_path);observations=read(observations_path)
            if data.get('observations_sha256')!=item['observations']['sha256']:
                raise ValueError('Timing statistics refer to another observation manifest')
            validate_summary(data,observations)
            if data['dataset_id'] in names:raise ValueError('Duplicate dataset identity')
            names.add(data['dataset_id']);self.scientific[data['dataset_id']]=data
            self.pooled[data['dataset_id']]={'observations':observations,'base':observations_path.parent,'manifest_path':observations_path,
                                           'manifest_sha256':item['observations']['sha256']}
        for field,item in [(field,item) for field in ('resource_limit_views','process_footprint_views') for item in config.get(field,[])]:
            if field=='resource_limit_views':
                from publicschemas.resource_limits_v1 import validate_summary
            else:
                from publicschemas.process_footprint_v1 import validate_summary
            summary_path=checked_file(item['summary'],path.parent)
            observations_path=checked_file(item['observations'],path.parent)
            data=read(summary_path);observations=read(observations_path)
            if data.get('observations_sha256')!=item['observations']['sha256']:
                raise ValueError('Resource statistics refer to another observation manifest')
            validate_summary(data,observations)
            if data['dataset_id'] in names:raise ValueError('Duplicate dataset identity')
            names.add(data['dataset_id']);self.scientific[data['dataset_id']]=data
            self.pooled[data['dataset_id']]={'observations':observations,'base':observations_path.parent,'manifest_path':observations_path,
                                           'manifest_sha256':item['observations']['sha256']}

        for item in config.get('application_views',[]):
            from publicschemas.application_v1 import validate_summary
            summary_path=checked_file(item['summary'],path.parent)
            observations_path=checked_file(item['observations'],path.parent)
            data=read(summary_path);observations=read(observations_path)
            if data.get('observations_sha256')!=item['observations']['sha256']:
                raise ValueError('Application statistics refer to another observation manifest')
            validate_summary(data,observations_path)
            if data['dataset_id'] in names:raise ValueError('Duplicate dataset identity')
            names.add(data['dataset_id']);self.scientific[data['dataset_id']]=data
            self.pooled[data['dataset_id']]={'observations':observations,'base':observations_path.parent,'manifest_path':observations_path,
                                           'manifest_sha256':item['observations']['sha256']}

        for field,module_name in (('application_latency_views','application_latency_v1'),('primitive_views','primitive_samples_v1'),('application_owner_views','application_owner_v1'),('instruction_views','profiling_v1'),('verification_record_views','verification_records_v1'),('qualification_views','signing_qualification')):
            import importlib
            module=importlib.import_module('publicschemas.'+module_name)
            for item in config.get(field,[]):
                summary_path=checked_file(item['summary'],path.parent)
                observations_path=checked_file(item['observations'],path.parent)
                data=read(summary_path);observations=read(observations_path)
                if data.get('observations_sha256')!=item['observations']['sha256'] or module.recompute(observations_path)!=data:
                    raise ValueError('Published measurements differ from their original observations')
                ident = 'standard-functional-verification' if field=='verification_record_views' else data['dataset_id']
                if ident in names:raise ValueError('Duplicate dataset identity')
                names.add(ident);self.scientific[ident]=data
                self.pooled[ident]={'observations':observations,'base':observations_path.parent,'manifest_path':observations_path,
                                               'manifest_sha256':item['observations']['sha256']}

        from publicschemas import measurement_reuse
        self.measurement_reuse = {}; self.equivalence_files = {}
        for item in config['libraries']:
            for association in item.get('measurement_reuse', []):
                ident = association['dataset_id']
                if ident not in self.scientific:raise ValueError('Measurement association dataset is not registered')
                receipt = checked_file(association['equivalence'], path.parent)
                binding = measurement_reuse.verify(association, self.descriptors[item['id']], self.scientific[ident], receipt)
                self.measurement_reuse[(item['id'], ident)] = binding
                self.equivalence_files[(item['id'], ident)] = (receipt, association['equivalence']['sha256'])

    def science_views(self,library=None):
        if library is not None and library not in self.descriptors:raise ValueError('Unknown library')
        descriptor=self.descriptors[library] if library else None
        if descriptor is not None and 'measured_binary_sha256' in descriptor:
            descriptor=dict(descriptor,binary_sha256=descriptor['measured_binary_sha256'])
        views=[]
        for data in self.scientific.values():
            binding=getattr(self,'measurement_reuse',{}).get((library,data.get('dataset_id')))
            selected=dict(descriptor,binary_sha256=binding['measured_binary_sha256']) if binding else descriptor
            view=science.summary(data,selected)
            if view is not None and binding:view['measurement_binding']=binding
            if view is not None and data['schema'] in (science.APPLICATION_LATENCY,science.PRIMITIVES):
                observed=self.pooled[data['dataset_id']]['observations']
                view['method']=observed['method'];view['configurations']=observed['configurations']
                if library is not None and data['schema']==science.PRIMITIVES:
                    from publicschemas.measurement_reuse import independent_archive_binding
                    view['measurement_binding']=independent_archive_binding(self.descriptors[library],observed['configurations'])
            if view is not None and data['schema'] in (science.POOLED,science.MEAN_TAIL):
                view['boundary']=self.pooled[data['dataset_id']]['observations']['experiment']['timing_boundary']
                if data['dataset_id'] in self.equal_frequency:
                    total=self.equal_frequency[data['dataset_id']]
                    ids={c['id'] for c in view['configurations']}
                    view['equal_frequency']=dict(totals=[r for r in total['totals'] if r['configuration'] in ids],
                        comparisons=[r for r in total['comparisons'] if r['candidate'] in ids or r['reference'] in ids])
            if view is not None and data['schema']==science.TIMING:
                observed=self.pooled[data['dataset_id']]['observations']
                selected={s['study_id'] for s in view['studies']}
                view['input_conditions']=[{k:s[k] for k in ('study_id','conditions','families','scope')}
                                          for s in observed['studies'] if s['study_id'] in selected]
            if view is not None and data['schema'] in (science.LIMITS,science.FOOTPRINT):
                observed=self.pooled[data['dataset_id']]['observations']
                view['raw_files_checked']=len(observed['raw_files'])
                view['configurations']=observed['configurations']
                if 'environment' in observed:view['environment']=observed['environment']
            views.append(view)
        return {'schema':1,'views':[v for v in views if v is not None]}

    def selected_scientific_result(self,dataset,library):
        if dataset not in self.scientific:raise ValueError('Unknown dataset')
        matches=[v for v in self.science_views(library)['views'] if v.get('dataset_id')==dataset]
        if len(matches)!=1:raise ValueError('Dataset does not apply to selected library')
        return matches[0]

    def equivalence_receipt(self,library,dataset):
        path,digest=self.equivalence_files[(library,dataset)]
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('Equivalence receipt changed')
        return raw

    def selected_record(self,row,library):
        lib = self.descriptors[library]
        if row['kind'] in ('resource','timing_series') and row.get('workspace_bytes')!=lib['workspace_bytes']:
            return False
        return (not row['historical'] and row.get('binary_sha256') == lib.get('measured_binary_sha256',lib['binary_sha256'])
                and row['configuration'] == lib['configuration'] and row['platform'] == lib['platform']
                and row['parameter'] in lib['parameters'])

    def public_results(self,library=None):
        views=[presentation.public_view(v) for v in self.science_views(library)['views']]
        from publicschemas import upgrade_views
        views.extend(v for entry in self.upgrades.values() if (v:=upgrade_views.view(entry,library)) is not None)
        return {'schema':'lattice.technical_result_catalog.v1','views':views}

    def observations(self, scope='current', library=None):
        if scope not in ('current','all'): raise ValueError('Unknown observation scope')
        if library is not None and library not in self.descriptors: raise ValueError('Unknown library')
        if scope=='all' and library is not None:raise ValueError('Complete archive has no deployment filter')
        records = []
        for data in self.datasets:
            for row in data['records']:
                if row['historical']:
                    continue
                selected = True if scope=='all' else any(self.selected_record(row,k) for k in ([library] if library else self.descriptors))
                if selected: records.append(row)
        return {'schema':1,'kind':'lattice_technical_observations','dataset_id':'selected_'+scope,'records':records}

    def deployment_builds(self):
        with self.lock:
            if not hasattr(self,'_deployment_builds'):
                self._deployment_builds=DeploymentBuilds(ROOT.parent/'deployment-runs',self.host)
        return self._deployment_builds

    def catalog(self):
        rows = []
        for key,item in self.descriptors.items():
            records = self.observations('current',key)['records']
            rows.append(item | {'archived_timing_records':sum(r['kind']=='timing_series' for r in records),
                               'archived_resource_records':sum(r['kind']=='resource' for r in records),
                               'archived_test_records':sum(r['kind']=='test_result' for r in records),
                               'technical_result_sets':len(self.public_results(key)['views'])})
        return {'schema':1,'kind':'technical_demo_catalog','libraries':rows,'deployment_scope':self.deployment,
                'archived_records':sum(len(d['records']) for d in self.datasets),
                'historical_records':sum(r['historical'] for d in self.datasets for r in d['records']),
                'message_lengths':[0,32,1024,16384],'context_lengths':[0,1,255],
                'workspace_scope':'功能调用使用当前映像已登记的32字节对齐内核工作区；它不包含输入输出、调用栈和完整应用内存。',
                'timing_scope':'功能运行展示返回结果；性能页展示归档测量。'}

    def resource_catalog(self):
        points=[p for d in self.scientific.values() if d['schema'] in resource_model.SCHEMAS+(science.COMPARISON_RESOURCES,) for p in d['points']]
        self._resource_objects = resource_objects(points, self.descriptors.values())
        builds = getattr(self, '_deployment_builds', None)
        if builds:
            completed = [x for x in list(builds.jobs.values()) if x['status']=='READY']
            if completed:
                last = completed[-1]
                self._resource_objects['exported_program']['last_completed'] = dict(
                    resource_object=last['resource_object'], image_sha256=last['image_sha256'],
                    parameters=last['request']['parameters'], operations=last['request']['operations'])
        return {'schema':1,'resource_objects':self._resource_objects,'datasets':[science.summary(d) for d in self.scientific.values()
                    if d['schema'] in resource_model.SCHEMAS+(science.COMPARISON_RESOURCES,)],
                'timing_studies':[{'dataset_id':d['dataset_id'],'platform':d['platform'],
                    'configurations':[c['id'] for c in d['configurations']]} for d in self.scientific.values()
                    if d['schema'] in resource_model.TIMING_SCHEMAS and any(c['provider']=='lattice' and
                        any(p['platform']==d['platform'] and p['binary_sha256']==c['library_sha256'] and
                            (p.get('statistics_dataset')==d['dataset_id'] or p['reserved_components']['workspace_bytes']==c['workspace_reserved']) for p in points) for c in d['configurations'])],
                'ram_presets_kib':[16,32,64,128,256],'program_presets_kib':[64,128,256,512]}

    def budget(self,request):
        required={'resource_dataset','timing_dataset','platform','ram_bytes','program_bytes'}
        if type(request) is not dict or not required<=set(request) or set(request)-required-{'operation_counts'}:
            raise ValueError('Explicit budget and study identities required')
        resources=self.scientific.get(request['resource_dataset']);statistics=self.scientific.get(request['timing_dataset'])
        if resources is None or resources['schema'] not in resource_model.SCHEMAS+(science.COMPARISON_RESOURCES,) or statistics is None or statistics['schema'] not in resource_model.TIMING_SCHEMAS:
            raise ValueError('Unknown registered resource/timing pair')
        model=resource_model
        if resources['schema']==science.COMPARISON_RESOURCES:
            from publicschemas import comparison_resources as model
        result=model.select(resources,statistics,{k:request[k] for k in required if k!='resource_dataset'},self.deployment)
        if 'operation_counts' in request:
            from publicschemas.workload_selection import rank
            result=rank(result,statistics,request['operation_counts'])
        return result

    def application_budget(self,request):
        from publicschemas.application_selection import select
        summaries=[d for d in self.scientific.values() if d['schema'] in ('lattice.application_owner_summary.v1','lattice.application_owner_summary.v2')]
        return select(summaries,self.deployment,request)

    def raw_shard(self,dataset,ordinal):
        if dataset not in self.pooled:raise ValueError('Unknown observation study')
        entry=self.pooled[dataset];data=entry['observations']
        if data['schema']=='lattice.block_observation_shards.v2':
            if not 0<=ordinal<len(data['runs']):raise ValueError('Unknown raw run')
            shard=data['runs'][ordinal]['sample_shard']
        elif data['schema']=='lattice.timing_observations.v1':
            records=[r for s in data['studies'] for r in s['records']]
            if not 0<=ordinal<len(records):raise ValueError('Unknown timing record')
            raw=records[ordinal]['raw'];shard={'path':raw['file'],'sha256':raw['sha256']}
        elif data['schema'] in ('lattice.resource_limit_observations.v1','lattice.process_footprint_observations.v1','lattice.application_owner_observations.v1','lattice.application_owner_observations.v2'):
            if not 0<=ordinal<len(data['raw_files']):raise ValueError('Unknown resource observation')
            shard=data['raw_files'][ordinal]
        elif data['schema']=='lattice.signing_pipeline_qualification.v1':
            if not 0<=ordinal<len(data['files']):raise ValueError('Unknown qualification record')
            shard=data['files'][ordinal]
        elif data['schema']==science.SHARED:
            if not 0<=ordinal<len(data['measurements']['jobs']):raise ValueError('Unknown shared-provider sample')
            shard=data['measurements']['jobs'][ordinal]['raw']
        elif data['schema']=='latticecore.verification_observations.v1':
            files=[x['records'] for x in data['runs']]
            if not 0<=ordinal<len(files):raise ValueError('Unknown verification record')
            shard={'path':files[ordinal]['file'],'sha256':files[ordinal]['sha256']}
        elif data['schema']=='lattice.instruction_samples.windows.v1':
            files=[x['raw'] for x in data['cells']]+[x['mapping'] for x in data['libraries']]
            if not 0<=ordinal<len(files):raise ValueError('Unknown instruction observation')
            shard=files[ordinal]
        elif data['schema']=='lattice.application_latency_observations.v1':
            if not 0<=ordinal<len(data['jobs']):raise ValueError('Unknown application run')
            shard=data['jobs'][ordinal]['raw']
        elif data['schema']=='lattice.primitive_samples_observations.v1':
            if not 0<=ordinal<len(data['processes']):raise ValueError('Unknown primitive process')
            shard=data['processes'][ordinal]['raw']
        elif data['schema']=='lattice.application_pool_observations.v1':
            if ordinal!=0:raise ValueError('The application archive contains one ordered XML record sequence')
            shard=data['raw']
        elif data['schema']==science.ATTRIBUTION:
            files=[r for s in data['studies'] for j in s['jobs'] for r in (j['files'].values() if 'files' in j else [j['raw']])]
            if not 0<=ordinal<len(files):raise ValueError('Unknown timing-attribution sample')
            shard=files[ordinal]
        else:raise ValueError('Unknown observation schema')
        if shard is None:raise ValueError('This run has no raw artifact')
        relative=Path(shard['path'])
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('Outside registered observations')
        path=(entry['base']/relative).resolve()
        if not path.is_relative_to(entry['base'].resolve()):raise ValueError('Outside registered observations')
        if not path.exists():
            path=entry.get('raw_aliases',{}).get(shard['path'],path)
        blob=path.read_bytes()
        if 'bytes' in shard and len(blob)!=shard['bytes']:raise ValueError('Raw observation size changed')
        if hashlib.sha256(blob).hexdigest()!=shard['sha256']:raise ValueError('Raw observation fingerprint changed')
        return blob

    def execute(self, library, parameter, message_bytes, context_bytes, capacity):
        lib = self.libs[library]; sizes=Sizes()
        if lib.lc_get_sizes(parameter,C.byref(sizes)): raise ValueError('Unsupported parameter')
        raw=C.create_string_buffer(capacity+96); address=(C.addressof(raw)+63)&~31
        C.memset(raw,0xa5,len(raw)); C.memset(address,0xcc,capacity)
        ctx=Context(); rc=lib.lc_context_init(C.byref(ctx),address,capacity,None,None)
        if rc: raise ValueError('Context initialization failed')
        pk=C.create_string_buffer(sizes.public_key); sk=C.create_string_buffer(sizes.secret_key)
        sensitive=[sk]; events=[]; high=0; failure_zero=None; checks={}; succeeded=False
        def call(operation,fn,*args):
            nonlocal high
            status=fn(C.byref(ctx),parameter,*args); high=max(high,ctx.arena_high_water)
            events.append({'operation':operation,'return_code':status,'outcome':outcome(status),'arena_high_water_bytes':ctx.arena_high_water})
            return status
        try:
            C.memset(pk,0xa5,len(pk)); C.memset(sk,0xa5,len(sk))
            rc=call('keygen',lib.lc_keypair,pk,len(pk),sk,len(sk))
            if rc: failure_zero=not any(pk.raw) and not any(sk.raw)
            elif sizes.ciphertext:
                ct=C.create_string_buffer(sizes.ciphertext); a=C.create_string_buffer(32); b=C.create_string_buffer(32); sensitive += [a,b]
                C.memset(ct,0xa5,len(ct)); C.memset(a,0xa5,32)
                rc=call('encaps',lib.lc_encaps,ct,len(ct),a,32,pk,len(pk))
                if rc: failure_zero=not any(ct.raw) and not any(a.raw)
                else:
                    rc=call('decaps',lib.lc_decaps,b,32,ct,len(ct),sk,len(sk))
                    checks['shared_secret_equal']=rc==0 and secrets.compare_digest(a.raw,b.raw)
                    ct[0]=bytes([ct.raw[0]^1])
                    bad=call('decaps_modified_ciphertext',lib.lc_decaps,b,32,ct,len(ct),sk,len(sk))
                    checks['implicit_rejection']=bad==0 and not secrets.compare_digest(a.raw,b.raw)
                    succeeded=all(checks.values())
            else:
                message=C.create_string_buffer(bytes((i*29+7)%256 for i in range(message_bytes)))
                domain=C.create_string_buffer(bytes((i*17+3)%256 for i in range(context_bytes)))
                sig=C.create_string_buffer(sizes.signature); C.memset(sig,0xa5,len(sig))
                rc=call('sign',lib.lc_sign,sig,len(sig),message,message_bytes,domain,context_bytes,sk,len(sk))
                if rc: failure_zero=not any(sig.raw)
                else:
                    rc=call('verify',lib.lc_verify,sig,len(sig),message,message_bytes,domain,context_bytes,pk,len(pk))
                    checks['signature_verified']=rc==0
                    sig[0]=bytes([sig.raw[0]^1])
                    bad=call('verify_modified_signature',lib.lc_verify,sig,len(sig),message,message_bytes,domain,context_bytes,pk,len(pk))
                    checks['modified_signature_rejected']=bad==-6; succeeded=all(checks.values())
            canaries_ok=C.string_at(address-32,32)==b'\xa5'*32 and C.string_at(address+capacity,32)==b'\xa5'*32
            for event in events:
                event['operation_title']=presentation.OPERATIONS.get(event['operation'],event['operation'])
                event['result_description']=presentation.observed_operation(event['operation'],event['return_code'],checks)
            return {'operations':events,'checks':checks,'functional_checks_passed':succeeded and canaries_ok,
                    'workspace_bytes':capacity,'observed_arena_high_water_bytes':high,
                    'canaries_ok':canaries_ok,
                    'failure_output_zero':failure_zero}
        finally:
            for buf in sensitive: C.memset(buf,0,len(buf))
            C.memset(address,0,capacity)

    def run(self, request):
        required={'library','parameter','message_bytes','context_bytes','mode'}
        if type(request) is not dict or not required<=set(request) or set(request)-required-{'workspace_bytes'}: raise ValueError('Unknown run fields')
        library=request['library']; p=request['parameter']; m=request['message_bytes']; c=request['context_bytes']; mode=request['mode']
        if type(library) is str and library in self.descriptors and library not in self.libs:
            raise UnavailableLibraryError(self.descriptors[library]['execution_reason'])
        if type(library) is not str or library not in self.libs or type(p) is not int or p not in self.descriptors[library]['parameters']: raise ValueError('Unknown library or parameter')
        if type(m) is not int or m not in (0,32,1024,16384) or type(c) is not int or c not in (0,1,255) or mode not in ('normal','insufficient'): raise ValueError('Unknown run preset')
        descriptor=self.descriptors[library]
        cap=request.get('workspace_bytes',descriptor['workspace_bytes'])
        if type(cap) is not int or cap not in descriptor.get('workspace_options',[descriptor['workspace_bytes']]):
            raise ValueError('Workspace capacity is not an available choice for this library')
        measured_sha=descriptor.get('measured_binary_sha256',descriptor['binary_sha256'])
        if not deployment.permits(self.deployment,descriptor['platform'],measured_sha,cap):
            raise ValueError('Workspace capacity is not registered for this exact algorithm image')
        with self.lock:
            result=self.execute(library,p,m,c,32 if mode=='insufficient' else cap)
            if not result['functional_checks_passed']:
                result['recovery']=self.execute(library,p,m,c,cap)
            ident=secrets.token_hex(8)
            result.update(schema=1,kind='local_functional_observation',run_id=ident,library=library,parameter=p,
                          algorithm='ML-KEM' if p>100 else 'ML-DSA',message_bytes=m,context_bytes=c,mode=mode,
                          binary_sha256=self.descriptors[library]['binary_sha256'],requested_workspace_bytes=cap,performance_measurement=False)
            if 'measured_binary_sha256' in self.descriptors[library]:
                result['measured_binary_sha256']=self.descriptors[library]['measured_binary_sha256']
                result['deployment_derivation_sha256']=self.descriptors[library]['deployment_derivation_sha256']
            self.runs[ident]=result
            if len(self.runs)>100: self.runs.pop(next(iter(self.runs)))
            return result

def samples_csv(data):
    s=io.StringIO(newline=''); w=csv.writer(s)
    fields=['algorithm','parameter','operation','configuration','platform','execution','historical','binary_sha256','round_id','sample_semantics','samples_per_batch','message_bytes','context_bytes','thread_count','timer']
    w.writerow(['record_index','sample_index',*fields,'elapsed_ns','outcome','return_code'])
    for i,r in enumerate(data['records']):
        if r['kind'] != 'timing_series': continue
        outcomes=r.get('outcomes',['']*len(r['samples_ns'])); codes=r.get('return_codes',['']*len(r['samples_ns']))
        for j,t in enumerate(r['samples_ns']):
            w.writerow([i,j,*[r.get(k,'') for k in fields],t,outcomes[j],codes[j]])
    return s.getvalue().encode('utf-8-sig')

def handler(app,host):
    assets={'/':('index.html','text/html'),'/app.js':('app.js','text/javascript'),'/deployment_ui.js':('deployment_ui.js','text/javascript'),'/scientific_ui.js':('scientific_ui.js','text/javascript'),'/app.css':('app.css','text/css'),'/favicon.ico':('icon.svg','image/svg+xml')}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def send(self,status,data,mime='application/json'):
            exporting = '/export/' in urlsplit(self.path).path
            export_path = urlsplit(self.path).path
            if (exporting and export_path.endswith('.xlsx') and status == 200 and
                    mime != 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'):
                from demo.spreadsheet_export import csv_workbook, functional_workbook
                data = csv_workbook(data) if mime == 'text/csv' else functional_workbook(data)
                mime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            if exporting and mime in ('application/json','application/x-ndjson') and status == 200:
                if isinstance(data, (bytes, str)):
                    data = json.loads(data)
                data = json.dumps(data, ensure_ascii=False, allow_nan=False).encode('utf-8')
                mime = 'application/xml'
            elif not isinstance(data,bytes):
                data=(data if isinstance(data,str) else wire_json.dumps(data,ensure_ascii=False,allow_nan=False)).encode('utf-8')
            self.send_response(status); self.send_header('Content-Type',mime+'; charset=utf-8'); self.send_header('Content-Length',str(len(data)))
            self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers(); self.wfile.write(data)
        def valid_host(self): return self.headers.get('Host')==host
        def do_GET(self):
            if not self.valid_host(): return self.send(403,{'error':'仅接受本地访问'})
            url=urlsplit(self.path); path=url.path
            if path in ('/export/results.xlsx','/export/science.xlsx','/export/samples.xlsx'):
                path=path[:-5]+'.csv'
            elif path.startswith('/export/run/') and path.endswith('.xlsx'):
                path=path[:-5]+'.xml'
            try:
                if path in assets:
                    if url.query: raise ValueError('Unexpected query')
                    name,mime=assets[path]; body=(Path(__file__).parent/name).read_text(encoding='utf-8')
                    return self.send(200,body.replace('__CSRF__',app.token),mime)
                if path=='/api/catalog' and not url.query: return self.send(200,app.catalog())
                if path=='/api/presentation' and not url.query:return self.send(200,presentation.catalog(app.scientific))
                if path=='/api/results':
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    if not set(q)<={'library'} or any(len(v)!=1 for v in q.values()):raise ValueError('Unknown result query')
                    return self.send(200,app.public_results(q.get('library',[None])[0]))
                if path.startswith('/export/upgrade/'):
                    from publicschemas import upgrade_views
                    name=path.removeprefix('/export/upgrade/').removesuffix('.xml').removesuffix('.csv')
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    fields={'dataset','ordinal'} if name=='raw' or name.startswith('resource-') else {'dataset'}
                    if set(q)!=fields or any(len(v)!=1 for v in q.values()) or q['dataset'][0] not in app.upgrades:raise ValueError('Unknown upgrade export')
                    return self.send(200,upgrade_views.export(app.upgrades[q['dataset'][0]],name,int(q['ordinal'][0]) if 'ordinal' in q else None),'text/csv' if name=='raw' else 'application/json')
                if path=='/api/resources' and not url.query:return self.send(200,app.resource_catalog())
                if path=='/api/application-budget':
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    fields={'platform','ram_bytes','program_bytes','kem','dsa','flows','fresh_identity'}
                    if set(q)!=fields or any(len(v)!=1 for v in q.values()):raise ValueError('Unknown application budget fields')
                    request={k:(v[0] if k=='platform' else int(v[0])) for k,v in q.items()}
                    return self.send(200,app.application_budget(request))
                if path=='/export/resource-scopes.xml' and not url.query:
                    if not hasattr(app,'_resource_objects'):app.resource_catalog()
                    return self.send(200,app._resource_objects)
                if path=='/api/deployment-builds' and not url.query:return self.send(200,app.deployment_builds().catalog())
                if path=='/api/deployment-build':
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    if set(q)!={'id'} or len(q['id'])!=1:raise ValueError('Explicit build identity required')
                    return self.send(200,app.deployment_builds().status(q['id'][0]))
                if path.startswith('/export/deployment/') and not url.query:
                    name=path.removeprefix('/export/deployment/');ident,extension=name.rsplit('.',1)
                    return self.send(200,app.deployment_builds().export(ident,extension),'application/zip' if extension=='zip' else 'application/json')
                if path=='/api/budget':
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    required={'resource_dataset','timing_dataset','platform','ram_bytes','program_bytes'}
                    if not required<=set(q) or set(q)-required-{'operation_counts'} or any(len(v)!=1 for v in q.values()):raise ValueError('Unknown budget fields')
                    request={k:v[0] for k,v in q.items()}
                    for k in ('ram_bytes','program_bytes'):request[k]=int(request[k])
                    if 'operation_counts' in request:request['operation_counts']=json.loads(request['operation_counts'])
                    return self.send(200,app.budget(request))
                if path in ('/api/observations-manifest','/export/observations-manifest.xml','/export/raw.csv','/export/raw.xml','/export/raw.records.xml','/export/raw.bin'):
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    fields={'dataset'} if path in ('/api/observations-manifest','/export/observations-manifest.xml') else {'dataset','ordinal'}
                    if set(q)!=fields or any(len(v)!=1 for v in q.values()) or q['dataset'][0] not in app.pooled:raise ValueError('Unknown observation export')
                    if path not in ('/api/observations-manifest','/export/observations-manifest.xml'):return self.send(200,app.raw_shard(q['dataset'][0],int(q['ordinal'][0])),'application/xml' if path.endswith('.xml') else 'application/octet-stream' if path.endswith('.bin') else 'text/csv')
                    entry=app.pooled[q['dataset'][0]]
                    if path=='/export/observations-manifest.xml':
                        blob=entry['manifest_path'].read_bytes()
                        if hashlib.sha256(blob).hexdigest()!=entry['manifest_sha256']:raise ValueError('Observation manifest fingerprint changed')
                        return self.send(200,blob,'application/xml')
                    return self.send(200,entry['observations'])
                if path=='/api/science':
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    if not set(q)<={'library'} or any(len(v)!=1 for v in q.values()):raise ValueError('Unknown scientific query')
                    return self.send(200,app.public_results(q.get('library',[None])[0]))
                if path in ('/export/science.xml','/export/science.csv'):
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    if set(q)!={'dataset'} or len(q['dataset'])!=1 or q['dataset'][0] not in app.scientific:raise ValueError('Unknown registered dataset')
                    data=app.scientific[q['dataset'][0]]
                    return self.send(200,science.samples_csv(data),'text/csv') if path.endswith('.csv') else self.send(200,data)
                if path=='/export/equal-frequency.xml':
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    if set(q)!={'dataset'} or len(q['dataset'])!=1 or q['dataset'][0] not in app.equal_frequency:
                        raise ValueError('Unknown equal-frequency result')
                    return self.send(200,app.equal_frequency[q['dataset'][0]])
                if path=='/export/image-equivalence.xml':
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    if set(q)!={'library','dataset'} or any(len(v)!=1 for v in q.values()):raise ValueError('Explicit association query required')
                    if (q['library'][0],q['dataset'][0]) not in app.equivalence_files:raise ValueError('Unregistered association')
                    return self.send(200,app.equivalence_receipt(q['library'][0],q['dataset'][0]))
                if path in ('/export/results.xml','/export/results.csv'):
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    if not {'dataset'}<=set(q)<={'dataset','library'} or any(len(v)!=1 for v in q.values()) or q['dataset'][0] not in app.scientific:raise ValueError('Unknown registered result')
                    if 'library' in q:
                        view=app.selected_scientific_result(q['dataset'][0],q['library'][0])
                        if path.endswith('.csv'):
                            from publicschemas.measurement_reuse import selected_csv
                            return self.send(200,selected_csv(view),'text/csv')
                        return self.send(200,{'schema':'lattice.selected_scientific_result.v1','dataset_id':q['dataset'][0],'result':presentation.public_view(view)})
                    data=app.scientific[q['dataset'][0]]
                    if path.endswith('.csv'):
                        if data['schema'] not in (science.POOLED,science.MEAN_TAIL):raise ValueError('This result is not an operation timing table')
                        return self.send(200,presentation.result_csv(data),'text/csv')
                    exported=presentation.result_export(data)
                    if q['dataset'][0] in app.equal_frequency:
                        exported['equal_frequency']=app.equal_frequency[q['dataset'][0]]
                    return self.send(200,exported)
                if path in ('/api/observations','/export/observations.xml','/export/samples.csv'):
                    q=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                    if not set(q)<= {'scope','library'} or any(len(v)!=1 for v in q.values()): raise ValueError('Unknown query')
                    data=app.observations(q.get('scope',['current'])[0],q.get('library',[None])[0])
                    return self.send(200,samples_csv(data),'text/csv') if path.endswith('.csv') else self.send(200,data)
                if path.startswith('/export/run/') and not url.query:
                    ident=path.removeprefix('/export/run/').removesuffix('.xml')
                    if ident in app.runs: return self.send(200,app.runs[ident])
                return self.send(404,{'error':'无此技术资源'})
            except (ValueError,TypeError): return self.send(400,{'error':'无效的技术查询'})
        def do_POST(self):
            if not self.valid_host() or self.path not in ('/api/run','/api/deployment-build') or self.headers.get('X-Demo-Token')!=app.token or self.headers.get('Origin') not in (None,'http://'+host):
                # Drain a short, explicitly sized rejected body before closing.
                # Otherwise Windows may reset TCP with unread request bytes and
                # discard the intended 403 response. No JSON or API is evaluated.
                timeout=self.connection.gettimeout()
                try:
                    size=int(self.headers.get('Content-Length','0'))
                    if 0<size<=2048:
                        self.connection.settimeout(0.25)
                        self.rfile.read(size)
                except (ValueError,OSError):pass
                finally:self.connection.settimeout(timeout)
                return self.send(403,{'error':'本地请求来源或令牌不匹配'})
            try:
                if self.headers.get('Content-Type','').split(';')[0]!='application/json': raise ValueError('JSON only')
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=2048: raise ValueError('Request too large')
                request=strict_json(self.rfile.read(size))
                if self.path=='/api/deployment-build':return self.send(202,app.deployment_builds().start(request))
                return self.send(200,app.run(request))
            except UnavailableLibraryError as e:return self.send(409,{'error':str(e),'kind':'UNAVAILABLE_ON_HOST'})
            except (ValueError,TypeError,KeyError): return self.send(400,{'error':'请选择有效的技术预设'})
            except Exception: return self.send(500,{'error':'实际执行未完成'})
    return Handler

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--config',type=Path,required=True); p.add_argument('--port',type=int,default=8134); a=p.parse_args()
    if not 1024<=a.port<=65535: raise ValueError('Use an unprivileged port')
    app=Application(a.config); server=ThreadingHTTPServer(('127.0.0.1',a.port),handler(app,f'127.0.0.1:{a.port}'))
    print('本地技术演示 http://127.0.0.1:'+str(a.port),flush=True)
    try: server.serve_forever()
    finally: server.server_close()
if __name__=='__main__': main()
