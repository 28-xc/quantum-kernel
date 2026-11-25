"""Deterministic deployment identity, loading, resource and HTTP boundaries.

Synthetic measurement records test attribution only. Functional calls use the
explicit hashed libraries supplied by --config; they are not speed measurements.
"""
from pathlib import Path
import json as wire_json
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
import argparse, copy, hashlib, http.client, record_io as json, sys, tempfile, threading, unittest
from http.server import ThreadingHTTPServer
from unittest import mock
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'demo')]
import server
from publicschemas import deployment,resources,science
from pooled_fixture import fixture as pooled_fixture,write
from science_fixture import fixture as block_fixture
from test_resources import fixture as resource_fixture

CONFIG=None;OUTPUT=None

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='deployment-',dir=OUTPUT.parent)
        cls.base=Path(cls.tmp.name);cls.serial=0
        config=server.read(CONFIG)
        for key in ('datasets','scientific_views','pooled_views','timing_views','resource_limit_views',
                    'process_footprint_views','application_views','application_latency_views','primitive_views'):
            config[key]=[]
        for key in ('deployment_profiles','host_probe'):
            if key in config:config[key]['path']=str((CONFIG.parent/config[key]['path']).resolve())
        for lib in config['libraries']:lib['artifact']['path']=str((CONFIG.parent/lib['artifact']['path']).resolve())
        cls.config=copy.deepcopy(config)
        cls.profiles=server.read(Path(config['deployment_profiles']['path']))
        cls.paired,cls.observed,cls.stats=pooled_fixture(config['libraries'][0],cls.base/'pooled')
        cls.data,_,_=resource_fixture();p=cls.data['points'][0];lib=config['libraries'][0]
        p.update(configuration=lib['configuration'],platform=lib['platform'],binary_sha256=lib['artifact']['sha256'])
        p['source_sha256']['image']=p['binary_sha256'];p['reserved_components']['workspace_bytes']=lib['workspace_bytes']
        p['core_reserved_bytes']=sum(p['reserved_components'].values())
        config['scientific_views']=[write(cls.base/'resources.xml',cls.data)]
        config['pooled_views']=[cls.paired]
        cls.complete=config;write(cls.base/'demo.xml',config);cls.app=server.Application(cls.base/'demo.xml')
        cls.lib=cls.app.descriptors[lib['id']]
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),server.handler(cls.app,'pending'))
        cls.host='127.0.0.1:'+str(cls.http.server_address[1]);cls.http.RequestHandlerClass=server.handler(cls.app,cls.host)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True);cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();cls.thread.join();cls.tmp.cleanup()

    def config_path(self,config,profiles=None):
        type(self).serial+=1;stem=str(self.serial);config=copy.deepcopy(config)
        if profiles is not None:config['deployment_profiles']=write(self.base/('profiles-'+stem+'.xml'),profiles)
        path=self.base/('config-'+stem+'.xml');write(path,config);return path

    def request(self,path,body=None):
        headers={'Host':self.host}
        if body is not None:headers.update({'Content-Type':'application/json','X-Demo-Token':self.app.token})
        c=http.client.HTTPConnection(self.host,timeout=20);c.request('GET' if body is None else 'POST',path,body,headers)
        r=c.getresponse();blob=r.read();c.close();return r.status,blob

    def test_01_profile_exact_identity(self):
        p=self.profiles['profiles'][0];deployment.validate(self.profiles)
        for changes in ({},{'platform':'other'},{'binary_sha256':'f'*64},{'workspace_bytes':p['workspace_bytes']+32}):
            q=p|changes
            self.assertEqual(deployment.permits(self.profiles,q['platform'],q['binary_sha256'],q['workspace_bytes']),not changes)

    def test_02_profile_closed_fields(self):
        for where in ('root','profile'):
            target=self.profiles if where=='root' else self.profiles['profiles'][0]
            for key in list(target)+['unknown']:
                with self.subTest(where=where,key=key):
                    d=copy.deepcopy(self.profiles);obj=d if where=='root' else d['profiles'][0]
                    if key=='unknown':obj[key]='synthetic'
                    else:del obj[key]
                    with self.assertRaises(ValueError):deployment.validate(d)

    def test_03_duplicate_identity_even_with_new_label(self):
        for label in (self.profiles['profiles'][0]['configuration'],'different-label'):
            d=copy.deepcopy(self.profiles);d['profiles'].append(d['profiles'][0]|{'configuration':label})
            with self.assertRaises(ValueError):deployment.validate(d)

    def test_04_distinct_capacity_is_distinct_identity(self):
        d=copy.deepcopy(self.profiles);p=d['profiles'][0];d['profiles'].append(p|{'workspace_bytes':p['workspace_bytes']+32})
        self.assertEqual(len(deployment.validate(d)['profiles']),len(self.profiles['profiles'])+1)
        for field,value in [('workspace_bytes',True),('workspace_bytes',31),('binary_sha256','A'*64),('platform','../bad')]:
            d=copy.deepcopy(self.profiles);d['profiles'][0][field]=value
            with self.assertRaises(ValueError):deployment.validate(d)

    def test_05_unregistered_image_platform_or_workspace_never_loaded(self):
        for field,value in [('binary_sha256','f'*64),('platform','linux_aarch64'),('workspace_bytes',self.lib['workspace_bytes']+32)]:
            config=copy.deepcopy(self.config);config['libraries']=config['libraries'][:1];lib=config['libraries'][0]
            if field=='binary_sha256':lib['artifact']['sha256']=value
            else:lib[field]=value
            with self.subTest(field=field),mock.patch.object(server,'bind') as loader:
                with self.assertRaisesRegex(ValueError,'deployment profiles'):server.Application(self.config_path(config))
                loader.assert_not_called()

    def test_06_registered_digest_still_requires_actual_file(self):
        config=copy.deepcopy(self.config);config['libraries']=config['libraries'][:1];lib=config['libraries'][0]
        lib['artifact']['sha256']='f'*64;profiles=copy.deepcopy(self.profiles)
        profiles['profiles']=[dict(platform=lib['platform'],configuration=lib['configuration'],binary_sha256='f'*64,workspace_bytes=lib['workspace_bytes'])]
        with mock.patch.object(server,'bind') as loader:
            with self.assertRaisesRegex(ValueError,'fingerprint'):server.Application(self.config_path(config,profiles))
            loader.assert_not_called()

    def test_07_actual_loader_paths_are_the_hashed_artifacts(self):
        with mock.patch.object(server,'bind',wraps=server.bind) as loader:app=server.Application(self.config_path(self.config))
        expected=[Path(x['artifact']['path']) for x in self.config['libraries'] if app.descriptors[x['id']]['execution_available']]
        self.assertEqual([c.args[0] for c in loader.call_args_list],expected)
        self.assertGreater(len(expected),0)
        for item in self.config['libraries']:
            self.assertEqual(hashlib.sha256(Path(item['artifact']['path']).read_bytes()).hexdigest(),item['artifact']['sha256'])

    def test_08_invalid_library_descriptors_fail_before_load(self):
        for mutation in ('duplicate_id','duplicate_parameter','missing_workspace','unknown_field'):
            config=copy.deepcopy(self.config);lib=config['libraries'][0]
            if mutation=='duplicate_id':config['libraries'].append(copy.deepcopy(lib))
            elif mutation=='duplicate_parameter':lib['parameters'].append(lib['parameters'][0])
            elif mutation=='missing_workspace':del lib['workspace_bytes']
            else:lib['unknown']='synthetic'
            with self.subTest(mutation=mutation),mock.patch.object(server,'bind') as loader:
                with self.assertRaises(ValueError):server.Application(self.config_path(config))
                loader.assert_not_called()

    def test_09_resource_and_pooled_views_require_full_identity(self):
        for data in (self.data,self.stats):
            self.assertIsNotNone(science.summary(data,self.lib))
            for field,value in [('binary_sha256','f'*64),('platform','other'),('workspace_bytes',self.lib['workspace_bytes']+32)]:
                with self.subTest(schema=data['schema'],field=field):self.assertIsNone(science.summary(data,self.lib|{field:value}))
            self.assertIsNotNone(science.summary(data))

    def test_10_block_timing_requires_exact_workspace(self):
        data=block_fixture(self.lib)
        data['configurations'][0]['workspace_reserved']=self.lib['workspace_bytes']
        self.assertIsNotNone(science.summary(data,self.lib))
        for field,value in [('binary_sha256','f'*64),('platform','other'),('workspace_bytes',self.lib['workspace_bytes']+32)]:
            with self.subTest(field=field):self.assertIsNone(science.summary(data,self.lib|{field:value}))
        before=copy.deepcopy(data);self.assertIsNotNone(science.summary(data));self.assertEqual(data,before)
        self.assertIn(b'99999999,-5',science.samples_csv(data))

    def test_11_shared_profile_projection_full_identity(self):
        # A projection unit fixture; full archival validation is tested separately.
        data=dict(schema=science.SHARED,dataset_id='synthetic_shared_projection',platform=self.lib['platform'],
            profile=dict(library_sha256=self.lib['binary_sha256'],workspace_bytes=self.lib['workspace_bytes']),
            comparisons=[],measurements=dict(jobs=[]),common_context={},resources=[],scope=[])
        self.assertIsNotNone(science.summary(data,self.lib))
        for field,value in [('binary_sha256','f'*64),('platform','other'),('workspace_bytes',self.lib['workspace_bytes']+32)]:
            with self.subTest(field=field):self.assertIsNone(science.summary(data,self.lib|{field:value}))
        self.assertIsNotNone(science.summary(data))

    def test_12_deployment_and_time_cannot_be_borrowed_by_name(self):
        d,s,q=resource_fixture();point=d['points'][0]
        profile=dict(schema=deployment.SCHEMA,profiles=[dict(platform=point['platform'],configuration=point['configuration'],
            binary_sha256=point['binary_sha256'],workspace_bytes=point['reserved_components']['workspace_bytes'])],scope='Synthetic boundary test')
        self.assertIsNotNone(resources.select(d,s,q,profile)['selected'])
        for field,value in [('binary_sha256','b'*64),('platform','other'),('workspace_bytes',10752)]:
            altered=copy.deepcopy(profile);altered['profiles'][0][field]=value
            result=resources.select(d,s,q,altered);self.assertIsNone(result['selected'])
            self.assertIn('DEPLOYMENT_PROFILE_UNAVAILABLE',result['excluded'][0]['reasons'])
        for field,value in [('library_sha256','b'*64),('workspace_reserved',10752)]:
            altered=copy.deepcopy(s);altered['configurations'][0][field]=value
            result=resources.select(d,altered,q,profile);self.assertIsNone(result['selected'])
            self.assertIn('NO_EXACT_IMAGE_WORKSPACE_MEASUREMENT',result['excluded'][0]['reasons'])

    def test_13_http_budget_boundaries_and_capacity_result(self):
        query='/api/budget?resource_dataset=resources&timing_dataset=synthetic_schema4_only&platform='+self.lib['platform']+'&ram_bytes=1&program_bytes=131072'
        code,body=self.request(query);self.assertEqual(code,200);result=json.loads(body)
        self.assertEqual(result['outcome'],'NO_MEASURED_CONFIGURATION_FITS');self.assertIsNone(result['selected'])
        self.assertIn('RAM_BUDGET_EXCEEDED',result['excluded'][0]['reasons'])
        for altered in (query+'&ram_bytes=2',query+'&unknown=x',query.replace('&ram_bytes=1','')):
            self.assertEqual(self.request(altered)[0],400)

    def test_14_duplicate_json_keys_file_and_run(self):
        with self.assertRaises(ValueError):server.strict_json('{"nested":{"platform":"first","platform":"second"}}')
        path=self.base/'duplicate.xml'
        nested=json.dumps(dict(nested=dict(platform='first')))
        field='<field><name>platform</name><string>first</string></field>'
        self.assertIn(field,nested)
        path.write_text(nested.replace(field,field+field,1),encoding='utf-8')
        with self.assertRaises(ValueError):server.read(path)
        body=wire_json.dumps(dict(library=self.lib['id'],parameter=65,message_bytes=32,context_bytes=0,mode='normal'))
        body=body[:-1]+',"parameter":65}'
        with mock.patch.object(self.app,'run',return_value={}) as run:
            self.assertEqual(self.request('/api/run',body)[0],400);run.assert_not_called()

    def test_15_real_capacity_failure_recovery_and_export(self):
        for library in self.app.libs:
            for parameter in self.app.descriptors[library]['parameters']:
                with self.subTest(library=library,parameter=parameter):
                    request=dict(library=library,parameter=parameter,message_bytes=32,context_bytes=1,mode='insufficient')
                    code,body=self.request('/api/run',wire_json.dumps(request));self.assertEqual(code,200);r=json.loads(body)
                    self.assertEqual(r['operations'][0]['return_code'],-5)
                    self.assertEqual(r['operations'][0]['outcome'],'CAPACITY_INSUFFICIENT')
                    self.assertTrue(r['failure_output_zero']);self.assertTrue(r['canaries_ok'])
                    self.assertFalse(r['functional_checks_passed']);self.assertFalse(r['performance_measurement'])
                    self.assertTrue(r['recovery']['functional_checks_passed']);self.assertTrue(r['recovery']['canaries_ok'])
                    self.assertEqual(r['binary_sha256'],self.app.descriptors[library]['binary_sha256'])
                    if parameter<100:self.assertEqual(r['recovery']['operations'][-1]['return_code'],-6)
                    else:self.assertTrue(r['recovery']['checks']['implicit_rejection'])
                    status,exported=self.request('/export/run/'+r['run_id']+'.xml');self.assertEqual(status,200);self.assertEqual(json.loads(exported),r)

    def test_16_unbound_time_archive_retained_without_deployment_claim(self):
        row=dict(kind='timing_series',algorithm='ML-DSA',parameter=65,operation='sign',configuration=self.lib['configuration'],
            platform=self.lib['platform'],execution='native',historical=False,binary_sha256=self.lib['binary_sha256'],round_id='synthetic',
            samples_ns=[1,99999999,2],sample_semantics='individual_call',samples_per_batch=1,
            outcomes=['SUCCESS','FAIL','CAPACITY_INSUFFICIENT'],return_codes=[0,-7,-5])
        dataset=dict(schema=1,kind='lattice_technical_observations',dataset_id='synthetic_unbound_capacity',records=[row])
        with mock.patch.object(self.app,'datasets',[dataset]):
            self.assertEqual(self.app.observations('current',self.lib['id'])['records'],[])
            code,body=self.request('/export/observations.xml?scope=all');self.assertEqual(code,200);self.assertEqual(json.loads(body)['records'],[row])
            code,csv=self.request('/export/samples.csv?scope=all');self.assertEqual(code,200);self.assertIn(b'99999999,FAIL,-7',csv)
            self.assertEqual(self.app.catalog()['archived_records'],1)
            self.assertEqual(dataset['records'],[row]);self.assertFalse(row['historical'])

    def test_17_legacy_resource_requires_capacity(self):
        row=dict(kind='resource',algorithm='ML-DSA',parameter=65,operation='sign',configuration=self.lib['configuration'],
            platform=self.lib['platform'],execution='native',historical=False,binary_sha256=self.lib['binary_sha256'],
            boundary='core_reserved',full_ram_bytes=20000,program_bytes=100000,workspace_bytes=self.lib['workspace_bytes'])
        self.assertTrue(self.app.selected_record(row,self.lib['id']))
        for changes in ({'workspace_bytes':self.lib['workspace_bytes']+32},{'platform':'other'},{'binary_sha256':'f'*64}):
            self.assertFalse(self.app.selected_record(row|changes,self.lib['id']))
        del row['workspace_bytes'];self.assertFalse(self.app.selected_record(row,self.lib['id']))

    def test_18_timing_screen_without_capacity_stays_in_complete_archive(self):
        study=dict(artifact_sha256=self.lib['binary_sha256'],platform=self.lib['platform'])
        data=dict(schema=science.TIMING,dataset_id='synthetic_timing_projection',studies=[study],raw_files_checked=0,
            raw_rows_checked=0,deleted_rows=0,observations_sha256='a'*64,analysis_scope='finite_input_group_timing')
        self.assertIsNone(science.summary(data,self.lib));self.assertEqual(science.summary(data)['studies'],[study])

    def test_19_resource_image_hash_is_bound(self):
        data=copy.deepcopy(self.data);data['points'][0]['source_sha256']['image']='f'*64
        with self.assertRaises(ValueError):resources.validate(data)

    def test_20_technical_archives_are_exported_unchanged(self):
        for data in (self.data,self.stats):
            code,body=self.request('/export/science.xml?dataset='+data['dataset_id'])
            self.assertEqual(code,200);self.assertEqual(json.loads(body),data)

    def test_21_duplicate_archival_fields_rejected(self):
        # This reaches the actual legacy observation loader, not only read().
        row=dict(kind='test_result',algorithm='ML-DSA',parameter=65,operation='verify',configuration=self.lib['configuration'],
            platform=self.lib['platform'],execution='native',historical=True,binary_sha256=self.lib['binary_sha256'],
            test_suite='synthetic',case_id='reject',outcome='REJECTED',return_code=-6)
        data=dict(schema=1,kind='lattice_technical_observations',dataset_id='synthetic_duplicate',records=[row])
        blob=json.dumps(data)
        field='<field><name>return_code</name><integer>-6</integer></field>'
        self.assertIn(field,blob)
        blob=blob.replace(field,field+field,1)
        path=self.base/'duplicate-observation.xml';path.write_text(blob,encoding='utf-8')
        config=copy.deepcopy(self.config);config['datasets']=[dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest())]
        with self.assertRaisesRegex(ValueError,'Duplicate'):server.Application(self.config_path(config))

    def test_22_malformed_profiles_fail_before_loading(self):
        for mutation in ('missing','unknown','duplicate'):
            data=copy.deepcopy(self.profiles)
            if mutation=='missing':del data['profiles'][0]['workspace_bytes']
            elif mutation=='unknown':data['profiles'][0]['extra']='synthetic'
            else:data['profiles'].append(copy.deepcopy(data['profiles'][0]))
            with self.subTest(mutation=mutation),mock.patch.object(server,'bind') as loader:
                with self.assertRaises(ValueError):server.Application(self.config_path(self.config,data))
                loader.assert_not_called()

    def test_23_application_budgets_keep_their_own_workspace_scope(self):
        # Full-application rows describe several actual capacities, rather than
        # the one capacity passed to this demonstrator's cryptographic calls.
        rows=[dict(binary_sha256=self.lib['binary_sha256'],workspace_bytes=w,status_counts={status:24})
              for w,status in ((32,'WORKSPACE_INSUFFICIENT'),(self.lib['workspace_bytes']+32,'PASS'))]
        data=dict(schema=science.APPLICATION,dataset_id='synthetic_application_projection',platform=self.lib['platform'],
            cells=rows,configuration_budgets=[],counts={},scope=[],observations_sha256='a'*64)
        self.assertIsNone(science.summary(data,self.lib))
        self.assertEqual(science.summary(data)['cells'],rows)

def main():
    global CONFIG,OUTPUT
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();CONFIG=a.config.resolve();OUTPUT=a.output.resolve();OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    if OUTPUT.exists():raise ValueError('Fresh result path required')
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    sources={f.relative_to(ROOT).as_posix():hashlib.sha256(f.read_bytes()).hexdigest()
             for folder in ('demo','publicschemas','tests/demo') for f in (ROOT/folder).glob('*') if f.is_file()}
    write(OUTPUT,dict(status='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,
        failures=[dict(case=str(t),trace=trace) for t,trace in result.failures],errors=[dict(case=str(t),trace=trace) for t,trace in result.errors],
        configuration_sha256=hashlib.sha256(CONFIG.read_bytes()).hexdigest(),libraries=server.read(CONFIG)['libraries'],sources=sources,
        scope='Deterministic schema, identity and HTTP controls; actual configured libraries, identified by their recorded artifact hashes; synthetic observation fixtures are not performance measurements. Functional recovery and export checks only.'))
    return 0 if result.wasSuccessful() else 1

if __name__=='__main__':raise SystemExit(main())
