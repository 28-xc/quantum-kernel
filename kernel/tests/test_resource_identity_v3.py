"""Source-identity and version-boundary tests with explicitly synthetic records.

These tests read and copy files; they do not execute a cryptographic library.
"""
from pathlib import Path
import copy
import hashlib
import importlib.util
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
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests/demo')]
from test_resources import fixture
from publicschemas import resources, science, common_context_v1 as common
from publicschemas import resource_watermarks_v1 as watermarks
from publicschemas.resource_identity_v3 import sha, read, point_binding
from tools.import_resource_identities import project, store
from tools.upgrade_resource_observations import upgrade
from demo import server


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    return path


class Identities(unittest.TestCase):
    def setUp(self):
        # An explicit D/workspace scratch root can be selected for local runs.
        import os
        self.temp=tempfile.TemporaryDirectory(prefix='identity-v3-',dir=os.environ.get('LATTICE_TEST_TMP'))
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.old,self.stats,self.request=fixture()
        source=self.root/'source';source.mkdir()
        (source/'core.c').write_bytes(b'/* Synthetic source identity fixture. */\n')
        (source/'README.md').write_bytes(b'Synthetic metadata unit test.\n')
        self.files={p.name:sha(p)for p in source.iterdir()}
        full=save(self.root/'source_manifest.xml',dict(files=self.files))
        binary=self.root/'not-an-executable.bin';binary.write_bytes(b'Synthetic image bytes, never loaded.')
        p=self.old['points'][0];p['binary_sha256']=p['source_sha256']['image']=sha(binary)
        self.stats['configurations'][0]['library_sha256']=sha(binary)
        build=save(self.root/'build.xml',dict(p['build'],parameters=p['parameters'],binary={'sha256':sha(binary)},
            source_hashes={str(source/'core.c'):self.files['core.c']},generated_source_hashes={}))
        p['source_sha256']['build']=sha(build)
        self.old_path=save(self.root/'old.xml',self.old)
        self.mapping=save(self.root/'mapping.xml',dict(points=[dict(id=p['id'],source=str(source),
            source_manifest=str(full),build=str(build),library=str(binary))]))
        self.public=self.root/'public'
        project(self.old_path,self.mapping,self.public)
        self.path=self.public/'resources.xml';self.new=resources.load(self.path)

    def replace_binding(self,change):
        value=self.new['points'][0]['source_identity'];binding=read(self.public/value['build_binding']['path'])
        change(binding);value['build_binding']=store(self.public,'builds',binding);save(self.path,self.new)

    def test_projector_checks_real_snapshot_and_image(self):
        self.assertEqual(self.new['schema'],resources.SCHEMA_V3)
        self.assertNotIn('core_source_commit',self.new)
        self.assertNotIn('verification_sha256',self.new)
        p=self.new['points'][0];value=p.pop('source_identity')
        self.assertEqual(p,self.old['points'][0])
        full=read(self.public/value['manifest']['path'])
        self.assertEqual(full['files'],self.files)
        self.assertEqual(len(list((self.public/'builds').glob('*.xml'))),1)

    def test_old_version_and_budget_unchanged(self):
        self.assertEqual(resources.load(self.old_path),self.old)
        self.assertEqual(resources.select(self.old,self.stats,self.request),resources.select(self.new,self.stats,self.request))
        for name in ('ram_bytes','program_bytes'):
            q=dict(self.request);q[name]=1
            self.assertEqual(resources.select(self.old,self.stats,q),resources.select(self.new,self.stats,q))

    def test_science_and_server_both_resource_versions(self):
        app=server.Application.__new__(server.Application);app.deployment=None
        for data in (resources.load(self.old_path),science.load(self.path)):
            app.scientific={data['dataset_id']:data,self.stats['dataset_id']:self.stats}
            self.assertEqual(len(app.resource_catalog()['datasets']),1)
            query=dict(self.request,resource_dataset=data['dataset_id'])
            self.assertEqual(app.budget(query),resources.select(data,self.stats,self.request))

    def test_source_changed_rejected_before_any_output(self):
        (self.root/'source/core.c').write_bytes(b'Changed source')
        target=self.root/'bad_projection'
        with self.assertRaises(ValueError):project(self.old_path,self.mapping,target)
        self.assertFalse(target.exists())

    def test_actual_build_changed_rejected(self):
        (self.root/'build.xml').write_text('{}',encoding='utf-8')
        with self.assertRaises(ValueError):project(self.old_path,self.mapping,self.root/'bad')

    def test_actual_image_changed_rejected(self):
        (self.root/'not-an-executable.bin').write_bytes(b'Another fixture')
        with self.assertRaises(ValueError):project(self.old_path,self.mapping,self.root/'bad')

    def test_missing_external_manifest(self):
        (self.public/self.new['points'][0]['source_identity']['manifest']['path']).unlink()
        with self.assertRaises(ValueError):science.load(self.path)

    def test_external_manifest_byte_change(self):
        path=self.public/self.new['points'][0]['source_identity']['manifest']['path']
        path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(ValueError):resources.load(self.path)

    def test_wrong_full_source_even_with_updated_digest(self):
        value=self.new['points'][0]['source_identity']
        value['manifest']=store(self.public,'sources',dict(schema='lattice.source_manifest.v1',files={'core.c':'b'*64}))
        self.replace_binding(lambda b:b.update(source_manifest_sha256=value['manifest']['sha256']))
        with self.assertRaises(ValueError):resources.load(self.path)

    def test_wrong_consumed_source(self):
        self.replace_binding(lambda b:b['consumed_files'].update({'core.c':'b'*64}))
        with self.assertRaises(ValueError):resources.load(self.path)

    def test_wrong_build_image(self):
        self.replace_binding(lambda b:b.update(binary_sha256='b'*64))
        with self.assertRaises(ValueError):resources.load(self.path)

    def test_wrong_build_record(self):
        self.replace_binding(lambda b:b.update(build_record_sha256='b'*64))
        with self.assertRaises(ValueError):resources.load(self.path)

    def test_wrong_parameters(self):
        self.replace_binding(lambda b:b.update(parameters=[768,65]))
        with self.assertRaises(ValueError):resources.load(self.path)

    def test_wrong_flags(self):
        self.replace_binding(lambda b:b['build'].update(lto=False))
        with self.assertRaises(ValueError):resources.load(self.path)

    def test_identity_path_escape(self):
        self.new['points'][0]['source_identity']['manifest']['path']='../source_manifest.xml';save(self.path,self.new)
        with self.assertRaises(ValueError):resources.load(self.path)

    def test_duplicate_and_nonfinite_identity_json(self):
        for text in ('{"schema":1,"schema":2}','{"a":NaN}'):
            with patch.object(Path,'read_text',return_value=text):
                with self.assertRaises(ValueError):resources.load(self.path)
        # Start from an accepted, complete identity. Each disk mutation changes one field.
        resources.load(self.path)
        valid=self.path.read_text(encoding='utf-8')
        import re
        schema_field=re.search(r'<field><name>schema</name>.*?</field>',valid).group()
        duplicate=valid.replace(schema_field,schema_field+schema_field,1)
        nonfinite=re.sub(r'<integer>-?[0-9]+</integer>','<number>NaN</number>',valid,count=1)
        for malformed in (duplicate,nonfinite):
            self.assertNotEqual(malformed,valid)
            self.path.write_text(malformed,encoding='utf-8')
            with self.assertRaises(ValueError):resources.load(self.path)

    def test_new_schema_forbids_global_commit(self):
        self.new['core_source_commit']=self.old['core_source_commit']
        with self.assertRaises(ValueError):resources.validate(self.new)

    def test_new_schema_forbids_global_verification(self):
        self.new['verification_sha256']=self.old['verification_sha256']
        with self.assertRaises(ValueError):resources.validate(self.new)

    def common_fixture(self,modern):
        p=self.new['points'][0] if modern else self.old['points'][0]
        methods={name:'a'*64 for name in ('probe_common.c','probe.c','run_common.py','latticecore.h')}
        a=dict(resource_id=p['id'],platform=p['platform'],binary_sha256=p['binary_sha256'],
            source_sha256={k:'a'*64 for k in ('result','trials','resource','probe','commands')},
            method_sha256=methods,seed_base=1,reported_reserved_components=p['reserved_components'],
            reported_core_reserved_bytes=p['core_reserved_bytes'],
            reported_budget_trials=[dict(budget_bytes=16384,arena_bytes=10720,charged_core_bytes=12864,
                order=0,status='SUCCESS',trial=i)for i in range(10)],negative_record_rejections=[],
            raw=dict(path='raw/synthetic.records.xml',sha256='a'*64,rows=68))
        data=dict(schema=common.SCHEMA_V2 if modern else common.SCHEMA,dataset_id='synthetic_common_identity',
            resources_sha256=sha(self.path if modern else self.old_path),protocol=common.PROTOCOL,artifacts=[a],
            method_sources=[dict(name=k,path='methods/'+v+'/'+k,sha256=v)for k,v in methods.items()])
        if modern:a['source_build_binding_sha256']=point_binding(p)
        else:data['core_source_commit']=self.old['core_source_commit']
        return data

    def test_common_identity_versions(self):
        common.validate_manifest(self.common_fixture(False),self.old)
        common.validate_manifest(self.common_fixture(True),self.new)
        for data,resource in [(self.common_fixture(False),self.new),(self.common_fixture(True),self.old)]:
            with self.assertRaises(ValueError):common.validate_manifest(data,resource)

    def test_common_wrong_point_build_binding(self):
        data=self.common_fixture(True);data['artifacts'][0]['source_build_binding_sha256']='b'*64
        with self.assertRaises(ValueError):common.validate_manifest(data,self.new)

    def test_watermark_identity_versions_and_wrong_binding(self):
        # Only numerical derivation is isolated. Actual manifest parsing, method
        # file hashing, schema selection and cross-file identity checks execute.
        folder=self.root/'watermarks_identity';folder.mkdir()
        method_bytes=b'/* synthetic method identity */\n';method_sha=hashlib.sha256(method_bytes).hexdigest()
        method=folder/('methods/'+method_sha+'/probe.c');method.parent.mkdir(parents=True);method.write_bytes(method_bytes)
        p=self.new['points'][0]
        a=dict(resource_id=p['id'],platform=p['platform'],binary_sha256=p['binary_sha256'],
            source_sha256={k:'a'*64 for k in ('resource','dataset_result','raw_trials','protocol')},
            method_sha256={'probe.c':method_sha},raw={'path':'raw/synthetic.records.xml','sha256':'a'*64,'rows':0})
        result=dict(trials=0,cells=[],classification_counts={})
        with patch.object(watermarks,'shard',return_value=[]),patch.object(watermarks,'derive_artifact',return_value=result):
            for modern,resource_path in [(False,self.old_path),(True,self.path)]:
                artifact=copy.deepcopy(a)
                data=dict(schema=watermarks.SCHEMA_V2 if modern else watermarks.SCHEMA,
                    dataset_id='synthetic_watermark_identity',resources_sha256=sha(resource_path),
                    protocol=watermarks.PROTOCOL,method_sources=[dict(name='probe.c',path=method.relative_to(folder).as_posix(),sha256=method_sha)],
                    artifacts=[artifact])
                if modern:artifact['source_build_binding_sha256']=point_binding(p)
                else:data['core_source_commit']=self.old['core_source_commit']
                path=save(folder/'observations.xml',data)
                self.assertEqual(watermarks.recompute(path,resource_path)['summary']['library_images'],1)
                if modern:
                    artifact['source_build_binding_sha256']='b'*64;save(path,data)
                    with self.assertRaises(ValueError):watermarks.recompute(path,resource_path)
                other=self.old_path if modern else self.path
                data['resources_sha256']=sha(other);save(path,data)
                with self.assertRaises(ValueError):watermarks.recompute(path,other)

    def test_copy_upgrade_keeps_every_raw_byte(self):
        # Identity/copy test, not a simulated measurement: the numerical
        # recomputer is replaced explicitly; its unchanged logic has separate tests.
        for kind,model in [('common',common),('watermarks',watermarks)]:
            folder=self.root/kind;folder.mkdir()
            raw=folder/'raw/fixture.records.xml';raw.parent.mkdir();json.write(raw,[{'synthetic':True}])
            method=folder/'methods/fixture.c';method.parent.mkdir();method.write_bytes(b'/* fixture */\n')
            a=dict(resource_id='portable',raw=dict(path='raw/fixture.records.xml',sha256=sha(raw)))
            obs=dict(schema=model.SCHEMA,core_source_commit=self.old['core_source_commit'],resources_sha256=sha(self.old_path),
                artifacts=[a],method_sources=[dict(path='methods/fixture.c',sha256=sha(method))])
            path=save(folder/'observations.xml',obs);output=self.root/(kind+'-upgraded')
            with patch.object(model,'recompute',return_value={'synthetic_identity_copy_check':True}):
                upgrade(kind,path,self.old_path,self.path,output)
            changed=read(output/'observations.xml')
            self.assertEqual(changed['schema'],model.SCHEMA_V2)
            self.assertEqual(changed['artifacts'][0]['source_build_binding_sha256'],point_binding(self.new['points'][0]))
            self.assertEqual(raw.read_bytes(),(output/'raw/fixture.records.xml').read_bytes())
            self.assertEqual(method.read_bytes(),(output/'methods/fixture.c').read_bytes())
            self.assertEqual(read(path),obs)

    def test_upgrade_rejects_changed_measurement_point(self):
        changed=copy.deepcopy(self.new);p=changed['points'][0];p['program_bytes']+=1;save(self.path,changed)
        with self.assertRaises(ValueError):upgrade('common',self.root/'unused',self.old_path,self.path,self.root/'bad')

if __name__=='__main__':unittest.main()
