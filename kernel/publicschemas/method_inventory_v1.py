"""Technical source links for original observation sets and independent binaries."""
import re
from .archived_images_v1 import relative, digest, need


def descriptor(value):
    need(type(value) is dict and set(value)=={'path','sha256'},'Explicit technical descriptor required')
    relative(value['path']);digest(value['sha256'])


def descriptors(data):
    result=[data['core_images']]
    for row in data['independent_binaries']:
        result.extend([row['artifact'],*row['source_files'],*row['license_files']])
    for row in data['datasets']:
        result.extend([row['observations'],row['runner'],row['validator'],row['driver'],row['crypto_runtime'],*row['driver_sources']])
    return result


def validate(data):
    need(type(data) is dict and set(data)=={'schema','core_images','independent_binaries','datasets'},'Unknown method inventory field')
    need(data['schema']=='lattice.observation_methods.v1','Wrong method inventory schema')
    descriptor(data['core_images'])
    need(type(data['independent_binaries']) is list and type(data['datasets']) is list,'Technical lists required')
    ids=set(); binaries=set()
    for row in data['independent_binaries']:
        need(type(row) is dict and set(row)=={'id','category','platform','artifact','bytes','format','machine','source_project','source_version','source_revision','source_files','license_files'},'Unknown independent binary field')
        need(type(row['id']) is str and re.fullmatch('[a-z0-9][a-z0-9_.-]{0,99}',row['id']) and row['id'] not in ids,'Unique binary id required');ids.add(row['id'])
        need(row['category'] in ('independent_baseline','benchmark_driver','benchmark_runtime'),'Unknown binary role')
        need(row['platform'] in ('windows_x86_64','linux_aarch64'),'Unknown binary platform')
        need((row['format'],row['machine'])==(('PE','x86_64') if row['platform']=='windows_x86_64' else ('ELF','aarch64')),'Wrong target')
        need(type(row['bytes']) is int and row['bytes']>0,'Positive image size required')
        for field in ('source_project','source_version','source_revision'):
            need(type(row[field]) is str and 0<len(row[field])<=160 and not any(x in row[field] for x in ('\\','/','\n','\r')),'Finite public source identifier required')
        need(type(row['source_files']) is list and row['source_files'] and type(row['license_files']) is list and row['license_files'],'Source and license descriptors required')
        descriptor(row['artifact']); name=row['artifact']['path'].casefold()
        need(name not in binaries,'Independent binary path repeated');binaries.add(name)
    dataset_ids=set()
    for row in data['datasets']:
        need(type(row) is dict and set(row)=={'dataset_id','observations','runner','validator','driver','crypto_runtime','driver_sources'},'Unknown observation method field')
        need(type(row['dataset_id']) is str and re.fullmatch('[a-z0-9][a-z0-9_-]{0,99}',row['dataset_id']) and row['dataset_id'] not in dataset_ids,'Unique dataset id required');dataset_ids.add(row['dataset_id'])
        need(type(row['driver_sources']) is list and row['driver_sources'],'Actual driver source descriptors required')
    identities={}
    for value in descriptors(data):
        descriptor(value);name=value['path'].casefold()
        need(name not in identities or identities[name]==(value['path'],value['sha256']),'Conflicting technical descriptor')
        identities[name]=(value['path'],value['sha256'])
    return data
