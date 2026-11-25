"""Exact binary, platform and workspace identities available for deployment."""
from .verification_v2 import keys,need,digest,token,text,integer
SCHEMA='lattice.deployment_profiles.v2'

def validate(d):
    keys(d,['schema','profiles','scope'])
    need(d['schema']==SCHEMA,'Unknown deployment profile schema')
    need(isinstance(d['profiles'],list) and d['profiles'],'Deployment profiles required')
    seen=set()
    for p in d['profiles']:
        keys(p,['platform','configuration','binary_sha256','workspace_bytes'])
        token(p['platform']);token(p['configuration']);digest(p['binary_sha256']);integer(p['workspace_bytes'],32)
        key=(p['platform'],p['binary_sha256'],p['workspace_bytes'])
        need(key not in seen,'Duplicate deployment identity');seen.add(key)
    text(d['scope'])
    return d

def permits(d,platform,binary_sha256,workspace_bytes):
    return any(p['platform']==platform and p['binary_sha256']==binary_sha256 and
               p['workspace_bytes']==workspace_bytes for p in d['profiles'])
