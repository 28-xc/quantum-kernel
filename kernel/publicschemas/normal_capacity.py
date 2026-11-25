"""Validate the ordered, finite normal-capacity recovery experiment."""
from .verification_v2 import keys, need, integer, digest, parameter

LEVELS=(512,44,768,65,1024,87)

def validate_case(r):
    keys(r,['mode','case','workspace_bytes','records','aggregate_sha256',
            'random_requests','context_and_workspace_stable'])
    need(r['mode'] in ('sequential','concurrent'),'Unknown execution mode')
    need(type(r['case']) is int and 0<=r['case']<4,'Unknown recovery case')
    integer(r['workspace_bytes'],32)
    need(r['workspace_bytes']%32==0,'Unaligned recovery workspace')
    digest(r['aggregate_sha256']);integer(r['random_requests'],1)
    need(r['context_and_workspace_stable'] is True,'Context identity changed')
    rows=r['records'];need(type(rows) is list and len(rows)==108,'Recovery record omission')
    cursor=0
    def take(level,phase):
        nonlocal cursor
        x=rows[cursor];cursor+=1
        need(x['parameter']==level and x['case']==r['case'] and x['phase']==phase,'Recovery sequence changed')
        parameter(x['parameter'])
        return x
    def normal(level,phase):
        x=take(level,phase)
        keys(x,['parameter','case','phase','status','workspace_bytes','peaks'])
        need(x['status']=='PASS' and x['workspace_bytes']==r['workspace_bytes'],'Normal operation failed')
        need(type(x['peaks']) is list and len(x['peaks'])==3,'Three operation peaks required')
        for value in x['peaks']:
            integer(value,1);need(value<=r['workspace_bytes'],'Workspace overflow')
        return x['peaks']
    for level in LEVELS:
        peaks=normal(level,'normal')
        for op in range(3):
            capacities=sorted({32,max(32,((peaks[op]-1)//32)*32)})
            need(len(capacities)==2,'Declared shortage design changed')
            for capacity in capacities:
                x=take(level,'workspace_shortage')
                keys(x,['parameter','case','phase','operation','capacity_bytes','status','outputs_zero'])
                need(type(x['operation']) is int and x['operation']==op and type(x['capacity_bytes']) is int and x['capacity_bytes']==capacity,'Shortage boundary changed')
                need(x['status']==-5 and x['outputs_zero'] is True,'Shortage recovery failed')
                peaks=normal(level,'normal_after_workspace_shortage')
        for op in (0,1):
            x=take(level,'entropy_failure')
            keys(x,['parameter','case','phase','operation','status','outputs_zero'])
            need(type(x['operation']) is int and x['operation']==op and x['status']==-4 and x['outputs_zero'] is True,'Entropy failure handling changed')
            normal(level,'normal_after_entropy_failure')
        x=take(level,'invalid_object_then_valid')
        keys(x,['parameter','case','phase','status','invalid_status'])
        need(x['status']=='PASS' and type(x['invalid_status']) is int and x['invalid_status']==(0 if level>100 else -6),'Invalid-object outcome differs')
    need(cursor==len(rows),'Extra recovery observations')
    return r

def validate_suite(rows):
    need(type(rows) is list and len(rows)==8,'Four sequential and concurrent cases required')
    for i,r in enumerate(rows):
        validate_case(r)
        need(r['mode']==('sequential' if i<4 else 'concurrent') and r['case']==i%4,'Recovery case ordering changed')
    for i in range(4):
        a={k:v for k,v in rows[i].items() if k!='mode'}
        b={k:v for k,v in rows[i+4].items() if k!='mode'}
        need(a==b,'Sequential/concurrent observations differ')
    need(len({r['workspace_bytes'] for r in rows})==1,'Recovery workspace changed')
    return rows
