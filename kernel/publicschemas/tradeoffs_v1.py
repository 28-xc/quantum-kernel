"""Finite measured time/RAM/program tradeoffs from complete public studies."""
import math
from . import resources,pooled_model

RAM_KIB=(16,32,64,128,256)
PROGRAM_KIB=(64,128,256,512)
AXES=('core_reserved_bytes','program_bytes','equal_weight_18_operation_mean_ns')

def frontier(points):
 """Retain every measured point not strictly dominated in the three axes."""
 for p in points:
  resources.need(all(type(p[k]) in (int,float) and math.isfinite(p[k]) and p[k]>0 for k in AXES),'Invalid tradeoff coordinate')
 return [p for p in points if not any(all(q[k]<=p[k] for k in AXES) and any(q[k]<p[k] for k in AXES) for q in points)]

def derive(observations,statistics,resource_data):
 pooled_model.validate(statistics,observations);resources.validate(resource_data)
 e=observations['experiment'];platform=statistics['platform']
 resources.need(platform in ('windows_x86_64','linux_aarch64'),'Unknown native platform')
 resources.need(e['blocks']==30 and e['samples_per_run']==300 and e['warmups_per_run']==32,'Full configuration acquisition required')
 resources.need(statistics['counts']['deleted_rows']==0,'Changed finite configuration observations')
 expected_count=28 if platform=='windows_x86_64' else 26
 configs=statistics['configurations'];points=[p for p in resource_data['points'] if p['platform']==platform]
 resources.need(len(configs)==len(points)==expected_count,'Incomplete measured configuration universe')
 resources.need(all(c['provider']=='lattice' for c in configs),'Configuration study requires core artifacts')
 identities={(c['library_sha256'],c['workspace_reserved']) for c in configs}
 resources.need(len(identities)==expected_count and identities=={(p['binary_sha256'],p['reserved_components']['workspace_bytes']) for p in points},'Resource/time identities differ')
 base=dict(platform=platform,timing_dataset=statistics['dataset_id'])
 all_query=resources.select(resource_data,statistics,dict(**base,ram_bytes=max(p['core_reserved_bytes'] for p in points),program_bytes=max(p['program_bytes'] for p in points)))
 resources.need(len(all_query['candidates'])==expected_count and not all_query['excluded'] and not all_query['unmeasured_configurations'],'Incomplete resource/time join')
 grid=[]
 for ram in RAM_KIB:
  for program in PROGRAM_KIB:
   grid.append(resources.select(resource_data,statistics,dict(**base,ram_bytes=ram*1024,program_bytes=program*1024)))
 return dict(schema='lattice.measured_tradeoffs.v1',platform=platform,timing_dataset=statistics['dataset_id'],resource_dataset=resource_data['dataset_id'],
  method=dict(candidate_domain='all_measured_configurations_in_one_platform_study',axes=list(AXES),
   objective='equal_weight_arithmetic_mean_of_18_pooled_operation_means',dominance='all_coordinates_no_greater_and_at_least_one_strictly_smaller',
   ram_budget_kib=list(RAM_KIB),program_budget_kib=list(PROGRAM_KIB)),points=all_query['candidates'],
  nondominated_points=frontier(all_query['candidates']),budget_queries=grid)
