"""Closed mean/tail inference schema with explicit candidate/reference ratios."""
import re
from .pooled_model import public_observations,comparisons,CELLS,BOOTSTRAP_UNIT
from .pooled_block_model import keys,need,number,integer,digest

SCHEMA='lattice.mean_tail_statistics.v1'
STATISTICS=('mean','median','p95','p99')
SOURCES=('analysis/mean_tail_statistics.py','analysis/pooled_statistics.py',
 'analysis/pooled_model.py','analysis/pooled_conditions.py','analysis/pooled_shards.py','analysis/block_model.py',
 'publicschemas/mean_tail_model.py','publicschemas/pooled_model.py','publicschemas/pooled_block_model.py',
 'publicschemas/pooled_conditions.py','publicschemas/pooled_shards.py')

def positive(value):number(value);need(value>0,'Positive statistic required')
def interval(value):
 need(type(value) is list and len(value)==2,'Two interval endpoints required')
 for x in value:positive(x)
 need(value[0]<=value[1],'Reversed interval')
def estimate(value,ratio=False):
 field,ci=('value','ci95') if ratio else ('ns','ci95_ns');keys(value,[field,ci]);positive(value[field]);interval(value[ci])

def validate(summary,observations):
 public_observations(observations)
 keys(summary,['schema','dataset_id','platform','execution','target_machine','observations_sha256',
  'ordered_observations_digest','source_code_sha256','source_code_hashes','configuration_order','configurations',
  'cell_order','method','counts','cells','comparisons','runtime'])
 need(summary['schema']==SCHEMA,'Wrong mean/tail schema')
 for k in ('dataset_id','platform','execution','target_machine'):need(summary[k]==observations[k],'Observation identity differs')
 for k in ('observations_sha256','ordered_observations_digest','source_code_sha256'):digest(summary[k])
 keys(summary['source_code_hashes'],SOURCES)
 for value in summary['source_code_hashes'].values():digest(value)
 need(summary['source_code_sha256']==summary['source_code_hashes']['analysis/mean_tail_statistics.py'],'Analysis source identity differs')
 labels=[c['id'] for c in observations['configurations']]
 need(summary['configuration_order']==labels and summary['configurations']==observations['configurations'],'Configuration/binary/workspace identity differs')
 need(summary['cell_order']==[list(c) for c in CELLS],'Changed operation order')
 method=summary['method'];keys(method,['estimator','ratio_direction','statistics','quantile','bootstrap_unit','bootstrap_rng',
  'bootstrap_seed','resamples','interval','block_draws_sha256','replicate_values_sha256','replicate_layout',
  'weighting','slow_observation_policy','warmup_policy','interval_scope'])
 expected=dict(estimator='ratios_of_pooled_call_statistics',ratio_direction='candidate_over_reference',statistics=list(STATISTICS),
  quantile='linear_type7',bootstrap_unit=BOOTSTRAP_UNIT,bootstrap_rng='PCG64',interval='percentile_0.025_0.975',
  replicate_layout='configuration_cell_statistic_resample',weighting='equal_18_operation_cells_for_mean_ratio_geomean',
  slow_observation_policy='retain_all',warmup_policy='retain_in_observations_exclude_only_from_statistics',interval_scope='pointwise')
 need(all(method[k]==v for k,v in expected.items()),'Changed mean/tail estimator or interpretation')
 integer(method['bootstrap_seed']);integer(method['resamples'],1);need(method['resamples']<=100000,'Resample bound exceeded')
 for k in ('block_draws_sha256','replicate_values_sha256'):digest(method[k])
 counts=summary['counts'];keys(counts,['blocks','samples_per_run','raw_rows','measured_rows','warmup_rows','deleted_rows'])
 for v in counts.values():integer(v)
 e=observations['experiment'];need(counts==dict(blocks=e['blocks'],samples_per_run=e['samples_per_run'],raw_rows=observations['completeness']['sample_rows'],
  measured_rows=e['blocks']*e['samples_per_run']*18*len(labels),warmup_rows=e['blocks']*e['warmups_per_run']*18*len(labels),deleted_rows=0),'Changed sample counts')
 rows=summary['cells'];need(type(rows) is list and len(rows)==18*len(labels),'Incomplete statistical matrix')
 need([(r.get('configuration'),r.get('parameter'),r.get('operation')) for r in rows]==[(label,p,o) for label in labels for p,o in CELLS],'Changed cell order')
 for row in rows:
  keys(row,['configuration','parameter','operation','pooled_samples','statistics','minimum_ns','maximum_ns']);integer(row['pooled_samples'],1)
  need(row['pooled_samples']==e['blocks']*e['samples_per_run'],'Wrong sample count');keys(row['statistics'],STATISTICS)
  positive(row['minimum_ns']);positive(row['maximum_ns'])
  for value in row['statistics'].values():
   estimate(value);need(row['minimum_ns']<=value['ns']<=row['maximum_ns'],'Point outside observed range')
   need(row['minimum_ns']<=value['ci95_ns'][0]<=value['ci95_ns'][1]<=row['maximum_ns'],'Interval outside observed range')
  need(row['statistics']['median']['ns']<=row['statistics']['p95']['ns']<=row['statistics']['p99']['ns'],'Inconsistent quantiles')
 pairs=summary['comparisons'];need(type(pairs) is list,'Comparison list required')
 comparisons([{k:p[k] for k in ('id','reference','candidate')} for p in pairs],labels)
 for pair in pairs:
  keys(pair,['id','reference','candidate','cells','mean_time_ratio_geomean','mean_time_ratio_geomean_ci95'])
  positive(pair['mean_time_ratio_geomean']);interval(pair['mean_time_ratio_geomean_ci95'])
  need(type(pair['cells']) is list and [(r.get('parameter'),r.get('operation')) for r in pair['cells']]==list(CELLS),'Missing comparison cells')
  for row in pair['cells']:
   keys(row,['parameter','operation','ratios']);keys(row['ratios'],STATISTICS)
   for ratio in row['ratios'].values():estimate(ratio,True)
 keys(summary['runtime'],['python','numpy'])
 for v in summary['runtime'].values():need(type(v) is str and re.fullmatch(r'[0-9A-Za-z.+_-]{1,80}',v),'Invalid runtime identity')
 return summary
