"""Closed public pooled-median statistics schema, distinct from mean statistics.

Consumes the existing public ordered observations; never accesses private input
archives, local manifests, network endpoints or host-specific build directories.
"""
import re
from pooled_conditions import validate_metadata
from block_model import validate as validate_blocks, keys, need, integer, number, token, digest, parameter

SCHEMA='lattice.pooled_median_statistics.v2'
CELLS=tuple((p,o) for p in (512,768,1024,44,65,87) for o in range(3))
PATH=re.compile(r'(?i)(?:[a-z]:[\\/]|/(?:home|root|Users)/|[\\/]\.ssh[\\/])')
BOOTSTRAP_UNIT='complete_paired_block_all_configurations_and_cells'

def public_observations(data):
    if data.get('schema')=='lattice.block_observation_shards.v2':
        from pooled_shards import validate_manifest
        validate_manifest(data)
    else:validate_blocks(data)
    need(data['analysis'] is None,'Mean analysis must remain separate; observations input requires analysis=null')
    need(data['completeness']['archive_status']=='COMPLETE' and
         data['completeness']['failed_sample_rows']==0 and data['completeness']['failed_runs']==0,
         'No successful-only statistics may hide failed or incomplete measurements')
    need(data['experiment']['blocks']>=2,'At least two complete blocks required')
    for r in data['runs']:
        for k in ('source_csv_sha256','source_log_sha256','source_stderr_sha256',
                  'input_sequence_sha256','output_sequence_sha256'):digest(r[k])
        need(r['entropy_mode']=='supplied_test_entropy','Different entropy boundary')
        validate_metadata(r['implementation_metadata'],data['experiment']['timing_boundary'],data['schedule'][r['ordinal']]['operation'])
        for value in r['implementation_metadata'].values():
            if isinstance(value,str):need(PATH.search(value) is None,'Host-specific path in public metadata')
    return data

def comparisons(pairs,labels):
    need(type(pairs) is list and len(pairs)>0,'Explicit comparisons required')
    ids=[];ends=[]
    for pair in pairs:
        keys(pair,['id','reference','candidate']);token(pair['id'])
        need(pair['reference'] in labels and pair['candidate'] in labels,'Unknown comparison configuration')
        ids.append(pair['id']);ends.append((pair['reference'],pair['candidate']))
    need(len(ids)==len(set(ids)) and len(ends)==len(set(ends)),'Duplicate comparison')

def interval(value):
    need(type(value) is list and len(value)==2,'Interval must have two endpoints')
    for x in value:number(x)
    need(0<value[0]<=value[1],'Invalid confidence interval')

def validate(summary,observations):
    public_observations(observations)
    keys(summary,['schema','dataset_id','platform','execution','target_machine',
         'observations_sha256','ordered_observations_digest','source_code_sha256','configuration_order',
         'configurations','cell_order','method','counts','cells','comparisons','runtime'])
    need(summary['schema']==SCHEMA,'Wrong pooled statistics schema')
    for k in ('dataset_id','platform','execution','target_machine'):
        need(summary[k]==observations[k],'Observation/statistics identity changed')
    for k in ('observations_sha256','ordered_observations_digest','source_code_sha256'):digest(summary[k])
    labels=[c['id'] for c in observations['configurations']]
    need(summary['configuration_order']==labels and summary['configurations']==observations['configurations'],
         'Configuration or binary/workspace identity changed')
    need(summary['cell_order']==[list(c) for c in CELLS],'Cell order changed')
    method=summary['method']
    keys(method,['estimator','ratio_direction','quantile','bootstrap_unit','bootstrap_rng','bootstrap_seed',
         'resamples','interval','block_draws_sha256','replicate_values_sha256','weighting',
         'slow_observation_policy','warmup_policy','mixture_estimator','interval_scope'])
    need(method['estimator']=='ratio_of_pooled_individual_medians' and
         method['ratio_direction']=='reference_over_candidate' and method['quantile']=='linear_type7' and
         method['bootstrap_unit']==BOOTSTRAP_UNIT and method['bootstrap_rng']=='PCG64' and
         method['interval']=='percentile_0.025_0.975','Changed estimator/resampling method')
    need(method['weighting']=='equal_18_operation_cells' and method['slow_observation_policy']=='retain_all' and
         method['warmup_policy']=='retain_in_observations_exclude_only_from_statistics' and
         method['mixture_estimator']=='arithmetic_mean_of_component_pooled_means' and
         method['interval_scope']=='pointwise_no_simultaneous_coverage_claim','Changed scientific interpretation')
    integer(method['bootstrap_seed']);integer(method['resamples'],1)
    digest(method['block_draws_sha256']);digest(method['replicate_values_sha256'])
    counts=summary['counts'];keys(counts,['blocks','samples_per_run','raw_rows','measured_rows','warmup_rows','deleted_rows'])
    e=observations['experiment'];expected_measured=e['blocks']*e['samples_per_run']*18*len(labels)
    need(counts==dict(blocks=e['blocks'],samples_per_run=e['samples_per_run'],
         raw_rows=observations['completeness']['sample_rows'],measured_rows=expected_measured,
         warmup_rows=e['blocks']*e['warmups_per_run']*18*len(labels),deleted_rows=0),'Sample counts changed')
    rows=summary['cells'];need(type(rows) is list and len(rows)==18*len(labels),'Incomplete statistics')
    need([(r.get('configuration'),r.get('parameter'),r.get('operation')) for r in rows]==
         [(label,p,o) for label in labels for p,o in CELLS],'Reordered/missing statistical cells')
    for r in rows:
        keys(r,['configuration','parameter','operation','pooled_samples','pooled_mean_ns','pooled_median_ns',
             'pooled_p95_ns','pooled_p99_ns','minimum_ns','maximum_ns'])
        need(r['pooled_samples']==e['blocks']*e['samples_per_run'],'Wrong pooled sample count')
        for k in ('pooled_mean_ns','pooled_median_ns','pooled_p95_ns','pooled_p99_ns','minimum_ns','maximum_ns'):
            number(r[k]);need(r[k]>0,'Nonpositive timing cannot define a ratio')
        need(r['minimum_ns']<=r['pooled_median_ns']<=r['pooled_p95_ns']<=r['pooled_p99_ns']<=r['maximum_ns'],
             'Inconsistent quantiles')
    pairs=summary['comparisons'];comparisons([{k:p[k] for k in ('id','reference','candidate')} for p in pairs],labels)
    for pair in pairs:
        keys(pair,['id','reference','candidate','cells','equal_weight_18_cell_median_ratio_geomean',
             'paired_complete_block_ci95','families','reference_equal_weight_mean_ns','candidate_equal_weight_mean_ns'])
        number(pair['equal_weight_18_cell_median_ratio_geomean']);interval(pair['paired_complete_block_ci95'])
        for k in ('reference_equal_weight_mean_ns','candidate_equal_weight_mean_ns'):number(pair[k])
        need([(r.get('parameter'),r.get('operation')) for r in pair['cells']]==list(CELLS),'Missing comparison cells')
        for r in pair['cells']:
            keys(r,['parameter','operation','pooled_median_ratio','paired_complete_block_ci95'])
            parameter(r['parameter'],r['operation']);number(r['pooled_median_ratio']);interval(r['paired_complete_block_ci95'])
        keys(pair['families'],['ML-KEM','ML-DSA'])
        for f in pair['families'].values():
            keys(f,['median_ratio_geomean','paired_complete_block_ci95']);number(f['median_ratio_geomean']);interval(f['paired_complete_block_ci95'])
    keys(summary['runtime'],['python','numpy'])
    for v in summary['runtime'].values():need(type(v) is str and re.fullmatch(r'[0-9A-Za-z.+_-]{1,80}',v),'Invalid runtime identity')
    return summary
