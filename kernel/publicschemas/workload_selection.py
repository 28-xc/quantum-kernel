"""Select an exact measured image using explicit operation call counts."""
import copy
import math
from .resources import CELLS, operation_mean
from .verification_v2 import need, keys, integer


def normalize(counts):
    need(type(counts) is list and 1<=len(counts)<=18,'Provide one to eighteen operation counts')
    seen=set();result=[]
    for row in counts:
        keys(row,['parameter','operation','calls'])
        integer(row['parameter']);integer(row['operation']);integer(row['calls'],1)
        cell=(row['parameter'],row['operation'])
        need(cell in CELLS and cell not in seen,'Unknown or repeated operation')
        need(row['calls']<=1000000,'Operation count exceeds supported range')
        seen.add(cell);result.append(dict(row))
    return sorted(result,key=lambda x:(x['parameter'],x['operation']))


def rank(budget,statistics,counts):
    counts=normalize(counts)
    need(budget['request']['timing_dataset']==statistics['dataset_id'],'Workload uses a different timing study')
    need(budget['request']['platform']==statistics['platform'],'Workload uses a different platform')
    result=copy.deepcopy(budget)
    configurations={c['id']:c for c in statistics['configurations']}
    total=sum(x['calls'] for x in counts)
    for candidate in result['candidates']:
        configuration=configurations[candidate['configuration']]
        need(configuration['library_sha256']==candidate['binary_sha256'],'Workload image differs from resource image')
        rows=[r for r in statistics['cells'] if r['configuration']==candidate['configuration']]
        need(len(rows)==18 and {(x['parameter'],x['operation']) for x in rows}==CELLS,'Complete operation matrix required')
        means={(x['parameter'],x['operation']):operation_mean(x,statistics['schema']) for x in rows}
        contributions=[dict(x,operation_mean_ns=means[x['parameter'],x['operation']],
                            service_ns=x['calls']*means[x['parameter'],x['operation']]) for x in counts]
        duration=math.fsum(x['service_ns'] for x in contributions)
        candidate.update(workload_total_service_ns=duration,workload_mean_ns=duration/total,
                         workload_operations=contributions)
    result['candidates'].sort(key=lambda x:(x['workload_mean_ns'],x['core_reserved_bytes'],x['program_bytes'],x['configuration']))
    result.update(schema='lattice.workload_budget_query.v1',
                  method='explicit_call_counts_times_complete_operation_arithmetic_means',
                  operation_counts=counts,total_calls=total,
                  selected=result['candidates'][0] if result['candidates'] else None,
                  resource_scope='complete_six_parameter_algorithm_reservation',
                  time_scope='sum_of_measured_complete_operation_means_for_the_requested_counts')
    return result
