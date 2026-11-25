"""Recompute paired means and pooled tail quantiles from public observations.

All comparisons share the same whole-block draws. Ratios are explicitly
candidate/reference; pooled-median summaries keep their separate schema.
"""
from pathlib import Path
import argparse,hashlib,math,platform,sys
import numpy as np
import pooled_statistics as shared
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from publicschemas import mean_tail_model as model

SEED=2026100313511
RESAMPLES=10000
QUANTILES={'median':.5,'p95':.95,'p99':.99}
def sources():return {p:shared.sha(ROOT/p) for p in model.SOURCES}
def ci(values):return [shared.q7(values,.025),shared.q7(values,.975)]

def analyze(data,pairs,observations_sha256,resamples=RESAMPLES,seed=SEED,base_dir=None):
 model.integer(resamples,1);model.need(resamples<=100000,'Resample bound exceeded');model.integer(seed)
 labels,arrays=shared.observations_arrays(data,base_dir);model.comparisons(pairs,labels);model.digest(observations_sha256)
 e=data['experiment'];counts,draw_hash=shared.draws(e['blocks'],resamples,seed)
 # Shape fixes the shared draws across all configurations, cells and statistics.
 replicates=np.empty((len(labels),18,4,resamples),dtype=np.float64);points=np.empty((len(labels),18,4));rows=[]
 for li,label in enumerate(labels):
  for cell,(parameter,operation) in enumerate(model.CELLS):
   x=arrays[label,parameter,operation];flat=x.ravel();block_means=np.mean(x,axis=1)
   replicates[li,cell,0]=np.einsum('ij,j->i',counts,block_means)/e['blocks']
   points[li,cell,0]=float(np.mean(block_means))
   weighted=shared.WeightedBlockCDF(x)
   for si,(name,q) in enumerate(QUANTILES.items(),1):
    replicates[li,cell,si]=weighted.quantiles(counts,q);points[li,cell,si]=shared.q7(flat,q)
   rows.append(dict(configuration=label,parameter=parameter,operation=operation,pooled_samples=x.size,
    statistics={name:dict(ns=float(points[li,cell,si]),ci95_ns=ci(replicates[li,cell,si])) for si,name in enumerate(model.STATISTICS)},
    minimum_ns=float(np.min(flat)),maximum_ns=float(np.max(flat))))
 results=[]
 for pair in pairs:
  left,right=labels.index(pair['candidate']),labels.index(pair['reference']);boot=replicates[left]/replicates[right];point=points[left]/points[right]
  gm=np.exp(np.mean(np.log(boot[:,0,:]),axis=0))
  results.append(dict(**pair,cells=[dict(parameter=p,operation=o,ratios={name:dict(value=float(point[i,si]),ci95=ci(boot[i,si])) for si,name in enumerate(model.STATISTICS)}) for i,(p,o) in enumerate(model.CELLS)],
   mean_time_ratio_geomean=float(np.exp(np.mean(np.log(point[:,0])))),mean_time_ratio_geomean_ci95=ci(gm)))
 code=sources()
 summary=dict(schema=model.SCHEMA,**{k:data[k] for k in ('dataset_id','platform','execution','target_machine','configurations')},
  observations_sha256=observations_sha256,ordered_observations_digest=shared.digest_value({'schedule':data['schedule'],'runs':data['runs']}),
  source_code_sha256=code['analysis/mean_tail_statistics.py'],source_code_hashes=code,configuration_order=labels,cell_order=[list(c) for c in model.CELLS],
  method=dict(estimator='ratios_of_pooled_call_statistics',ratio_direction='candidate_over_reference',statistics=list(model.STATISTICS),quantile='linear_type7',
   bootstrap_unit=model.BOOTSTRAP_UNIT,bootstrap_rng='PCG64',bootstrap_seed=seed,resamples=resamples,interval='percentile_0.025_0.975',
   block_draws_sha256=draw_hash,replicate_values_sha256=hashlib.sha256(replicates.astype('<f8',copy=False).tobytes()).hexdigest(),replicate_layout='configuration_cell_statistic_resample',
   weighting='equal_18_operation_cells_for_mean_ratio_geomean',slow_observation_policy='retain_all',warmup_policy='retain_in_observations_exclude_only_from_statistics',interval_scope='pointwise'),
  counts=dict(blocks=e['blocks'],samples_per_run=e['samples_per_run'],raw_rows=data['completeness']['sample_rows'],measured_rows=e['blocks']*e['samples_per_run']*len(labels)*18,
   warmup_rows=e['blocks']*e['warmups_per_run']*len(labels)*18,deleted_rows=0),cells=rows,comparisons=results,runtime=dict(python=platform.python_version(),numpy=np.__version__))
 model.validate(summary,data)
 return summary,dict(complete_block_counts=counts,mean_tail_replicates_ns=replicates)

def recompute(data,summary,observations_sha256,base_dir=None):
 model.validate(summary,data);model.need(summary['observations_sha256']==observations_sha256,'Observation bytes changed')
 model.need(summary['source_code_hashes']==sources(),'Statistical implementation or schema source changed')
 pairs=[{k:p[k] for k in ('id','reference','candidate')} for p in summary['comparisons']]
 actual,_=analyze(data,pairs,observations_sha256,summary['method']['resamples'],summary['method']['bootstrap_seed'],base_dir)
 for key in actual:
  if key!='runtime':model.need(actual[key]==summary[key],'Exact public mean/tail reconstruction differs: '+key)
 return dict(status='EXACT_PUBLIC_MEAN_TAIL_RECOMPUTED',dataset_id=data['dataset_id'],statistical_cells=len(summary['cells']),comparisons=len(pairs),
  block_draws_sha256=summary['method']['block_draws_sha256'],sample_rows=summary['counts']['raw_rows'])

def main():
 parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
 for action in ('derive','recompute'):
  p=sub.add_parser(action);p.add_argument('--observations',type=Path,required=True)
  if action=='derive':
   p.add_argument('--comparisons',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
   p.add_argument('--resamples',type=int,default=RESAMPLES);p.add_argument('--seed',type=int,default=SEED)
  else:p.add_argument('--summary',type=Path,required=True)
 a=parser.parse_args();data=shared.read_observations(a.observations);identity=shared.sha(a.observations)
 if a.action=='derive':
  summary,_=analyze(data,shared.read(a.comparisons),identity,a.resamples,a.seed,a.observations.resolve().parent);shared.write(a.output,summary)
  result=dict(status='PUBLIC_MEAN_TAIL_DERIVED',dataset_id=data['dataset_id'],statistical_cells=len(summary['cells']),comparisons=len(summary['comparisons']),summary_sha256=shared.sha(a.output))
 else:result=recompute(data,shared.read(a.summary),identity,a.observations.resolve().parent)
 print(shared.json.dumps(result))
if __name__=='__main__':main()
