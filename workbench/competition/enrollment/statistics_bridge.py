"""Explicit raw replay for cross-runtime paired statistics; frozen sources stay intact."""
from pathlib import Path
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
import copy, hashlib, importlib.util, json as canonical_json, record_io as json, tempfile

def need(value,message):
    if not value:raise ValueError(message)
def sha(path):
    with path.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def read(path):return json.loads(path.read_text(encoding='utf8'))
def checked(root,row):
    path=(root/row['path']).resolve()
    need(path.is_relative_to(root.resolve())and path.is_file()and sha(path)==row['sha256'],
         'Numerical replay input differs')
    return path


def historical_summary(value, identities):
    """Project the recorded input fingerprints into their original file representation."""
    result=copy.deepcopy(value)
    for identity in identities:
        names=identity['field']
        need(names in (['observations_sha256'],['source_code_sha256']) or
             (len(names)==2 and names[0]=='source_code_hashes'), 'Unexpected historical identity field')
        parent=result if len(names)==1 else result[names[0]]
        field=names[-1]
        if parent[field]==identity['supplied']:
            parent[field]=identity['original']
    return result



def install(source,bundle,descriptor):
    """Bind a fresh GUI reconstruction to a complete, explicitly recorded array replay."""
    from tools import recompute_operation_statistics as original_consumer
    bundle=bundle.resolve();source=source.resolve();cfg=read(descriptor)
    need(cfg['schema']=='lattice.gui_numerical_replay.v1','Unknown numerical replay contract')
    for binding in cfg['method_bindings']:checked(bundle,binding)
    method=checked(bundle,cfg['method'])
    for binding in cfg['reference_bindings']:checked(bundle,binding)
    observations=checked(bundle,cfg['observations'])
    originals={kind:checked(bundle,row)for kind,row in cfg['summaries'].items()}
    need(set(originals)=={'mean-tail','equal-frequency'},'Both original statistical summaries required')
    reference=(bundle/cfg['reference_directory']).resolve()
    need(reference.is_relative_to(bundle),'Reference arrays escape the bundle')
    need({str(p.resolve())for p in reference.rglob('*')if p.is_file()}==
         {str(checked(bundle,row))for row in cfg['reference_bindings']},'Unexpected reference-array inputs')
    spec=importlib.util.spec_from_file_location('registered_gui_paired_runtime',method)
    model=importlib.util.module_from_spec(spec);spec.loader.exec_module(model)
    receipt=read(checked(bundle,cfg['certificate']))
    need(receipt['status']=='CROSS_RUNTIME_NUMERICAL_EQUIVALENCE_VERIFIED','Full array certificate is not complete')
    need(receipt['observations_sha256']==sha(observations),'Certificate observed another dataset')
    certificates={x['kind']:x for x in receipt['analyses']}
    registered=cfg.get('historical_summary_inputs',{})
    for kind,path in originals.items():
        archived=historical_summary(read(path),registered.get(kind,[]))
        encoded=(canonical_json.dumps(archived,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
        evidence_sha=hashlib.sha256(encoded).hexdigest() if kind in registered else sha(path)
        need(certificates[kind]['original_summary_sha256']==evidence_sha and
             model.canonical_summary(archived)==certificates[kind]['original_canonical_sha256'],
             'Original statistical summary is not certified')
    expected=read(originals['equal-frequency'])
    result=dict(schema='lattice.gui_numerical_replay_result.v1',status='AWAITING_GUI_RECONSTRUCTION',
                original_observations_sha256=sha(observations),
                original_summary_sha256={k:sha(v)for k,v in originals.items()},
                method_sha256=sha(method),frozen_source_modified=False)
    old_compare=original_consumer.compare
    def compare_registered(left,right,*args,**kwargs):
        if isinstance(left,dict)and left.get('dataset_id')==expected['dataset_id']:
            need(left==expected,'GUI original summary changed after replay')
            active=receipt
            mode='FRESH_GUI_RECONSTRUCTION_MATCHES_CERTIFIED_ARRAY_REPLAY'
            checked_left=historical_summary(left,registered.get('equal-frequency',[]))
            checked_right=historical_summary(right,registered.get('equal-frequency',[]))
            if model.canonical_summary(checked_right)!=certificates['equal-frequency']['reconstructed_canonical_sha256']:
                # Another processor may produce different final bits. Such a
                # reconstruction is accepted only after a new complete raw and
                # original-array replay, never by ignoring the changed digest.
                temporary=Path(tempfile.mkdtemp(prefix='lattice-numerical-replay-'))
                active=model.run(source,observations.parent,reference,temporary/'verified')
                checked_left,checked_right=left,right
                mode='FRESH_COMPLETE_RAW_AND_ARRAY_REPLAY'
            certificate=next(r for r in active['analyses']if r['kind']=='equal-frequency')
            verified=model.verify_previously_replayed_summary(checked_left,checked_right,certificate)
            result.update(status='CROSS_RUNTIME_NUMERICAL_EQUIVALENCE_VERIFIED',validation_mode=mode,replay=active)
            return verified
        return old_compare(left,right,*args,**kwargs)
    original_consumer.compare=compare_registered
    return result
