"""Reconstruct complete-operation buffer accounting from named allocation logs."""
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
import argparse, hashlib, record_io as json


def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()


def trace(path):
    path=Path(path);d=json.loads((path/'result.xml').read_text(encoding='utf-8'))
    assert d['status']=='PASS' and sha(path/'trace-run.log')==d['events_sha256']
    assert sha(path/'control-run.log')==d['control_sha256']
    assert sha(path/'trace-outputs.bin')==d['full_output_sha256']==sha(path/'control-outputs.bin')
    assert (path/'trace-outputs.bin').read_bytes()==(path/'control-outputs.bin').read_bytes()
    cells=[];current=None;stack=[];used=0
    for line in (path/'trace-run.log').read_text(encoding='utf-8').splitlines():
        if not line.startswith('{'):continue
        e=json.loads(line)
        if e['event']=='begin':
            assert not stack and used==0
            current=dict(parameter=e['parameter'],operation=e['operation'],peak=0,peak_owners=[])
        elif e['event']=='alloc':
            assert e['ok'] and used==e['before'] and e['offset']%32==0
            assert 8<=e['offset']-used<=39 and e['after']==e['offset']+e['bytes']
            stack.append(e);used=e['after']
            if used>current['peak']:
                current.update(peak=used,peak_owners=[dict(function=x['function'],owner=x['owner'],bytes=x['bytes'],offset=x['offset'],padding_and_header=x['offset']-x['before']) for x in stack])
        elif e['event']=='free':
            assert used==e['before'];last=stack.pop()
            assert e['after']==last['before'] and e['bytes']==last['bytes'];used=e['after']
        elif e['event']=='end':
            assert not stack and used==0 and e['cleared'] and e['rc']==0 and current['peak']==e['peak']
            assert current['peak']==sum(x['bytes']+x['padding_and_header'] for x in current['peak_owners'])
            current['output_checksum']=e['output_checksum'];cells.append(current)
    assert cells==d['cells'] and len(cells)==9
    return d


def analyze(reference,candidate):
    a=trace(reference);b=trace(candidate)
    assert a['full_output_sha256']==b['full_output_sha256']
    def dec(d):return next(x for x in d['cells'] if (x['parameter'],x['operation'])==(1024,2))
    first,last=dec(a),dec(b)
    # Objects are grouped by their actual final use in the encryption path.
    groups=[('encapsulation_state','封装流程状态',['buf','kr','tmp'],['buf','kr','tmp']),
            ('matrix','公共矩阵',['at'],['tile']),
            ('secret','秘密向量',['sp'],['s_owner','s']),
            ('public_key','展开公钥',['pkpv'],[]),
            ('noise','误差向量',['ep'],['allocated_noise','epacked']),
            ('temporaries','乘加与输出临时数据',['b','v','k','epp'],['work']),
            ('product_and_sampling','乘积缓存与采样状态',['sp_cache'],['cache_owner']),
            ('public_seed','公钥种子副本',['seed'],[])]
    rows=[];covered=[set(),set()]
    for ident,label,left,right in groups:
        result=dict(id=ident,label=label)
        for i,(cell,names) in enumerate(((first,left),(last,right))):
            owners=[x for x in cell['peak_owners'] if x['owner'] in names]
            for x in owners:
                assert x['owner'] not in covered[i];covered[i].add(x['owner'])
            result['reference_bytes' if i==0 else 'candidate_bytes']=sum(x['bytes'] for x in owners)
            result['reference_owners' if i==0 else 'candidate_owners']=owners
        result['saved_bytes']=result['reference_bytes']-result['candidate_bytes'];rows.append(result)
    for i,cell in enumerate((first,last)):assert covered[i]=={x['owner'] for x in cell['peak_owners']}
    rows.append(dict(id='allocation_alignment',label='分配元数据与对齐',
        reference_bytes=sum(x['padding_and_header'] for x in first['peak_owners']),
        candidate_bytes=sum(x['padding_and_header'] for x in last['peak_owners'])))
    rows[-1]['saved_bytes']=rows[-1]['reference_bytes']-rows[-1]['candidate_bytes']
    assert sum(x['saved_bytes'] for x in rows)==first['peak']-last['peak']
    return dict(schema='lattice.memory_contribution.v1',reference_library_sha256=a['source_library_sha256'],
        candidate_library_sha256=b['source_library_sha256'],parameter=1024,operation=2,
        reference_workspace=first['peak'],candidate_workspace=last['peak'],groups=rows,
        reference_all_kem_cells=a['cells'],candidate_all_kem_cells=b['cells'],
        reference_kem_max=max(x['peak'] for x in a['cells']),candidate_kem_max=max(x['peak'] for x in b['cells']),
        full_output_bytes=a['full_output_bytes'],full_output_sha256=a['full_output_sha256'],
        method='Replayed allocation/free events at the peak of complete decapsulation; partition by simultaneously live owners. The component differences are storage accounting, not an execution order or independent speed effects.')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reference',type=Path,required=True);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    d=analyze(a.reference,a.candidate);a.output.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:d[k] for k in ('reference_workspace','candidate_workspace','reference_kem_max','candidate_kem_max')}))

if __name__=='__main__':main()
