"""Actual same-image direct call/tail-call witnesses to the shared provider.

Address identity handles symbol aliases. Indirect branches never provide an edge.
"""
from collections import deque,defaultdict
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
import argparse, hashlib, record_io as json, re
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def analyze(entities,disassembly):
    functions=defaultdict(set)
    for e in entities:
        if e.get('address') is not None and e.get('symbol'):functions[int(e['address'])].add(e['symbol'])
    providers=[e for e in entities if e['symbol']=='lc_shared_keccakf1600']
    if len(providers)!=1:raise ValueError('Need exactly one named shared provider')
    target=int(providers[0]['address']);graph=defaultdict(set);edge_text={};caller=None;unresolved=[]
    for line in disassembly.splitlines():
        m=re.match(r'^([0-9a-fA-F]+) <([^>]+)>:',line)
        if m:caller=int(m[1],16);functions[caller].add(m[2]);continue
        if caller is None:continue
        branch=re.search(r'\b(callq?|jmpq?|bl|b)\s+([0-9a-fA-Fx]+)\s+<([^>]+)>',line)
        if branch:
            destination=int(branch[2],16)
            if destination in functions:
                graph[caller].add(destination);edge_text[(caller,destination)]=line.strip()
        elif re.search(r'\b(?:blr|br)\s+x\d+|\b(?:callq?|jmpq?)\s+\*',line):unresolved.append({'caller_address':caller,'instruction':line.strip()})
    witnesses=[]
    for family,prefix in [('ML-KEM','lc_base_mlk'),('ML-DSA','lcbase')]:
        roots=sorted(a for a,names in functions.items() if any(name.startswith(prefix) for name in names))
        queue=deque(roots);previous={a:None for a in roots}
        while queue and target not in previous:
            current=queue.popleft()
            for nxt in sorted(graph[current]):
                if nxt not in previous:previous[nxt]=current;queue.append(nxt)
        if target not in previous:raise ValueError('No direct same-image path for '+family+'; unknown indirect edges are not proof')
        path=[target]
        while previous[path[-1]] is not None:path.append(previous[path[-1]])
        path.reverse()
        if len(path)<2:raise ValueError('Provider cannot establish a family root by alias alone')
        witnesses.append({'family':family,'family_prefix':prefix,'path':[{'address':a,'aliases':sorted(functions[a])} for a in path],'edges':[{'from':x,'to':y,'instruction':edge_text[(x,y)]} for x,y in zip(path,path[1:])]})
    return {'status':'BOTH_FAMILIES_REACH_UNIQUE_PROVIDER','shared_provider':providers[0],'witnesses':witnesses,'known_direct_edge_count':sum(map(len,graph.values())),'unresolved_indirect_edges':unresolved,'indirect_edges_used':False,'scope':'Existence of actual direct call/tail-call paths from retained family-namespaced functions to the one shared provider. Not a complete dynamic call graph or proof that every path uses that provider.'}
def main():
    p=argparse.ArgumentParser();p.add_argument('--inspection',type=Path,required=True);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise ValueError('Fresh result required')
    data=json.loads((a.inspection/'entities.xml').read_text());result=analyze(data['entities'],(a.inspection/'disassembly.log').read_text())
    result.update(library_sha256=sha(a.library),entities_sha256=sha(a.inspection/'entities.xml'),disassembly_sha256=sha(a.inspection/'disassembly.log'),review_source_sha256=sha(__file__))
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(result['status'])
if __name__=='__main__':main()
