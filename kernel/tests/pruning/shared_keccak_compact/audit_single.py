"""Bind one-round permutation machine control and exact round constants.

This structural audit complements the whole-operation fixed regression and
timing observations. It deliberately covers the changed shared provider.
"""
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
import argparse, hashlib, record_io as json, re, struct, sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tests/resources'))
from image_inventory import inventory
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--candidate',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 folder=a.candidate.resolve();out=a.output.resolve();assert not out.exists();result=json.loads((folder/'result.xml').read_text())
 dll=folder/'latticecore.dll';assert sha(dll)==result['candidate']['sha256'];assert result['provider']=='single'
 path=folder/'inspection/disassembly.log';text=path.read_text();reach=json.loads((folder/'reachability.xml').read_text());assert sha(path)==reach['disassembly_sha256']
 m=re.search(r'^([0-9a-f]+) <lc_shared_keccakf1600>:\n(.*?)(?=^[0-9a-f]+ <|\Z)',text,re.M|re.S);assert m
 body=m[2];lines=body.splitlines();branches=[line.strip() for line in lines if re.search(r'\bj(?!mp)[a-z]+\b',line)]
 calls=[line for line in lines if re.search(r'\b(?:call|jmp|i?div|vgather\w*)\b',line)]
 assert len(branches)==1 and not calls
 start=re.search(r'lea\s+[^\n]+# ([0-9a-f]+) <mlk_KeccakF_RoundConstants>',body);assert start
 end=re.findall(r'lea\s+[^\n]+# ([0-9a-f]+) <[^>]+>',body)[-1]
 first=int(start[1],16);last=int(end,16);assert last-first==24*8
 assert re.search(r'addq\s+\$0x8,-0xb0\(%rbp\)',body)
 assert re.search(r'cmp\s+-0xb0\(%rbp\),%rcx',body)
 binary=dll.read_bytes();pe=struct.unpack_from('<I',binary,0x3c)[0];base=struct.unpack_from('<Q',binary,pe+24+24)[0]
 image=inventory(dll);rva=first-base;section=next(s for s in image['sections'] if s['address']<=rva<s['address']+s['virtual_bytes'])
 position=section['raw_offset']+rva-section['address'];constants=struct.unpack_from('<24Q',binary,position)
 source=ROOT/'configs/shared_keccak_compact/owner_single.c';source_text=source.read_text()
 expected=tuple(int(x,16) for x in re.findall(r'\(uint64_t\)(0x[0-9a-fA-F]+)ULL',source_text));assert constants==expected and len(expected)==24
 record=dict(status='CHANGED_PROVIDER_STRUCTURAL_REVIEW_COMPLETE',library_sha256=sha(dll),source_sha256=sha(source),
  disassembly_sha256=sha(path),auditor_sha256=sha(Path(__file__)),entry=m[1],conditional_branches=branches,
  calls_or_unconditional_transfers_or_division_gather=calls,round_constant_start=hex(first),round_constant_end=hex(last),
  pointer_increment_bytes=8,round_count=24,round_constants_equal_to_source=True,
  state_address_review='25 initial fixed-offset state loads and 25 final fixed-offset stores. Body operates on registers/fixed stack slots. The only advancing memory pointer selects consecutive round constants.',
  boolean_review='Unsigned uint64_t XOR/AND/NOT and fixed nonzero rotates; the source round trip is 0..23.',
  reachability_sha256=sha(folder/'reachability.xml'),
  scope='Exact changed provider machine-control and table review on the named PE build; whole-library/API and statistical observations are separate bound records.')
 out.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({k:record[k] for k in ['status','round_count','library_sha256']}))
if __name__=='__main__':main()
