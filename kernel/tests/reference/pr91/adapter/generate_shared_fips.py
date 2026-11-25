"""Replace one PR91 permutation body in a generated copy; preserve original files."""
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

ORIGINAL_SHA = 'e4e486d8c839805ae9ad0c2976c3ad4455eeb9a4126835cb1583d7c287ccd9f6'
OWNER_SHA = '0e05db5631b38128769b89eb487aafdeb731b68186e8cb0c078237760dfc56ac'


def digest(b): return hashlib.sha256(b).hexdigest()


def generate(original, owner, output, receipt):
    original, owner, output, receipt = map(Path,(original,owner,output,receipt))
    assert not output.exists() and not receipt.exists()
    raw=original.read_bytes();own=owner.read_bytes()
    assert digest(raw)==ORIGINAL_SHA and digest(own)==OWNER_SHA
    signature=b'static void KeccakF1600_StatePermute(uint64_t state[25])'
    assert raw.count(signature)==1
    start=raw.index(signature);opening=raw.index(b'{',start)
    depth=0;end=None
    for i in range(opening,len(raw)):
        if raw[i:i+1]==b'{':depth+=1
        elif raw[i:i+1]==b'}':
            depth-=1
            if depth==0:end=i+1;break
    assert end is not None
    replacement=(b'/* Generated backend adaptation: SHAKE framing remains original PR91. */\n'
                 b'extern void lc_shared_keccakf1600(uint64_t state[25]);\n'
                 +signature+b'\n{\n  lc_shared_keccakf1600(state);\n}')
    result=raw[:start]+replacement+raw[end:]
    assert result.count(b'lc_shared_keccakf1600(state);')==1
    output.write_bytes(result)
    record=dict(schema='ch32.pr91.permutation_adapter.v1',
        original_sha256=digest(raw),common_owner_sha256=digest(own),generated_sha256=digest(result),
        generator_sha256=digest(Path(__file__).read_bytes()),
        replacement=dict(original_start=start,original_end=end,original_function_sha256=digest(raw[start:end]),
                         generated_function_sha256=digest(replacement)),
        unchanged_prefix=dict(bytes=start,sha256=digest(raw[:start])),
        unchanged_suffix=dict(bytes=len(raw)-end,sha256=digest(raw[end:])),
        scope='Only the local Keccak-f[1600] permutation body forwards the same uint64_t[25] state to the common DSA-owner function. Original SHAKE absorption, domain separation, padding, squeezing, sampling, arithmetic and API cleanup remain unchanged.',
        upstream_modified=False,hardware_access=False)
    receipt.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    return record


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('original','owner','output','receipt'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(generate(a.original,a.owner,a.output,a.receipt)))
