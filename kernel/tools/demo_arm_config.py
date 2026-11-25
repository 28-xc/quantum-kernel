"""Make a functional-only ARM configuration from an explicitly pinned ELF.

Run on the deployment host so absolute paths identify that host's real files.
No library is loaded and no scientific measurement is generated here.
"""
from pathlib import Path
import argparse
import hashlib
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
import record_io as json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from publicschemas.demo import validate_config
from publicschemas.deployment import validate as validate_profiles


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifact', type=Path, required=True)
    p.add_argument('--sha256', required=True)
    p.add_argument('--library-id', required=True)
    p.add_argument('--configuration', required=True)
    p.add_argument('--workspace-bytes', type=int, required=True)
    p.add_argument('--title', default='ARM 实时功能')
    p.add_argument('--output', type=Path, required=True, help='Fresh output directory')
    a = p.parse_args()
    artifact = a.artifact.resolve(strict=True)
    content = artifact.read_bytes()
    sha = hashlib.sha256(content).hexdigest()
    if sha != a.sha256 or content[:6] != b'\x7fELF\x02\x01' or int.from_bytes(content[18:20], 'little') != 183:
        raise ValueError('Expected the pinned little-endian ELF64 AArch64 artifact')
    output = a.output.resolve()
    if output.exists():
        raise ValueError('Fresh output directory required')
    profile = dict(platform='linux_aarch64', configuration=a.configuration,
                   binary_sha256=sha, workspace_bytes=a.workspace_bytes)
    profiles = dict(schema='lattice.deployment_profiles.v2', profiles=[profile],
                    scope='Explicit live functional deployment. Workspace is an owner-supplied capacity, not a RAM benchmark.')
    validate_profiles(profiles)
    profile_bytes = (json.dumps(profiles, ensure_ascii=False, indent=2) + '\n').encode('utf8')
    config = dict(schema=4, kind='local_lattice_demo', datasets=[], scientific_views=[], pooled_views=[],
                  deployment_profiles=dict(path='deployment_profiles.xml', sha256=hashlib.sha256(profile_bytes).hexdigest()),
                  libraries=[dict(id=a.library_id, title=a.title, configuration=a.configuration,
                                  platform='linux_aarch64', parameters=[512,768,1024,44,65,87],
                                  workspace_bytes=a.workspace_bytes, artifact=dict(path=str(artifact), sha256=sha),
                                  execution=dict(backend='aarch64', required_features=['fp','asimd'], required_xcr0=0))])
    validate_config(config)
    output.mkdir(parents=True)
    (output/'deployment_profiles.xml').write_bytes(profile_bytes)
    (output/'demo.xml').write_text(json.dumps(config, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print(json.dumps(dict(config=str(output/'demo.xml'), library_id=a.library_id, image_sha256=sha,
                          workspace_bytes=a.workspace_bytes, scope='functional-only'), ensure_ascii=False))


if __name__ == '__main__':
    main()
