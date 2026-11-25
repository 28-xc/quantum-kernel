"""Prepare the pinned CommonJS runtime without writing a source archive or npm metadata."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
REVISION = '52576c92bccf6ac60c8223ec7eb2565637cae9ba'
TREE = 'f59c498a45b19dbace065723bc8ad038a51f943c5f709a92374d9f6e5d91cc3c'
SOURCE = 'https://codeload.github.com/benchmark-action/github-action-benchmark/tar.gz/' + REVISION
LIMIT = 32 * 1024 * 1024

def extract(stream):
    archive_bytes = stream.read(LIMIT + 1)
    if len(archive_bytes) > LIMIT:
        raise ValueError('Upstream archive too large')
    contents = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode='r:*') as archive:
        for item in archive:
            if item.isdir():
                continue
            parts = PurePosixPath(item.name).parts
            if not item.isfile() or len(parts) < 2 or '..' in parts or item.name.startswith('/') or '\\' in item.name:
                raise ValueError('Invalid upstream member')
            key = '/'.join(parts[1:])
            total += item.size
            if key in contents or total > LIMIT or len(contents) >= 1011:
                raise ValueError('Unexpected upstream member set')
            contents[key] = archive.extractfile(item).read()
    identity = hashlib.sha256()
    for name, data in sorted(contents.items()):
        identity.update(name.encode('utf8') + b'\0' + hashlib.sha256(data).digest())
    if len(contents) != 1011 or identity.hexdigest() != TREE:
        raise ValueError('Upstream release tree differs from the pinned identity')
    return contents

def write(out, name, data):
    dest = out / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)

def project(out, files):
    for name, data in files.items():
        if name.endswith(('.js', '.cjs')) or PurePosixPath(name).name.lower().startswith(('license','notice','copying')):
            write(out, name, data)
    for name, data in files.items():
        if not name.startswith('node_modules/') or not name.endswith('/package.json'):
            continue
        parent = PurePosixPath(name).parent
        main = json.loads(data).get('main')
        if not main:
            continue
        entry = parent / main
        if entry.as_posix() not in files:
            raise ValueError('Missing package entry: ' + str(entry))
        if entry.name != 'index.js' or entry.parent != parent:
            write(out, parent / 'index.js', ("module.exports = require('./" + entry.relative_to(parent).as_posix() + "');\n").encode())
    folder = 'node_modules/node-fetch/node_modules/tr46'
    table = json.loads(files[folder + '/lib/mappingTable.json'])
    lines = ['first\tlast\tstatus\tmapping\tflag']
    for limits, status, *extra in table:
        mapped = '-' if not extra else ','.join(map(str,extra[0]))
        flag = extra[1] if len(extra) == 2 else ''
        lines.append(f'{limits[0]}\t{limits[1]}\t{status}\t{mapped}\t{flag}')
    write(out, folder + '/lib/mapping.tsv', ('\n'.join(lines)+'\n').encode())
    entry = out / folder / 'index.js'
    source = entry.read_text(encoding='utf8')
    entry.write_text(source.replace('require("./lib/mappingTable.json")','require("./lib/read-mapping.cjs")'),encoding='utf8')
    shutil.copyfile(HERE/'read-mapping.cjs', out/folder/'lib/read-mapping.cjs')
    for name in ('publish.cjs','history.cjs','xml_bridge.py','record_io.py','page-data.js'):
        shutil.copyfile(HERE/name, out/name)
    from adapt_release import adapt
    adapt(out)

if __name__ == '__main__':
    dest = Path(sys.argv[1])
    if any(dest.iterdir()):
        raise ValueError('Publisher staging directory must be empty')
    if len(sys.argv) == 3 and sys.argv[2] == '--stdin':
        records = extract(sys.stdin.buffer)
    else:
        with urllib.request.urlopen(SOURCE, timeout=45) as remote:
            records = extract(remote)
    project(dest, records)
