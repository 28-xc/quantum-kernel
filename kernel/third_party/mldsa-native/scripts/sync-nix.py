#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
"""Update the vendored Nix settings and verify every upstream Git blob before replacing it."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import urllib.request

def pins_text(graph):
    if graph['version'] != 7 or graph['root'] not in graph['nodes']:
        raise ValueError('Unsupported upstream dependency graph')
    lines = []
    def table(keys, obj):
        if keys:
            lines.extend(['', '[' + '.'.join(keys) + ']'])
        children = []
        for key, value in obj.items():
            quoted = key if re.fullmatch('[A-Za-z0-9_-]+', key) else json.dumps(key)
            if isinstance(value, dict):
                children.append((quoted, value))
            else:
                if not isinstance(value, (str, int, list, bool)):
                    raise ValueError('Unsupported pin value')
                lines.append(quoted + ' = ' + json.dumps(value, ensure_ascii=False))
        for key, value in children:
            table([*keys, key], value)
    table([], graph)
    return ('\n'.join(lines) + '\n').encode()

def migrate_entry(name, blob):
    text = blob.decode()
    if name == '.github/actions/setup-nix/action.yml':
        if text.count('$(which nix) develop') != 2:
            raise ValueError('Updated setup-nix command needs review')
        text = text.replace('$(which nix) develop', 'bash ./scripts/dev-shell')
    elif name == '.github/workflows/nix.yml':
        if 'flake.lock flake.nix nix/' not in text or 'nix develop' not in text:
            raise ValueError('Updated Nix CI entry needs review')
        text = text.replace('flake.lock flake.nix nix/', 'shell.nix flake.nix nix/ scripts/dev-shell')
        text = text.replace('nix develop', 'bash ./scripts/dev-shell')
    return text.encode()

def check_source(name, data):
    # Only text inputs used by the vendored Nix settings may enter the project.
    if PurePosixPath(name).suffix.lower() not in ('.nix','.sh','.patch','.txt','.md','.yml','.yaml'):
        raise ValueError('New file type needs review: ' + name)
    text=data.decode('utf-8-sig')
    def is_record(s):
        try:return isinstance(json.loads(s), (list,dict))
        except ValueError:return False
    lines=[line for line in text.splitlines() if line.strip()]
    marked_lines=bool(lines) and all(is_record(line) for line in lines)
    if '\0' in text or is_record(text) or marked_lines or (PurePosixPath(name).suffix.lower()=='.txt' and any(is_record(line) for line in lines)):
        raise ValueError('Non-source record needs migration: ' + name)

def fetch(repo, suffix):
    headers = {'User-Agent': 'mldsa-native-nix-sync', 'Accept': 'application/vnd.github+json'}
    req = urllib.request.Request('https://api.github.com/repos/' + repo + '/' + suffix, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as response:
        return json.load(response)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', default='HEAD', help='Full upstream commit or branch')
    args = parser.parse_args()
    if not re.fullmatch(r'[\w./-]+', args.ref):
        parser.error('Invalid upstream reference')
    root = Path(__file__).resolve().parents[1]
    repo = 'pq-code-package/mlkem-native'
    commit = fetch(repo, 'commits/' + args.ref)
    listing = fetch(repo, 'git/trees/' + commit['commit']['tree']['sha'] + '?recursive=1')
    if listing.get('truncated'):
        raise ValueError('Incomplete upstream tree')
    changes = {}
    # These two recipes consume this distribution's XML-aware proof tools.
    local_recipes = {'nix/cbmc/litani.nix', 'nix/cbmc/cbmc-viewer.nix'}
    for item in listing['tree']:
        name = item['path']
        if not (name == 'flake.lock' or name == '.github/workflows/nix.yml' or name.startswith(('nix/', '.github/actions/setup-nix/'))):
            continue
        if item['type'] == 'tree':
            continue
        if item['mode'] not in ('100644', '100755') or '..' in PurePosixPath(name).parts or '\\' in name or name.startswith('/'):
            raise ValueError('Unsupported upstream file: ' + name)
        if name in ('nix/pins.toml','nix/resolve-inputs.nix') or name.lower().endswith(('.json','.jsonl','.ndjson')):
            raise ValueError('Upstream file requires format review: ' + name)
        obj = fetch(repo, 'git/blobs/' + item['sha'])
        raw = base64.b64decode(obj['content'])
        expected = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        if obj['encoding'] != 'base64' or obj['sha'] != item['sha'] or expected != item['sha']:
            raise ValueError('Upstream blob identity mismatch: ' + name)
        if name in local_recipes:
            if not (root/name).is_file():
                raise ValueError('Missing local proof-tool recipe: ' + name)
            continue
        if name == 'flake.lock':
            changes['nix/pins.toml'] = (pins_text(json.loads(raw)), 0o644)
        else:
            check_source(name, raw)
            data = migrate_entry(name,raw) if name in ('.github/actions/setup-nix/action.yml','.github/workflows/nix.yml') else raw
            changes[name] = (data, int(item['mode'][-3:], 8))
    for required in ('nix/pins.toml','.github/actions/setup-nix/action.yml','.github/workflows/nix.yml','nix/util.nix'):
        if required not in changes:
            raise ValueError('Missing upstream input: ' + required)
    with tempfile.TemporaryDirectory(dir=root.parent) as tmp:
        staging = Path(tmp)
        for name,(data,mode) in changes.items():
            pending = staging/name
            pending.parent.mkdir(parents=True,exist_ok=True)
            pending.write_bytes(data)
            pending.chmod(mode)
            if not (root/name).resolve().is_relative_to(root):
                raise ValueError('Destination escapes project')
        # Retain each old file until every prepared replacement was installed.
        previous = staging/'previous'
        installed = []
        try:
            for name in changes:
                target = root/name
                target.parent.mkdir(parents=True,exist_ok=True)
                backup = previous/name
                if target.exists():
                    backup.parent.mkdir(parents=True,exist_ok=True)
                    os.replace(target, backup)
                try:
                    os.replace(staging/name, target)
                except BaseException:
                    if backup.exists():os.replace(backup, target)
                    raise
                installed.append(name)
        except BaseException:
            for name in reversed(installed):
                backup=previous/name
                target=root/name
                if backup.exists():os.replace(backup,target)
                else:target.unlink()
            raise
    print(commit['sha'])

if __name__ == '__main__':
    main()
