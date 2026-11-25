"""Identify a distributed six-parameter image from HELLO, or a read-only ROM prefix."""
from pathlib import Path
import hashlib,struct,xml.etree.ElementTree as ET
from . import resident_dfu
from . import unified_engine as unified
def manifests(folder):
    default=Path(folder)/'stm32f407-unified.xml'
    if not default.is_file():return []
    rows=[];index=default.parent/'部署索引.xml'
    if not index.is_file():raise unified.EngineError('image_invalid','missing deployment catalogue')
    root=ET.parse(index).getroot()
    items=root.findall('deployment')
    budgets={'low':24576,'high':32768}
    if root.get('default')!='high' or len(items)!=2 or {r.get('role') for r in items}!=set(budgets):
        raise unified.EngineError('image_invalid','expected two representative deployments')
    tags=set();hashes=set()
    for row in items:
        role=row.get('role');target=(default.parent/row.get('manifest')).resolve(strict=True)
        if not target.is_relative_to(default.parent.resolve()):raise unified.EngineError('image_invalid','deployment path')
        info,cells=unified.read_manifest(target)
        if (int(info['ram_budget_bytes'])!=budgets[role] or int(row.get('budget'))!=budgets[role]
            or info['sha256']!=row.get('sha256') or info['tag']!=row.get('tag') or len(cells)!=12
            or (target==default.resolve())!=(role=='high') or info['tag'] in tags or info['sha256'] in hashes):
            raise unified.EngineError('image_invalid','deployment identity')
        tags.add(info['tag']);hashes.add(info['sha256']);rows.append(target)
    return rows
def select_cdc(folder,identity):
    choices=[p for p in manifests(folder) if ET.parse(p).getroot().get('tag')==identity.get('build_tag')]
    if len(choices)!=1:raise unified.EngineError('identity','unregistered or ambiguous installed application')
    return choices[0]
def select_rom(folder,serial):
    paths=manifests(folder)
    if not paths:return None
    if len(paths)==1:return paths[0] if resident_dfu.check_installed(paths[0],serial) else None
    data={path:path.with_suffix('.bin').read_bytes() for path in paths}
    # Choose only bytes that distinguish these actual binaries. Complete readback still
    # precedes ROM GO, and a second SHA-256 executes on the CPU after enumeration.
    step=32;shortest=min(map(len,data.values()));offsets=[0]
    while True:
        keys={p:tuple(blob[i:i+step] for i in offsets) for p,blob in data.items()}
        groups={}
        for p,key in keys.items():groups.setdefault(key,[]).append(p)
        group=next((members for members in groups.values() if len(members)>1),None)
        if group is None:break
        offset=next((i for i in range(step,shortest-step,step) if i not in offsets and len({data[p][i:i+step] for p in group})>1),None)
        if offset is None:raise unified.EngineError('image_invalid','cannot distinguish resident images')
        offsets.append(offset)
    base=resident_dfu.BASE
    def inspect(dev):
        key=tuple(resident_dfu._read(dev,base+i,step,base+shortest) for i in offsets)
        found=[p for p,k in keys.items() if k==key]
        return found[0] if len(found)==1 else None
    return resident_dfu._session(serial,inspect)
