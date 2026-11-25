"""Exact official board selection and display history. Read-only at runtime."""
from package_layout import bound

import csv
import hashlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROLES = {('stm32f407','low'):24, ('stm32f407','high'):32,
         ('ch32','low'):28, ('ch32','high'):80}
DISPLAY = {('stm32f407','low'):'compact', ('stm32f407','high'):'cached',
           ('ch32','low'):'low', ('ch32','high'):'high'}
TITLES = {'stm32f407':'STM32F407', 'ch32':'CH32V307'}
FIELDS = ('board','role','budget_kib','bin_sha256','build_id','cohort','scope',
          'parameter','operation','strategy','sample','cycles','clock_hz')
PARAMETERS = (512,768,1024,44,65,87)
INDEX = Path('03_复现环境与运行程序/软件演示程序/入口/history/代表板端.xml')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def resolve(root, value):
    if not value or Path(value).is_absolute():
        raise ValueError('代表档输入须使用相对路径')
    target=bound(root, value).resolve(strict=True)
    if not target.is_relative_to(root.resolve()):
        raise ValueError('代表档路径超出包目录')
    return target

def firmware(role, board, budget, ram, binary, identity):
    expected=ROLES[board,role]
    if int(budget)!=expected or not 0<int(ram)<=expected*1024:
        raise ValueError(f'{TITLES[board]} {role} 所选映像与 {expected} KiB 预算不符')
    if not re.fullmatch('[0-9a-f]{64}',binary or '') or not re.fullmatch('[0-9a-f]{'+('32' if board=='stm32f407' else '64')+'}',identity or ''):
        raise ValueError('代表固件的身份格式无效')

def load_index(package):
    package=Path(package);root=ET.parse(resolve(package,INDEX.as_posix())).getroot()
    if root.tag!='representative-boards' or root.get('version')!='1':
        raise ValueError('代表档索引格式无效')
    records={}
    for n in root.findall('deployment'):
        key=n.get('board'),n.get('role')
        if key in records or key not in ROLES:raise ValueError('代表档重复或未登记')
        if n.get('display_strategy',DISPLAY[key])!=DISPLAY[key]:raise ValueError('展示策略与预算不符')
        firmware(key[1],key[0],n.get('budget_kib'),n.get('ram'),n.get('bin_sha256'),n.get('build_id'))
        if digest(resolve(package,n.get('bin'))) != n.get('bin_sha256'):raise ValueError('实物固件未通过代表身份校验')
        if not n.get('cohort'):raise ValueError('缺少已选数据组')
        records[key]=n
    if set(records)!=set(ROLES):raise ValueError('双板代表档不完整')
    if len({n.get('bin_sha256') for n in records.values()})!=4:raise ValueError('代表固件存在重复身份')
    return records

def snapshot(package,board=None):
    idx=load_index(package);entries=[];allrows=[]
    for key in ROLES:
        if board and board!=key[0]:continue
        e=idx[key];item=dict(board=key[0],role=key[1],budget_kib=ROLES[key],strategy=DISPLAY[key],
                bin_sha256=e.get('bin_sha256'),build_id=e.get('build_id'),
                elf_sha256=e.get('elf_sha256'),ram=int(e.get('ram')),flash=int(e.get('flash')))
        entries.append(item)
        history=e.find('history')
        if history is None:raise ValueError('缺少代表档历史索引')
        src=resolve(Path(package),history.get('path'))
        if digest(src)!=history.get('sha256'):raise ValueError('历史样本文件摘要不符')
        with src.open(encoding='utf-8-sig',newline='') as stream:
            reader=csv.DictReader(stream,delimiter='\t')
            if not set(FIELDS)<=set(reader.fieldnames or ()):raise ValueError('代表档历史字段不全')
            seen=set()
            for row in reader:
                if (row['board'],row['role'],row['budget_kib'],row['bin_sha256'],row['build_id'],row['cohort'],row['scope']) != (
                     *key,str(ROLES[key]),e.get('bin_sha256'),e.get('build_id'),e.get('cohort'),'measurement'):
                    continue
                op=row['operation'];p=int(row['parameter']);cycles=int(row['cycles']);hz=int(row['clock_hz'])
                if p not in PARAMETERS or op not in (('keygen','encaps','decaps') if p>100 else ('keygen','sign','verify')) or cycles<=0 or hz<=0:
                    raise ValueError('入选样本的参数、操作或计时无效')
                allowed=('compact','cached') if key[0]=='stm32f407' else (key[1],)
                if not row['sample'] or row['strategy'] not in allowed:
                    raise ValueError('入选样本的编号或策略无效')
                test=p,op,row['strategy'],row['sample']
                if test in seen:raise ValueError('入选测量样本重复')
                seen.add(test)
                if row['strategy']!=DISPLAY[key]:continue
                allrows.append(dict(item,parameter=p,operation=op,strategy=row['strategy'],
                                           sample=row['sample'],cycles=cycles,clock_hz=hz))
            expected={(p,op,s) for p in PARAMETERS for op in (('keygen','encaps','decaps') if p>100 else ('keygen','sign','verify')) for s in (('compact','cached') if key[0]=='stm32f407' else (key[1],))}
            groups={(p,op,s) for p,op,s,sample in seen}
            if groups!=expected:raise ValueError('代表档独立计时未覆盖六参数和全部操作')
    from collections import defaultdict
    from statistics import median
    bins=defaultdict(list)
    for row in allrows:
        k=tuple(row[x] for x in ('board','role','budget_kib','bin_sha256','parameter','operation','strategy','clock_hz'))
        bins[k].append(row['cycles'])
    rows=[]
    for k,vals in bins.items():
        rows.append(dict(zip(('board','role','budget_kib','bin_sha256','parameter','operation','strategy','clock_hz'),k),
                         samples=len(vals),median_cycles=median(vals)))
    return {'deployments':entries,'rows':rows}

def export_timings(view):
    import io
    output=io.StringIO(newline='')
    fields=('board','role','budget_kib','strategy','bin_sha256','parameter','operation','samples','median_cycles','clock_hz')
    writer=csv.DictWriter(output,fieldnames=fields,delimiter='\t',lineterminator='\n')
    writer.writeheader()
    for row in view['rows']:writer.writerow({col:row[col] for col in fields})
    return output.getvalue().encode('utf-8-sig')

def catalog_rows(rows,entries):
    eligible={('ch32-finals-'+e['role'],e['elf_sha256']) for e in entries if e['board']=='ch32'}
    return [r for r in rows if r.get('platform_id')!='ch32' or (r.get('id'),r.get('binary_sha256')) in eligible]
