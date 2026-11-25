"""Typed XML records. JSON is accepted only as an in-memory legacy wire input.

Files written by dump/dumps contain XML. Order, null, booleans, arbitrary-size
integers and decimal numeric spelling survive round trips. This module uses
only the standard library and is shared by the build and demonstration tools.
"""
from pathlib import Path
from decimal import Decimal
import base64
import json as _wire_json
import math
import re
import xml.etree.ElementTree as ET

JSONDecodeError = _wire_json.JSONDecodeError
_BAD_XML = re.compile(r'[\x00-\x08\x0b\x0c\x0d\x0e-\x1f\ud800-\udfff\ufffe\uffff]')

def _text(node, value):
    if _BAD_XML.search(value):
        node.set('encoding', 'base64-utf8-surrogatepass')
        node.text = base64.b64encode(value.encode('utf-8', 'surrogatepass')).decode('ascii')
    else:
        node.text = value
    return node

def _encode(value, allow_nan=False):
    if value is None: return ET.Element('null')
    if isinstance(value, bool):
        n=ET.Element('boolean'); n.text='true' if value else 'false'; return n
    if isinstance(value, int):
        n=ET.Element('integer'); n.text=str(value); return n
    if isinstance(value, (float, Decimal)):
        if not allow_nan and not math.isfinite(value): raise ValueError('Nonfinite record number')
        n=ET.Element('number'); n.text=str(value) if isinstance(value, Decimal) else repr(value); return n
    if isinstance(value, str): return _text(ET.Element('string'),value)
    if isinstance(value, (list,tuple)):
        n=ET.Element('list')
        for v in value: n.append(_encode(v,allow_nan))
        return n
    if isinstance(value, dict):
        n=ET.Element('object')
        for k,v in value.items():
            if not isinstance(k,str):
                if k is None:k='null'
                elif isinstance(k,bool):k='true' if k else 'false'
                elif isinstance(k,(int,float)):k=str(k)
                else:raise TypeError('Record object keys must be strings')
            e=ET.SubElement(n,'field');e.append(_text(ET.Element('name'),k));e.append(_encode(v,allow_nan))
        return n
    raise TypeError('Unsupported record value: '+type(value).__name__)

def _string(node):
    value=node.text or ''
    if node.get('encoding')=='base64-utf8-surrogatepass':
        return base64.b64decode(value,validate=True).decode('utf-8','surrogatepass')
    if node.get('encoding'):raise ValueError('Unknown XML text encoding')
    return value

def _decode(node, object_hook=None, object_pairs_hook=None, parse_float=float, parse_int=int):
    tag=node.tag
    if tag=='null':return None
    if tag=='boolean':
        if node.text not in ('true','false'):raise ValueError('Invalid boolean')
        return node.text=='true'
    if tag=='integer':return parse_int(node.text)
    if tag=='number':return parse_float(node.text)
    if tag=='string':return _string(node)
    def decode(n):return _decode(n,object_hook,object_pairs_hook,parse_float,parse_int)
    if tag=='list':return [decode(n) for n in node]
    if tag=='object':
        rows=[];seen=set()
        for f in node:
            if f.tag!='field' or len(f)!=2 or f[0].tag!='name':raise ValueError('Invalid object field')
            k=_string(f[0])
            if k in seen:raise ValueError('Duplicate XML field: '+k)
            seen.add(k);rows.append((k,decode(f[1])))
        if object_pairs_hook:return object_pairs_hook(rows)
        value=dict(rows)
        return object_hook(value) if object_hook else value
    raise ValueError('Unknown typed XML element: '+tag)

def dumps(value, *, ensure_ascii=False, indent=None, allow_nan=False, sort_keys=False,
          separators=None, default=None, **kwargs):
    # Field order is data. sort_keys is retained only for callers hashing a
    # canonical object; presentation callers leave it false.
    if sort_keys:
        def ordered(v):
            if isinstance(v,dict):return {k:ordered(v[k]) for k in sorted(v)}
            if isinstance(v,(list,tuple)):return [ordered(x) for x in v]
            return v
        value=ordered(value)
    if default:
        def convert(v):
            if isinstance(v,dict):return {k:convert(x) for k,x in v.items()}
            if isinstance(v,(list,tuple)):return [convert(x) for x in v]
            if v is None or isinstance(v,(str,int,float,Decimal,bool)):return v
            return convert(default(v))
        value=convert(value)
    root=ET.Element('record',{'format':'typed-xml-v1'});root.append(_encode(value,allow_nan))
    # Compact XML also supports captured process output without line splitting.
    return ET.tostring(root,encoding='unicode',short_empty_elements=True)

def loads(blob, *, object_hook=None, object_pairs_hook=None, parse_float=float,
          parse_int=int, parse_constant=None, **kwargs):
    if isinstance(blob,(bytes,bytearray)):blob=bytes(blob).decode('utf-8-sig')
    clean=blob.lstrip('\ufeff \t\r\n')
    if not clean.startswith('<'):
        return _wire_json.loads(blob,object_hook=object_hook,object_pairs_hook=object_pairs_hook,
                                parse_float=parse_float,parse_int=parse_int,parse_constant=parse_constant,**kwargs)
    if '<!DOCTYPE' in clean.upper() or '<!ENTITY' in clean.upper():raise ValueError('XML entities are not supported')
    root=ET.fromstring(clean)
    if root.tag!='record' or root.get('format')!='typed-xml-v1' or len(root)!=1:
        raise ValueError('Unsupported record format')
    return _decode(root[0],object_hook,object_pairs_hook,parse_float,parse_int)

def dump(value, stream, **kwargs):stream.write(dumps(value,**kwargs))
def load(stream, **kwargs):return loads(stream.read(),**kwargs)
def read(path, **kwargs):return loads(Path(path).read_bytes(),**kwargs)
def write(path,value,**kwargs):Path(path).write_text(dumps(value,**kwargs)+'\n',encoding='utf-8')

def read_records(path, **kwargs):
    value=read(path,**kwargs)
    if not isinstance(value,list):raise ValueError('Record sequence must contain a list')
    return iter(value)

def write_records(path, values, **kwargs):write(path,list(values),**kwargs)

def append_record(path,value,**kwargs):
    """Append by replacing one valid XML document; no concatenated roots."""
    path=Path(path)
    existing=list(read_records(path)) if path.exists() else []
    existing.append(value)
    temporary=path.with_name(path.name+'.tmp')
    write_records(temporary,existing,**kwargs)
    temporary.replace(path)

class RecordWriter:
    """A journal writer that always flushes one complete XML list document."""
    def __init__(self,path,append=False):
        self.path=Path(path)
        self.values=list(read_records(path)) if append and self.path.exists() else []
        self.flush()
    def write(self,text):
        if text.strip():self.values.append(loads(text))
        return len(text)
    def flush(self):
        temporary=self.path.with_name(self.path.name+'.tmp')
        write_records(temporary,self.values);temporary.replace(self.path)
    def close(self):self.flush()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()

def record_stream(path,append=False):return RecordWriter(path,append)

def capture_text(text):
    """Persist structured subprocess output as XML; retain ordinary diagnostics."""
    if isinstance(text,bytes):text=text.decode('utf-8')
    clean=text.strip()
    if not clean or clean.startswith('<'):return text
    try:
        value=_wire_json.loads(clean,parse_float=Decimal)
    except (ValueError,TypeError):
        rows=[];found=False;all_records=True
        for index,line in enumerate(text.splitlines(keepends=True),1):
            content=line.rstrip('\r\n');ending=line[len(content):]
            try:
                record=_wire_json.loads(content,parse_float=Decimal)
                rows.append(dict(line=index,kind='record',value=record,ending=ending));found=True
            except (ValueError,TypeError):
                rows.append(dict(line=index,kind='text',text=content,ending=ending));all_records=False
        if not found:return text
        value=[row['value'] for row in rows] if all_records else rows
    return dumps(value)+'\n'

def capture_bytes(blob):
    try:return capture_text(blob.decode('utf-8')).encode('utf-8')
    except UnicodeError:return blob


def record_lines(text):
    """Keep existing per-record validation; ordinary text keeps its lines."""
    if text.lstrip().startswith('<record'):
        value=loads(text,parse_float=Decimal)
        if isinstance(value,list):
            if value and all(isinstance(x,dict) and {'line','kind','ending'}<=set(x) and x['kind'] in ('text','record') for x in value):
                return [dumps(x['value']) if x['kind']=='record' else x['text'] for x in value]
            return [dumps(x) for x in value]
    return text.splitlines()

def write_sequence_item(stream,value):
    """Persist a journal as one complete XML list, including after flush."""
    if isinstance(stream,RecordWriter):
        stream.write(dumps(value));stream.flush();return
    rows=getattr(stream,'_typed_record_rows',None)
    if rows is None:
        rows=[];stream._typed_record_rows=rows
    rows.append(value)
    stream.seek(0);stream.write(dumps(rows)+'\n');stream.truncate();stream.flush()
