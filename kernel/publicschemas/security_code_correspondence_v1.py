"""Independently decode the shipped PE images and check code/data correspondence."""
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
import argparse, hashlib, importlib.util, record_io as json, re, struct, subprocess, sys
sys.dont_write_bytecode=True
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def require(ok,msg):
    if not ok:raise ValueError(msg)
def pe(raw):
    h=struct.unpack_from('<I',raw,60)[0];require(raw[h:h+4]==b'PE\0\0','PE identity');o=h+24;ib=struct.unpack_from('<Q',raw,o+24)[0]
    n=struct.unpack_from('<H',raw,h+6)[0];s=o+struct.unpack_from('<H',raw,h+20)[0];sections=[struct.unpack_from('<IIII',raw,s+40*i+8)for i in range(n)]
    def at(rva,size):
        for vs,sa,rs,off in sections:
            if sa<=rva and rva+size<=sa+rs:return raw[off+rva-sa:off+rva-sa+size]
        raise ValueError('Unbacked address')
    def cstr(rva):
        out=bytearray()
        while len(out)<1024:
            b=at(rva+len(out),1)
            if b==b'\0':return out.decode('ascii')
            out.extend(b)
        raise ValueError('Unterminated import string')
    imports={};imp_rva,imp_size=struct.unpack_from('<II',raw,o+120)
    if imp_rva:
        off=0
        while off<imp_size:
            ilt,ts,forwarder,name,iat=struct.unpack('<IIIII',at(imp_rva+off,20))
            if not any((ilt,ts,forwarder,name,iat)):break
            source=ilt or iat;index=0
            while True:
                value=struct.unpack('<Q',at(source+index*8,8))[0]
                if value==0:break
                imports[iat+index*8]=('#'+str(value&0xffff))if value>>63 else cstr(value+2);index+=1
            off+=20
    return ib,at,imports
def verify(root,objdump):
    root=Path(root);m=read(root/'correspondence.xml');require(m['schema']=='lattice.code_correspondence.v1','Schema')
    model_path=root/'deployment_image.py';require(sha(model_path.read_bytes())==m['deployment_model_sha256'],'Model identity')
    spec=importlib.util.spec_from_file_location('correspondence_deployment',model_path);model=importlib.util.module_from_spec(spec);spec.loader.exec_module(model)
    decoded={};objects={};counts={};phase={}
    for label,im in m['images'].items():
        image=root/im['path'];model.load_deployment_image(image,root/im['derivation_path'],im['derivation_sha256'],measured_sha256=im['measured_image_sha256'],binary_sha256=im['deployment_image_sha256'])
        raw=image.read_bytes();base,at,pe_imports=pe(raw);functions=im['functions'];exact={f['rva']:name for name,f in functions.items()}
        constants=im['objects'];imports=im['imports'];callseen=set();references=set();graph={name:set()for name in functions}
        require(set(im['root_functions'])<=set(functions),'Missing public root')
        for item in imports:require(pe_imports.get(item['rva'])==item['symbol'].removeprefix('__imp_'),'Import-table identity')
        for ob in constants:require(sha(at(ob['rva'],ob['bytes']))==ob['sha256'],'Read-only object: '+label+'/'+ob['symbol'])
        objects[label]={o['symbol']:(o['bytes'],o['sha256'])for o in constants}
        def role(rva,fn):
            if fn['rva']<=rva<fn['rva']+fn['bytes']:return 'SELF+'+hex(rva-fn['rva'])
            if rva in exact:callseen.add(exact[rva]);graph[name].add(exact[rva]);return 'FUNCTION:'+exact[rva]
            for ob in constants:
                if ob['rva']<=rva<ob['rva']+ob['bytes']:references.add(ob['symbol']);return 'OBJECT:'+ob['symbol']+'+'+hex(rva-ob['rva'])
            for ob in imports:
                if rva==ob['rva']:return 'IMPORT:'+ob['symbol']
            raise ValueError('Unresolved instruction target '+label+'/'+hex(rva))
        cmd=[str(objdump),'-d','--insn-width=16',str(image)];r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='strict');require(r.returncode==0,'Disassembler failed')
        instructions={}
        for line in r.stdout.splitlines():
            a=re.match(r'^\s*([0-9a-f]+):\s*\t([0-9a-f ]+)\t?(.*)$',line)
            if a:instructions[int(a[1],16)-base]=(bytes.fromhex(a[2]),a[3].strip())
        norm={}
        for name,fn in functions.items():
            require(sha(at(fn['rva'],fn['bytes']))==fn['machine_sha256'],'Function bytes: '+label+'/'+name)
            off=fn['rva'];end=off+fn['bytes'];lines=[];body=b''
            while off<end:
                require(off in instructions,'Instruction gap');blob,op=instructions[off];require(blob and off+len(blob)<=end,'Instruction boundary');body+=blob
                if '%rip' in op:
                    a=re.search(r'#\s*([0-9a-f]+)',op);require(a is not None,'Unresolved RIP operand')
                    target=role(int(a[1],16)-base,fn)
                    if re.search(r'\b(call|jmp)\s+\*',op):require(target.startswith('IMPORT:'),'Unresolved indirect transfer')
                    op=re.sub(r'-?0x[0-9a-f]+\(%rip\)','RIP_TARGET',op.split('#')[0].rstrip())+' # '+target
                else:
                    require(not re.search(r'\b(call|jmp)\s+\*',op),'Unresolved register-indirect transfer')
                    def replace(a):return a[1]+' '+role(int(a[2],16)-base,fn)
                    op=re.sub(r'\b(call|j[a-z]+)\s+([0-9a-f]+)(?:\s+<[^>]+>)?',replace,op)
                lines.append(op);off+=len(blob)
            require(body==at(fn['rva'],fn['bytes']),'Decoded byte identity');norm[name]=sha('\n'.join(lines).encode())
        visited=set();pending=list(im['root_functions'])
        while pending:
            item=pending.pop()
            if item in visited:continue
            visited.add(item);pending.extend(graph[item]-visited)
        require(visited==set(im['full_operation_reachable_functions']),'Rooted transitive closure differs')
        if label.startswith('pipeline'):
            phase_reached=set();pending=['lc_kem_hj_prefix']
            while pending:
                item=pending.pop()
                if item in phase_reached:continue
                phase_reached.add(item);pending.extend(graph[item]-phase_reached)
            require(phase_reached==set(m['phase_function_names']),'Phase rooted closure differs')
        decoded[label]=norm;counts[label]=dict(functions=len(norm),rooted_reachable_functions=len(visited),objects=len(constants),resolved_direct_targets=len(callseen),referenced_objects=len(references))
        phase[label]={k:v for k,v in norm.items()if k in m['phase_function_names']}
    changed={}
    for kind in ('compact','pipeline'):
        old,new=decoded[kind+'-reference'],decoded[kind+'-current'];require(set(old)==set(new),'Function-name closure')
        differences=sorted(k for k in old if old[k]!=new[k]);require(differences==m['expected_changes'][kind],'Unexpected changed instruction body')
        require(objects[kind+'-reference']==objects[kind+'-current'],'Referenced read-only objects changed');changed[kind]=differences
    require(phase['pipeline-reference']==phase['pipeline-current']and len(phase['pipeline-current'])==5,'Phase closure correspondence')
    return dict(schema='lattice.code_correspondence_verification.v1',status='VERIFIED',correspondence_sha256=sha((root/'correspondence.xml').read_bytes()),objdump_sha256=sha(Path(objdump).read_bytes()),counts=counts,changed_functions=changed,phase_normalized_functions_equal=True,phase_function_count=5,statistics_binding='Each statistical dataset retains its measured image digest; this check compares machine bodies and referenced read-only bytes.')
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data',type=Path,required=True);p.add_argument('--objdump',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();require(not a.output.exists(),'Use a new output file');r=verify(a.data,a.objdump);a.output.write_text(json.dumps(r,indent=2,ensure_ascii=False)+'\n',encoding='utf-8');print(json.dumps(r))
if __name__=='__main__':main()
