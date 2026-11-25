import re,csv
from toolchain import need,write
import toolchain as core
def compile_ir(src,dst):
    ir=dst/'lifecycle.ll'
    core.run([core.LLVM/'clang.exe',*core.ARM,'-fno-inline','-S','-emit-llvm',src,'-o',ir],dst)
    defs={}
    for match in re.finditer(r'^define [^\n]*?@([\w.$]+)\([^\n]*?\)[^\n]*\{\n(.*?)^\}',ir.read_text(encoding='utf-8'),re.M|re.S):
        name,body=match.groups()
        defs[name]=body
    need(defs,'missing IR functions')
    return defs

def verify_allocation_sites(body,allocator):
    blocks={'entry':[]};current='entry'
    for line in body.splitlines():
        m=re.match(r'^([\w.$-]+):',line)
        if m:
            current=m[1];blocks[current]=[]
        blocks[current].append(line)
    edges={k:set(re.findall(r'label %([\w.$-]+)','\n'.join(lines))) for k,lines in blocks.items()}
    for key,lines in blocks.items():
        if not any('@'+allocator+'(' in s for s in lines):continue
        visited=set();todo=list(edges[key])
        while todo:
            node=todo.pop()
            need(node!=key,('allocation in a cycle requires manual ownership proof',key))
            if node not in visited:
                visited.add(node);todo.extend(edges[node]-visited)

def derive(p,kind,src,dst):
    defs=compile_ir(src,dst)
    if p<100:
        alloc='lc_dsa_alloc';roots=[f'lcbase{p}_{s}' for s in ('keypair_internal','signature_internal','verify')]
    else:
        alloc='lc_arena_alloc';roots=[f'lc_base_mlk{p}_{s}' for s in ('keypair_derand','enc_derand','dec')]
    trace=[];memo={}
    def measure(fun,seen):
        if fun in memo:return memo[fun]
        need(fun not in seen,('recursive workspace graph',fun))
        body=defs[fun]
        calls=re.findall(r'\bcall\b[^\n@]*@([\w.$]+)\(',body)
        external={'lc_dsa_alloc','lc_dsa_free','lc_arena_alloc','lc_arena_free','memcpy','memset','ntt','invntt',
                  'pqcrystals_dilithium_ntt','pqcrystals_dilithium_invntt_tomont','pqcrystals_dilithium_asm_pointwise_montgomery'}
        for callee in calls:
            need(callee in defs or callee in external or callee.startswith('llvm.'),('unreviewed external function',fun,callee))
        for ln in body.splitlines():
            if 'call ' in ln and '@' not in ln:
                need(re.search(r'\basm(?: sideeffect)? "(|ldr [^"]+|pkhbt [^"]+|smladx? [^"]+)"',ln),('indirect call or unaudited assembly',fun,ln))
        verify_allocation_sites(body,alloc)
        sizes=[]
        for line in body.splitlines():
            if '@'+alloc+'(' in line:
                m=re.search(r'@'+alloc+r'\([^,]+, i32(?: [a-z_]+)* (\d+)\)',line)
                need(m,(fun,'dynamic allocation size',line));sizes.append(int(m[1]))
        children=[(callee,measure(callee,seen|{fun})) for callee in dict.fromkeys(calls) if callee in defs]
        own=sum((n+31)&~31 for n in sizes)
        if p>100:own+=32*len(sizes)
        child,total=max(children,key=lambda item:item[1],default=('',0))
        memo[fun]=own+total
        if own or total:trace.append(dict(function=fun,allocation_bytes=','.join(map(str,sizes)),own_aligned_cost=own,
            max_child=child if total else '',max_child_cost=total,total=own+total))
        return own+total
    sizes=[measure(fun,set()) for fun in roots]
    write(dst/'lifetimes.tsv',trace)
    print(p,kind,sizes,flush=True)
    return sizes
