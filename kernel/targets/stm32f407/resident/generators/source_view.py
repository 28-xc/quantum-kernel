import re
def definitions(src):
    """Match complete top-level function bodies in already-preprocessed C."""
    names={};level=0;start=0;in_body=None
    token=re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]')
    for m in token.finditer(src):
        t=m[0]
        if t=='{':
            if level==0:
                pre=src[start:m.start()].strip()
                clean=re.sub(r'__attribute__\s*\(\([^;{}]{0,400}?\)\)','',pre)
                n=re.search(r'([A-Za-z_]\w*)\s*\((?!.*\)\s*=\s*)[^{};]*\)\s*$',clean,flags=re.S)
                in_body=(n[1],start,m.start()) if n and '=' not in clean.split('(')[0] else None
            level+=1
        elif t=='}':
            level-=1
            if level==0:
                if in_body:
                    n,a,z=in_body;names[n]=(a,z,m.end())
                in_body=None;start=m.end()
        elif t==';' and level==0:start=m.end()
    return names
