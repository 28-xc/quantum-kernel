from source_view import definitions
def put(p,s):p.parent.mkdir(exist_ok=True,parents=True);p.write_text(s,encoding='utf-8',newline='\n')
def read(p):return p.read_text(encoding='utf-8')
def later(s,a,b):
    if s.count(a)!=1:raise ValueError('unexpected source: '+a[:65])
    return s.replace(a,b)
