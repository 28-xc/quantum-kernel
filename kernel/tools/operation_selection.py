"""Public operation requirements and exact generated dispatch restrictions."""
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

PARAMETERS = (512, 768, 1024, 44, 65, 87)

def names(parameter):
    return ('keypair', 'encaps', 'decaps') if parameter > 100 else ('keypair', 'sign', 'verify')

def normalize(value, parameters):
    if value is None:
        return None
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict) or set(value) != {str(p) for p in parameters}:
        raise ValueError('Operations must specify every required parameter exactly once')
    result = {}
    for p in parameters:
        ops = value[str(p)]
        if not isinstance(ops, list) or not ops or len(ops) != len(set(ops)) or not set(ops) <= set(names(p)):
            raise ValueError('Invalid, empty or duplicate operation requirement for '+str(p))
        result[str(p)] = [n for n in names(p) if n in ops]
    return result

def cells(value, parameters):
    return {(p, i) for p in parameters for i, n in enumerate(names(p))
            if value is None or n in value[str(p)]}

def body_span(text, name):
    import re
    m = re.search(r'\bint\s+'+re.escape(name)+r'\s*\([^;]*?\)\s*\{', text)
    if not m:
        raise ValueError('Missing operation definition '+name)
    start = m.end()-1
    depth = 1; at = start+1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}'); at += 1
    return start, at

def restrict_public(text, operations, parameters):
    if operations is None:
        return text
    for name in ('keypair', 'encaps', 'decaps', 'sign', 'verify'):
        allowed = [p for p in parameters if name in operations[str(p)]]
        begin, end = body_span(text, 'lc_'+name)
        # A retained parameter of the wrong algorithm remains an argument
        # error, as in the full API. An omitted parameter still reports the
        # parameter-pruning contract before inspecting argument buffers.
        family = '' if name == 'keypair' else ('p==512||p==768||p==1024' if name in ('encaps','decaps') else 'p==44||p==65||p==87')
        argument_guard = (' if(lc_pruned_supports(p)&&!('+family+'))return LC_E_ARGUMENT;\n') if family else ''
        if not allowed:
            text = text[:begin]+'{\n'+argument_guard+' return lc_standard_parameter(p)?LC_E_UNSUPPORTED:LC_E_ARGUMENT; }'+text[end:]
        else:
            guard = ' if(lc_standard_parameter(p)&&!('+ '||'.join('p=='+str(p) for p in allowed)+'))return LC_E_UNSUPPORTED;\n'
            text = text[:begin+1]+'\n'+argument_guard+guard+text[begin+1:]
    return text

def restrict_kem(text, operations, parameters):
    if operations is None or not any(p > 100 for p in parameters):
        return text
    begin, end = body_span(text, 'lc_mlk_call')
    calls = ['keypair_derand(out1,out2,in1,arena)', 'enc_derand(out1,out2,in1,in2,arena)', 'dec(out1,in1,in2,arena)']
    body = ['{ switch(level) {']
    for p in parameters:
        if p < 100:
            continue
        body.append('case '+str(p)+': switch(op) {')
        for op, name in enumerate(names(p)):
            if name in operations[str(p)]:
                body.append('case '+str(op)+': return lc_base_mlk'+str(p)+'_'+calls[op]+';')
        body.append('} break;')
    body.append('} return -8; }')
    return text[:begin]+'\n'.join(body)+text[end:]

def restrict_adapter(text, operations, parameters):
    if operations is None:
        return text
    functions = {'keypair_internal':'keypair', 'signature_internal':'sign', 'verify_internal':'verify',
                 'keypair':'keypair', 'signature':'sign', 'verify':'verify'}
    import re
    # Replace each concrete macro invocation, not the macro definition itself.
    for call, operation in functions.items():
        pattern = r'DISPATCH\('+call+r',([^;]+)\);'
        def replace(match):
            args = match.group(1)
            choices = ['case '+str(p)+': ret=lcbase'+str(p)+'_'+call+'('+args+',&a); break;'
                       for p in parameters if p < 100 and operation in operations[str(p)]]
            return 'switch(l) { '+' '.join(choices)+' default: ret=-8; }'
        text = re.sub(pattern, replace, text)
    if re.search(r'^\s*DISPATCH\(', text, re.M):
        raise ValueError('Unmapped DSA dispatch operation')
    return text
