import json
import sys
import record_io

data = sys.stdin.buffer.read()
if sys.argv[1] == 'encode':
    output = record_io.dumps(json.loads(data)) + '\n'
elif sys.argv[1] == 'decode':
    if not data.lstrip().startswith(b'<record '):
        raise ValueError('Expected a typed XML history file')
    output = json.dumps(record_io.loads(data.decode('utf8')), ensure_ascii=True, allow_nan=False)
else:
    raise ValueError('Unknown history operation')
sys.stdout.buffer.write(output.encode('utf8'))
