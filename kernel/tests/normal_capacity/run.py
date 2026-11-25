"""Fixed API recovery cases at the configuration's normal workspace capacity.

All inputs are locally generated test objects. Independent contexts are compared
between sequential and concurrent execution; raw secret bytes stay in memory.
"""
from pathlib import Path
import argparse, concurrent.futures, ctypes as C, hashlib, importlib.util
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
import record_io as json, os, platform, threading

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('public_abi', ROOT/'tests/platform/compare_public.py')
abi = importlib.util.module_from_spec(spec); spec.loader.exec_module(abi)
LEVELS = (512, 44, 768, 65, 1024, 87)

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

class Buffer:
    def __init__(self, n, initial=None, alignment=1):
        self.n = n
        self.raw = (abi.U*(n+64+alignment))()
        C.memset(self.raw, 0xa5, len(self.raw))
        self.offset = 32 + (-C.addressof(self.raw)-32) % alignment
        self.p = C.cast(C.byref(self.raw, self.offset), abi.P)
        if initial is not None:
            assert len(initial) == n
            C.memmove(self.p, initial, n)
    def read(self): return C.string_at(self.p, self.n)
    def fill(self, x): C.memset(self.p, x, self.n)
    def check(self):
        assert bytes(self.raw[:self.offset]) == b'\xa5'*self.offset
        tail = self.offset+self.n
        assert bytes(self.raw[tail:]) == b'\xa5'*(len(self.raw)-tail)

class Session:
    def __init__(self, lib, capacity, case):
        self.lib, self.capacity, self.case = lib, capacity, case
        self.workspace = Buffer(capacity, b'\0'*capacity, 32)
        self.context = abi.Context(); self.calls = 0; self.fail = False
        self.seed = b'normal-capacity-v1'+case.to_bytes(4,'little')
        self.records = []; self.digest = hashlib.sha256()
        @abi.RANDOM
        def entropy(user, out, n):
            self.calls += 1
            if self.fail:
                if n: out[0] = 0x7e
                return -1
            C.memmove(out, hashlib.shake_256(self.seed+self.calls.to_bytes(8,'little')).digest(n), n)
            return 0
        self.random = entropy
        self.initialize(capacity)
    def initialize(self, capacity):
        assert 32 <= capacity <= self.capacity
        self.workspace.fill(0)
        assert self.lib.lc_context_init(C.byref(self.context),self.workspace.p,capacity,self.random,None) == 0
    def check(self, objects):
        for x in [self.workspace, *objects]: x.check()
        assert self.context.arena_high_water <= self.context.workspace_bytes
        assert C.string_at(self.workspace.p, self.context.arena_high_water) == b'\0'*self.context.arena_high_water
    def parameter(self, level):
        sizes = abi.Sizes(); assert self.lib.lc_get_sizes(level,C.byref(sizes)) == 0
        pk,sk = Buffer(sizes.public_key),Buffer(sizes.secret_key)
        obj = Buffer(sizes.ciphertext or sizes.signature)
        ss,ss2 = Buffer(32),Buffer(32)
        n = (0,1,1024,4096)[self.case % 4]; dn = (0,1,32,255)[self.case % 4]
        msg = Buffer(n,hashlib.shake_256(self.seed+b'm').digest(n))
        dom = Buffer(dn,hashlib.shake_256(self.seed+b'd').digest(dn))
        objects = [pk,sk,obj,ss,ss2,msg,dom]
        def invoke(op):
            ctx = C.byref(self.context)
            if op == 0: return self.lib.lc_keypair(ctx,level,pk.p,pk.n,sk.p,sk.n)
            if sizes.ciphertext:
                if op == 1: return self.lib.lc_encaps(ctx,level,obj.p,obj.n,ss.p,32,pk.p,pk.n)
                return self.lib.lc_decaps(ctx,level,ss2.p,32,obj.p,obj.n,sk.p,sk.n)
            if op == 1: return self.lib.lc_sign(ctx,level,obj.p,obj.n,msg.p,n,dom.p,dn,sk.p,sk.n)
            return self.lib.lc_verify(ctx,level,obj.p,obj.n,msg.p,n,dom.p,dn,pk.p,pk.n)
        def outputs(op):
            if op == 0: return [pk,sk]
            if op == 1: return [obj,ss] if sizes.ciphertext else [obj]
            return [ss2] if sizes.ciphertext else []
        def sequence(label):
            peaks=[]
            for op in range(3):
                assert invoke(op) == 0,(level,label,op)
                self.check(objects);peaks.append(self.context.arena_high_water)
            if sizes.ciphertext: assert ss.read() == ss2.read()
            for x in [pk,sk,obj,ss if sizes.ciphertext else msg]: self.digest.update(x.read())
            self.records.append(dict(parameter=level,case=self.case,phase=label,status='PASS',workspace_bytes=self.capacity,peaks=peaks))
            return peaks
        peaks=sequence('normal')
        for op in range(3):
            # Both gross shortage and the preceding 32-byte capacity boundary.
            for short in sorted({32, max(32,((peaks[op]-1)//32)*32)}):
                assert short < peaks[op]
                self.initialize(short)
                for x in outputs(op): x.fill(0xa5)
                assert invoke(op) == -5,(level,op,short)
                assert all(x.read() == b'\0'*x.n for x in outputs(op))
                self.check(objects)
                self.records.append(dict(parameter=level,case=self.case,phase='workspace_shortage',operation=op,capacity_bytes=short,status=-5,outputs_zero=True))
                self.initialize(self.capacity)
                peaks=sequence('normal_after_workspace_shortage')
        for op in (0,1):
            self.fail=True
            for x in outputs(op): x.fill(0xa5)
            assert invoke(op) == -4,(level,op)
            self.fail=False
            assert all(x.read() == b'\0'*x.n for x in outputs(op))
            self.check(objects)
            self.records.append(dict(parameter=level,case=self.case,phase='entropy_failure',operation=op,status=-4,outputs_zero=True))
            sequence('normal_after_entropy_failure')
        # Ordinary functional negative result followed by a valid invocation.
        obj.p[0] ^= 1
        rc=invoke(2)
        if sizes.ciphertext:
            assert rc == 0 and ss2.read() != ss.read()
        else: assert rc == -6
        self.check(objects); obj.p[0] ^= 1
        assert invoke(2) == 0
        self.check(objects)
        self.records.append(dict(parameter=level,case=self.case,phase='invalid_object_then_valid',status='PASS',invalid_status=rc))
    def run(self, barrier=None):
        if barrier: barrier.wait(timeout=30)
        context_id=C.addressof(self.context); workspace_id=C.addressof(self.workspace.raw)
        for level in LEVELS: self.parameter(level)
        assert context_id == C.addressof(self.context) and workspace_id == C.addressof(self.workspace.raw)
        return dict(case=self.case,records=self.records,aggregate_sha256=self.digest.hexdigest(),random_requests=self.calls,context_and_workspace_stable=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',type=Path,required=True);p.add_argument('--capacity',type=int,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert 32 <= a.capacity <= 262144 and a.capacity % 32 == 0
    out=a.output.resolve();assert not out.exists()
    if os.name=='nt': assert out.drive.upper() == 'D:'
    lib=abi.library(a.library.resolve())
    sequential=[Session(lib,a.capacity,i).run() for i in range(4)]
    barrier=threading.Barrier(4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures=[pool.submit(Session(lib,a.capacity,i).run,barrier) for i in range(4)]
        parallel=[x.result() for x in futures]
    assert sequential == parallel
    result=dict(schema='lattice.normal_capacity.v1',status='PASS',library_sha256=sha(a.library),test_sha256=sha(__file__),
                loader_sha256=sha(ROOT/'tests/platform/compare_public.py'),workspace_bytes=a.capacity,
                parameters=list(LEVELS),independent_contexts=4,sequential_concurrent_exact_match=True,
                message_bytes=[0,1,1024,4096],domain_bytes=[0,1,32,255],platform=platform.platform(),
                total_records=sum(len(x['records']) for x in sequential+parallel),sequential=sequential,concurrent=parallel)
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('sequential','concurrent')}))
if __name__=='__main__':main()
