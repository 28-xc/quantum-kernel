"""Read CPU capabilities through a separately hashed baseline-ISA helper."""
import ctypes as C
import sys
import platform
from publicschemas.cpu_features import FEATURES,AARCH64_FEATURES


def query(probe):
    machine=platform.machine().lower()
    architecture='aarch64' if sys.platform.startswith('linux') and machine in ('aarch64','arm64') else 'x86_64' if sys.platform=='win32' and machine in ('amd64','x86_64') and C.sizeof(C.c_void_p)==8 else 'unknown'
    result=dict(architecture=architecture,
                query_succeeded=False,features=[],xcr0=0)
    if architecture=='aarch64':
        try:
            fn=C.CDLL(None,use_errno=True).getauxval
            fn.argtypes=[C.c_ulong];fn.restype=C.c_ulong
            C.set_errno(0);capabilities=int(fn(16))  # AT_HWCAP
            if C.get_errno() or not capabilities:return result
            result.update(query_succeeded=True,features=sorted(name for name,bit in AARCH64_FEATURES.items() if capabilities&(1<<bit)))
        except (OSError,AttributeError):pass
        return result
    if probe is None or result['architecture']!='x86_64':return result
    try:lib=C.CDLL(str(probe));fn=lib.lc_host_query
    except (OSError,AttributeError):return result
    fn.argtypes=[C.POINTER(C.c_uint32),C.c_size_t];fn.restype=C.c_int
    words=(C.c_uint32*13)()
    if fn(words,13)!=0 or words[0]!=1:return result
    result.update(query_succeeded=True,features=sorted(k for k,(i,b) in FEATURES.items() if words[i]&(1<<b)),
                  xcr0=int(words[8]) | (int(words[9])<<32))
    return result
