"""Resource objects shown by the UI and returned unchanged in its exports."""
import ctypes
import datetime
import os
import sys
from pathlib import Path


def host_snapshot():
    record = dict(object='demo_service_process', label='演示服务进程',
                  pid=os.getpid(), utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  measured=False, current_resident_bytes=None,
                  includes=['Python interpreter', 'loaded libraries', 'service data'],
                  excludes=['browser processes', 'compiler child processes'],
                  relation_to_core='process measurement; not an additive core component')
    try:
        if sys.platform == 'win32':
            class Counters(ctypes.Structure):
                _fields_ = [('cb', ctypes.c_ulong), ('PageFaultCount', ctypes.c_ulong)] + [
                    (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
                    'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
                    'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage')]
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            psapi = ctypes.WinDLL('psapi', use_last_error=True)
            kernel.GetCurrentProcess.restype = ctypes.c_void_p
            psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
            psapi.GetProcessMemoryInfo.restype = ctypes.c_int
            counters = Counters(); counters.cb = ctypes.sizeof(counters)
            if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
                raise ctypes.WinError(ctypes.get_last_error())
            size = counters.WorkingSetSize
            method = 'GetProcessMemoryInfo.WorkingSetSize'
        else:
            values = Path('/proc/self/statm').read_text().split()
            size = int(values[1]) * os.sysconf('SC_PAGE_SIZE')
            method = '/proc/self/statm resident pages × page size'
        if size <= 0:
            raise ValueError('Resident size must be positive')
        record.update(measured=True, current_resident_bytes=size, method=method)
    except (OSError, ValueError, IndexError) as error:
        record['measurement_error'] = str(error)
    return record


def resource_objects(points, libraries=()):
    interfaces = {item.get('measured_binary_sha256',item['binary_sha256']): item for item in libraries}
    def core_point(point):
        result = dict(platform=point['platform'], binary_sha256=point['binary_sha256'],
                      ram_bytes=point['core_reserved_bytes'], program_bytes=point['program_bytes'],
                      components=point['reserved_components'])
        interface = interfaces.get(point['binary_sha256'])
        if interface is not None:
            parameters = list(interface['parameters'])
            result['parameters'] = parameters
            result['operations'] = {str(p): (['keypair', 'encaps', 'decaps'] if p > 100 else
                                             ['keypair', 'sign', 'verify']) for p in parameters}
            result['operation_count'] = sum(map(len, result['operations'].values()))
        return result
    return dict(schema='lattice.resource_objects.v1',
        core=dict(object='cryptographic_core', label='密码核心',
                  memory_scope='workspace + stack + context + writable globals + external heap',
                  program_scope='allocated non-debug core image sections',
                  points=[core_point(p) for p in points]),
        exported_program=dict(object='exported_verifier', label='导出验证程序',
                  memory_scope='actual linked verifier writable sections; bare-metal also charges read-only RAM',
                  included_objects=['core', 'input/output objects', 'context', 'workspace', 'reserved call stack'],
                  evidence='Each completed build returns its actual image and section accounting.'),
        host=host_snapshot())


def verifier_resources(resources):
    accounting = resources['accounting']
    result = dict(object='exported_verifier', label='导出验证程序',
                  program_bytes=resources['program_bytes'], ram_bytes=resources['ram_bytes'],
                  accounting=accounting)
    # These are subsets of the already charged writable sections, never added again.
    if accounting.get('components_already_in_writable_sections'):
        stack = accounting['call_stack_reservation_bytes']
        workspace = accounting['workspace_bytes']
        remainder = resources['ram_bytes'] - stack - workspace
        if remainder < 0:
            raise ValueError('Verifier section accounting is inconsistent')
        result['included_components'] = dict(call_stack_reserved_bytes=stack,
            workspace_reserved_bytes=workspace, other_writable_bytes=remainder)
    return result
