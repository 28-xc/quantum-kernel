"""One bounded JSON stdin request to the existing functional Application.

Deploy and invoke through the owning operator's authenticated SSH connection.
This program neither starts SSH nor opens a serial port.
"""
from pathlib import Path
import argparse
import platform
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo import platform_protocol as wire


def acvp_runner(application):
    package = ROOT.parents[1]
    entry = package/'03_复现环境与运行程序/软件演示程序/入口'
    if not (entry/'unified_workbench/vectors.py').is_file():
        return None
    sys.path.insert(0,str(entry))
    from unified_workbench import vectors
    def run(payload):
        name=payload['library']
        descriptor=application.descriptors[name]
        return vectors.execute_acvp(application.libs[name],descriptor['workspace_bytes'],ROOT,package,
                                    payload['cases'],descriptor['binary_sha256'])
    return run


def performance_runner(application):
    entry = ROOT.parents[1]/'03_复现环境与运行程序/软件演示程序/入口'
    if not (entry/'unified_workbench/crypto.py').is_file():
        return None
    sys.path.insert(0,str(entry))
    from unified_workbench import crypto

    def run(payload):
        library = payload['library']
        descriptor = application.descriptors[library]
        parameter = payload['parameter']
        wire.require(parameter in descriptor['parameters'], 'Unsupported performance parameter')
        row = crypto.measure_operation(application.libs[library], descriptor['workspace_bytes'],
                                       library, parameter, payload['operation'])
        return dict(payload, binary_sha256=descriptor['binary_sha256'],
                    duration_ns=round(row['duration_ms'] * 1_000_000),
                    return_code=row['return_code'], verified=row['verified'],
                    workspace_bytes=descriptor['workspace_bytes'],
                    workspace_used_bytes=row['workspace_used_bytes'], inputs=row['inputs'],
                    public_outputs=row['public_outputs'])
    return run


def security_runner(application):
    entry = ROOT.parents[1]/'03_复现环境与运行程序/软件演示程序/入口'
    if not (entry/'unified_workbench/crypto.py').is_file():
        return None
    sys.path.insert(0, str(entry))
    from unified_workbench import crypto

    def run(payload):
        library, parameter, case = (payload[key] for key in ('library', 'parameter', 'case'))
        descriptor = application.descriptors[library]
        wire.require(parameter in descriptor['parameters'], 'Unsupported security parameter')
        result = crypto.security(application.libs[library], descriptor['workspace_bytes'], library, parameter, case)
        recovery = result.get('recovered')
        return dict(payload, binary_sha256=descriptor['binary_sha256'], return_code=result.get('return_code'),
                    verified=result['verified'], failure_output_zero=result.get('checks', {}).get('failure_output_zero'),
                    recovered=recovery['verified'] if recovery else None,
                    **{key: result[key] for key in ('security_input', 'original_return_code',
                        'recovery_return_code', 'function') if key in result})
    return run


def arithmetic_runner():
    package = ROOT.parents[1]
    entry = package/'03_复现环境与运行程序/软件演示程序/入口'
    if not (entry/'unified_workbench/arithmetic/native_arithmetic_aarch64.so').is_file():
        return None
    sys.path.insert(0,str(entry))
    from unified_workbench import arithmetic
    dll,digest = arithmetic.linux_adapter()
    bindings,binding_digest=arithmetic.linux_primitives()
    def run(payload):
        if 'binding' in payload:
            packet=wire.binary_field(payload['binding'],wire.PRIMITIVE_INPUT.size)
            status,output,elapsed=arithmetic.call_primitive(bindings,packet)
            return dict(status=status,duration_ns=elapsed,binary_sha256=binding_digest,
                        output=wire.b64encode(output).decode('ascii'))
        operation,q = payload['operation'],payload['modulus']
        values = wire.decode_polynomials(payload['coefficients'],256 if operation in wire.UNARY else 512,q)
        status,output,elapsed = arithmetic.native_polynomial(dll,operation,q,values[:256],values[256:])
        return dict(status=status,duration_ns=elapsed,binary_sha256=digest,
                    coefficients=wire.encode_polynomials(output))
    return digest,run,binding_digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--platform', choices=['arm'], required=True)
    args = parser.parse_args()
    wire.require(sys.platform.startswith('linux') and platform.machine().lower() in ('aarch64', 'arm64'),
                 'ARM live runner requires the actual Linux AArch64 host')
    # Transport closes stdin after the one request. Reject trailing or duplicate JSON.
    payload = wire.request(wire.decode(sys.stdin.buffer.read(wire.MAX_REQUEST + 1), wire.MAX_REQUEST))
    from demo.server import Application, read
    from publicschemas.demo import validate_config
    config = validate_config(read(args.config))
    for name in ('datasets', 'scientific_views', 'pooled_views', 'timing_views', 'resource_limit_views',
                 'process_footprint_views', 'application_views', 'application_latency_views', 'primitive_views',
                 'mean_tail_views', 'equal_frequency_views', 'application_owner_views', 'instruction_views',
                 'verification_record_views', 'qualification_views','upgrade_views'):
        wire.require(not config.get(name), 'Use a functional-only remote configuration; archived statistics remain in the UI')
    application = Application(args.config)
    wire.require(application.host['architecture'] == 'aarch64' and application.libs, 'No actual executable ARM library')
    runner = wire.FunctionalRunner(application, args.platform, secrets.token_hex(16),
                                   acvp_runner(application), arithmetic_runner(),
                                   performance_runner(application), security_runner(application))
    sys.stdout.buffer.write(wire.encode(runner.dispatch(payload), wire.MAX_RESPONSE))
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
