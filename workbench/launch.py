"""Run Quantum Kernel locally with libraries built from the repository."""
import argparse
import hashlib
from http.server import ThreadingHTTPServer
from pathlib import Path
import platform
import secrets
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
KERNEL = ROOT / "kernel"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True, help="Path to the built DLL or shared object")
    parser.add_argument("--performance-library", type=Path, help="Optional second library")
    parser.add_argument("--output", type=Path, required=True, help="Fresh directory outside the repository for results")
    parser.add_argument("--port", type=int, default=8134)
    args = parser.parse_args()

    output = args.output.resolve()
    if output.exists() or output.is_relative_to(ROOT):
        parser.error("--output must be a fresh directory outside the repository")
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    if sys.platform == "win32" and platform.machine().lower() in ("amd64", "x86_64"):
        local_platform = "windows"
    elif sys.platform.startswith("linux") and platform.machine().lower() in ("aarch64", "arm64"):
        local_platform = "arm"
    else:
        parser.error("The workbench runs on Windows x86-64 and Linux AArch64")

    sys.path.insert(0, str(KERNEL))
    from demo import server
    from unified_workbench.web import wrap

    choices = [("low-memory", args.library)]
    if args.performance_library:
        choices.append(("performance", args.performance_library))
    current = SimpleNamespace(token=secrets.token_urlsafe(32), libs={}, descriptors={})
    for profile, path in choices:
        path = path.resolve(strict=True)
        current.libs[profile] = server.bind(path)
        current.descriptors[profile] = {
            "workspace_bytes": 262144,
            "binary_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "execution_reason": path.name,
        }

    output.mkdir(parents=True, exist_ok=False)
    address = f"127.0.0.1:{args.port}"
    live = SimpleNamespace(providers={}, remote_rows={})
    routes = wrap(server.handler(current, address), current, live, None, KERNEL, ROOT,
                  output, address, local_platform=local_platform)
    with ThreadingHTTPServer(("127.0.0.1", args.port), routes) as httpd:
        print(f"Quantum Kernel: http://{address}/", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
