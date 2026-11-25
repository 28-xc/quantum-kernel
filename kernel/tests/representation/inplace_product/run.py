#!/usr/bin/env python3
"""Build and execute the production-header component tests; Python stdlib only."""
import argparse
import datetime
import hashlib
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
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def invoke(command, env, cwd):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                            text=True, encoding="utf-8", errors="replace")
    return {"command": [str(x) for x in command], "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--header-root", type=Path,
                        help="Optional overlay containing production headers")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default=shutil.which("gcc") or "gcc")
    parser.add_argument("--backend", choices=("avx2", "neon"),
                        default="neon" if platform.machine().lower() in ("aarch64", "arm64") else "avx2")
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() and (output / "result.xml").exists():
        parser.error("Choose a new output directory; existing evidence is preserved.")
    output.mkdir(parents=True, exist_ok=True)
    temp = output / "tmp"
    temp.mkdir(exist_ok=True)
    env = dict(os.environ, TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp), PYTHONDONTWRITEBYTECODE="1")
    cc = str(Path(shutil.which(args.cc) or args.cc).resolve())
    test = Path(__file__).with_name("test_inplace_product.c").resolve()
    include_dirs = [args.source_root.resolve() / "src" / "dsa_packed"]
    if args.header_root:
        include_dirs.insert(0, args.header_root.resolve())
    names = ["lc_a_planes24.h"] + (["lc_inplace_ay.h", "lc_stream4_vector.h"]
            if args.backend == "avx2" else ["lc_speed32_neon.h", "lc_stream_neon.h"])
    headers = []
    for name in names:
        path = next((root / name for root in include_dirs if (root / name).is_file()), None)
        if path is None:
            parser.error("Missing actual production header: " + name)
        headers.append({"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size})
    compiler_version = invoke([cc, "--version"], env, output)
    compiler_target = invoke([cc, "-dumpmachine"], env, output)
    record = {
        "schema": "inplace-product-component-v1", "status": "RUNNING",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": {"system": platform.system(), "release": platform.release(),
                 "machine": platform.machine(), "python": platform.python_version()},
        "backend": args.backend, "compiler": {"path": cc, "sha256": sha256(cc),
                    "version": compiler_version, "target": compiler_target},
        "source_root": str(args.source_root.resolve()), "included_production_headers": headers,
        "test_source": {"path": str(test), "sha256": sha256(test)},
        "runner": {"path": str(Path(__file__).resolve()), "sha256": sha256(__file__)},
        "scope": "Actual production SIMD product and plane encode/decode, with NTT-domain input injection; every output compared with independent int64 modular arithmetic.",
        "excluded_scope": ["NTT correctness", "SHAKE or matrix generation", "complete signature equivalence", "production allocator layout", "side-channel proof"],
        "runs": [],
    }
    result_path = output / "result.xml"
    def save():
        result_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    save()
    flags = ["-std=c11", "-O3", "-flto", "-Wall", "-Wextra", "-Werror",
             "-Wno-unused-function", "-Wno-unused-parameter"]
    if args.backend == "avx2":
        flags.append("-mavx2")
    for root in include_dirs:
        flags.extend(["-I", str(root)])
    for parameter in (44, 65, 87):
        executable = output / ("product_" + str(parameter) + (".exe" if os.name == "nt" else ""))
        base = [cc] + flags + ["-DTEST_PARAMETER=" + str(parameter)]
        run = {"parameter": parameter}
        preprocessed = output / ("product_" + str(parameter) + ".i")
        run["preprocess"] = invoke(base + ["-E", str(test), "-o", str(preprocessed)], env, output)
        if run["preprocess"]["exit_code"] == 0:
            run["preprocessed_sha256"] = sha256(preprocessed)
        run["build"] = invoke(base + [str(test), "-o", str(executable)], env, output)
        if run["build"]["exit_code"] == 0:
            run["binary"] = {"path": str(executable), "sha256": sha256(executable),
                             "bytes": executable.stat().st_size}
            run["execution"] = invoke([str(executable)], env, output)
            if run["execution"]["exit_code"] == 0:
                try:
                    run["result"] = json.loads(run["execution"]["stdout"])
                except ValueError:
                    run["result"] = {"status": "INVALID_JSON"}
        record["runs"].append(run)
        save()
        print(json.dumps({"parameter": parameter, "build_exit": run["build"]["exit_code"],
                          "result": run.get("result"), "error": run["build"]["stderr"]
                          or run.get("execution", {}).get("stderr", "")}, ensure_ascii=False))
        if run.get("result", {}).get("status") != "PASS":
            break
    unchanged = all(sha256(item["path"]) == item["sha256"] for item in headers)
    unchanged = unchanged and sha256(test) == record["test_source"]["sha256"]
    record["inputs_unchanged_during_run"] = unchanged
    record["status"] = "PASS" if (unchanged and len(record["runs"]) == 3 and all(
        item.get("result", {}).get("status") == "PASS" and item["preprocess"]["exit_code"] == 0
        for item in record["runs"])) else "FAIL"
    record["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    record["totals"] = {field: sum(run.get("result", {}).get(field, 0) for run in record["runs"])
                        for field in ("cases", "coefficients_checked", "plane_coefficients_checked", "guard_bytes_checked")}
    save()
    print(str(result_path))
    return 0 if record["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
