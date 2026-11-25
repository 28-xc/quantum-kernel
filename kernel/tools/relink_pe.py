"""Relink a GCC PE build after auditing selected native archive members.

Inputs are the build's recorded commands and unchanged object files. A control
replay establishes identical generated code before the selected members are
omitted. The resulting closure and interface probes describe this exact build.
"""
from pathlib import Path
import argparse
import copy
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
import re
import shutil
import struct
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ref(path):
    return {"path": str(Path(path).resolve()), "sha256": sha(path)}


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def basename(value):
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def distinct_paths(parent, control, output):
    paths = [Path(x).resolve() for x in (parent, control, output)]
    for i, p in enumerate(paths):
        for q in paths[i + 1:]:
            require(p != q and p not in q.parents and q not in p.parents,
                    "Parent, control and output must be separate directories")
    for p in paths[1:]:
        require(not p.exists(), f"Preserve existing output: {p}")
    return paths


def selected_commands(commands):
    selected = []
    for index, record in enumerate(commands):
        args = record["argv"]
        names = {basename(x) for x in args}
        archive = "rcs" in args and bool(names & {"libnative_assembly.a", "liblatticecore.a"})
        if archive or "-shared" in args or names & {"probe_shared.exe", "probe_static.exe"}:
            require(record["exit_code"] == 0, "Parent replay command failed")
            selected.append((index, args))
    require(len(selected) == 7, "Expected two archives, one DLL link and two compiled/run probes")
    return selected


def native_members(commands):
    matches = [a for _, a in selected_commands(commands)
               if "rcs" in a and "libnative_assembly.a" in map(basename, a)]
    require(len(matches) == 1, "Native archive command must be unique")
    members = [basename(x) for x in matches[0] if basename(x).endswith(".o")]
    require(members and len(members) == len(set(members)), "Ambiguous native archive members")
    return members


def validate_omissions(names, members):
    require(names and len(names) == len(set(names)), "Specify distinct native members to omit")
    for name in names:
        require(name == basename(name) and name in members,
                f"Omission is not an exact native archive member: {name}")
    return set(names)


def remap(args, parent, dest):
    variants = {str(parent), parent.as_posix(), str(parent).replace("/", "\\")}
    result = []
    for value in args:
        for old in sorted(variants, key=len, reverse=True):
            value = value.replace(old, str(dest))
        result.append(value)
    return result


class Runner:
    def __init__(self, directory, tool_dirs):
        self.directory = directory
        self.commands = []
        self.env = os.environ.copy()
        self.env["TEMP"] = self.env["TMP"] = str(directory / "tmp")
        self.env["PATH"] = os.pathsep.join(tool_dirs + [self.env.get("PATH", "")])

    def run(self, args, label):
        started = time.monotonic()
        proc = subprocess.run([str(x) for x in args], cwd=self.directory,
                              env=self.env, capture_output=True, text=True)
        log = self.directory / (label + ".log")
        log.write_text(json.capture_text(proc.stdout + proc.stderr), encoding="utf-8")
        record = {"argv": [str(x) for x in args], "exit_code": proc.returncode,
                  "elapsed_seconds": time.monotonic() - started,
                  "log": log.name, "log_sha256": sha(log)}
        self.commands.append(record)
        write(self.directory / "commands.xml", self.commands)
        require(proc.returncode == 0, f"Command failed; preserved log: {log}")
        return proc.stdout


class PE:
    """Small strict PE32+ reader for sections, import/export ABI and unwind."""
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        b = self.data
        require(len(b) >= 64 and b[:2] == b"MZ", "Invalid DOS header")
        pe = self.u32(60)
        require(self.slice(pe, 4) == b"PE\0\0", "Invalid PE signature")
        self.machine, nsec = self.unpack("<HH", pe + 4)
        require(self.machine == 0x8664, "Only AMD64 PE is supported")
        symoff, nsym = self.unpack("<II", pe + 12)
        strtab = symoff + 18 * nsym
        opt = pe + 24
        require(self.unpack("<H", opt)[0] == 0x20B, "Only PE32+ is supported")
        optional_size = self.unpack("<H", pe + 20)[0]
        require(optional_size >= 240, "Missing PE data directories")
        self.imagebase = self.unpack("<Q", opt + 24)[0]
        self.directories = [self.unpack("<II", opt + 112 + 8 * i) for i in range(16)]
        self.sections = {}
        for index in range(nsec):
            off = opt + optional_size + 40 * index
            name = self.slice(off, 8).split(b"\0", 1)[0].decode("ascii")
            if name.startswith("/"):
                name = self.cstr(strtab + int(name[1:]))
            vs, va, rs, rp = self.unpack("<IIII", off + 8)
            require(name not in self.sections, "Duplicate section name")
            self.sections[name] = {"va": va, "size": vs, "raw_size": rs,
                "raw_pointer": rp, "flags": self.u32(off + 36),
                "data": self.slice(rp, min(vs, rs))}

    def slice(self, off, size):
        require(off >= 0 and size >= 0 and off + size <= len(self.data), "PE field outside file")
        return self.data[off:off + size]

    def unpack(self, fmt, off):
        return struct.unpack(fmt, self.slice(off, struct.calcsize(fmt)))

    def u32(self, off):
        return self.unpack("<I", off)[0]

    def cstr(self, off):
        require(0 <= off < len(self.data), "PE string outside file")
        end = self.data.find(b"\0", off)
        require(end >= off, "Unterminated PE string")
        return self.data[off:end].decode("ascii")

    def offset(self, rva, count=1):
        for s in self.sections.values():
            delta = rva - s["va"]
            if 0 <= delta and delta + count <= min(s["size"], s["raw_size"]):
                return s["raw_pointer"] + delta
        raise ValueError(f"RVA outside initialized section: {rva:x}")

    def abi(self):
        exports = []
        rva, size = self.directories[0]
        require(rva and size >= 40, "Missing export directory")
        e = self.offset(rva, 40)
        base, count, named, eat, npt, opt = self.unpack("<IIIIII", e + 16)
        require(named <= count, "Invalid export count")
        names = {}
        for i in range(named):
            ordidx = self.unpack("<H", self.offset(opt + 2 * i, 2))[0]
            require(ordidx < count, "Invalid export ordinal")
            name = self.cstr(self.offset(self.u32(self.offset(npt + 4 * i, 4))))
            names.setdefault(ordidx, []).append(name)
        for i in range(count):
            target = self.u32(self.offset(eat + 4 * i, 4))
            if target:
                exports.append({"ordinal": base + i, "names": sorted(names.get(i, [])),
                    "forwarder": self.cstr(self.offset(target)) if rva <= target < rva + size else None})
        imports = []
        rva, size = self.directories[1]
        if rva:
            terminated = False
            for pos in range(0, size, 20):
                desc = self.unpack("<IIIII", self.offset(rva + pos, 20))
                if not any(desc):
                    terminated = True
                    break
                thunk, _, _, dllname, iat = desc
                table = thunk or iat
                names = []
                for i in range(len(self.data) // 8):
                    v = self.unpack("<Q", self.offset(table + i * 8, 8))[0]
                    if not v:
                        break
                    names.append({"ordinal": v & 65535} if v >> 63 else
                                 {"name": self.cstr(self.offset(v, 3) + 2)})
                else:
                    raise ValueError("Unterminated import thunk")
                imports.append({"dll": self.cstr(self.offset(dllname)).lower(), "symbols": names})
            require(terminated, "Unterminated import directory")
        require(self.directories[13] == (0, 0), "Delay imports require a separate audit")
        return {"machine": self.machine, "exports": exports, "imports": imports}

    def program(self):
        sections = [{k: v for k, v in s.items() if k != "data"} | {"name": n}
                    for n, s in self.sections.items()]
        total = sum(s["size"] for s in sections if not s["name"].startswith(".debug")
                    and s["flags"] & 0x40000000 and not s["flags"] & 0x80000000)
        total += sum(min(s["size"], s["raw_size"]) for s in sections
                     if s["flags"] & 0x80000000 and s["name"] != ".bss")
        return {"program_bytes": total, "sections": sections}


def defined_symbols(text, types=None):
    result = {}
    for line in text.splitlines():
        m = re.fullmatch(r"([0-9a-fA-F]+)\s+([A-Za-z])\s+(.+)", line.strip())
        if m and (types is None or m[2] in types) and not m[3].startswith("."):
            result[m[3]] = int(m[1], 16)
    return result


def symbol_references(text, symbols):
    # Exact symbol tokens, including objdump's optional +/- hexadecimal addend.
    found = []
    for line in text.splitlines():
        tokens = re.findall(r"[A-Za-z_.$][A-Za-z0-9_.$@]*", line)
        matches = sorted(set(tokens) & set(symbols))
        if matches:
            found.append({"line": line, "symbols": matches})
    return found


def unwind_rows(pe, nm_text):
    names = {}
    for name, address in defined_symbols(nm_text, "Tt").items():
        names.setdefault(address - pe.imagebase, []).append(name)
    pdata = pe.sections.get(".pdata", {}).get("data", b"")
    require(len(pdata) % 12 == 0, "Malformed runtime function table")
    rows = {}
    for i in range(0, len(pdata), 12):
        begin, end, info = struct.unpack_from("<III", pdata, i)
        require(begin in names and end > begin, "Unnamed or invalid runtime function")
        p = pe.offset(info, 4)
        flags, version = pe.data[p] >> 3, pe.data[p] & 7
        require(version in (1, 2) and not (flags & ~7), "Unsupported unwind metadata")
        require(not (flags & 4 and flags & 3), "Conflicting unwind flags")
        length = (4 + 2 * pe.data[p + 2] + 3) & ~3
        length += 12 if flags & 4 else 4 if flags & 3 else 0
        data = pe.slice(pe.offset(info, length), length)
        key = tuple(sorted(names[begin]))
        require(key not in rows, "Ambiguous runtime function identity")
        rows[key] = {"function_bytes": end - begin, "unwind_bytes": data.hex()}
    return rows


def compare_unwind(control, candidate, omitted_symbols):
    require(set(candidate) <= set(control), "Candidate added an unreviewed runtime function")
    for name, row in candidate.items():
        require(control[name] == row, f"Retained unwind record changed: {name}")
    removed = set(control) - set(candidate)
    for names in removed:
        require(set(names) <= set(omitted_symbols), f"Removed unrelated runtime function: {names}")
    return sorted(removed)


def replay(dest, omit, config, original):
    dest.mkdir(parents=True, exist_ok=False)
    (dest / "tmp").mkdir()
    (dest / "closure").mkdir()
    shutil.copytree(config.parent / "obj", dest / "obj")
    shutil.copy2(config.parent / "exports.def", dest / "exports.def")
    dirs = list(dict.fromkeys(str(Path(x).resolve().parent) for x in
                             (config.cc, config.ar, config.nm, config.objdump)))
    runner = Runner(dest, dirs)
    checks = {}
    for index, command in selected_commands(original):
        args = remap(command, config.parent, dest)
        if "rcs" in args:
            args[0] = config.ar
            args = [x for x in args if basename(x) not in omit]
        elif basename(args[0]) in {"probe_shared.exe", "probe_static.exe"}:
            pass
        else:
            args[0] = config.cc
        if "-shared" in args:
            args.insert(1, "-save-temps=obj")
        output = runner.run(args, f"replay-{index:03d}")
        if basename(args[0]) in {"probe_shared.exe", "probe_static.exe"}:
            linkage = basename(args[0]).split("_")[1].split(".")[0]
            rows = [json.loads(x) for x in output.splitlines() if x.strip()]
            require(len(rows) == len(config.parameters) and
                    {x.get("parameter") for x in rows} == set(config.parameters) and
                    all(x.get("status") == "PASS" for x in rows), "Incomplete public probe matrix")
            checks[linkage] = {"exit_code": 0, "stdout": json.capture_text(output),
                              "sha256": sha(dest / basename(args[0])),
                              "log_sha256": runner.commands[-1]["log_sha256"]}
    require(set(checks) == {"shared", "static"}, "Both linkage probes are required")
    return runner, checks


def audit(dest, runner, omitted, omit_map, members, config):
    symbols = set().union(*map(set, omit_map.values()))
    native_assembly = sorted(dest.glob("*.ltrans.s"))
    require(native_assembly, "Link did not retain final LTO machine assembly")
    optimized_objects = []
    for i, source in enumerate(native_assembly):
        obj = dest / (source.stem + ".audit-native.o")
        runner.run([config.cc, "-c", str(source), "-o", str(obj)], f"reassemble-{i:03d}")
        optimized_objects.append(obj)
    files = []
    own_files = []
    for index, obj in enumerate(optimized_objects + [dest / "obj" / n for n in members if n not in omitted]):
        reloc = runner.run([config.objdump, "-r", str(obj)], f"relocations-{index:03d}")
        undef = runner.run([config.nm, "-u", str(obj)], f"undefined-{index:03d}")
        references = symbol_references(reloc + "\n" + undef, symbols)
        item = {"path": str(obj.relative_to(dest)), "sha256": sha(obj),
                "relocations": f"relocations-{index:03d}.log",
                "undefined": f"undefined-{index:03d}.log", "references": references}
        if obj.name in omit_map:
            # Control keeps these objects, including their own CFI/debug refs.
            own_files.append(item)
        else:
            files.append(item)
    require(not any(x["references"] for x in files), "Live optimized reference to omitted entity")
    nm_text = runner.run([config.nm, "-n", "--defined-only", str(dest / "latticecore.dll")], "final-defined")
    final_symbols = defined_symbols(nm_text)
    if omitted:
        require(not symbols & final_symbols.keys(), "An omitted symbol remains defined")
    for kind, flags in (("headers", "-p"), ("symbols", "-t"), ("disassembly", "-d")):
        runner.run([config.objdump, flags, str(dest / "latticecore.dll")], "final-" + kind)
    unchanged = [{"path": p.name, "sha256": sha(p),
                  "parent_sha256": sha(config.parent / "obj" / p.name)}
                 for p in sorted((dest / "obj").glob("*.o"))]
    require(all(x["sha256"] == x["parent_sha256"] for x in unchanged), "Input object changed")
    require(sha(dest / "exports.def") == sha(config.parent / "exports.def"), "Export definition changed")
    pe = PE(dest / "latticecore.dll")
    result = {"schema": "latticecore.pe_closure.v1", "parent": ref(config.parent / "latticecore.dll"),
              "library": ref(dest / "latticecore.dll"), "excluded_archive_members": sorted(omitted),
              "audited_omission_definitions": omit_map, "omitted_symbols": sorted(symbols),
              "unchanged_input_objects": unchanged, "final_optimized_relocation_closure": files,
              "control_omitted_member_local_metadata": own_files,
              "final_optimized_symbol_references": 0,
              "saved_native_assembly": [{"path": p.name, "sha256": sha(p)} for p in native_assembly],
              "program": pe.program(), "abi": pe.abi(),
              "scope": "Every relocation section and undefined name in reassembled final LTO code and all retained original native objects. Control-only omitted objects are logged separately; their local metadata is not an incoming reference."}
    write(dest / "closure.xml", result)
    return result, pe, unwind_rows(pe, nm_text)


def perform(config):
    config.parent, config.control, config.output = distinct_paths(config.parent, config.control, config.output)
    parent_build = read(config.parent / "build.xml")
    require(sha(config.parent / "latticecore.dll") == parent_build["binary"]["sha256"], "Parent DLL identity mismatch")
    require(sha(config.parent / "commands.xml") == parent_build["commands_sha256"], "Parent command identity mismatch")
    commands = read(config.parent / "commands.xml")
    config.parameters = parent_build["parameters"]
    members = native_members(commands)
    omissions = validate_omissions(config.omit_member, members)
    object_hashes = {p.name: sha(p) for p in (config.parent / "obj").glob("*.o")}
    parent_pe = PE(config.parent / "latticecore.dll")
    runner0, checks0 = replay(config.control, set(), config, commands)
    actual_members = runner0.run([config.ar, "t", str(config.parent / "libnative_assembly.a")], "parent-archive-members").splitlines()
    require(actual_members == members, "Native archive differs from recorded member order")
    omit_map = {}
    for index, name in enumerate(sorted(omissions)):
        text = runner0.run([config.nm, "-g", "--defined-only", str(config.parent / "obj" / name)], f"omit-definitions-{index:03d}")
        definitions = sorted(defined_symbols(text))
        require(definitions, f"No global definitions in omitted member: {name}")
        omit_map[name] = definitions
    flat = [s for values in omit_map.values() for s in values]
    require(len(flat) == len(set(flat)), "Omitted members define duplicate symbols")
    result0, pe0, unwind0 = audit(config.control, runner0, set(), omit_map, members, config)
    for name in (".text", ".pdata", ".xdata"):
        require(parent_pe.sections[name]["data"] == pe0.sections[name]["data"], f"Control differs from parent {name}")
    require(parent_pe.abi() == pe0.abi(), "Control import/export ABI changed")
    runner1, checks1 = replay(config.output, omissions, config, commands)
    result1, pe1, unwind1 = audit(config.output, runner1, omissions, omit_map, members, config)
    require(result0["saved_native_assembly"] == result1["saved_native_assembly"], "Optimized C machine assembly changed")
    require(pe0.abi() == pe1.abi(), "Candidate import/export ABI changed")
    removed = compare_unwind(unwind0, unwind1, flat)
    require(object_hashes == {p.name: sha(p) for p in (config.parent / "obj").glob("*.o")}, "Parent input objects changed during replay")
    build = copy.deepcopy(parent_build)
    build["created_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    build["binary"]["sha256"] = sha(config.output / "latticecore.dll")
    build["binary"]["static_sha256"] = sha(config.output / "liblatticecore.a")
    build["public_checks"] = checks1
    build["commands_sha256"] = sha(config.output / "commands.xml")
    build["map_sha256"] = sha(config.output / "latticecore.map")
    build["elapsed_seconds"] = sum(x["elapsed_seconds"] for x in runner1.commands)
    build["deployment_relink"] = {
        "parent_build": ref(config.parent / "build.xml"), "parent_library": ref(config.parent / "latticecore.dll"),
        "control": ref(config.control / "closure.xml"), "closure": ref(config.output / "closure.xml"),
        "replay": ref(__file__), "removed_archive_members": sorted(omissions),
        "same_optimized_C_machine_assembly": True,
        "original_to_control_text_pdata_xdata_identical": True,
        "retained_windows_runtime_unwind_identical": True,
        "removed_windows_runtime_functions": [list(x) for x in removed],
        "retained_windows_runtime_function_count": len(unwind1),
        "import_export_abi_unchanged": True,
        "scope": "Exact object replay and post-LTO closure, both linkage interface probes and retained PE unwind verified. Source identities are inherited from the bound parent build. Complete algorithm qualification is recorded separately."}
    write(config.output / "build.xml", build)
    paired = {"status": "CLOSURE_AND_LINKAGE_PROBES_PASS", "control": ref(config.control / "closure.xml"),
              "output": ref(config.output / "closure.xml"), "build": ref(config.output / "build.xml"),
              "control_public_checks": checks0, "candidate_public_checks": checks1,
              "P": result1["program"]["program_bytes"],
              "parent_P": parent_pe.program()["program_bytes"],
              "retained_runtime_functions": len(unwind1), "removed_runtime_functions": [list(x) for x in removed],
              "runtime_records": [{"symbols": list(k), **v} for k, v in unwind1.items()]}
    write(config.output / "paired-link-record.xml", paired)
    return paired


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("parent", "control", "output"):
        ap.add_argument("--" + name, type=Path, required=True)
    ap.add_argument("--omit-member", action="append", required=True, help="Exact native archive member name; repeat as needed")
    for name in ("cc", "ar", "nm", "objdump"):
        ap.add_argument("--" + name, required=True, help="Explicit matching toolchain executable")
    config = ap.parse_args(argv)
    existed = {Path(p).resolve() for p in (config.control, config.output) if Path(p).exists()}
    try:
        result = perform(config)
    except Exception as exc:
        failure = {"status": "FAILED", "error_type": type(exc).__name__, "error": str(exc),
                   "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        for directory in (config.control, config.output):
            if directory.resolve() not in existed and directory.exists() and (directory / "commands.xml").exists():
                write(directory / "failure.xml", failure)
        raise
    print(json.dumps({k: result[k] for k in ("status", "P", "parent_P", "build")}))


if __name__ == "__main__":
    main()
