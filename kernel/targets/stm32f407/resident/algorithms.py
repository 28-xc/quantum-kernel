"""Generate each finite resource/schedule configuration from the parameterized project sources."""
import argparse,csv,hashlib,importlib.util,os,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parent
UP=ROOT/"algorithm-project"
GEN=ROOT/"generators"
sys.dont_write_bytecode=True
def normalized(s):return hashlib.sha256(s.encode("utf-8")).hexdigest()
def module(name,path):
    import importlib.util
    sp=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);return m
def baseline(p,k,cap,matrix,rows,where,llvm):
    # The single source tree provides parameterized ML-KEM and ML-DSA, the encode/decode functions and production kernels.
    for folder in (UP/"target",UP/"project",UP/"project/tools",UP/"project/tests/targets",UP/"recipe"):
        if str(folder) not in sys.path:sys.path.insert(0,str(folder))
    import toolchain as tc,transforms
    PROJECT=UP/"project";TARGET=UP/"target"
    raw=where/"raw";raw.mkdir(parents=True,exist_ok=True)
    opt=module("f407_compiler_options",UP/("recipe/pipeline_options.py" if k=="paired" else "target/algorithm_build.py"))
    if k=="paired":os.environ.update(F407_A_POLYS=str(matrix),F407_KEEP_LOW="1",F407_SCHEDULE_SRC=str(UP/"pipeline"))
    units,common=opt.algorithm_units(p,"cached" if k=="paired" else "compact",cap,PROJECT,raw)
    flags=tc.ARM+["-I"+str(q) for q in (TARGET/"freestanding",PROJECT/"targets/include",PROJECT/"targets/common",PROJECT/"include",TARGET/"vendor/libopencm3/include",TARGET,raw)]
    flags += [f"-DPARAM={p}",f"-DPROFILE={58 if k=='paired' else 1}",f"-DARENA_BYTES={cap}",*common]
    unit,opts=units[4 if p<100 else 0]
    if k=="paired":opts=opts+["-DF407_PAIR=1",f"-DF407_FUTURE_ROWS={rows}","-DF407_ROW_DOT=0","-DF407_RAW_COLUMNS=0","-DF407_KEY_CACHE=0"]
    expanded=where/"preprocessed.i"
    subprocess.run([str(llvm/"clang.exe"),*flags,*opts,"-E","-P",str(unit),"-o",str(expanded)],cwd=where,check=True,capture_output=True)
    body=expanded.read_text(encoding="utf-8")
    return transforms.native_text(body) if p<100 else transforms.change(p,k,body)
def mode_config(name):
    return ET.parse(ROOT/"routes"/(name+".xml")).getroot()
def generate(name,where,llvm):
    if name=="balanced-reference":return {}
    where.mkdir(parents=True,exist_ok=True)
    spec=mode_config(name);parents=where/"parents";parents.mkdir(exist_ok=True)
    for cell in spec:
        p=int(cell.get("parameter"));k=cell.get("backend");src=parents/(f"{p}-{k}.c")
        txt=baseline(p,k,int(cell.get("capacity")),int(cell.get("matrix")),int(cell.get("future_rows")),where/f"{p}-{k}",llvm)
        if normalized(txt)!=cell.get("origin_sha256"):raise ValueError(f"initial source divergence {name}/{p}/{k}")
        rows=txt.splitlines(keepends=True)
        for item in reversed(cell.findall("span")):
            lo=int(item.get("from"));hi=int(item.get("to"))
            if normalized("".join(rows[lo:hi]))!=item.get("old_sha256"):raise ValueError("original adapter signature mismatch")
            rows[lo:hi]=[(item.text or "")]
        txt="".join(rows)
        if normalized(txt)!=cell.get("parent_sha256"):raise ValueError(f"bound parent divergence {p}/{k}")
        src.write_text(txt,encoding="utf-8",newline="\n")
    if str(GEN) not in sys.path:sys.path.insert(0,str(GEN))
    import generation
    generation.run(spec,parents,where)
    files={}
    for cell in spec.findall("cell"):
        dest=where/("kernel-"+cell.get("parameter")+"-"+cell.get("backend")+".c")
        if normalized(dest.read_text(encoding="utf-8"))!=cell.get("source_sha256"):raise ValueError(("algorithm source differs",name,dest))
        files[dest.name]=dest
    for filename in ("shared_ntt8380417.c","shared_mlkem_roots.c"):
        if (where/filename).exists():files[filename]=where/filename
    return files

