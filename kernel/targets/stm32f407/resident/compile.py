"""Rebuild Cortex-M4 images from archived C and assembly in a separate directory."""
import argparse,concurrent.futures,csv,hashlib,os,re,shutil,subprocess,sys,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def digest(file):
    return hashlib.sha256(file.read_bytes()).hexdigest()

def inside(path,base):
    p=(base/path).resolve()
    if not p.is_relative_to(base.resolve()):raise ValueError("path escapes recipe: "+str(path))
    return p

def main():
    a=argparse.ArgumentParser()
    a.add_argument("configuration",choices=sorted(p.stem for p in (ROOT/"configurations").glob("*.xml")))
    a.add_argument("--output",type=Path,required=True)
    a.add_argument("--llvm-bin",type=Path,default=os.environ.get("LLVM_BIN"))
    a.add_argument("--arm-as",type=Path,default=os.environ.get("ARM_AS") or shutil.which("arm-none-eabi-as"))
    a.add_argument("--jobs",type=int,default=4)
    a.add_argument("--project-polynomials-only",action="store_true",help="omit all unused third-party polynomial objects from the independent deployment link")
    opt=a.parse_args()
    catalog=ROOT/"source-hashes.tsv"
    if catalog.is_file():
        with catalog.open(encoding="utf-8",newline="") as file:
            for row in csv.DictReader(file,delimiter="\t"):
                path=inside(row["source"],ROOT)
                if not path.is_file() or digest(path)!=row["sha256"]:raise ValueError("source integrity mismatch: "+row["source"])
    llvm=Path(opt.llvm_bin).resolve() if opt.llvm_bin else Path(shutil.which("clang") or "").resolve().parent
    versions={}
    def tool(name):
        if name=="arm-none-eabi-as":
            if not opt.arm_as:raise SystemExit("specify GNU Arm assembler using --arm-as")
            path=Path(opt.arm_as).resolve()
        else:path=llvm/(name+(".exe" if os.name=="nt" else ""))
        if not path.is_file():raise SystemExit("tool not found: "+str(path))
        if name not in versions:
            versions[name]=subprocess.check_output([str(path),"--version"],text=True,errors="replace").splitlines()[0]
        return str(path)
    out=opt.output.resolve()
    if out.is_relative_to(ROOT):raise SystemExit("output must be outside the source tree")
    out.mkdir(parents=True,exist_ok=True)
    config=ET.parse(ROOT/"configurations"/(opt.configuration+".xml")).getroot()
    def source(node):
        p=inside(node.get("path"),ROOT)
        if digest(p)!=node.get("sha256"):raise ValueError("source identity: "+str(p))
        return p
    files={e.get("id"):source(e) for e in config.find("sources")}
    steps={s.get("id"):s for s in config.find("build")}
    if opt.project_polynomials_only:
        if opt.configuration!="independent-28":raise ValueError("this link option requires independent-28")
        final=next(s for s in steps.values() if s.get("file").endswith(".elf"))
        omitted=0
        for e in list(final.findall("input")):
            name=Path(steps[e.get("id")].get("file")).name
            if re.fullmatch(r"\d+-(?:21-fastntt|20-fastinvntt|26-ntt|16-ntt|18-pointwise_mont)\.o",name):
                final.remove(e);omitted+=1
        if omitted!=7:raise ValueError("polynomial-object inventory changed")
        final.set("sha256","fc541ca3b49f6dd86550763a7e10bee68740d6aaf547f836f5aa14a9b5127cda")
        reachable=set()
        def include(id):
            if id in reachable:return
            reachable.add(id)
            for input in steps[id].findall("input"):include(input.get("id"))
        include(next(i for i,s in steps.items() if s.get("file").endswith(".bin")))
        steps={i:s for i,s in steps.items() if i in reachable}
    if (ROOT/"routes"/(opt.configuration+".xml")).is_file():
        import algorithms
        generated=algorithms.generate(opt.configuration,out/"generated-algorithms",llvm)
        bound=set()
        for k,prior in list(files.items()):
            if prior.name not in generated:continue
            # Re-expand the newly generated project code with its declared shared C ABI headers.
            dest=out/"expanded"/prior.name;dest.parent.mkdir(exist_ok=True)
            process=subprocess.run([tool("clang"),"--target=arm-none-eabi","-mcpu=cortex-m4","-mthumb","-mfloat-abi=soft","-ffreestanding","-fno-builtin","-mno-unaligned-access","-Os","-DSTM32F4","-I"+str(ROOT/"generators"),"-E","-P",str(generated[prior.name])],capture_output=True,check=True)
            dest.write_bytes(process.stdout.replace(b"\r\n",b"\n"))
            if digest(dest)!=digest(prior):raise ValueError("generated algorithm does not match source binding: "+prior.name)
            files[k]=dest;bound.add(prior.name)
        if set(generated)!=bound:raise ValueError("generated unit has no actual compiler target")
    ready=set();count=0
    def execute(s):
        args=[];cwd=out
        dst=inside(s.get("file"),out);dst.parent.mkdir(parents=True,exist_ok=True)
        for e in s:
            if e.tag=="arg":args.append(e.text)
            elif e.tag=="source":args.append((e.get("prefix") or "")+str(files[e.get("id")]))
            elif e.tag=="input":args.append(str(inside(steps[e.get("id")].get("file"),out)))
            elif e.tag=="output":args.append(str(dst))
            elif e.tag=="map":args.append("-Map="+str(out/"stm32f407-unified.map"))
            else:raise ValueError(e.tag)
        if s.get("tool")=="arm-none-eabi-as":
            # The Windows GNU assembler accepts ASCII argv even when CreateProcessW supplies a Unicode working directory.
            input_source=Path(args[-1]);cwd=dst.parent
            shutil.copyfile(input_source,cwd/input_source.name)
            args[args.index("-o")+1]=dst.name;args[-1]=input_source.name
        r=subprocess.run([tool(s.get("tool")),*args],cwd=cwd,capture_output=True,errors="replace",text=True)
        if r.returncode:raise RuntimeError(r.stderr)
        got=digest(dst)
        if got!=s.get("sha256"):
            raise ValueError("compiler output mismatch for "+s.get("id")+" "+s.get("file")+": "+got+" != "+s.get("sha256"))
        return s.get("id")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(16,opt.jobs))) as pool:
        while len(ready)<len(steps):
            current=[s for k,s in steps.items() if k not in ready and all(x.get("id") in ready for x in s.findall("input"))]
            if not current:raise ValueError("cyclic or missing build binding")
            ready.update(pool.map(execute,current))
            count+=len(current)
    expected=source(config.find("manifest"))
    if opt.project_polynomials_only:
        meta=ET.parse(expected);meta.getroot().set("elf_sha256",digest(out/"stm32f407-unified.elf"));meta.getroot().set("linkage","project-polynomials-only");ET.indent(meta);meta.write(out/"stm32f407-unified.xml",encoding="utf-8",xml_declaration=True)
    else:shutil.copyfile(expected,out/"stm32f407-unified.xml")
    with (out/"rebuild.tsv").open("w",encoding="utf-8",newline="\n") as f:
        f.write("tool\tversion\n")
        for k,v in sorted(versions.items()):f.write(k+"\t"+v+"\n")
        f.write("steps\t"+str(count)+"\n")
        for s in steps.values():f.write(s.get("file")+"\t"+s.get("sha256")+"\n")
    print(opt.configuration,count,digest(out/"stm32f407-unified.bin"),flush=True)
if __name__=="__main__":main()

