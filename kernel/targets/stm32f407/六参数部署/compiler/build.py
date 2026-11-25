"""Derive and compile six-parameter configurations from the shipped, hash-bound source graph."""
import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from schedule import PARAMS, low_kernel, fast_kernel, once, key_verify_columns
from frontier import group_prefix,matrix_prefix

HERE=Path(__file__).resolve().parent
DSA=(44,65,87)
RETAINED={44:4,65:6,87:3}
SCHEDULE={
    24:({44:4,65:6,87:0},{44:6,65:1,87:0}),
    28:({44:4,65:6,87:7},{44:12,65:5,87:0}),
    32:({44:4,65:6,87:8},{44:16,65:10,87:0})
}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def text(p):return p.read_text(encoding="utf-8")
def put(p,s):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s,encoding="utf-8",newline="\n")
def capture(argv,cwd):
    r=subprocess.run(list(map(str,argv)),cwd=cwd,capture_output=True)
    if r.returncode:raise RuntimeError(subprocess.list2cmdline(list(map(str,argv)))+"\n"+r.stderr.decode("utf-8","replace"))
    return r.stdout.decode("utf-8","replace")

def geometry(m,ram,whole,secret_cache,optimized_compact,compact_stack,frontier):
    future,matrix=SCHEDULE[ram];caps={};bounds={};old={}
    for cell in m:
        p,st=int(cell.get("parameter")),cell.get("strategy")
        key=(p,st);b=[int(cell.get("bound"+str(i))) for i in range(3)]
        old[key]=b[:]
        cap=int(cell.get("workspace_capacity"))
        if p in DSA and st=="compact":
            retained=4 if compact_stack and p==87 else RETAINED[p]
            b[1]+=768+retained*(32+PARAMS[p][5])
            if whole:
                cols=PARAMS[p][1];b[0]+=min(cols,6)*768-32
                b[2]+=(min(cols,5 if compact_stack else 4) if p==87 else cols)*768-32
            cap=max(b)+64
        elif p in DSA and ram==24 and p==87:
            b=bounds[p,"compact"].copy();cap=max(b)+64
        elif p in DSA:
            fr=future[p];ma=matrix[p];ali=min(fr,PARAMS[p][4]//768)
            saved=secret_cache if p==87 else 0
            frontier_bytes={"dual":0,"triple3":3328,"triple4":4096,"matrix5":3840,"matrix85":4096}.get(frontier,0) if p==87 else 0
            oldf,oldm=int(cell.get("future_rows","0")),int(cell.get("matrix_cache","0"))
            if not (oldf and "matrix_cache" in cell.attrib):
                oldf={44:4,65:6,87:7}[p];oldm={44:13,65:6,87:0}[p]
            b[1]+=768*(fr-ali+ma+saved-oldf-oldm)
            b[1]+=32*(int(ma+saved>0)-int(oldm>0)+int(fr>ali)-int(oldf>0))
            if frontier_bytes:b[1]+=frontier_bytes+32
            cap=max(b)+64
        caps[key]=cap;bounds[key]=b
        cell.set("workspace_capacity",str(cap))
        cell.set("transaction_bytes",str(cap+96+int(cell.get("io_bytes"))))
        for i in range(3):cell.set("bound"+str(i),str(b[i]))
        if p in DSA:
            cell.set("parent_implementation_image",cell.get("source_image_sha256"))
            for attr in ("source_image_sha256","qualified_source_sha256","standalone_balanced_sha256","matrix_cache","future_rows"):
                cell.attrib.pop(attr,None)
            islow=st=="compact" or (ram==24 and p==87)
            if islow:
                cell.set("schedule","current-mask-columns-and-retained-low-rows")
                cell.set("output_scratch_columns",str(PARAMS[p][1]-1))
                cell.set("retained_low_rows",str(4 if compact_stack and p==87 else RETAINED[p]))
                if whole:
                    c=PARAMS[p][1]
                    cell.set("key_packed_columns",str(min(c,6)));cell.set("verify_packed_columns",str(min(c,5 if compact_stack else 4) if p==87 else c))
                if st=="cached":cell.set("backend","native")
            else:
                cell.set("schedule","next-candidate-rows-in-signature")
                cell.set("matrix_cache",str(matrix[p]));cell.set("future_rows",str(future[p]))
                cell.set("output_scratch_rows",str(min(future[p],PARAMS[p][4]//768)))
                if secret_cache and p==87:cell.set("s1_ntt_columns",str(secret_cache))
                if frontier and p==87:
                    cell.set("experiment",frontier)
                    if frontier.startswith("triple"):cell.set("third_candidate_rows",frontier[-1])
                    elif frontier!="dual":
                        cell.set("matrix_cache","5")
                        if frontier=="matrix85":cell.set("next_matrix_prefix_coefficients","85")
    if optimized_compact:
        if ram!=24 or not whole:raise ValueError("optimized compact dispatch expects 24 KiB and all-operation cache")
        for p in (44,65):
            compact=next(c for c in m if int(c.get("parameter"))==p and c.get("strategy")=="compact")
            cached=next(c for c in m if int(c.get("parameter"))==p and c.get("strategy")=="cached")
            compact.attrib.clear();compact.attrib.update(cached.attrib)
            compact.attrib.update(strategy="compact",profile="1",dispatch="budget-selected")
            caps[p,"compact"]=caps[p,"cached"];bounds[p,"compact"]=bounds[p,"cached"][:]
    return caps,bounds,old

def rewrite(name,s,ram,caps,bounds,old,whole,secret_cache,optimized_compact,compact_stack,frontier):
    future,matrix=SCHEDULE[ram]
    if name=="flash.ld":
        if compact_stack:s=once(s,". += 3328;",". += 2752;")
        s=re.sub(r"(ORIGIN = 0x20008000, LENGTH = )\d+K",r"\g<1>"+str(ram)+"K",s)
        s=re.sub(r"ASSERT\(__reserved_ram <= \d+,[^)]*\)",f'ASSERT(__reserved_ram <= {1024*ram}, "complete writable allocation exceeds selected budget")',s)
    if "union transaction_views {" in s:
        def fix(m):
            return m[1]+str(caps[int(m[3]),m[4]])+m[2]
        s=re.sub(r"(struct \{uint8_t before\[32\],data\[)\d+(\],after\[32\].*?\} c(\d+)_(compact|cached);)",fix,s)
        if name=="dispatch.c":
            s=re.sub(r"(?m)^( \{(\d+),([12]),)\d+(,sizeof\(combined_storage)",lambda m:m[1]+str(caps[int(m[2]),"compact" if m[3]=="1" else "cached"])+m[4],s)
        if name=="registry.c" and ram==24:
            a=re.search(r"static const f407_route cfg_c87_compact=\{(.*?)\n\};",s,re.S)[1]
            b=re.search(r"static const f407_route cfg_c87_cached=\{(.*?)\n\};",s,re.S)[1]
            # Only replace function pointers. Selection, identity, guards and storage stay profile-specific.
            s=once(s,b,b[:b.index(".init=")]+a[a.index(".init="):])
            if optimized_compact:
                for p in (44,65):
                    left=re.search(r"static const f407_route cfg_c"+str(p)+r"_compact=\{(.*?)\n\};",s,re.S)[1]
                    right=re.search(r"static const f407_route cfg_c"+str(p)+r"_cached=\{(.*?)\n\};",s,re.S)[1]
                    s=once(s,left,left[:left.index(".init=")]+right[right.index(".init="):])
    if name=="target_workspace.c":
        m=re.search(r"if \(parameter != (44|65|87) \|\|",s)
        if m:
            p=int(m[1]);arr=re.search(r"aligned\[3\] = \{(\d+)u,(\d+)u,(\d+)u\}",s)
            if arr:
                keys=[st for st in ("compact","cached") if [int(v) for v in arr.groups()]==old[p,st]]
                if keys:
                    arrnew=bounds[p,keys[0]]
                    s=once(s,arr[0],"aligned[3] = {"+",".join(str(v)+"u" for v in arrnew)+"}")
    low=re.fullmatch(r"kernel-(44|65|87)-native.c",name)
    if low:
        p=int(low[1]);s=low_kernel(s,p,4 if compact_stack and p==87 else RETAINED[p])
        if whole:s=key_verify_columns(s,p,compact_stack)
    fast=re.fullmatch(r"kernel-(44|65|87)-paired.c",name)
    if fast and (ram!=24 or int(fast[1])!=87):
        p=int(fast[1]);s=fast_kernel(s,p,future[p],matrix[p],secret_cache if p==87 else 0)
        if p==87 and frontier and frontier!="dual":s=matrix_prefix(s,5,85 if frontier=="matrix85" else 0) if frontier.startswith("matrix") else group_prefix(s,int(frontier[-1]))
    if name=="dsa_sign_shared.c":
        s=once(s,"unsigned can_look_ahead;","unsigned can_look_ahead;\n    uint8_t *output;")
        if secret_cache:s=once(s,"uint8_t *output;","uint8_t *output;\n    const uint8_t *key_ntt;")
        if frontier and frontier!="dual":s=once(s,"uint8_t *output;","uint8_t *output;\n    uint8_t *extra;")
        s=once(s,"state.look.pending=state.slot[D_PENDING];","state.look.output=sig;state.look.pending=state.slot[D_PENDING];")
        s=once(s,"state.look.can_look_ahead=state.look.pending &&","state.look.can_look_ahead=")
    return s

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("kib",type=int,choices=SCHEDULE)
    ap.add_argument("--resident",type=Path,default=HERE.parent)
    ap.add_argument("--output",type=Path,required=True)
    ndk=Path(os.environ.get("LOCALAPPDATA","."))/"Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin"
    ap.add_argument("--llvm-bin",type=Path,default=Path(os.environ.get("LLVM_BIN",ndk)))
    ap.add_argument("--arm-as",type=Path,default=os.environ.get("ARM_AS") or shutil.which("arm-none-eabi-as"))
    ap.add_argument("--jobs",type=int,default=6)
    ap.add_argument("--compact-image",action="store_true",help="lossless public KAT regeneration, shared FO and size-optimized service")
    ap.add_argument("--reference",action="store_true",help="use unchanged pqm4 arithmetic and a 10432-byte reserved stack at 24 KiB")
    ap.add_argument("--all-operation-cache",action="store_true",help="spend the same bounded RAM on keygen, verify and sign in disjoint lifetimes")
    ap.add_argument("--sign-key-cache",action="store_true",help="spend remaining high-profile workspace on transforms of the first s1 columns")
    ap.add_argument("--optimize-compact-dispatch",action="store_true",help="use benchmark-selected per-parameter signing schedules inside the 24 KiB deployment")
    ap.add_argument("--grouped-mask",action="store_true",help="decode fixed public-size groups of four 18-bit or two 20-bit ExpandMask coefficients")
    ap.add_argument("--mont-product",action="store_true",help="use high-word exact Cortex-M4 Montgomery product in fused streamed matrix rows")
    ap.add_argument("--compact-stack",action="store_true",help="24-KiB configuration: reserve 2752 stack bytes and give the released SRAM to low-bit row and verify column storage")
    ap.add_argument("--frontier",choices=("dual","triple3","triple4","matrix5","matrix85"),help="use the dedicated 32-KiB ML-DSA-87 workspace for this matched scheduling ablation")
    a=ap.parse_args();root=a.resident.resolve();out=a.output.resolve()
    if a.compact_stack and not (a.kib==24 and a.all_operation_cache and a.optimize_compact_dispatch):raise ValueError("compact stack belongs to the complete compact deployment")
    if a.frontier and (a.kib!=32 or a.sign_key_cache):raise ValueError("frontier replaces the 32 KiB secret transform cache")
    saved=({28:1,32:5}[a.kib] if a.sign_key_cache else 0)
    if out.is_relative_to(root):raise ValueError("build output inside protected source tree")
    out.mkdir(parents=True,exist_ok=True)
    kind="balanced-reference" if a.reference else ("integrated-twist" if a.kib==32 else "integrated-28")
    config=ET.parse(root/"configurations"/(kind+".xml")).getroot()
    mapped={}
    if (root/"inputs.tsv").is_file():
        source=root.parents[2]
        with (root/"inputs.tsv").open(encoding="utf-8",newline="") as fi:
            for row in csv.DictReader(fi,delimiter="\t"):
                base=source if row["root"]=="source" else source.parents[1]
                f=(base/row["source"]).resolve()
                if not f.is_relative_to(base):raise ValueError("bad path "+row["source"])
                mapped[row["input"]]=f
    def bound(e):
        logical=e.get("path");f=mapped.get(logical,(root/logical).resolve())
        if Path(logical).is_absolute() or ".." in Path(logical).parts or sha(f)!=e.get("sha256"):raise ValueError("source binding "+str(f))
        return f
    files={e.get("id"):bound(e) for e in config.find("sources")}
    m=ET.parse(bound(config.find("manifest"))).getroot()
    if a.reference:
        if a.kib!=24 or not a.compact_image:raise ValueError("same-budget reference expects 24 --compact-image")
        caps={(int(c.get("parameter")),c.get("strategy")):int(c.get("workspace_capacity")) for c in m}
        m.set("stack_capacity","10432")
    else:
        caps,bounds,old=geometry(m,a.kib,a.all_operation_cache,saved,a.optimize_compact_dispatch,a.compact_stack,a.frontier)
        if a.compact_stack:m.set("stack_capacity","2752")
    changes={}
    operators=HERE/"fixture"
    if a.compact_image:
        from public_fixture_view import materialize
        sys.path.insert(0,str(operators))
        import replay,share_fo
        if a.reference:import replay_reference as replay
        public_json=materialize(operators/"nist-sigver-projection.tsv",out/"public-fixture")
        replay.SOURCE=public_json.parent
        for name in ("fixture.c","fixture_hash.c","replay.py","nist-sigver-projection.json","share_fo.py","runtime_shift.S"):
            changes["fixture/"+name]=sha(public_json if name=="nist-sigver-projection.json" else operators/name)
        if a.reference:changes["fixture/replay_reference.py"]=sha(operators/"replay_reference.py")
        else:assert all(cap>=(2432 if p<100 else 3072) for (p,st),cap in caps.items())
    if a.grouped_mask:
        sys.path.insert(0,str(operators))
        from gamma_small import small
        changes["fixture/gamma_small.py"]=sha(operators/"gamma_small.py")
    if a.mont_product:
        sys.path.insert(0,str(operators))
        from mont_product import apply as fast_mont
        changes["fixture/mont_product.py"]=sha(operators/"mont_product.py")
    common_fo=None
    for i,fp in list(files.items()):
        if fp.suffix not in (".c",".ld"):continue
        prior=text(fp)
        if a.reference:
            new=prior
            if fp.name=="flash.ld":
                new=once(new,"LENGTH = 32K","LENGTH = 24K")
                new=once(new,". += 11008;",". += 10432;")
                new=once(new,"<= 32768,","<= 24576,")
        else:new=rewrite(fp.name,prior,a.kib,caps,bounds,old,a.all_operation_cache,saved,a.optimize_compact_dispatch,a.compact_stack,a.frontier)
        dsa=re.fullmatch(r"kernel-(44|65|87)-(?:native|paired)\.c",fp.name)
        if a.grouped_mask and dsa:new=small(new,int(dsa[1]))
        if a.mont_product and dsa:new=fast_mont(new,int(dsa[1]))
        if a.compact_image:
            kernel=re.fullmatch(r"kernel-(512|768|1024)-(combined|ntt)\.c",fp.name)
            if kernel and not a.reference:
                new,parts=share_fo.apply(new,int(kernel[1]),kernel[2])
                normalized=[re.sub(r"\s+","",p) for p in parts]
                if common_fo is None:common_fo=normalized
                if normalized!=common_fo:raise ValueError("non-identical FO bodies")
            if fp.name in ("instances.c","transaction.c"):
                new=replay.transform(new,fp.name,local_scratch=True) if a.reference else replay.transform(new,fp.name)
        if new!=prior:
            f=out/"generated"/i/fp.name;put(f,new);files[i]=f;changes[i]=sha(f)
    extras=[]
    if a.compact_image:
        clang=a.llvm_bin/"clang.exe"
        arm=["--target=arm-none-eabi","-mcpu=cortex-m4","-mthumb"]
        f=out/"fixture.o"
        capture([clang,*arm,"-mfloat-abi=soft","-ffreestanding","-fno-builtin","-ffunction-sections","-fdata-sections","-Os","-c",operators/"fixture.c","-o",f],out)
        shift=out/"shift.o";lib=out/"libshift.a"
        capture([clang,*arm,"-c",operators/"runtime_shift.S","-o",shift],out)
        capture([a.llvm_bin/"llvm-ar.exe","rcs",lib,shift],out)
        extras=[f,lib]
    ii=next(i for i,p in files.items() if p.name=="board.c")
    tag=hashlib.sha256(json.dumps([m.get("sha256"),a.kib,sorted(changes.items())]).encode()).digest()[:16]
    board,n=re.subn(r"(static const uint32_t tag\[4\]\s*=\s*)\{[^}]+\}",lambda x:x[1]+"{"+",".join(hex(v)+"u" for v in struct.unpack("<4I",tag))+"}",text(files[ii]))
    assert n==1
    board_c=out/"generated"/ii/"board.c";put(board_c,board);files[ii]=board_c;changes[ii]=sha(board_c)
    nodes={e.get("id"):e for e in config.find("build")};done=set();observed={}
    def execute(i):
        unit=nodes[i];dst=out/unit.get("file");dst.parent.mkdir(parents=True,exist_ok=True)
        cwd=out;argv=[]
        for item in unit:
            if item.tag=="arg":argv.append(item.text)
            elif item.tag=="source":argv.append((item.get("prefix") or "")+str(files[item.get("id")]))
            elif item.tag=="input":argv.append(str(out/nodes[item.get("id")].get("file")))
            elif item.tag=="output":argv.append(str(dst))
            elif item.tag=="map":argv.append("-Map="+str(out/"stm32f407-unified.map"))
            else:raise ValueError(item.tag)
        tool=unit.get("tool");exe=a.llvm_bin/(tool+".exe")
        if a.compact_image and tool=="clang" and "-Os" in argv:
            cold={"public.c","adapter.c","resource_plan.c","transaction.c","registry.c","dispatch.c","board.c","identity.c","usb.c","usb_control.c","usb_standard.c","usb_microsoft.c","usb_dwc_common.c","usb_f107.c","rcc_common_all.c"}
            if Path(argv[argv.index("-c")+1]).name in cold:argv[argv.index("-Os")]="-Oz"
        if tool=="ld.lld" and dst.suffix==".elf":
            output=argv.index("-o");argv[output:output]=list(map(str,extras))
        if tool=="arm-none-eabi-as":
            if not a.arm_as:raise ValueError("specify GNU assembler with --arm-as")
            exe=a.arm_as;f=Path(argv[-1]);cwd=dst.parent;shutil.copyfile(f,cwd/f.name)
            argv[-1]=f.name;argv[argv.index("-o")+1]=dst.name
        capture([exe,*argv],cwd)
        return i,sha(dst)
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        while len(done)<len(nodes):
            ready=[i for i,u in nodes.items() if i not in done and all(v.get("id") in done for v in u.findall("input"))]
            if not ready:raise ValueError("cyclic build specification")
            observed.update(pool.map(execute,ready));done.update(ready)
    elf=out/"stm32f407-unified.elf";binfile=elf.with_suffix(".bin")
    symbols={t[2]:int(t[0],16) for line in capture([a.llvm_bin/"llvm-nm.exe","-n",elf],out).splitlines() if len(t:=line.split())==3}
    full=symbols["__reserved_ram"];size=binfile.stat().st_size
    assert size==symbols["__image_bytes"] and full<=1024*a.kib and tag in binfile.read_bytes()
    area=max(int(i.get("transaction_bytes")) for i in m)
    m.attrib.update(full_reserved_ram_bytes=str(full),ram_budget_bytes=str(1024*a.kib),headroom_bytes=str(1024*a.kib-full),
         workspace_capacity=str(max(caps.values())),transaction_union_bytes=str(area),non_union_ram_bytes=str(full-area),
         sha256=sha(binfile),elf_sha256=sha(elf),tag=tag.hex(),image_bytes=str(size),end_exclusive=hex(int(m.get("base"),0)+size),
         layout="pqm4-reserved-stack-10432" if a.reference else "sign-output-"+str(a.kib),kat_representation="lossless-public-reconstruction" if a.compact_image else "embedded-bytes")
    ET.indent(m);ET.ElementTree(m).write(elf.with_suffix(".xml"),encoding="utf-8",xml_declaration=True)
    put(out/"source-bindings.tsv","id\torigin\teffective_sha256\n"+"".join(i+"\t"+config.find("sources").find(f"file[@id='{i}']").get("path")+"\t"+sha(p)+"\n" for i,p in files.items()))
    put(out/"objects.tsv","id\tfile\tsha256\n"+"".join(i+"\t"+nodes[i].get("file")+"\t"+h+"\n" for i,h in sorted(observed.items())))
    print(a.kib,"KiB",full,"RAM",size,"Flash",sha(binfile))

if __name__=="__main__":main()
