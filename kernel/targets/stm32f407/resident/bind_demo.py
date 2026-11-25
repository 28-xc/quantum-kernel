"""Bind one checked resident firmware to the existing dual-board Windows launcher."""
import argparse,hashlib,os,shutil,subprocess,sys,tempfile,xml.etree.ElementTree as ET
from pathlib import Path
SRC=Path("01_源代码/可参数化格运算内核")
ENTRY=Path("03_复现环境与运行程序/软件演示程序/入口")
FIRM=Path("03_复现环境与运行程序/firmware/STM32F407/固件")
BOOT=(ENTRY/"fast_launch.py",ENTRY/"prepared/manifest.xml",ENTRY/"prepared/build-inputs.xml")
def safe_copy(src,dst):
    dst.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=dst.parent,delete=False) as tmp:
        name=tmp.name
        with src.open("rb") as f:shutil.copyfileobj(f,tmp)
    try:os.replace(name,dst)
    finally:Path(name).unlink(missing_ok=True)
def bind(base,image,lab,overlay):
    base=base.resolve(strict=True);image=image.resolve(strict=True);lab=lab.resolve();overlay=overlay.resolve()
    if lab==overlay or lab.is_relative_to(base) or base.is_relative_to(lab) or overlay.is_relative_to(base) or base.is_relative_to(overlay) or overlay.is_relative_to(lab) or lab.is_relative_to(overlay):
        raise ValueError("use separate siblings for the source package, overlay and dry-run package")
    scripts=("demo/f407_provider.py","targets/stm32f407/qualified_engine.py","tools/update_demo_manifest.py")
    if not all((base/SRC/n).is_file() for n in scripts) or not any((base/SRC/"demo").glob("*ch32*")):raise ValueError("a checked dual-board package is required")
    root=ET.parse(image).getroot();binary=image.with_suffix(".bin")
    sha=hashlib.sha256(binary.read_bytes()).hexdigest()
    if sha!=root.get("sha256") or binary.stat().st_size!=int(root.get("image_bytes")) or len(root)!=12:raise ValueError("incomplete or inconsistent firmware set")
    if {(int(e.get("parameter")),e.get("strategy")) for e in root}!={(p,s) for p in (512,768,1024,44,65,87) for s in ("compact","cached")}:raise ValueError("missing deployment choices")
    for rel in BOOT:safe_copy(base/rel,overlay/rel)
    names=[FIRM/"stm32f407-unified.bin",FIRM/"stm32f407-unified.xml"]
    for f,rel in zip((binary,image),names):safe_copy(f,overlay/rel)
    tool=base/SRC/scripts[-1]
    args=[sys.executable,"-B",tool,base,"--overlay",overlay]
    for rel in names:args+=["--accept",rel.as_posix()]
    subprocess.run(args,check=True)
    # The original directory and pre-existing files are never overwritten through a hard link.
    for f in base.rglob("*"):
        if not f.is_file() or "__pycache__" in f.parts:continue
        rel=f.relative_to(base);dst=lab/rel;replacement=overlay/rel
        if replacement.is_file():safe_copy(replacement,dst);continue
        if dst.exists():
            if os.path.samefile(f,dst):continue
            if f.read_bytes()!=dst.read_bytes():raise ValueError("unexpected existing file in trial directory: "+str(rel))
            continue
        dst.parent.mkdir(parents=True,exist_ok=True)
        try:os.link(f,dst)
        except OSError:shutil.copyfile(f,dst)
    subprocess.run([sys.executable,"-B",lab/SRC/scripts[-1],lab,"--check"],check=True)
    assert hashlib.sha256((lab/"启动演示软件.exe").read_bytes()).digest()==hashlib.sha256((base/"启动演示软件.exe").read_bytes()).digest()
    print("EXE",hashlib.sha256((lab/"启动演示软件.exe").read_bytes()).hexdigest(),"firmware",sha,"RAM",root.get("full_reserved_ram_bytes"))
if __name__=="__main__":
    ap=argparse.ArgumentParser();ap.add_argument("--base",type=Path,required=True);ap.add_argument("--image",type=Path,required=True);ap.add_argument("--lab",type=Path,required=True);ap.add_argument("--overlay",type=Path,required=True);a=ap.parse_args();bind(a.base,a.image,a.lab,a.overlay)

