"""Build the two CH32V307 deployment images from pinned inputs in the shared project."""
import argparse,os,shutil,subprocess,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
SRC=HERE.parents[2];PKG=SRC.parents[1]
sys.path.insert(0,str(SRC/"targets"))
from input_tree import materialize
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--strategy",choices=("high","low","both"),default="both")
    ap.add_argument("--out",type=Path,required=True)
    ap.add_argument("--cc",type=Path,default=os.environ.get("WCH_GCC") or shutil.which("riscv-none-embed-gcc.exe"))
    a=ap.parse_args()
    if not a.cc:ap.error("用 --cc 指定 WCH 的 riscv-none-embed-gcc.exe，或设置 WCH_GCC")
    dest=a.out.resolve()
    if dest.is_relative_to(PKG.resolve()):ap.error("输出目录应位于支撑材料之外")
    with tempfile.TemporaryDirectory(prefix="ch32-src-") as tmp:
        view=materialize(HERE/"inputs.tsv",SRC,Path(tmp)/"source",PKG)
        subprocess.run([sys.executable,"-B",view/"rebuild.py","--strategy",a.strategy,"--out",dest,"--cc",a.cc.resolve(strict=True)],check=True)
if __name__=="__main__":main()

