"""Build one of the three resident STM32F407 configurations from the shared source tree."""
import argparse,os,shutil,subprocess,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE=HERE.parents[2]
PACKAGE=SOURCE.parents[1]
sys.path.insert(0,str(SOURCE/"targets"))
from input_tree import materialize
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("configuration",choices=("integrated-28","independent-28","integrated-twist"))
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--llvm-bin",type=Path,default=os.environ.get("LLVM_BIN"))
    parser.add_argument("--arm-as",type=Path,default=os.environ.get("ARM_AS"))
    parser.add_argument("--jobs",type=int,default=4)
    parser.add_argument("--project-polynomials-only",action="store_true")
    args=parser.parse_args();out=args.output.resolve()
    if out.is_relative_to(PACKAGE.resolve()):parser.error("输出目录须位于支撑材料以外")
    if args.llvm_bin is None:
        known=Path(os.environ.get("LOCALAPPDATA","."))/"Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin"
        if (known/"clang.exe").is_file():args.llvm_bin=known
    if args.arm_as is None:
        picked=shutil.which("arm-none-eabi-as")
        if picked:args.arm_as=Path(picked)
    if args.arm_as is None:parser.error("请用 --arm-as 指定 GNU Arm Embedded 13.2.rel1 汇编器")
    with tempfile.TemporaryDirectory(prefix="f407-src-") as temp:
        view=materialize(HERE/"inputs.tsv",SOURCE,Path(temp)/"source",PACKAGE)
        cmd=[sys.executable,"-B",str(view/"build.py"),args.configuration,"--output",str(out),"--arm-as",str(args.arm_as.resolve()),"--jobs",str(args.jobs)]
        if args.llvm_bin:cmd+=["--llvm-bin",str(args.llvm_bin.resolve())]
        if args.project_polynomials_only:cmd.append("--project-polynomials-only")
        subprocess.run(cmd,check=True)
if __name__=="__main__":main()

