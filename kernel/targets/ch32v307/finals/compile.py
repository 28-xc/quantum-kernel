"""从两套板端源码重建已登记的 CH32V307 发布 ELF、BIN 与 HEX。"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import record_io
from release_elf import canonical

ROOT=Path(__file__).resolve().parent


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strategy",choices=("high","low","both"),default="both")
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--cc",type=Path,help="已安装的 WCH riscv-none-embed-gcc.exe")
    args=parser.parse_args()
    lock=record_io.loads((ROOT/"构建锁.xml").read_bytes())
    cc=args.cc or os.environ.get("WCH_GCC") or shutil.which("riscv-none-embed-gcc.exe")
    if not cc:parser.error("请用 --cc 指定已安装的 WCH GCC 8.2.0，或设置 WCH_GCC。")
    cc=Path(cc).resolve(strict=True)
    for rel,digest in lock["tools"].items():
        if file_hash(cc.parent.parent/rel)!=digest:raise ValueError("工具文件身份不符 "+rel)
    if args.out.exists():raise ValueError("请指定新的输出目录")
    args.out.mkdir(parents=True)
    for role,p in lock["strategies"].items():
        if args.strategy not in ("both",role):continue
        src=ROOT/"sources"/role
        for rel,digest in p["integration_files"].items():
            if file_hash(src/rel)!=digest:raise ValueError("构建入口变化 "+rel)
        target=src/"targets/ch32v307"
        if file_hash(target/"profiles"/p["name"]/"recipe.xml")!=p["recipe_sha256"]:
            raise ValueError("源配方身份变化")
        with tempfile.TemporaryDirectory(prefix="ch32build-") as tmp:
            scratch=Path(tmp);work=scratch/"build"
            if not scratch.as_posix().isascii():
                raise ValueError("WCH 工具需使用 ASCII 临时目录，请将 TEMP 设为已有的 ASCII 目录。")
            subprocess.run([sys.executable,"-B",str(target/"build_research.py"),"--profile",p["name"],
                "--output",str(work),"--cc",str(cc)],cwd=tmp,check=True,env={**os.environ,"PYTHONUTF8":"1"})
            result=record_io.loads((work/"result.xml").read_bytes())
            assert result["build_id"]==p["build_id"] and result["resources"]==p["resources"]
            elf=canonical((work/"latticecore-live.elf").read_bytes())
            assert hashlib.sha256(elf).hexdigest()==p["release_elf_sha256"]
            out=args.out/role;out.mkdir()
            for ext in ("bin","hex"):
                f=work/("latticecore-live."+ext)
                assert file_hash(f)==p["artifacts"][ext]
                shutil.copyfile(f,out/("firmware."+ext))
            (out/"firmware.elf").write_bytes(elf)
            (out/"构建复核.xml").write_text(record_io.dumps({"build_id":p["build_id"],
                "release_elf_sha256":p["release_elf_sha256"],"actual_measured_elf_sha256":p["artifacts"]["elf"],
                "bin_sha256":file_hash(out/"firmware.bin"),"hex_sha256":file_hash(out/"firmware.hex"),
                "resources":p["resources"]}),encoding="utf8")
            print(role,p["name"],p["release_elf_sha256"],flush=True)


if __name__=="__main__":main()
