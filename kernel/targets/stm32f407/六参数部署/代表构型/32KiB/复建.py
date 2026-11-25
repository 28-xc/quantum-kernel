"""Rebuild one registered STM32 image. Compare compiled bytes before emitting its public manifest."""
from pathlib import Path
from xml.etree import ElementTree as ET
import argparse,hashlib,shutil
from rebuild_embedded import rebuild
def main():
    a=argparse.ArgumentParser()
    for k in ('output','llvm','gas'):a.add_argument(k,type=Path)
    p=a.parse_args();here=Path(__file__).resolve().parent;out=p.output.resolve()
    manifest=here/'measured.xml';root=ET.parse(manifest).getroot()
    rebuild(here/'recipe.xml',out,p.llvm.resolve(),p.gas.resolve())
    bn=out/'stm32f407-unified.bin';elf=bn.with_suffix('.elf');h=lambda x:hashlib.sha256(x.read_bytes()).hexdigest()
    if h(bn)!=root.get('sha256') or h(elf)!=root.get('elf_sha256') or bn.stat().st_size!=int(root.get('image_bytes')):raise ValueError('独立重建与登记的实测固件身份不一致')
    shutil.copyfile(manifest,bn.with_suffix('.xml'))
if __name__=='__main__':main()
