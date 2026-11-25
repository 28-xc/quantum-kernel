"""Build the bounded USB ACVP diagnostic against both pinned resident ELFs."""
import argparse
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory
import xml.etree.ElementTree as ET


def build(package, source, output):
    ring = package/'02_测试代码与数据/performance/多项式运算/完整环乘实板测量/stm32'
    sys.path.insert(0,str(ring))
    import build_driver as driver

    output.mkdir(parents=True,exist_ok=True)
    include=package/'01_源代码/可参数化格运算内核/include'
    firmware=package/'03_复现环境与运行程序/firmware/STM32F407/固件'
    manifests = {int(row.get('budget'))//1024: firmware/row.get('manifest')
                 for row in ET.parse(firmware/'部署索引.xml').getroot().findall('deployment')}
    with TemporaryDirectory() as directory:
        temporary=Path(directory)
        driver.HERE=temporary
        driver.SYMS={}
        driver.FLAGS.extend(['-I'+str(temporary),'-I'+str(include)])
        for profile, strategy in ((24,'compact'), (32,'cached')):
            name=f'{profile}KiB'
            manifest=ET.parse(manifests[profile]).getroot()
            assert manifest.get('sha256')==driver.PROD[name]
            resident=driver.ST/'images'/driver.PROD[name]/'firmware.elf'
            symbols=driver.symbols(resident)
            addresses=[symbols[f'cfg_c{p}_{strategy}'] for p in (512,768,1024,44,65,87)]
            assert len(set(addresses))==6 and all(0x08020000<=a<0x08100000 for a in addresses)
            capacities=[int(row.get('workspace_capacity')) for row in manifest.findall('implementation')
                        if row.get('strategy')==strategy]
            assert len(capacities)==6 and max(capacities)<=profile*1024 and all(n%32==0 for n in capacities)
            header=f'#define WORKSPACE {max(capacities)}\n#define STRATEGY {1 if strategy=="compact" else 2}\n'
            header+='static const resident_route *const routes[] = {\n'
            header+='\n'.join(f'  (const resident_route *)0x{a:08x}u,' for a in addresses)+'\n};\n'
            (temporary/'ring_driver.c').write_bytes(source.read_bytes()+b'\n/* ' + header.encode() + b' */\n')
            (temporary/'acvp_routes.h').write_text(header,encoding='ascii')
            driver.main(name)
            for ext in ('bin','json'):
                binary=temporary/name/f'driver.{ext}'
                if ext=='bin':
                    sp,pc=struct.unpack_from('<II',binary.read_bytes())
                    assert 0x20008000<sp<=0x20020000 and 0x20008000<pc<0x20020000 and pc&1
                (output/f'stm32-acvp-{profile}.{ext}').write_bytes(binary.read_bytes())


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    build(args.package.resolve(),Path(__file__).with_name('stm32-acvp.c'),args.output.resolve())
