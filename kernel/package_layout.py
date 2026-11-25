"""Map references in the frozen capture records to their delivery locations."""

from pathlib import Path, PurePosixPath
import posixpath


SOURCE = '01_源代码/可参数化格运算内核'
TEST = '02_测试代码与数据'
RUNTIME = '03_复现环境与运行程序'
RESULT = '04_实验结果与验证材料'
EVIDENCE = '05_设备与运行记录'
OLD_RUNTIME = '02_软件演示与固件'
OLD_TEST = '03_实验数据与复现'
OLD_EVIDENCE = '04_实板与仿真运行证据'
APPLICATION = f'{RUNTIME}/完整设备接入应用'
DEMO = f'{RUNTIME}/软件演示程序'
REPLAY = f'{TEST}/复算数据'

PATHS = {
    f'{OLD_RUNTIME}/软件演示程序': DEMO,
    f'{OLD_RUNTIME}/Windows': f'{RUNTIME}/host/Windows',
    f'{OLD_RUNTIME}/AArch64': f'{RUNTIME}/host/AArch64',
    f'{OLD_RUNTIME}/CH32V307': f'{RUNTIME}/firmware/CH32V307',
    f'{OLD_RUNTIME}/STM32F407': f'{RUNTIME}/firmware/STM32F407',
    f'{OLD_RUNTIME}/Cortex-M4_QEMU': f'{RUNTIME}/仿真/Cortex-M4_QEMU',
    f'{OLD_RUNTIME}/RV32IM_QEMU': f'{RUNTIME}/仿真/RV32IM_QEMU',
    f'{OLD_RUNTIME}/完整设备接入应用': APPLICATION,
    f'{OLD_TEST}/01_标准向量与互操作验证': f'{TEST}/correctness',
    f'{OLD_TEST}/02_实现安全与时序检测': f'{TEST}/security',
    f'{OLD_TEST}/03_完整密码操作性能': f'{TEST}/performance/完整密码操作',
    f'{OLD_TEST}/04_多项式运算性能': f'{TEST}/performance/多项式运算',
    f'{OLD_TEST}/05_CH32V307性能与资源': f'{TEST}/resources/CH32V307',
    f'{OLD_TEST}/06_完整设备接入实验': f'{TEST}/performance/完整接入',
    f'{OLD_TEST}/07_关键优化机制对照': f'{TEST}/ablation',
    f'{OLD_TEST}/08_构建记录与统计复算': REPLAY,
    f'{OLD_TEST}/实验结果汇总.xlsx': f'{RESULT}/performance/实验结果汇总.xlsx',
    f'{OLD_TEST}/实验结果索引.xlsx': f'{RESULT}/performance/实验结果索引.xlsx',
    OLD_RUNTIME: RUNTIME,
    OLD_TEST: TEST,
    OLD_EVIDENCE: EVIDENCE,
}
FORWARD = sorted(PATHS.items(), key=lambda row: len(row[0]), reverse=True)
REVERSE = sorted(((new, old) for old, new in PATHS.items()),
                 key=lambda row: len(row[0]), reverse=True)


def _prefix(value, rules):
    for old, new in rules:
        if value == old or value.startswith(old + '/'):
            return new + value[len(old):]
    return value


def relocated(value):
    return _prefix(str(value).replace('\\', '/'), FORWARD)


def package_root(path):
    path = Path(path).resolve()
    for candidate in (path, *path.parents):
        if (candidate / SOURCE / 'record_io.py').is_file() and (candidate / RUNTIME).is_dir():
            return candidate
    raise FileNotFoundError('Could not identify delivery root')


def bound(root, value):
    root = Path(root).resolve()
    relative = PurePosixPath(relocated(value))
    if relative.is_absolute() or '..' in relative.parts or ':' in relative.as_posix():
        raise ValueError('Delivery reference is not package-relative')
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        raise ValueError('Delivery reference escapes its package')
    return target


def from_legacy_anchor(anchor, relative):
    """Resolve a relative reference from a moved capture/configuration directory."""
    anchor = Path(anchor).resolve()
    direct = (anchor / relative).resolve()
    if direct.exists() or Path(relative).is_absolute():
        return direct
    try:
        root = package_root(anchor)
    except FileNotFoundError:
        return direct
    former = _prefix(anchor.relative_to(root).as_posix(), REVERSE)
    return bound(root, posixpath.normpath(posixpath.join(former, relative)))
