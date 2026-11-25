# Linux / AArch64 普通接口回归与检测器重放

本说明给出 Linux 本地库回归检查的源码、配置和命令。

已测核心源提交为 `20f877df0dab0f68058b548c5a0af3c457212b76`，环境为 Linux AArch64、GCC 11.4.0。三种配置 `compact-fixed`、`stream40`、`staged56-s3` 各有 portable C 与 AArch64 后端的独立 ASan+UBSan 构建。实际原生发布库另做相同普通回归；只有 AArch64 C 部分得到编译器检测器插桩，汇编没有插桩。portable 指在该 AArch64 主机运行的 C 后端。

## 源码与配置依赖

从完整工程根目录取用以下文件及其正常 include 依赖，不抽取或重写算法实现：

- `tests/robustness/sequence.c`：固定边界、固定种子接口序列及本地产生对象的变异回归。
- `tests/robustness/prefix_cleanup.c`：秘密前缀释放前观察器，仅用于指定的三多项式前缀配置。
- `tools/build_variants.py`、`tools/binary_build_utils.py`、`tests/public_api/probe.c`：实际构建配方、产物记录及 shared/static 公开接口检查。
- `include/`、`configs/hosted/`、`baselines/mlkem/all.c`、`build/adapted_mlkem/`、`src/kem/`、`src/dsa_compact/build/sign_bitmap_stream_alias/adapted/`、`src/dsa_packed/`、`src/common/`、`src/platform/`：本次配置使用的头文件和编译单元。保留工程内第三方实现的原有 include 树和许可证。

精确到文件的依赖由实际 GCC `-MMD` 结果收集到各包 `build.xml.source_hashes`；命令参数、退出码和日志 SHA 在 `commands.xml`。读取者应核对整个源码树及实际 `.so`/`.a` 的 SHA，不能仅凭相同配置名称视为同一个产物。不同工具链重新构建的文件哈希可不同，应保留自己的新清单。

三种配置共享以下定义：`LC_KEM_NOISE_CACHE=0`，`LC_DSA_ALIAS_SIGN_CP=1`，`LC_DSA_ALIAS_VERIFY_TMP=1`，`LC_DSA_STREAM_KEYGEN=1`，`LC_DSA_PACK_W0=1`，`LC_DSA_W0_CODEC=1`，`LC_DSA_A_CACHE_BITS=24`，`LC_DSA_RETAIN_FULL_HIGH=0`，以及 `MLD_CONFIG_REDUCE_RAM`。

| 配置 | KEM rows / batch | A cache poly | SIGN_ONLY | BATCH4 | STREAM_BATCH4 | S1_CACHE_POLYS |
|---|---:|---:|---:|---:|---:|---:|
| compact-fixed | 1 / 1 | 0 | 0 | 0 | 0 | 0 |
| stream40 | 2 / 4 | 40 | 1 | 1 | 1 | 0 |
| staged56-s3 | 2 / 4 | 56 | 1 | 1 | 0 | 3 |

表头后的 DSA 宏分别为 `LC_DSA_A_CACHE_POLYS`、`LC_DSA_A_CACHE_SIGN_ONLY`、`LC_DSA_A_CACHE_BATCH4`、`LC_DSA_A_STREAM_BATCH4`、`LC_DSA_S1_CACHE_POLYS`。AArch64 后端另定义 `LC_NATIVE`、`MLD_CONFIG_USE_NATIVE_BACKEND_ARITH`、`MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202`，并链接原生 `.S` 编译单元；portable 不启用这些选项。每个 DSA 参数分别编译 `MLD_CONFIG_PARAMETER_SET=44/65/87`，44 使用 `MLD_CONFIG_MULTILEVEL_WITH_SHARED`，另两个使用 `MLD_CONFIG_MULTILEVEL_NO_SHARED`。KEM 由原工程的 `baselines/mlkem/all.c` 汇合三个参数，不用手工删减。

检测构建的实际公共编译参数为 `-O3 -g -std=c11 -ffunction-sections -fdata-sections -fno-omit-frame-pointer -fstack-usage -Wall -Wextra -fPIC -fsanitize=address,undefined -fno-sanitize-recover=all`，AArch64 后端增加 `-mcpu=neoverse-n1`；本次没有 LTO。共享库链接保留 `-shared -Wl,-z,defs -Wl,-z,noexecstack`、导出映射、`--gc-sections`、map 和检测器运行库。下列 `build_variants.py` 命令生成完整参数数组，不需要手工复制每个编译单元的长命令。

## 本地目录和检测器阳性对照

将 `SRC` 替换为完整工程根目录，`OUT` 替换为一个尚不存在的本地输出目录；`NATIVE` 指包含三种对应原生发布包子目录的目录。

```bash
set -eu
export SRC=/path/to/latticecore
export OUT=/path/to/new-linux-regression
export NATIVE=/path/to/native-release-packages
test -f "$SRC/include/latticecore.h"
test ! -e "$OUT"
mkdir -p "$OUT/tmp"
export TMPDIR="$OUT/tmp"
export PYTHONDONTWRITEBYTECODE=1
export ASAN_OPTIONS=halt_on_error=1:detect_leaks=0
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
gcc --version > "$OUT/compiler.txt"
gcc -print-file-name=libasan.so > "$OUT/libasan-path.txt"
gcc -print-file-name=libubsan.so > "$OUT/libubsan-path.txt"
```

确认输出路径指向实际存在的 `libasan.so` 和 `libubsan.so`，并保存运行库 SHA。原检查对每个配置/后端均运行下列两个阳性对照。它们必须产生非零退出和对应检测器报告；未检出时不能把后续“没有报告”解释为通过。

```bash
cat > "$OUT/asan_positive.c" <<'EOF'
#include <stdlib.h>
int main(int n,char**v){volatile unsigned char*p=malloc(8);(void)v;p[n+15]=7;free((void*)p);return 0;}
EOF
cat > "$OUT/ubsan_positive.c" <<'EOF'
#include <limits.h>
int main(void){volatile int a=INT_MAX,b=1;volatile int c=a+b;return c==0;}
EOF
gcc -O2 -g -fsanitize=address -fno-sanitize-recover=all \
  "$OUT/asan_positive.c" -o "$OUT/asan_positive"
gcc -O2 -g -fsanitize=undefined -fno-sanitize-recover=all \
  "$OUT/ubsan_positive.c" -o "$OUT/ubsan_positive"
if "$OUT/asan_positive" > "$OUT/asan_positive.log" 2>&1; then RC=0; else RC=$?; fi
printf '%s\n' "$RC" > "$OUT/asan_positive.exit"
test "$RC" -ne 0
grep -q AddressSanitizer "$OUT/asan_positive.log"
grep -q heap-buffer-overflow "$OUT/asan_positive.log"
if "$OUT/ubsan_positive" > "$OUT/ubsan_positive.log" 2>&1; then RC=0; else RC=$?; fi
printf '%s\n' "$RC" > "$OUT/ubsan_positive.exit"
test "$RC" -ne 0
grep -q 'runtime error' "$OUT/ubsan_positive.log"
grep -q 'signed integer overflow' "$OUT/ubsan_positive.log"
```

ASan 日志须同时包含 `AddressSanitizer` 和 `heap-buffer-overflow`；UBSan 须同时包含 `runtime error` 和 `signed integer overflow`。同时保存两个预期失败命令的退出码。

## 六个独立检测构建与固定输入

对配置表中的三项和 `portable`、`aarch64` 两个后端分别执行。示例先给一个组合，将 `CONFIG`、`BACKEND` 替换为其余五个组合即可。每个组合应有自己的新输出目录与阳性对照记录。

```bash
CONFIG=staged56-s3
BACKEND=aarch64
CASE="$OUT/$CONFIG-$BACKEND"
mkdir "$CASE"
PKG="$CASE/package"
python3 -B "$SRC/tools/build_variants.py" \
  --output "$PKG" --config "$CONFIG" --backend "$BACKEND" \
  --opt O3 --sanitize address,undefined --probe-count 100 \
  > "$CASE/build.log" 2>&1
gcc -O2 -g -std=c11 -fsanitize=address,undefined \
  -fno-sanitize-recover=all -I"$SRC/include" \
  "$SRC/tests/robustness/sequence.c" \
  -L"$PKG" -llatticecore -Wl,-rpath,"$PKG" \
  -o "$CASE/instrumented_sequence"
```

必须先确认构建命令 exit 0、`build.xml` 存在且 shared/static probe 成功，并核对 `build.xml.schedule` 与上表。任何一步非零都停止该组合并保留失败，不能继续使用残留文件。若本地还没有作为对照的原生发布包，可以用同一工具、同一配置、`--backend aarch64 --opt O3 --sanitize none --probe-count 100` 构建到另一个新目录；应明确它是本地新产物，而不是原实验 `.so` 的相同二进制。

三个实际固定种子和每个参数的输入规模如下。每次程序调用依次检查 512、768、1024、44、65、87；每个参数为 2,048 步普通接口序列及两个解析目标各 10,000 次本地对象变异。

```bash
for SEED in a127202609240001 a127202609240002 a127202609240003; do
  RUN="$CASE/instrumented-$SEED"
  mkdir "$RUN"
  if (cd "$RUN" && "$CASE/instrumented_sequence" "$SEED" 2048 10000 \
    > stdout.log 2> stderr.log); then RC=0; else RC=$?; fi
  printf '%s\n' "$RC" > "$RUN/exit_code.txt"
  test "$RC" -eq 0
done
```

每个日志须有六条 JSON 结果，参数顺序正确、种子相同、`status` 均为 `PASS`，且进程 exit 0。实际计划不丢弃失败输入、不自动重试；程序若发现错误会留下 `failure.xml`，并在有具体输入时保存 `failure_input.bin`。执行前应保证 `CASE` 为绝对路径，以免切换工作目录后找不到可执行文件。

## 实际原生库的同输入检查

三种配置的实际原生 `.so` 分别运行以下构建及相同的三个种子。它们不使用检测器，包含实际汇编路径。开始和结束均核对 `.so`、`.a` 与 `build.xml` 的 SHA；与检测构建比较 `schedule` 和源文件 SHA，不能把后端不同误写成同一个可执行文件。

```bash
RELEASE="$NATIVE/$CONFIG"
gcc -O2 -std=c11 -I"$SRC/include" \
  "$SRC/tests/robustness/sequence.c" \
  -L"$RELEASE" -llatticecore -Wl,-rpath,"$RELEASE" \
  -o "$CASE/release_sequence"
for SEED in a127202609240001 a127202609240002 a127202609240003; do
  RUN="$CASE/release-$SEED"
  mkdir "$RUN"
  if (cd "$RUN" && "$CASE/release_sequence" "$SEED" 2048 10000 \
    > stdout.log 2> stderr.log); then RC=0; else RC=$?; fi
  printf '%s\n' "$RC" > "$RUN/exit_code.txt"
  test "$RC" -eq 0
done
```

实际检查要求同种子、同参数的六条结果对象与检测版本一致。`transcript_fnv64` 仅是辅助回归摘要，不能替代另外完成的标准向量、整操作逐字节差分或独立互操作。普通序列本身还执行有效封装/解封装共享秘密相等、签名/验签、容量失败后的恢复及错误输出检查。

本工具故意提供 262,144 B 的可访问测试工作区并有小容量失败分支。这不测最小部署容量，也不能用它推导 64 KiB 资源结论；最小成功容量、保护栈和映像分账由资源方法另行测量。

## 三多项式秘密前缀的释放前观察

仅对原生 `staged56-s3` 的实际静态库执行以下命令。观察器使用链接包装而不改库内核心代码，匹配此源码顺序中的首个 3,072 B 签名分配；若分配顺序、前缀大小或源码变更，须重新核查该识别条件。

```bash
RELEASE="$NATIVE/staged56-s3"
gcc -O2 -std=c11 -I"$SRC/include" -I"$SRC/src/dsa_packed" \
  "$SRC/tests/robustness/prefix_cleanup.c" \
  "$RELEASE/liblatticecore.a" \
  -Wl,--wrap=lc_dsa_alloc -Wl,--wrap=lc_dsa_free \
  -o "$OUT/prefix_cleanup"
"$OUT/prefix_cleanup" > "$OUT/prefix_cleanup.log" 2>&1
printf '%s\n' "$?" > "$OUT/prefix_cleanup.exit"
```

须有 `PREFIX_ERASURE_DETECTOR_POSITIVE_CONTROL_PASS`，以及 44/65/87 三条结果，每参数 18 次固定签名、交替两个序列化密钥、复用同一上下文，并观察到前缀释放前全部归零。实际合计 54 次。阳性对照确认观察器能拒绝非零残留。

## 已测计数与检测范围

已执行六个独立检测构建，共 108 个参数/种子记录；三个实际原生库另有 54 个记录。每个检测构建分别运行 ASan 与 UBSan 阳性对照，合计 12 次均检出。计数为跨配置/构建的执行次数，包含重复输入。

回归使用本工程生成的密钥、密文和签名，覆盖接口、格式、容量失败与恢复。ASan/UBSan 检查插桩 C 路径，arena 子对象边界另用保护字节检查；`detect_leaks=0` 关闭 LeakSanitizer。
