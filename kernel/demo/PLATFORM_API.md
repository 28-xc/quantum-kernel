# 实时平台适配接口

界面与传输层调用已经验证的密码内核。Windows 调用 `Application.run`，ARM 在 Linux AArch64 主机执行，板端通过设备驱动接入。

## 三个执行器

- `LocalProvider(application)`：调用原应用对象，保留原返回码、容量不足后的恢复、清理与边界检查。
- `SshProvider(config)`：固定 SSH 命令启动 `tools/demo_remote.py`，仅将请求 JSON 传入 stdin；不自动重发。连接配置来自包外文件。
- `BoardProvider(exchange, image_pins)`：`exchange(request_dict)` 由板级驱动拥有者实现，并返回下述响应字典；本模块不打开串口、USB 或调试器。驱动必须先完成真实固件/启动身份和完整帧验证，再返回成功。

`image_pins` 是 `{library_id: actual_image_sha256}`。每次目录和每次运行均校验实际固件版本。板端身份同时绑定烧录与读回记录。

`demo.ch32_bridge.Ch32Exchange` 负责将设备驱动的 `SerialDevice` 映射到此接口。传入 `driver_factory`、`expected_elf_sha256`、实际 `expected_hello`、`timer_receipt={path,sha256}` 与包外绝对 `records_directory`，再将 `.provider()` 注入 `create_application(..., board_provider=...)`。工厂每次新建驱动；目录也实际握手，运行再调用 `flow(parameter,message,domain)`，不覆盖驱动的 OS CSPRNG 熵参数，最后关闭。板端使用主机测试熵。160 B 时钟原件与逐字段自测 JSON/SHA、ELF 身份一起核验；真实烧录与 ELF→build ID 对应仍由设备拥有者保证。

每次请求将原 HELLO/FLOW、驱动的原始响应记录和关闭状态保存到包外证据目录；不在公开结果中加入秘密、共享秘密摘要或主机私有路径。连接 nonce 用作主机连接标签。未运行的 API 原记录保留 `-127`，不会变成成功的零时长行；完整响应中的失败会作为真实失败显示，不自动重试。

`expected_hello` 同时核验 build ID、时钟、内存布局、`rcc_control`、`rcc_config` 和 `usart1_brr`。每次 HELLO 都与登记值逐项比较，缺项或变化即拒绝。时钟资格绑定实际固件、复位及调试器脱离状态；连接时仍核验当前返回值。

`tools/demo_unified.py --board-config external/board.xml` 提供相同注入的命令行入口；`platform_config.py` 校验闭字段、相对路径及驱动/依赖 SHA，加载配置不执行驱动模块，直到明确连接/运行请求才创建串口对象。`--check-connections` 仅做文件校验。驱动实现由设备操作者提供。

每个远程执行器提供 `catalog()`、`run(preset)` 和只读状态 `state`，一次只允许一个在途请求。会话入口共用同一把执行器锁。`state=connected` 表示最近一次完整响应通过合同校验，每次调用后刷新。

## 请求和响应

每次 stdin 是一个 UTF-8 JSON 文档，以 EOF 结束，最多 4096 字节。stdout 是一个完整 JSON 文档（最多 1 MiB）。操作数据绝不拼入远程命令。

```json
{"schema":"lattice.live_platform.v1","request_id":"0123456789abcdef0123456789abcdef","action":"run","payload":{"library":"arm-speed","parameter":87,"message_bytes":1024,"context_bytes":0,"mode":"normal"}}
```

`action=catalog` 时 payload 必须为 `{}`。`run` 的五字段与原功能 API 相同；参数为 512/768/1024/44/65/87，消息与上下文长度仍只接收原预设，KEM 两者为 0。`mode=insufficient` 表示一次具名的“不足容量调用＋恢复容量调用”流程，不是传输失败后的重试。

```json
{"schema":"lattice.live_platform.v1","request_id":"0123456789abcdef0123456789abcdef","action":"run","platform_id":"arm","session_id":"runner-process-session","sequence":1,"ok":true,"body":{}}
```

示例中的 `body` 占位必须由实际结果替换：目录为原 `Application.catalog()`；运行结果为原 `Application.run()`，保留原 `run_id`、实际 `binary_sha256` 和完整操作/检查。运行结果采用闭字段校验，不接收私钥或任意附加数据。恢复结果仍位于 `recovery`。失败 envelope 使用 `ok=false,error=有限错误标识` 且无 body，不会转成成功记录。

SSH 的 `session_id` 标识本次远端进程；板级驱动使用可核验的固件启动身份。`sequence` 在同 session 中递增。请求 ID、平台、输入、映像或顺序不匹配均拒绝；远端未返回时仅记未完成。取消 SSH 后，远端结束与清理状态由远端记录确认。

未提供设备指标时只返回功能结果，`performance_measurement=false`。CH32 执行器的 transport 为 `serial-uart`；可选 `device_metrics` 采用闭字段 `lattice.device_metrics.v1`，只有真实时钟已验证后才接收。原始四项 tick、每项观测栈/arena 与固定链接布局分列。`static_ram_bytes` 是整个测试固件固定 RAM；workspace、I/O 和两栈是其中具名保留区，不能再次相加。

设备指标的 timer 字段为 `{source: "systick-hclk", frequency_hz, counter_bits: 64, validated: true}`；resources 为 `flash_bytes, static_ram_bytes, workspace_bytes, test_stack_reserved_bytes, control_stack_reserved_bytes, caller_io_bytes`。operations 恰四项，每项为 `operation, return_code, ticks, observed_stack_bytes, observed_arena_high_water_bytes`，与功能返回逐项对应；未运行项必须返回 -127 和零观测。scope 固定为 `public-api-including-internal-cleanup;excluding-outer-cleanup-hash-uart`。有此独立指标时 `performance_measurement=true`，表示单次设备观测。

`execution.host_round_trip_ns` 是主机观察的一次设备执行与传输总等待时间，与设备 tick 分列，并注明各自 scope。

## ARM 部署

在 ARM 主机从已绑定库的现有配置生成轻量功能配置。它保留原 schema4、库/派生收据和部署资格，仅不登记归档统计：

```sh
python3 -B source/tools/demo_remote_config.py --input demo.xml --library arm-speed --output functional-arm.xml
```

其中库 ID 必须使用输入文件中真实登记的 ID；这是示意名称，不预设当前主机 ID。转换器核每个被选文件 SHA 后写入本机绝对路径；功能配置留在实际部署主机，不作为通用发行配置。

首次配置部署主机时，可使用 `tools/demo_arm_config.py --artifact /实际/liblatticecore.so --sha256 实际摘要 --library-id arm_live --configuration 实际配置 --workspace-bytes 实际容量 --output /新目录`。它检查实际 ELF64/AArch64 和 SHA，生成 `demo.xml` 与相邻部署清单；不加载库、不生成测量。ARM runner 随后用 `getauxval` 检查 FP/ASIMD 能力并调用原八接口，无额外 CPU 探测库依赖。容量必须来自实际库的有效声明/已有资格，不把此容量等同完整应用 RAM。

ARM 执行器固定命令形状为：

```text
ssh -F none -T -a -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes ... user@host python3 -B /部署/source/tools/demo_remote.py --config /部署/functional-arm.xml --platform arm
```

包外配置字段：`ssh_executable,host,user,port,identity_file,known_hosts_file,remote_python,remote_runner,remote_config,timeout_seconds,image_pins`。本机可执行文件/密钥/known_hosts 必须为存在的绝对路径；远端 runner/config 必须是固定绝对路径。允许用户选择解释器路径；不会下载依赖、复制私钥或执行请求中的任意命令。部署时登记并核对 host-key。

## 协议验证

`python -B tests/demo_platform/test_protocol.py` 检查原接口委托、请求闭字段、重复 JSON、错身份、假成功/额外秘密字段、忙、单次超时不重发、重放序号、固定命令及有界输出。子进程测试使用本机 Python fixture；各平台的六参数运行、板端错误路径和时钟由平台测试检查。
