# 真机验证记录（2026-11-17）

## 环境

| 项 | 值 |
|---|---|
| 宿主 | DESKTOP-TEHL32U（当日从 192.168.50.78 变更为 10.143.208.78） |
| 虚拟化 | VMware Workstation，VM: Windows 11（`E:\win11\Windows 11.vmx`，`vmx.encryptionType=partial`） |
| 客户机 | **10.143.208.49**（原 192.168.50.50），Windows 11，用户 gogo（管理员） |
| 通道 | SMB `C$` + 远程计划任务 `schtasks`；VM 内 WinRM 已启用，宿主 WinRM 客户端 TrustedHosts 缺失未使用 |
| 二进制 | 含本轮全部修复的 `trft.exe`（F1 修复后 01:27 构建） |

## A 段结果（15/15 通过）

| ID | 用例 | 结果 | 证据 |
|---|---|---|---|
| A1 | UDT 单文件 5 MiB | ✅ | 两端 `63C04802…9362`，接收 exit=0 |
| A2 | TCP 5 GiB（>4 GiB） | ✅ | 33.8s；VM 侧 certutil `7f06c623…d1d5` 与源一致 |
| A3 | 0x01 文件夹（3 文件/2 层/中文名） | ✅ | `fold\a.txt`、`子目录\b.txt`、`子目录\深\c.bin` 长度与源一致 |
| A4 | `a..b.txt` 名字边界 | ✅ | 18 B，`3D7182FC…8C98` 与源一致 |
| A5 | 20 MiB UDT `--chunks 4` | ✅（注记） | `8BB318DF…6058`；UDT 槽位按设计回落 0x03 |
| A5b | 25 MiB TCP 分块（真 0x02） | ✅ | `856D3633…CD8E6`，「分块组装」日志 |
| A6 | 50 MiB 分块中断重传 | ✅ | 52,428,800 B，`D68850DB…230E` 与源一致；接收进程存活期间可读 |
| A7 | UDT 断点续传 | ✅ | 20,971,520 B，`053A9917…BE9D` |
| A8 | 0x03 残件尾部截断后续传 | ✅（语义注记） | 截掉 1 KiB 后重发：偏移回退、客户端补发，最终 20,971,520 B、`18745E85…6E18` 与源一致——**无假成功**；「声明长度 vs 磁盘」硬校验由 A7 参数变化用例覆盖 |
| A9 | 0x04 目录同步 | ✅ | `sync.49510179\` 全哈希一致；缓存文件未同步 |
| A10 | junction 越出保存目录（负向） | ✅ | `early eof`、exit=1，树外无落盘 |
| A11 | 加密 + 配对码（对/错） | ✅ | 正确码成功（`F5664984…9D35`）；错误码双向拒绝 |
| A12 | 配对锁定 | ✅ | 10 次错码后「配对失败次数过多，已临时锁定」，正确码亦被拒 |
| A13 | 文本（中文 + emoji） | ✅ | 接收日志完整回显 `你好，测试文本 😀` |
| A14 | 6 组并发 0x02 | ✅ | 6/6 发送 exit=0，杀接收进程后 6/6 哈希一致 |

## 真机发现 F1（已修复并复核）

**0x02 组装完成后会话仍持有最终文件句柄，文件被锁到 TTL（10 分钟）。**

- 现象：A14 的 6 个文件长度正确，接收进程存活期间 `Get-FileHash` 报 `being used by another process`；杀进程后哈希立即一致。
- 根因：`GroupSession.file` 是半成品文件句柄，`publish_part` 用 `rename` 换名后句柄不变。
- 修复：`file` 改 `Mutex<Option<File>>`；`finish` 成功后在 file→state 同序锁下置 `None`；写路径幂等分支优先，异常回收才报「请整组重发」。
- 判别：`finish_releases_published_file_handle`；真机复核（A6/A14 场景可读且哈希一致）。

## B 段结果（部分）

| ID | 用例 | 结果 | 证据 |
|---|---|---|---|
| B4 | 0x03 单文件 200 MiB 完成瞬间硬断电 | ✅ | 重启后 `recv\b4.bin` 最终名、209,715,200 B、`3052b906…414c` 与源一致，无 `.trft-part`（共用 F2 修复后的 `publish_part`） |
| B5 | 0x04 覆盖同步完成瞬间硬断电 | ✅ **修复后通过** | 第一次断电发现 **F3**（最终名在、内容不符）；补 `sync_all` 后二次断电：`b5b.2441c301\b5b.bin` 在最终名、52,428,800 B、`b4d8bded…e6e2` 与覆盖后源一致，无 `.trft-part` | 断电后 `b5.ec503463\b5.bin` 在最终名、50 MB 完整，但哈希 `8565a714…` 与覆盖前的 v1 `53ec89ca…`、源 v2 `25d9f6d8…` **都不符**（与 v2 有 99.6% 字节不同）——接收端当时已回「同步完成」。与「0x04 发布前未对临时文件 fsync 数据」吻合（F2 只补了改名落盘；0x02/0x03 的数据 fsync 在轮 UI-5 续 2 已补，**0x04 未补**） |
| B3 | 0x02 500 MiB 完成瞬间硬断电（杀 `vmware-vmx`） | ✅ **修复后通过** | 第一次断电暴露 **F2**：part 内容哈希与源完全一致但**最终名丢失**（文件仍是 `.trft-part`）；修复（`MoveFileExW(WRITE_THROUGH)`）后二次断电：`recv\b3b.bin` 最终名存在、524,288,000 B、`36b7e118…b376` 与源一致，无残留 |

## C 段结果（CDP 驱动，5/5）

| ID | 用例 | 结果 | 证据 |
|---|---|---|---|
| C1 | 启动与渲染 | ✅ | 标题 `TrFileTransfer`、`appState` 已加载、5 个共享目录选项 |
| C2 | 语言切换 | ✅ | 「开启共享」→「Start sharing」→ 切回中文；活动页签 `Send` |
| C7 | 共享启停 + 链接 | ✅ | 启动后 `http://10.143.208.78:8090/`、`httpRunning=true`、目录行正确；停止后 `false` |
| C8 | 共享下载边界 | ✅ | 空文件 200/0 字节；多区间 200 全量 1 MiB；不可满足 416 |
| C3 | 接收器启停 | ⚠️ 动作走通/状态为圆点 | 点「启动」后「停止」可用、卡片 `TCP 0.0.0.0:8080`；再点停止；状态非文字（圆点），无法用文案断言 |
| C5 | 暂停/继续/取消 | ✅ | 500 MB + 2 MB/s 限速传输中：任务卡「暂停」「继续」「取消」均可用；取消后日志「#2 已取消」 |
| C6 | 文本发送（GUI→本地接收器） | ✅ | 日志「传输完成: 文本: GUI 冒烟文本 你好 😀」「#1 OK」；接收器「TCP 接收器启动 :8080」 |
| C4 | GUI 文件发送（TCP 本地） | ✅（TCP 腿） | 日志「传输完成: a11.bin」「#1 OK」；其余四协议共用同一发送面板接线，传输路径由 CLI A 段覆盖 |
| C9 | 校验中止 | ✅ **修复后通过** |
| C10 | 监控失败退避 | ⚠️ 事件可见、无时间戳 | 32 秒内仅出现 5 条事件（发送中×3/失败×1/入队×1），与 1s→2s→4s→8s→16s 退避一致（若每轮重连应有 ~30 条）；列表未带时间戳，无法逐条断言间隔 |
| C11 | 统计刷新 | ✅ | `#stats-list` 渲染记录（时间/方向/协议/大小/路径） |
| C12 | 队列增删 | ✅ | 设 `#send-path` 后点 `#btn-queue-add`，`#queue-list` 出现 `a11.bin ✕`；清空生效 | 第一次运行仍报「校验完成」（`scanned=1118/2002`）——GUI 聚合丢 `stopped`（**F4**）；修复后提示「校验已中止（仅扫描了部分文件）」、进度 1620/2002 |

驱动方式：`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222` + CDP `Runtime.evaluate`（Node 内置 WebSocket）。
## C# 2.14 互通（UIA 驱动，双向通过）

| 方向 | 结果 | 证据 |
|---|---|---|
| trft（UDT）→ C# 2.14 服务端 | ✅ | C# 侧启动 UDT 18080、目录 `C:\Users\chen\interop\recv`；trft 发送 1 MiB，收到文件哈希 `f5664984…9d35` 与源一致 |
| C# 2.14 客户端 → trft（UDT）接收端 | ✅ | C# 客户端选 UDT、127.0.0.1:18081、关加密/压缩，发送 1 MiB；trft 接收端最终名 `a11.bin`、哈希 `f5664984…9d35` 与源一致（发布完成有几秒延迟，首发列表会看到满长度 `.trft-part`） |
| trft（TCP）→ C# 2.14 TCP 服务端 | ✅ **2026-11-17 改造后互通** | 见下节「C# 2.14 TCP 互通改造」（改造前记录：trft 退出码 1、C# 日志「错误」、目录无落盘） |
| trft（单向 UDP）→ C# 2.14 UDP 服务端 | ❌ **不互通（设计如此）** | C# 侧 UDP 18083 监听；trft 退出码 0（单向发送无回执，**不代表成功**）、C# 日志「错误」、目录无落盘 |

驱动方式：`System.Windows.Automation`（UIA）按 AutomationId 设值/点按钮，无需前台焦点。

## C# 2.14 TCP 互通改造（2026-11-17，CLI 驱动；TECH-STACK §7.56）

TCP 槽位应用层并入 C# 方言后，用 C# 2.14.0.0 自带无头 CLI（`TrFileTransfer.exe send|recv|sync`）
与 trft CLI 对打，全部 SHA-256 逐字节一致：

| 方向 | 结果 | 证据 |
|---|---|---|
| trft（TCP）→ C# 2.14 TCP 服务端 | ✅ | 1 MiB；C# 日志「Resume: src.bin offset=0 … status=0」「Compression (deflate)」「Transfer complete」；落盘哈希一致（C# `Received: …src.bin`） |
| C# 2.14 TCP 客户端 → trft 接收端 | ✅ | 1 MiB；C# 日志「Connected」「Compression (deflate)」「Transfer complete」；trft 落盘哈希一致 |
| 配对码 + 0x09 加密（双向） | ✅ | C# 侧「Encrypted session established (AES-256)」/「Connection encrypted (AES-256)」+ 压缩；两侧落盘哈希一致 |
| 明文/关压缩（双向） | ✅ | C# `--noencrypt --nocompress`（不读判决 ACK）与 trft `--nocompress` 均完整落盘，哈希一致 |
| 目录 0x01（双向） | ✅ | 3 文件（含中文名/子目录）；C# 侧「Folder transfer complete: fold (3 files)」、trft 侧子目录与中文名完整 |
| 差量同步 0x04（双向） | ✅ | C#→trft：会话目录 `fold.8e4228f9`；trft→C#：`fold.4b7ed953`（`<folder>.<guid8>`，与 C# 服务端同式） |
| trft 文本 0x06 → C# | ✅ | C# 日志「Text received: …」 |
| trft `--chunks` → C# 服务端 | ✅（回退） | C# 服务端对 0x02 不发判决 → 客户端按探针回退 0x03；**只落一份** `src.bin`（修复前会多出 `src_1.bin`） |
| trft↔trft TCP 回归 | ✅ | 单文件 0x03 / `--chunks 4` 0x02（逐块判决）/ 目录 0x01；CLI 退出码 0、哈希一致 |

驱动方式：`Start-Process` 起 C# CLI 与 trft CLI，日志/哈希比对；无需 UIA（C# CLI 与 GUI 共用同一
`TransferClient`/`TransferServer` 线协议代码）。

## GUI 真机冒烟：TCP 槽位改造后（2026-11-17，CDP 驱动真机 exe）

`cargo build -p trft-gui` 后以 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222`
启动真机 exe，用 CDP `Runtime.evaluate` 驱动 DOM（填值/点击），落盘一律以 SHA-256 复核；
对端用 trft CLI 与 C# 2.14 CLI，避免手工拨号误差。

| 项 | 结果 | 证据（GUI 日志 / 落盘） |
|---|---|---|
| GUI 接收（TCP）← CLI 发送 | ✅ | 接收卡绿点 `0.0.0.0:19200`、启动禁用/停止可用；日志 `gui-recv.bin`；1.5 MB 哈希一致；最近文件列表出现该文件 |
| GUI 发送（TCP 0x03 + 压缩）→ CLI | ✅ | `传输完成: gui-send.bin` + `#1 OK`；2 MiB 哈希一致 |
| GUI 并行分块（0x02，4 路）→ CLI | ✅ | 8 MiB；`传输完成: gui-chunk.bin` + `#2 OK`；哈希一致 |
| GUI 发送 + 配对码（0x09） | ✅ | 先出安全告警（TCP 已纳入），随后 `传输完成` + `#3 OK`；带码 CLI 接收端哈希一致 |
| C# 2.14 客户端 → GUI 接收（0x09 + 压缩） | ✅ | C# 日志「Encrypted session established / compression / Transfer complete」；GUI 日志收到 `cs-to-gui.bin`；3 MiB 哈希一致 |
| GUI 目录发送（0x01 整夹） | ✅ | `gui-folder/f1.bin`（500 000 B 哈希一致）+ `gui-folder/sub/说明.txt`（中文内容正确） |
| GUI 目录发送（0x04 差量同步） | ✅ | 会话目录 `gui-folder.95bcbd8a/`（与 C# 服务端同式），文件哈希一致 |
| GUI 文本发送（0x06） | ✅ | 接收端打印 `[文本] GUI 文本互通 hello 😀` |
| 接收器停止/改端口重启 | ✅ | 停止后绿点灭、启动恢复；19204 重启后 C# 加密连接可收 |
| JS 异常/控制台错误 | 0 | CDP eval 无 exception；日志无 error（两条 err 是驱动脚本先填端口后切协议、目标落到 8080 的拒绝连接，属驱动失误非产品缺陷） |
| 环境复原 | ✅ | 测试设置的配对码已从设置页清空并保存；测试结束关闭 GUI 进程 |

驱动脚本：`.zcode/gui-cdp.mjs`（gitignored，CDP eval/eval-file/shot/front）。
截图（真机窗口）：`target/tmp/gui-01..02.png`（窗口失去前台后 WebView2 合成器不再出新帧，
后续断言以 DOM/文件系统为准）。


## 真机补验（第二轮：C# GUI 0x02/0x03、>4 GiB、GUI 暂停/取消、st=3）

C# GUI 用 UIA（System.Windows.Automation，按 x:Name 作 AutomationId）驱动——不必前台焦点；
Rust GUI 用 CDP；落盘一律 SHA-256 复核。

| 项 | 结果 | 证据 |
|---|---|---|
| **C# GUI 并发分块（0x02，4 路）→ trft** | ✅ | C# 日志 `Concurrent send: … in 4 chunks`；8 MiB 单文件哈希一致；服务端统计行「分块传输」 |
| **C# GUI 单流（0x03，自动续传默认开）→ trft** | ✅ | C# 日志 `续传协商: 起点=0`；4 MiB 哈希一致；统计行「续传传输」 |
| C# GUI 0x03 暂停/继续 | ✅ | 暂停后 `续传 cgui-pause.bin`→`起点=4194304 服务端=4194304`；8 MiB 完成、哈希一致 |
| **C# GUI 0x02 组暂停/继续** | ✅（先抓缺陷后修复） | 修复前 `Chunk resume: 0 gap(s)` + 客户端报成功但只剩 `.trft-part`；修复后 `1 gap(s), 4 piece(s)`，补发发布、哈希一致（见 TECH-STACK §7.57） |
| **>4 GiB 单文件（4.004 GiB）** | ✅ | trft↔trft TCP 25.1s；trft→C# 26.5s（C# 日志 `remaining=4.0 GB`）；两向单文件、SHA-256 一致 |
| Rust GUI 暂停/继续（0x03） | ✅ | 20 MiB @1000 KB/s，暂停后续传完成；接收端「续传传输」20 MiB，无 `.trft-part` |
| Rust GUI 取消 + 断点复用 | ✅ | 取消于 4 MiB（日志 `#3 已取消`）；接收端留 4 MiB 断点；原样重发 2.3s 续传完成（发送行记增量 16 MiB） |
| **st=3（源文件变更）** | ✅ | 断点 1 MiB 后改同尺寸内容：重发失败「服务端全文件校验失败（服务端已丢弃该文件）」且接收端清空；再发成功、新内容哈希一致 |
| 0x05 明文配对（双向）+ `--srcport` | ✅ | C# `--noencrypt --code`→trft 与 trft→C# 均哈希一致；trft 带 `--srcport 45678` 发送成功 |
| 测试基线 | ✅ | **301 项全绿**（新增 `aborted_chunk_is_not_counted_as_covered` 判别用例） |


## 真机补验（第三轮：UDT GUI 级、旧版本、RTT、服务端重启）

| 项 | 结果 | 证据 |
|---|---|---|
| C# GUI UDT 并发（0x02，4 路）→ trft | ✅ | C# 日志 `Concurrent send: … in 4 chunks`；4 MiB 哈希一致；统计行「分块传输」 |
| C# GUI UDT 单流（0x03）→ trft | ✅ | C# 日志「续传协商」；3 MiB 哈希一致 |
| 旧版 trft（v2 TCP 线，665f99e 构建）↔ 新版 | ⚠️ 按设计不互通 | 新→旧 **1.6s** 连接重置；旧→新 **91.9s**（30s 读超时 ×3）后失败；两向均无数据落盘 |
| 旧版 trft ↔ 新版（UDT） | ✅ | 双向传输哈希一致——版本断层只在 TCP 线格式 |
| 50ms RTT（Node 延迟代理） | ✅ | 4 MiB 0.3s，哈希一致，单文件 |
| 200ms RTT | ✅ | 2 MiB 0.7s，哈希一致 |
| 0x02 组会话 + 服务端重启 | ✅ | 重启后覆盖查询为空 → 整组重发（C# 日志 `1 gap(s), 4 piece(s)`）→ 发布 20 MiB、哈希一致；旧 `.trft-part` 按 7 天孤儿策略回收 |
| 0x02 尾哈希失配 | ✅ | 新增 e2e：0x00 拒收 + 组装器丢弃 + 整组补发发布（**302 项全绿**） |
| IPv6 | ⚠️ 仅库级 | CLI/GUI 接收端固定绑 `0.0.0.0`（无 `--bind`）；`::1` 路径仅 e2e 覆盖，C# 侧本就只绑 IPv4 |


## VM 真机互通（10.143.208.49，TCP 改造后首次）

**环境**：宿主 10.143.208.78（WLAN）↔ VM 10.143.208.49（Windows，用户 `gogo`）；经 SMB `C$` 部署二进制、`schtasks /S /U /P` 远端拉起接收器；被测二进制为 `be21b91` 的 release 构建（TCP 全走 cswire）。此前各轮的 VM 对打跑的是 **v2 TCP 帧**，本轮是 TCP 并入 C# 方言后的首次真实链路验证。

| 项 | 结果 | 证据 |
|---|---|---|
| 宿主 trft → VM trft（TCP 0x03） | ✅ | 64 MiB / **0.87s**（≈77 MB/s），VM 落盘 SHA-256 一致 |
| 宿主 **C# 2.14** → VM trft（0x09 加密 + 配对码 + deflate） | ✅ | 8 MiB / 0.8s，C# 日志 `Encrypted session established (AES-256)`，VM 落盘哈希一致 |
| 宿主 trft `--chunks 4` → VM trft（0x02） | ✅ | 8 MiB / 0.2s，VM 日志先记探针 `0x02 头非法` 再收分块，落盘哈希一致 |
| 宿主 trft `sync` → VM trft（0x04） | ✅ | 会话目录 `syncsrc.0da1f5a0/`，两文件哈希一致；**二次同步 0.06s**、无重复副本（逐文件跳过生效） |
| **VM trft → 宿主 trft（反向 0x03）** | ✅ | 放行入站 19611 后 64 MiB 哈希一致 |
| **VM trft `--chunks 4` → 宿主 trft（反向 0x02）** | ✅ | 64 MiB 哈希一致；宿主日志先记探针 `0x02 头非法` 再收分块 |
| **VM trft `sync` → 宿主 trft（反向 0x04）** | ✅ | 会话目录 `syncsrc2.ace398b9/`，两文件哈希一致 |
| **VM trft `--code` → 宿主 C# 接收端（0x09）** | ✅ | 补 C# 程序的入站规则后 8 MiB 通过；C# 日志 `Connection encrypted (AES-256)` + `deflate` + `Resume: big8.bin offset=0`，落盘哈希一致 |

**清理**：VM 上本轮创建的计划任务（trft-recv1/3/4/5、trft-send1、trft-sendA–D）与新增的 exe/bat/日志/接收目录/同步源已删除；SMB 映射保留（`net use \\10.143.208.49\C$`，此前既有记忆映射）。VM 上更早会话遗留的 `trft-test` 负载（a2.bin 5GiB 等）未动。宿主侧临时目录（revA–D、big64）已清。

## 未完成（需人工/其它环境）

| ID | 原因 |
|---|---|
| B1/B4/B5（0x00/0x03/0x04 掉电） | 与 B3 共用同一发布函数（`publish_part` / `public::move_replace`），代码路径已修复并有单测；剩余为逐路径真机复核，需再次断电 |
| C1–C12（GUI 冒烟） | 视觉/交互项需人在控制台 |
| ~~C# 2.14 GUI 级对打~~ | ✅ 已补：UIA 驱动 C# GUI，TCP（0x02 并发、0x03 单流与暂停/继续）与 UDT（0x02/0x03）均通过；文件选择框/气泡等视觉项需人在控制台 |
| ~~TCP 槽位 GUI 冒烟~~ | ✅ 已补：见「GUI 真机冒烟：TCP 槽位改造后」 |
| 旧版 trft（TCP）| ✅ 已验（1.6s / 91.9s 失败，无落盘）；**旧 C#（<2.14）** 无二进制可测 |
| 真实链路 | 仅 RTT（50/200ms 延迟代理）覆盖；**跨子网/丢包**未测 |
| IPv6 interop | CLI/GUI 只绑 IPv4（无 `--bind`），仅库级 e2e |
| 规模压测（万级文件目录、64 并发闸） | 按要求暂不做 |
| ~~0x02 组块哈希不符/服务端重启~~ | ✅ 已补：见第三轮（e2e + 真机重启） |

## 运行观察

1. **SMB 缓存/句柄**：同进程 `Get-ChildItem` 可能显示 0 字节；被远端进程持有句柄的文件读取失败——必须新进程复核。
2. **远程执行**：`schtasks /S ... /U gogo /P a` 可用；带参数的 `/TR` 偶发不启动，改用**硬编码端口的 .bat** 更稳。
3. **`--chunks` 的协议分叉**：TCP/UDT 走 C# 方言 0x02（UDT/TCP 服务端逐块判决）；对 **C# 服务端**（0x02 无判决）自动回退 0x03；QUIC/RUDP 走 v2 帧 0x02（A5b/A6/A14 覆盖 TCP 旧帧路径，改造后 TCP 由 §7.56 的 CLI 对打覆盖）。
4. **锁定按来源 IP**：A12 后该 IP 10 分钟内不能做配对相关测试。

## 清理

- VM：`trft-recv`/`trft-kill`/`trft-hash` 等任务已删，接收进程已终止。
- 宿主 C 盘（2026-11-17 补清）：`C:\Users\chen\trft-remote\`（85 个文件 / **6.54 GB** 测试负载、脚本、截图）已删；`%TEMP%\trft-*` 11 项已删；`%APPDATA%\TrFileTransfer` 下测试残留——`stats.log` 测试行 49 条、hash 缓存测试条目（1.39 MB→89 KB、698 KB→4 KB）、`resume`/`server-resume` 测试会话 246 个、默认接收目录 `tcp\` 2006 个测试文件（18.9 MB）——全部清除；`devices.json` 清空、`client_port` 恢复 8080、配对码保持清空。应用日志（`logs\`）与真实历史保留。
- 宿主网络：`net use \\10.143.208.49\C$` 仍为 Disconnected 记忆映射（未删，按需清理）。


