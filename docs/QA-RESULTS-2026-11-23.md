# 双机验证记录（2026-11-23，VM 10.184.213.49）

## 环境

| 项 | 值 |
|---|---|
| 宿主 | 10.184.213.78（本机，Windows，非管理员——未改本机防火墙） |
| 客户机 | **10.184.213.49**，Windows 10.0.26200，用户 gogo（管理员） |
| 通道 | SMB `C$` 投放二进制/回收产物 + 远程计划任务 `schtasks /ru SYSTEM` 运行接收端；WinRM 未使用（客户端 TrustedHosts 缺失） |
| 二进制 | 本批全部改动的 `trft.exe` 0.3.0（release；含 0x04 `known_complete` 修复，14:2x 构建） |
| 方向 | 发送端 = 宿主，接收端 = VM（仅出站；未在两端放行入站规则） |
| 数据 | 随机二进制 8 MiB（T1–T4）、4 MiB（T5）、32 MiB（T6）、16 MiB（T9）；文件夹 3 文件/2 层（T7）；同步目录 3 文件（T8） |

## 结果（修复后复跑 10/10 通过）

| ID | 用例 | 结果 | 证据 |
|---|---|---|---|
| T1 | TCP 单文件 8 MiB（0x03 C# 方言） | ✅ | 0.2s；接收端 SHA-256 与源一致，进程 exit=0 |
| T2 | QUIC 单文件 8 MiB | ✅ | 0.2s；SHA-256 一致 |
| T3 | RUDP 单文件 8 MiB | ✅ | 0.2s；SHA-256 一致 |
| T4 | UDT 单文件 8 MiB | ✅ | 0.2s；SHA-256 一致 |
| T5 | UDP 单向 4 MiB（`--passes 2 --fec-parity 2`） | ✅ | 1.0s；接收端发布后哈希一致 |
| T6 | TCP 并行分块 32 MiB（`--chunks 4`，0x02 组会话） | ✅ | 0.5s；SHA-256 一致 |
| T7 | TCP 文件夹 0x01（3 文件/2 层目录） | ✅ | 3/3 落地，逐文件 SHA-256 一致 |
| T8 | TCP 同步 0x04 两轮（二轮把文件改大且内容不同） | ✅ | 首轮全量、二轮差量；rc=0/0，目标文件哈希与源一致（修复前失败，见 DEF-1） |
| T9 | TCP 断点续传（限速 3 MB/s，传至 11,534,336/16,777,216 B 强杀发送端） | ✅ | 重发一次补完，16,777,216 B、SHA-256 一致，无 `.trft-resume`/`.trft-part` 残留 |
| T10 | 校验瞬态文件排除（1 个真实文件 + 伪造 `.trft-resume`/`.meta`/`.trft-part`） | ✅ | 输出「已扫描 1 个文件（12 字节）… 无法读取 0」，rc=0；三个半成品均未被计入 |

复跑前的首轮（同一 VM、同一时刻的手工矩阵）：T1–T7、T9、T10 通过，**T8 失败**——见下。

## 缺陷 DEF-1：0x04 二轮同步遇到「变长文件」失败并丢目标文件（已修复）

- **现象**：`sync` 首轮正常；把某个文件改成**更长的不同内容**（非追加）后再同步，
  客户端报 `错误: 同步失败: 对端拒绝: 被对端拒绝接收`（rc=1），且目标目录里**该文件消失**；
  再跑一次即成功（自愈）。
- **定位**：本地回放（loopback，同一二进制）稳定复现，排除网络因素；读码确认服务端续点
  扫描只判 `len > 0 && len < 入参 size` 就把既有短文件当断点半成品（按旧长度续传），
  而 C# 原实现该分支还有 `KnownComplete` 守卫——移植 TCP 槽位时丢失。
- **机理**：旧文件是「上一个完整版本」、其字节不是新内容的前缀 → 服务端从旧长度续传 →
  拼出的文件尾哈希不符 → 删档 + 回拒绝（防御方向正确：绝不发布拼接文件；代价是丢目标副本）。
- **修复**（TECH-STACK §7.64）：0x04 每收完一个文件把摘要登记进 `sync_hashes`
  （C# `FileHashes.Store` 同构）；续点判定加 `known_complete`（`FileHashes.Knows` 同义）——
  已知完整的短文件整文件重传（offset 0），只有从未登记过的短文件才续传。
- **判别**：`cs_dialect_sync_replaces_file_that_grew`（UDT 槽位端到端）。去修复必红：
  `Err(Rejected("被对端拒绝接收"))`，与双机现场一致。
- **复核**：双机 T8 复跑 rc=0/0、哈希一致；本地 grow/same-size/shrink 三形态全绿。

## T11 接收端重启场景（补测：仅内存 → 落盘 journal）

DEF-1 修复后仍留一个缺口：`known_complete` 只查进程内存，**服务端重启**（新进程、空状态）
后首轮同步仍会误判。补 `.trft-hash-cache-server.txt` 落盘 journal 后复测——同一端口 19028/19029、
接收端进程完整重启，二轮前把文件改大且内容不是旧前缀：

| 变体 | 处置 | 结果 | 证据 |
|---|---|---|---|
| T8R0（模拟旧行为） | 二轮前删除 `.trft-hash-cache-server.txt` | ❌ 如预期复现 | rc=1「同步失败: 对端拒绝: 被对端拒绝接收」，目标 `log.txt` 消失 |
| T8R（本次修复） | 保留 journal | ✅ | rc=0「同步完成」，目标哈希与源一致 |

两变体首轮均「同步完成」。T8R0 复现的正是 §7.64 描述的现象，说明该用例对修复有判别力。

## C 段：GUI 本机冒烟（2026-11-23，CDP 驱动）

环境：本机 `target\release\trft-gui.exe`（含本批全部改动），
`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222` 启动，Node CDP
`Runtime.evaluate` 驱动 DOM（驱动脚本 `.zcode/gui-verify.mjs`，gitignored）；接收端为同机 CLI `trft recv`。
验证前备份 `%APPDATA%\TrFileTransfer\config.toml`，结束后原样还原（含 `hash_cache_days`）。

| ID | 用例 | 结果 | 证据 |
|---|---|---|---|
| C18a | 类型=文件夹、排除 `.tmp, LOG`、整夹发送 | ✅ | 排除行可见；日志「传输完成: src」；接收端仅 `src\keep.bin`、`src\sub\noext`（`.tmp`/`.LOG` 未传） |
| C18b | 同参数切「差量同步」再发 | ✅ | 日志「传输完成: 同步: src」；接收端仅 `src.c025e4ca\keep.bin` 与 `sub\noext` |
| C18c | 队列：入队文件夹项后执行 | ✅ | 日志「队列 1/src」「#4 1 完成」；接收端仅未被排除的两个文件（入队快照生效） |
| C18d | 重启 GUI 后回填 | ✅ | `#send-exclude` = `.tmp, LOG`（config `folder_exclude_exts` 持久化） |
| C16 | 监控：目录 + 排除 `.tmp, LOG`，预置三个落料 | ✅ | 监控列表「入队/发送中/已发送 keep-m.bin」；`skip-m.tmp`、`skip-m.LOG` 留在监控目录未入队；停止后状态复位 |
| C16b | 重启 GUI 后回填 | ✅ | `#monitor-exclude` = `.tmp, LOG` |
| C17 | 设置页「摘要缓存/同步续点有效期」 | ✅ | 改 0 保存 → `config.toml hash_cache_days = 0`；改回 7 → `= 7` |

JS 异常/控制台错误：0（CDP eval 无 exception，无遮挡弹层）；截图：`target/gui-folder.png`（文件夹类型的排除行）、
`target/gui-monitor.png`（监控卡排除行）。

备注：驱动脚本首跑把源路径写成 `C:\Users\...\Temp`（本机实际 TEMP 为 `D:\cache\temp`），
产生一次「目录为空」的预期内失败；修正路径后全部通过——该失败属驱动路径错误，非产品缺陷。

## 已知限制 / 未覆盖

- 服务端 journal（`.trft-hash-cache-server.txt`）与保存目录同生命周期：删掉目录即失效，
  属缓存语义；条目 TTL 7 天，过期后退化为「多失败一次、重试自愈」。
- 未在 VM 上跑 GUI 交互冒烟（远程任务为 SYSTEM 会话，无交互桌面）；GUI 侧仅验证了构建产物。
- 未覆盖 C# 2.14 客户端互通（宿主无 C# 侧二进制）；该方向由 `cargo test` 的
  `e2e_interop`/`e2e_udt` 用例与既有真机记录覆盖。
- 断点续传仅验证 TCP（C# 方言，直接写最终名）；v2 帧（QUIC/RUDP）的 `.trft-resume` 路径由单测覆盖。
