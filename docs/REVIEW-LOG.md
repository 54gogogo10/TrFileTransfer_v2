# TrFileTransfer v2 审查日志（8 轮代码/安全审查）

| 项 | 内容 |
|------|------|
| 文档性质 | M2' 里程碑 8 轮独立审查的发现、修复与判别验证记录 |
| 审查方式 | 每轮由独立上下文的审查代理执行（代码轮与安全轮交替、成对并行），修复后全量回归 |
| 基线演进 | 46 项测试（M2' 完成）→ 75 项测试（8 轮审查闭环），全程 0 警告 |

---

## 总览

| 轮 | 视角 | P0 | P1 | P2 | P3 | 状态 |
|---|---|---|---|---|---|---|
| 1 | 协议/传输正确性 | — | 3 | 4 | 9 | ✅ 全部修复 |
| 2 | 威胁模型 §5.1 | — | 3 | 5 | 4 | ✅ 全部修复 |
| 3 | 并发/生命周期 | — | 1 | 3 | 7 | ✅ 全部修复 |
| 4 | UDP 引擎 DoS/输入校验 | — | — | 2 | 4 | ✅ 全部修复 |
| 5 | 规格符合性抽查 | — | 2 | 4 | 7 | ✅ 修复/文档收敛 |
| 6 | 密码学/TOCTOU | 1 | 1 | 1 | 5 | ✅ 全部修复 |
| 7 | 测试质量/判别纪律 | — | 2 | 10 | 8 | ✅ 修复+补测 |
| 8 | 安全收尾/残余风险 | — | 2 | — | 4 | ✅ 修复+清单交付 |

合计约 90 项发现，全部闭环或登记为已声明偏离（见 TECH-STACK.md §7 与本文 §残余风险）。

## 各轮要点与关键修复

### 轮 1（协议/传输正确性）
- **P1 并发同名接收竞态**：两个并发同名传输共用 `.trft-part` 交叉写、双方假成功、落盘混合内容（实测复现）。→ 修复：每连接唯一随机半成品名 + `hard_link` fail-if-exists 原子发布（`publish_part`，AlreadyExists 重取冲突名）。
- **P1 完成哈希读取无超时**：单连接可挂死整个限量接收器。→ 全部读统一走 30s/5min 超时。
- **P1 UDP 发送端整文件驻留内存**（300MB 文件实测 458MB 堆）。→ `send_pass` 逐组流水线，O(组) 内存。
- P2：QUIC IPv6 绑定、0x05 宽容接受、0x00 Skip 语义对齐、磁盘预检缺失。
- P3：`write_str_u16` 静默截断、Windows 保留名、32 位 `as usize` 死循环、`_dupe` 兜底覆盖等。

### 轮 2（威胁模型）
- **P1 0x09 加密未接线**（TCP 明文为唯一路径）。→ 实现 0x09 加密装饰器（Encrypted 流状态机，帧协议零改动）。
- **P1 配对无 IP 锁定 + PBKDF2 预认证 CPU 放大**。→ PairingGate（10 次/锁 10 分钟/成功清零）+ spawn_blocking + 并发闸 64。
- **P1 UDP 伪造 START 磁盘放大**（set_len 预分配 ≈1.5TiB）。→ 磁盘预检 + 声明总量 64GiB 封顶 + 空闲会话 10 分钟回收（删半成品）。
- P2：ADS 冒号写入（可抹 MotW）、QUIC 指纹钉扎、verify 假成功、Web 全网卡绑定。
- P3：Windows 保留名/尾点、Cf 格式字符、并发同名锁、常驻连接上限。

### 轮 3（并发/生命周期）
- **P1 `Encrypted::poll_write` Pending 重试重复封段**（真实背压下传输必败，回环测试恰好掩盖）。→ 重试语义改为「补完在途信封即代表 buf 写完」+ Trickle mock 判别测试。
- **P1 发明现读侧段状态机缺陷**（审查中实测抓到）：`poll_read` Pending 丢失已读进度 → 段错位 HMAC 失败。→ `sealed/sealed_pos` 跨 poll 持久化。
- P2：TCP/QUIC 半成品孤儿清扫、UDP 收尾 rename 静默覆盖（并入 hard_link 发布）、文件夹根目录解析 TOCTOU（create_dir 原子占用）。
- P3：门双重计数、QUIC JoinSet 对齐、`--count` 按帧收口、flush/shutdown 冲刷半写信封。

### 轮 4（UDP DoS/输入校验）
- **P2 逐包位图全扫**（≈10 万倍字节放大 + 合法大文件 O(n²)）。→ Session.done 增量计数。
- **P2 已恢复组重复 RS 重构**（多轮重发放大）。→ 组完整早退。
- P3：PARITY idx 域校验、DATA 精确长度校验（建立「位图=已落盘」不变量）、逐出改 last_seen 主序、Progress 节流备忘。

### 轮 5（规格符合性）
- **P1 verify 无比对基准**（「不一致退出码 1」不可达）。→ 实现 `hashcache`（FNV-1a 行校验 + TTL + 坏行丢弃）+ verify 真实比对（不一致退出 1 + 指出文件）。
- **P1 0x09 缺服务端→客户端确认**。→ 双向确认重设计（见轮 6）。
- P2：锁定误计业务拒绝（→ `Error::AuthRejected` 独立计数）、加密分段 4MiB 与规格冲突（→ 256KB 分段，poll_write 多段状态机）、TECH-STACK 状态漂移（→ 文档更新）、CLI 参数面偏离（→ TECH-STACK §7 偏离声明）。
- P3：用法错误退出码统一 2、`--pin` 文案、`--count 0`/UDP 组合拒绝、sync 补 `--code/--limit`、UDP SO_RCVBUF 4MB、注释漂移三处。

### 轮 6（密码学/TOCTOU）
- **P0 0x09 仅单向证明**：盲接受型 MITM + 单臂冒充均不可防（证明未混入配对码时 ECDH 自派生即可伪造）。→ 重设计：**双向确认移入加密通道内**，证明 = HMAC(conf_key, cpub‖spub‖域) 且混入 `PBKDF2(配对码)` 派生钥（盐=转写哈希，两侧独立重算）；任一侧要求配对码而另一侧未配置 → fail-closed。新增判别测试：盲接受 MITM 必须失败、伪造服务端证明必须失败、错误配对码双侧拒绝、配置失配 fail-closed。
- P1 QUIC 0x05 可双臂中继（无 --pin 时）→ 注释/帮助文案对齐 + 偏离声明（通道绑定证明 ⬜ M3'）。
- P2 verify 无基线（同轮 5 F1）。
- P3：门容量清扫、客户端 PBKDF2 spawn_blocking、Skip 双读复核、hard_link 卷回退、config .bak 原子化。
- **复核通过**：PBKDF2 向量、HMAC 构造、ECDH contributory behavior、HKDF 分域、恒时比较、0x05/0x09 证明域分隔（不可交叉重放）。

### 轮 7（测试质量/判别纪律）
- **P1 Trickle mock 永不 Pending**——对轮 3 修复无判别力；read_exact 掩盖重复段。→ 改造为「先 Pending 再放行 1 字节」+ `read_to_end` 整流断言；新增 `read_resumes_mid_segment_after_pending`（隔次 Pending 的分段读）。
- **P1 SHA-256 不一致 fail-closed 全链路零覆盖**。→ 新增 UDP 单元（错哈希 END → 删除+会话清空+无残留）与 TCP e2e（手工坏哈希帧 → STATUS_REJECT + 无落盘 + 无残留）。
- **P2 QUIC 每连接双重持并发闸**（32 并发即挂死，被测试缺口掩盖）。→ handle_conn_quic 移除重复 precheck。
- P2：CLI 层零测试（→ `cli_exit_codes.rs`：用法错误=2、verify 篡改=1、全命中=0）、伪造/错码双测、恒真断言三处清理、空文件/IPv6/明文组合/UDP 二轮收敛/Skip 修改保留测试补齐。
- P3：limiter 测试套超时、e2e 辅助函数归并建议（记录待办）。

### 轮 8（安全收尾）
- **P1 明文 0x05 编排自相矛盾**：服务端先读首字节再写盐 vs 客户端先读盐——死锁 + 盐首字节被误读为状态字节的 1/256 假成功（§7.1 红线）。→ 协议改为「客户端宣告 0x05 → 服务端分流：0x05→盐→证明 / 非法→不写盐直接拒绝（排水后关闭）」；新增明文双码全链路 + 确定性拒绝测试。
- **P1 非硬链接卷拷贝回退残留半成品到最终路径**（2×空间瞬时需求 + ENOSPC 中途）。→ candidate error-guard（任何失败路径清掉候选文件）。
- P3：门清扫只重置 fails 保留锁定、folder Skip 补双读复核、UDP 引擎 panic 不拖垮接收器 + 注释对齐串行语义、发布失败清理 part。
- **全量 panic 审计**：网络输入路径 0 可达 panic（逐个判定 unwrap/切片/索引）。
- **交付残余风险清单 R1–R13** 与 **Rust 版发布检查单**（自互通矩阵替代 C# 互通矩阵；WIRE-PROTOCOL.md 列为首个对外发布硬项）。

## 判别纪律执行记录

每项行为修复均要求「去掉修复测试必须变红」，轮 7 对全部修复做了判别力抽查：
- 抽查不合格 2 项（Trickle 无判别力、哈希 fail-closed 零覆盖）→ 当轮修复。
- 抽查合格：PairingGate（单测+e2e 双红）、publish_part（并发同名 e2e 红）、限速超容量（死锁即红）、0x09 双向确认（盲接受/伪造/错码三测）、UDP FEC 恢复/抑制/去重、摘要缓存三测。

## 残余风险（交付时状态，详表见轮 8 报告 R1–R13）

已声明接受：单向 UDP 无认证（§5.2）、6 位码爆破空间（PBKDF2+锁定缓解）、QUIC 无 --pin 不防主动 MITM（M3' 通道绑定）、摘要缓存 FNV 非 MAC（本地攻击者出模型）。
已声明延后：0x02/0x03/0x04/0x08/0x0A/0x0B（M3'）、进度事件（M4'）、缓存 8MB 收敛（M3'）、Web 鉴权/Range/上传（M3'）、WIRE-PROTOCOL.md 抽取（首个对外发布前）。

---

## M3' 交付记录（2026-10-31）

按 TECH-STACK §6 完成 M3'：0x02/0x03/0x04 续传与分块 → 0x08 压缩 → Web 管理面 → 自更新器；
同时闭环轮 7/8 登记的三项测试计划（限速接线判别、互通矩阵 e2e 化、WIRE-PROTOCOL.md 抽取）。
基线 75 项 → **121 项测试全绿**（rustc 0 告警），CLI 与 trft-server 实机演练通过。

### 交付清单

| 项 | 落点 | 判别测试（去修复必红） |
|---|---|---|
| 0x03 单文件续传（0x10 协商、服务端偏移权威、陈旧前缀保护、per-session 锁） | `transfer/resume.rs` | `resume_survives_interrupted_transfer`（半途掐断→重连接续）+ meta 失配测试 |
| 0x02 分块（groupId、覆盖判完成、8192 区间守卫、0x0B 查询、0x0C 收尾） | `transfer/chunked.rs` | `merge_and_coverage`（部分覆盖不算覆盖）、`coverage_query_reports_written_ranges`（落盘即状态）、`chunked_path_limit_wired` |
| 0x04 文件夹同步（0x11 位图、hasHash=0 必发、同步覆盖语义、稳定会话 ID） | `transfer/resume.rs` | 实机演练：二次同步 0/3（缓存命中全跳过）；`matrix_sync_vs_old_server` |
| 0x08 压缩（rawLen+wireLen+mode 段、采样 30%、64B 最小段、64MB 炸弹守卫） | `transfer/compress.rs` | `incompressible_goes_raw`（零膨胀）、`compressed_bomb_rejected`、`small_segment_goes_raw` |
| 前导协商（0x0A 能力位 / 0x08 各至多一次）+ `Framed` 栈 | `receiver.rs` / `sender.rs::connect_stack` | `capability_frame_reports_feature_bits` |
| Web 管理面（会话+`?t=` 令牌+IP 锁定、Range 206/416、multipart 流式上传、CSRF 双校验、CSP/XFO/no-store） | `trft-server/src/lib.rs`（lib/bin 拆分） | 15 项 oneshot 套件（`tests/web.rs`）：锁定 429、穿越 400、413 半成品零残留、CSRF 拦截 |
| ed25519 自更新器（清单验签 verify_strict、https 强制明文仅回环、流式哈希、换入前重校验、原子换入+回滚） | `update.rs` + CLI `update` 动词 | `manifest_roundtrip_and_tamper`（篡改必红）、`url_policy_https_enforced`、实机：明文源被拒 |
| 缓存 8MB 收敛（追加日志 + 阈值重写 + 两代分代淘汰 + 不可写退化内存） | `hashcache.rs` | `rewrite_at_threshold_and_two_generation_eviction` |
| 限速接线判别（轮 7 计划项） | `tests/e2e_limits.rs` | 发送/接收/0x02 三路时间下界判别（绕桶即 <0.3s 变红） |
| 互通矩阵 e2e 化（轮 8 计划项） | `tests/e2e_interop.rs` | 新↔旧 8 行矩阵（0x03 降级、0x02/0x04 显式 Unsupported、压缩三态、能力位收敛） |
| e2e 辅助归并（轮 7 P3） | `tests/common/mod.rs` | 四处复制的 listener/opts 收敛为单一来源 |

### 本轮开发中发现并修复的缺陷（全部由测试或实机演练暴露）

1. **0x02 组装后移除会话 → 迟到 0x0C 判 0x00（假失败）+ RST**：改设计为组装成功后会话保留完成态（0x0C→0x01、0x0B 回满覆盖、重复块幂等跳过）——重试收敛于成功；失败路径仍移除（fail-closed 不变）。
2. **0x0B 应答把内部 `(start,end)` 当 `(offset,len)` 发送**：互通 e2e 抓到；线上语义修正为 (offset, len)。
3. **`config.rs::write_atomic` 自拷贝**：目标已是 `.bak` 时 `fs::copy(src, src)` 以共享冲突失败（错误 32）——既有 bug，被缓存重写路径首次触发；补 `bak != path` 守卫。
4. **压缩段格式缺线上长度**：仅 rawLen 时 mode=1 读侧无法定界——设计期修正为 rawLen+wireLen+mode（WIRE-PROTOCOL.md §4 同步）。
5. **`collect_files` 把发送端 `.trft-hash-cache.txt` 当内容**：二次同步多传元数据文件（实机 2/4 暴露）；与 verify 同口径排除。
6. **0x02 接收路径缺 `create_dir_all`**（其余路径均有）；**resident 模式连接错误静默吞掉**（补 `[连接失败]` 日志）。

### 判别纪律执行

新增行为修复均以「去修复必红」验证：chunked 会话保留（回退即 0x0C 全 0x00 红）、0x0B 线上语义（回退即区间断言红）、自拷贝守卫（hashcache 重写测试红）、缓存排除（同步计数 2/4 红）。限速接线判别为新增判别维度（轮 7 登记）——桶单测无法证明「路径接线」，以传输时间下界补齐。

### 残余风险更新

- 新增接受：0x02 组装哈希无对端声明可比（规格 §3.1：0x02 无整文件哈希，完整性依赖传输层 + 可选 0x09）；0x04 位图差分信任两侧摘要缓存（FNV 行校验防损坏，非防恶意——本地攻击者出模型）。
- 移入已落地：0x02/0x03/0x04/0x08/0x0A/0x0B、缓存 8MB 收敛、Web 鉴权/Range/上传、WIRE-PROTOCOL.md。
- 仍延后：进度事件（M4'）、QUIC 通道绑定证明、FEC 吞吐基准、多平台发布矩阵（无交叉工具链，登记至发布阶段）。
- 自更新公钥为开发占位（`UPDATE_PUBKEY_HEX`）：**首个对外发布前必须由发布工具链替换并妥善保管私钥**（发布检查单硬项）。

---

## M4' 交付记录（2026-10-31）

按 TECH-STACK §6 完成 M4'：Tauri 2 桌面 GUI（托盘/主题三态/双语/拖放/进度卡片/共享二维码/校验/设置/
检查更新/开机自启/文本互传）+ **进度事件**（节流在 core，规格 §3.1）+ scrub 校验引擎抽取 + WebView2 检测引导。
基线 121 项 → **128 项测试全绿**（rustc 0 告警），GUI 实机启动 + WebView2 冒烟通过。

### 交付清单

| 项 | 落点 | 判别测试（去修复必红） |
|---|---|---|
| `progress` 模块（惰性 100ms 节流、首报立即、终态必达、`Outcome` Drop 即失败、`total=0` 不定进度） | `trft-core/src/progress.rs` | 3 项暂停时钟单测：节流期 1000 次 add 只发 1 事件、终态绕过节流、fail 后 add 忽略 |
| 进度全链路接线（0x00/0x01/0x02/0x03/0x04 收发双侧 + UDP 发侧按轮加权 + UDP 收侧逐包事件节流映射） | `transfer/{sender,folder,resume,chunked,udp}.rs`（`SendOptions.progress` / `RecvOptions.progress` / `UdpRecvOptions.progress`） | TCP e2e：收发两侧事件 done==total、终态 done、单调不减（去掉任一侧接线即红）；UDP e2e：50KB 两轮 42+ 数据包 → 事件 <30（无节流即红）、终态字节精确 |
| scrub 校验引擎（GUI/CLI 共用；聚合多目录、可中途停止、进度回调） | `trft-core/src/scrub.rs` + CLI `verify` 改薄 | 2 项单测：篡改点名（同长度+保 mtime 命中 mismatch 路径）、stop 置位即停 |
| Tauri 2 GUI（命令层全部复用 trft-core 入口——§3.6 同层纪律） | `trft-gui`（main/state/commands/tray + dist 前端） | 实机：进程存活 + WebView2 数据目录 + msedgewebview2 子进程；JS `node --check` |
| WebView2 检测引导（注册表三处 + 原生对话框 + 官方 Bootstrapper 短链） | `trft-gui/src/main.rs` | —（环境必然已装，路径无法在测试机判别；逻辑直检） |
| 接收端多地址绑定（规格 §3.3：族通配 + 具体网卡，每勾选地址一个监听器；逐地址绑定失败上报） | `trft-gui/src/commands.rs`（recv_start 重写：`server_endpoint`/`serve_udp_on`/`serve_on` 每地址一个任务，gate/并发闸/分块会话表/缓存经 RecvOptions Clone 共享） | 实机：Windows 通配+具体网卡同端口共存语义实测（更具体绑定优先接收）；全失败路径返回逐地址错误明细 |
| 补齐批次二：暂停/继续（取消型暂停——暂停即断、继续复用 0x03 服务端会话/0x04 位图差分；任务↔进度卡经 `Reporter::id()`+`task-start` 事件绑定）、群发（手输多目标并行 + 逐目标卡 + {ok}/{total} 汇总）、`SyncVerifyContent` strict（`RecvOptions.strict_verify` 绕过缓存 + 发送侧不携哈希 + CLI 读配置）、文本历史落盘 200 条（`text-history.txt`）、`PairingLength` 生成、`NotifySound` 开关（判别 e2e：strict 开关改变二次同步传输量）
| `trft-core/{transfer/receiver.rs,transfer/resume.rs,config.rs}` + `trft-gui/*` + `trft-cli`（sync 读 strict） | e2e `sync_strict_verify_bypasses_digest_cache`（非 strict 二次同步总量 0 → strict 全量重传，去旁路必红）；128→129 项 |
| 补齐批次三：设备发现与记忆（`trft-core::discovery`——0xD1/0xD2 帧协议入 WIRE-PROTOCOL.md §6、应答服务随监听器启停且 flags 实时、回环 e2e 判别；`devices.json` 10 条按 IP 去重、发送成功/发现应答双源合并）+ IP 过滤（规格 §3.3 全匹配规则：精确/通配/CIDR v4+v6/跨族不匹配/坏条目 fail-closed；TCP/UDT 在 conn_precheck 先行判定不耗并发闸、UDP 引擎处理前逐包静默丢弃——单元 + 三态 e2e 判别）+ 129→133 项
| `trft-core/{discovery.rs,transfer/receiver.rs,transfer/udp.rs}` + `trft-gui/*` | `frame_roundtrip_and_guards`、`answer_service_replies_to_discovery`、`ip_filter_matching_rules`、`ip_filter_blocks_and_allows`（去钩子必红） |
| 对齐需求补批（规格 §3.2/§3.3/§3.4/§3.7 可落地项）：队列持久化 queue.txt + 完成后动作（关机/休眠/命令，前端确认）、端口全占用换端口提议、防睡眠（`SetThreadExecutionState` **派生计数**——从状态重算而非加减配对，abort 路径不可能泄漏）、防火墙提示首启一次（`firewall_hinted`）、共享目录三选一 + `QrAddress` 记忆、运行中冻结该协议页输入、重复文件/缓存有效期 UI、红框校验（空值中性）、提示音、启动 3s 静默检查更新 + `skip_version`、最小化隐藏到托盘、Config 新键（serde default 向后兼容） | `trft-core/src/config.rs` + `trft-gui/*` | config roundtrip 测试保持绿（旧 config 文件兼容）；Windows 通配/具体绑定语义实测；其余为 UI/流程项——实机冒烟覆盖 |

### 本轮开发中发现并修复的缺陷（全部由测试或实机暴露）

1. **`hashcache::save` 未关追加句柄 → Windows 上恒失败（既有 bug）**：`insert` 保持的追加句柄锁死
   `atomic_write` 的 persist 换入（错误 5）。CLI `verify` 「看起来正常」纯靠追加日志先落盘 + save 失败被
   当警告吞掉（exit-code 测试恰好覆盖不到）。→ 修复：`save` 先关句柄再换入（与 `rewrite` 同纪律）。
   判别：scrub 单测在修复前必然报 PermissionDenied。
2. **`.trft-hash-cache.bak` 未入缓存族排除**：save 修复后原子换入留下 `.bak` 镜像，被校验扫描/发送清单
   当作内容（scrub 测试抓到「新记录多 1」）。→ `hashcache::is_cache_artifact` 统一口径，scrub 与
   `collect_files` 共用。
3. **UDP 引擎 `UdpEvent::Progress` 语义是块数**（total=chunk_count）：GUI 接线若直发即假进度。→
   `Started` 事件扩展 `chunk_len`，serve_udp_on 按块换算字节并以 `min(块数×chunk_len, size)` 钳制末块
   余数（UDP e2e 判别：终态 done == size 精确命中）。
4. tokio 暂停时钟不影响 `std::time::Instant`：节流实现改用 `tokio::time::Instant`（生产语义一致，
   判别测试可确定性推进）。

### 判别纪律执行

新增行为修复均以「去修复必红」验证：进度接线（TCP/UDP e2e 双红）、节流（暂停时钟单测计数断言）、
save 句柄（修复前 PermissionDenied 稳定复现）、.bak 排除（新记录计数断言）。
GUI 层判别以实机冒烟 + core 同层测试替代（UI 无自动化框架，登记为已知限制）。

### 残余风险更新

- 移入已落地：进度事件（M4'）、WebView2 检测引导。
- 仍延后：QUIC 通道绑定证明、FEC 吞吐基准、多平台发布矩阵、自更新公钥占位（发布检查单硬项）、
  GUI 完整产品范围项（队列持久化/群发/监控/暂停继续/接收选项对话框/设备发现/统计历史——TECH-STACK §7.9）。
- 新增接受：接收器「停止」= abort（半成品由孤儿清扫兜底，与进程被杀同口径）。

---

## M5' 交付记录（2026-10-31）

按 TECH-STACK §7.10 完成 M5'：设备层下沉 core + `ConfirmReceive` + `PerDeviceFolder` +
`AutoArchive` + 统计与历史（stats）+ 监控模式（monitor）。
基线 133 项 → **156 项测试全绿**（rustc 0 告警），CLI 实机收发 + GUI 实机启动/WebView2 冒烟通过。

### 交付清单

| 项 | 落点 | 判别测试（去修复必红） |
|---|---|---|
| `devices` 模块（DeviceInfo/DeviceStore 写穿持久化、upsert/known/name_for；从 GUI 下沉） | `trft-core/src/devices.rs` | store 解析/去重/淘汰/持久化往返 4 项单测；GUI 改薄调用 |
| `ConfirmReceive`（确认钩子 + 30s 超时 + 无应答/通道缺省 fail-closed + 同 IP 10 分钟免重复 + unknown 已知放行） | `receiver.rs::confirm_once` + RecvOptions（confirm_mode/tx/seen/timeout） | e2e 五连：通过应答落盘、拒绝不落盘、无应答不落盘、通道缺省拒绝、known 免弹窗、窗口内免重复 |
| `PerDeviceFolder` + `AutoArchive`（`resolve_save_dir`：`<save>/<设备|IP>/<日期>/`；设备名 sanitize 防穿越；会话建立时固定目录） | `receiver.rs::resolve_save_dir`；接线 recv_single/recv_folder_over/recv_resume_file/recv_resume_folder/chunked（会话 part 派生发布目录）/UDP 引擎（handle_from 按来源 IP） | e2e：记忆名分目录、未知回退 IP、仅归档一层、叠加 `<设备>/<日期>/`、0x04 分目录二次同步全跳过（缓存键同口径）、UDP 引擎按来源 IP 落设备/日期目录 |
| `stats` 模块（stats.log 追加 + 2MB 重写留 5000 + 今日/7 天/累计聚合 + 按设备明细 + CSV BOM 导出） | `trft-core/src/stats.rs` | 单测：行往返/旧 6 字段/重写收敛/聚合桶/CSV 转义 |
| stats 接线（成功完成记账；发送 6 入口 + 接收 0x00/0x01/0x02/0x03/0x04/0x06/UDP 双侧；GUI/CLI 同一 stats.log，不加开关） | `sender.rs/resume.rs/folder.rs/chunked.rs/receiver.rs/udp.rs` + CLI + GUI | 实机：CLI 收发后 stats.log 出现 S/R 两行（0x03 续传） |
| `monitor` 模块（轮询扫描唯一事实源 + notify 事件仅提前触发 + 独占打开+500ms 稳定窗双门 + 未就绪后移一位 + 已消失丢弃 + 日志 60s 节流 + 成功移入「已发送文件/」） | `trft-core/src/monitor.rs` | 单测：增长文件不就绪、重名追加序号、扫描排除已发送/子目录；e2e：监控目录→自动发送→落盘→归档全链路 |
| GUI 接线（设备薄调用、确认弹窗 30s 倒计时、设置三选项、统计页签概览/明细/导出/清除、监控面板、状态/命令层扩展） | `trft-gui/{state,commands,main}.rs` + dist 前端 | core 同层 e2e 覆盖（UI 无自动化框架——已知限制沿用）；实机冒烟 |

### 本轮开发中发现并修复的缺陷（全部由测试或实机暴露）

1. **GUI 版 `device_upsert` 空名清掉已有记忆名（既有缺陷，随下沉暴露）**：条件
   `old.name.is_empty() || d.name != old.ip` 对空名恒真——仅发送成功记忆（匿名）会
   清空 discovery 学到的名字，进而令 PerDeviceFolder 回退 IP。→ 修复：只有「真实名字」
   （非空且非 IP 回退）才覆盖。判别：upsert 单测（空名重记录保留已知名）。
2. **stats 旧格式行被当坏行丢弃（实机冒烟抓到）**：本机已有 C# 版 stats.log（时间列 =
   `"2026-10-30 21:14:43"` 本地时间字符串、秒列带小数 `"0.0"`），首版解析仅认 Unix 秒。
   → 修复：时间列双格式（数字/手解析旧格式转 Unix，macros/parsing 特性不引入）、
   秒列兼容小数、时间列损坏按 0 兜底（仅进累计桶——判错方向是多读不是漏报）。
   判别：`legacy_csharp_eight_field_lines_parse`（以实机真实行样本为断言）。
3. **限量模式 handled=0 不收尾（既有语义，测试编排踩中）**：拒绝路径（确认未通过/
   fail-closed）不递增 served，`--count` 模式永不满足计数——与配对拒绝同口径，
   属既有行为；判别测试改用「处理时间 + abort」收尾，语义登记在案。

### 判别纪律执行

- 确认三态 e2e：去掉 confirm_once 钩子（或 fail-closed 短路）即红；known 免弹窗用
  「通道存在但必须未被消费」断言钉住。
- 分目录/归档：去掉 resolve_save_dir 接线（回落 save_dir）即落点断言红；0x04 二次
  同步全跳过钉住缓存键与落盘键同口径。
- UDP 目录解析：去掉 resolver（engine.handle 路径）即落根目录红。
- 监控：copy_complete 对增长文件必须 false（稳定窗期间写入即红）；monitor e2e 去掉
  发送或归档任一段即红。
- stats 重写收敛：6000×420B 压到 2MB 之上，重写后 ≤5001 行且最新一条保留。

### 残余风险更新

- 移入已落地：监控模式、ConfirmReceive、PerDeviceFolder、统计与历史、AutoArchive
  （TECH-STACK §7.9 缺口清单清零，Win11 Mica 仍延后）。
- 新增接受：单向 UDP 不参与 ConfirmReceive（无握手确认点——TECH-STACK §7.10）；
  stats 仅记成功完成（失败可见于进度终态/日志）；UDP 发送侧统计为「已发出」口径
  （无回传链路，对端落盘侧另记账）；限量模式对拒绝路径不计数（既有语义）。
- 仍延后：QUIC 通道绑定证明、FEC 吞吐基准、多平台发布矩阵、自更新公钥占位、Win11 Mica。

---

## M6' 交付记录（独立审查轮 ×8 + QUIC 通道绑定，2026-11-01）

按 TECH-STACK §7.11/§7.12 完成 M6'：QUIC 0x0D 证书指纹通道绑定（双向确认）
+ 8 轮独立审查（代码/安全交替，M2' 纪律）。
基线 156 项 → **165 项测试全绿**（rustc 0 告警），CLI/GUI 实机冒烟通过。

### QUIC 0x0D 通道绑定（新帧，WIRE-PROTOCOL.md §2.1）

- C→S 证明绑定「客户端所见服务器证书指纹」（`peer_identity` 端实体 SHA-256）：
  双臂中继两腿证书必然不同 → 证明必败（判别：`mitm_dual_arm_relay_rejected_by_channel_binding`，
  去 binding 接线 = legacy 过中继假成功，实测变红）；
- S→C 证明（轮 2 P1 补齐）：`HMAC(K, "trft-pair-bind-s2c-v1"‖盐‖fp)`——盲接受型假
  服务端（不知码、窃数据模型）必败（判别：`blind_accept_fake_server_rejected_by_s2c_proof`，
  去 s2c 校验实测假成功变红）；
- 新版服务端 QUIC+配对强制 0x0D（明文 0x05 确定性拒绝）；新客户端遇旧服务端自动
  回退明文 0x05 并记警告（§7.11 兼容口径）。

### 8 轮审查发现与修复（全部闭环或登记偏离；判别纪律执行）

| 轮 | 视角 | 关键发现 → 修复 |
|---|---|---|
| 1 | 接收路径正确性 | **P1 缓存投毒**：0x03 冲突改名后按旧路径填缓存 → 0x04 同步静默不更新（判别：Skip 模式同尺寸重发必须真收，去修复实测红）；0x00 缓存免费填充缺席；IPv6 IP 回退目录含冒号；confirm_seen 容量防线；publish_part 退化路径崩溃残留 |
| 2 | 威胁模型/Web | **P1 发现应答污染**：伪造 0xD2 把自己洗成「已知」绕过 ConfirmReceive → DeviceSource 分级（is_known 只信 Transfer/User，判别单测）；**P1 0x0D 缺 S→C 证明**（见上）；**P1 Web 慢连接锁死**（/health、/login 豁免闸 + 闸获取 30s 上限 + hyper header_read_timeout 15s——规格 §6.1 此前零实现）；/login 4GB body 缓冲（8KB 上限）；下载全量驻留内存（流式）；发布改 hard_link fail-if-exists |
| 3 | 并发/生命周期 | **P1 GUI 幽灵任务**（spawn/insert 竞态 → settled 补偿摘除；queue/verify 任务永驻表 → 防睡眠计数永久泄漏 → 自摘除）；**P1 分块取消语义失效**（游离 tokio::spawn 继续传完 → JoinSet）；UDP Reporter 逐出悬空（惰性清扫补终态）；pending_confirms 看门狗；connect 10s 超时；recv_start 占位防孤儿监听器 |
| 4 | 输入校验/DoS | **P0 0x03 偏移权威**（服务端把客户端 declared 置于磁盘事实之上——审查代理用真实二进制实测：1MiB 输入绕过磁盘预检写满 2GiB，放大比 2,000,000:1。修复：offset = 磁盘事实 + 收尾长度硬校验；判别测试去修复实测红）；**P1 UDP kill-switch**（一个超长数据报 → WSAEMSGSIZE → 接收器退出，实测复现；判别测试去修复实测红）；**P1 0x0B 无界分配**（恶意应答 n=2^32-1 → 64GB with_capacity；MAX_MERGED_RANGES 上限 + saturating 运算）；压缩段 9B 头悬持 64MB（增量缓冲）；上传字段数上限 1000；update sig/chunked/多字节切片 panic |
| 5 | monitor/update/CLI | **P1 归档失败无限重发**（待归档列表 + 事件节流）；chunked 下载不支持 chunked 定界（增量解码）；staged 拷贝第 3 次校验（换入物=staged——原「重校验」没封住 copy 窗口）；CLI 坏 IP 退出码 2；sync 补 stats；monitor stop 热自旋（自查自纠：修复引入的 has_changed 恒 false 被自家测试环境抓到挂死）；updates/ 陈旧清扫 |
| 6 | 密码学/TOCTOU 复核 | 无 P0/P1；**P2 令牌可反推配对码**（无密钥快速哈希 → 每安装 HMAC 密钥 + token_for/check_token 64/32 hex 错位修复——扫码直连同链修复）；**P2 IPv6 绕过锁定门**（/64 聚合，判别单测）；GUI 配置 validate 失败静默降级（告警）；0x0D 无码互等（补 32B 零证明） |
| 7 | GUI 命令层 + 规格符合性 | **P1 monitor_start invoke 形状错误**（缺 req 包裹——GUI 监控必败，实机冒烟未覆盖该步的教训）；**P1 queue.txt 读写分隔符错位**（恢复恒空）；**P1 防睡眠漏发送/共享/校验路径**；**P1 进度 ID 跨 Hub 冲突**（群发卡片串台、按钮错绑 → Hub 全局基址）；群发汇总收敛（send_cancel 补终态事件）；暂停态被 failed 覆盖（保持已暂停）；update_install 前端接线（此前零触发点）；拖放目录自动路由；设备 proto 记忆、端口探测传输类型、防火墙协议等 P3 |
| 8 | 判别力抽查 + 回扫 | UDP kill-switch 判别补齐（去修复实测红）；全量回扫 165 项绿；CLI/GUI 实机冒烟复验 |

### 本轮开发中引入并被测试环境抓住的缺陷（自愈记录）

- 轮 5 monitor 停止臂改为 `has_changed()` 判定——`changed()` 已消费变更标记 →
  恒 false → 主循环热自旋。`monitor_sends_ready_file_and_archives` 环境挂死暴露；
  修复为 `changed()` 就绪即停（协议上发送端只发 true）。

### 判别纪律执行

五个关键判别均实测「去修复必红」：0x03 偏移权威（P0）、缓存投毒（轮 1 P1）、
双臂中继（M6' 特性）、盲接受假服务端（轮 2 P1）、UDP kill-switch（轮 4 P1）。
前端无自动化判别（monitor_start 形状错误即漏网案例）——实机冒烟步骤在下一批
补「启动监控 → mon_queued 事件出现」。

### 残余风险更新

- 新增接受：明文 0x05 无 S→C 证明（0x09/0x0D 覆盖默认路径）；UDP 发送统计
  「已发出」口径；限量模式拒绝路径不计数；GUI 前端文案/日志中文残留（EN）；
  文件日志/crash.log/路径红框等 §3.7 在案缺口（§7.9 未声明落地）。
- 移入已落地：QUIC 通道绑定证明（M3' 延后项）。
- 仍延后：FEC 吞吐基准、多平台发布矩阵、自更新公钥占位（发布检查单硬项）、Win11 Mica。

---

## 第二轮全量审查交付记录（8 轮制·含前端 JS，2026-11-01）

按用户需求对齐执行：范围 = 全量（4 crate + 前端 JS 专项轮）、组织 = 专项视角 ×8
（每轮独立上下文审查代理、发现当场修 + 全量回归 + 判别纪律）、git init + 每轮一提交、
release 全 workspace 构建。
基线 **165 项** → **180 项测试全绿**（rustc 0 告警，含全部测试目标）。

### 总览

| 轮 | 视角 | P0 | P1 | P2 | P3 | 提交 |
|---|---|---|---|---|---|---|
| 1 | 协议/传输正确性 | — | 3 | 1 | 4 | 4c90207 |
| 2 | 威胁模型/安全 | — | 1 | 2 | 3 | 6ff03cb |
| 3 | 并发/生命周期 | — | 2 | 3 | 3 | 9bd1fc1 |
| 4 | 输入校验/DoS | — | 1 | 1 | 7 | c311e44 |
| 5 | 资源泄漏/性能 | — | — | 3 | 5 | 1c669be |
| 6 | 规格符合性抽查 | — | — | 5 | 9 | 5e6e4fc |
| 7 | GUI/CLI 命令层 + 前端 JS | — | 1 | 3 | 9 | e965500 |
| 8 | 判别力抽查 + 全量回扫 | — | — | 2 | 3 | （本提交） |

约 **90 项发现全部闭环**或登记为已声明偏离（TECH-STACK §7.13–§7.18）。

### 关键发现与修复（按轮）

**轮 1（协议/传输）**——三个 P1 全部为假成功/机密性级：
- **0x0C 假成功窗口**：`assembling`（覆盖达成即置位）被当作「组装完成」回 0x01——
  组装失败时并行连接已拿到过早 0x01 → 客户端报成功、服务端无文件。拆
  `assembling`/`assembled` 两态 + Notify 等待组装结论（暂停时钟判别测试 ×2）。
- **UDP FEC 末块确定性拒绝**：`size % 1200 ≠ 0` 时发送端补零到块长、接收端按余数
  精确校验——末块 DATA 每次必拒，交付完全依赖末组 PARITY（全丢即失败）。发送端
  末块改发实际余数（RS 编码内部仍补零），WIRE §5 同步（同时修正该节 20B/24B 头
  布局自相矛盾）。
- **0x01 文件夹明文降级**：`send_folder` 直连 + 仅 0x05——`opts.encrypt` 被静默
  忽略。改走 `connect_stack`（0x09 接线）。
- P2：0x10/0x11 协商读 30s 窗口错配服务端冷缓存哈希（→ `read_u8_long` 5 分钟 +
  `dest_hash` 现算回填缓存）。P3：0x06/confirm 拒绝字节、0x09 无码分支流对称、
  0x02 补发轮压缩协商。

**轮 2（威胁模型）**：
- **P1 QUIC 0x0D 通道绑定被「伪装旧服务端」强制降级绕过**（审查代理 PoC 实测）：
  MITM 对 0x0D 回裸 0x00 → 客户端自动回退明文 0x05（无 S→C 证明）→ 盲接受 +
  窃取 + 假成功——推翻「回退只可能发生在旧服务端上」前提。降级改 fail-closed
  （`--allow-legacy-pair` / `--pin` 显式放行；GUI 无放行开关）。
- 实施中发现的旁路（纵深防御）：`connect_quic_auth` 的 if-let 只接 AuthRejected，
  超时/EOF 等被吞后以未认证流继续——改一律上抛（两个利用变体实证在本栈不可达，
  如实登记）。
- P2：PairingGate 把全部 IPv4-mapped IPv6 + ::1 折叠进 `::` 桶（任一攻击者连带
  锁定全部 IPv4 用户）→ mapped 归一内嵌 v4；接收器并发闸获取无超时 → 30s 上限。
- P3：非硬链接卷 rename 覆盖 TOCTOU（→ create_new+copy）、解压聚合内存（登记）、
  Web 请求体慢滴（→ 60s 空闲超时）。

**轮 3（并发/生命周期）**：
- **P1×2（代理 PoC 实证）**：分块会话逐出（TTL/LRU）丢弃接收 Reporter 无终态
  （GUI 进度卡永久 running + 语言锁死）→ 逐出补 `fail_if_running()`（done 不得
  翻转）；发送侧 `?` 早退绕过进度终态（UDP 全部错误路径、分块建连失败）→
  Outcome 守卫统一收口。
- P2：防睡眠 `SetThreadExecutionState` 每线程语义（worker A 置位 B 清不掉 → 系统
  永不休眠）→ 收敛 Tauri 主线程；`recv_stop`/`recv_start` 占位窗口竞态 → 代际
  令牌；serve 任务异常退出句柄残留 → 自摘注册表。
- P3：settled 补偿协议残余窗口（锁内置位）、HashCache 持锁阻塞 IO（登记）、
  发现应答死槽（done 标志重建）。

**轮 4（输入校验/DoS）**：
- **P1 Web 全量不可用（轮 2 修复自身缺陷，代理对真实 TCP 实证）**：hyper 未配
  Timer——每次读请求头即 panic（明文 HTTP/1 全被 RST、slowloris 守卫归零），
  被进程内 oneshot 测试缺口掩盖。补 Timer + 真实 TCP e2e ×2（GET 成功/半开 15s
  掐断，去 Timer 必红）。
- P2：`server-auto` 的 h2c prior-knowledge 绕过 h1 专属读超时（→ 去 server-auto，
  http1 直连）。
- P3：0x02 载荷预分配（→ 流式）、更新器 chunked 行无上限（→ 8KB）、0x0B 逐字段
  拖延（→ 60s 总预算）、UDP MSGSIZE 仅匹配 Windows 码（→ 跨平台）、Range 后缀
  N≥size（→ RFC 9110 200 全量）、裸 IPv6 URL、GUI invoke 信任边界（登记）。

**轮 5（资源泄漏/性能）**：
- P2：**摘要缓存 degraded 模式无界增长**（代理 GlobalAlloc PoC：200 万条 +260MB
  零收敛 vs 可写路径 +32.5MB 收敛——degraded 下分代淘汰不可达）→ 条目数硬封顶
  200k（满则清空重建）；**Web 上传 `.up*.part` 不在任何清扫器覆盖**（进程被杀
  后永久残留用户目录）→ `cleanup_upload_orphans`（7 天）；**文本历史单条 1MB
  × 200 条**（稳态 ~200MB + 写放大 200:1）→ 单条截断 2KB。
- P3：JoinSet 完成条目驻留（随 accept 收割）、前端 taskByProgress 只增不减、
  refreshStats 终态风暴、队列前端无上限、UDP events 通道（登记）。
- §6.2 各内存封顶设计点全表核查（UDP 位集/FEC 超块/进度节流/容量防线成立）。

**轮 6（规格符合性）**——P1=0，§6.1 全部容量常量逐项命中、假成功红线零违例：
- P2×5 全部修复：配置自愈缺「不可读/解析为空」两场景（→ 回退 .bak）；HTTP 共享
  未随窗口隐藏停止（§3.4）；QueueRetries 缺席（→ config `queue_retries` 默认 1）；
  队列不快照面板参数（→ 9 字段行持久化）；文件夹失败未转 0x04（→
  `send_folder_auto`：0x01 回填本地缓存 → 稳定会话 ID 差量续传，判别 e2e）。
- P3×9：分块默认 4 路对齐、防火墙提示按协议生成、WIRE §3.4 文档漂移修正等；
  5 项登记（update --restart、同步会话对话框、数据文件布局、GUI SrcPort、
  TCP 4MB 缓冲）。

**轮 7（GUI/CLI 命令层 + 前端 JS 专项，M6' 轮 7 同型）**：
- **P1 暂停/继续自毁回归**（本轮 r7 历史修复与取消终态事件互相打架——事件先于
  invoke 返回，前端清掉继续按钮的依赖 → TypeError + 暂停守卫死代码）：
  `send_cancel` 增 `paused` 标记 + 前端先置位再 invoke + paused 任务保留映射。
- P2：队列 UDP 项静默改走 TCP（kind 映射不一致）→ 对齐 + UDP 参数入快照；
  0x02 回退 0x03 卡无按钮（→ 补发 task-start）；窗口隐藏停共享后前端死二维码
  （→ `trft://sync-state` 事件重拉状态）；监控槽位写入竞态（→ MonitorTask 代际
  令牌）。
- P3×9：校验重入守卫、主题/语言即时持久化、GUI UDP 约束提示、CLI 静默忽略组合
  显式报错、死代码删除、队列逐项校验等；确认弹窗并发（登记）。
- 机械对照全干净：~30 个 invoke 参数键、10 类事件 payload、L10N 180 键 zh/en
  对称、DOM id 全存在。

**轮 8（判别力抽查 + 回扫）**：
- **判别力 12/12 强**：本轮周期 12 组修复-测试对全数具备真实判别力（6 项实测
  「去修复必红」：0x0C 窗口、拒绝字节、gate_key、degraded 封顶、hyper Timer、
  空主文件回退；6 项静态确认），无恒真/恒假/被兜底。
- 回扫：180 绿、构建 0 告警（含测试目标）、JS 语法 OK、无调试残留。
- 收尾修复：测试面 2 条编译警告（r6 引入——全 workspace 唯二告警破口）；
  `is_upload_part_name` 按自产名严格同形（附判别单测，误伤面归零）；EMSGSIZE
  注释平台值更正；REVIEW-LOG/TECH-STACK 文档欠账补齐（r1/r3 入审计轨迹）。

### 判别纪律执行

新增行为修复均以测试钉住；轮 8 对全部 12 组做判别力抽查（含 6 项「去修复必红」
实测）。轮 1–8 各轮提交信息中含判别测试名与实测红记录。

### 残余风险更新

- 移入已落地：QUIC 旧服务端降级 fail-closed（§7.11 前提修正）、Web 请求体超时、
  0x01 加密接线、文件夹失败转 0x04、QueueRetries、队列参数快照、配置自愈全场景。
- 新增登记接受：0x08 解压聚合内存、接收器慢滴占用、UDP events 通道直发、GUI
  invoke 信任边界、确认弹窗并发、CLI update --restart、同步会话对话框、数据文件
  布局差异、GUI SrcPort、TCP 4MB 缓冲（详见 TECH-STACK §7.13–§7.18）。
- 仍延后：FEC 吞吐基准、多平台发布矩阵、自更新公钥占位（发布检查单硬项）、
  Win11 Mica。

## UDT/QUIC 槽位拆分交付记录（2026-11-10）

**决策**（用户拍板）：原「UDT」模式恢复 UDT 语义（原生 Rust 自研可靠 UDP 流，`transfer::udt`——
ARQ+SACK+固定窗口，与 UDT4/C# 不做包级互通，规格 §4.3 口径不变）；原「UDT (QUIC)」实现
（quinn）改名 **QUIC** 独立成第四模式。本轮随行排障修复四处自研传输层缺陷（实现坑实录见
TECH-STACK §7.28）：

1. **tokio `Notify` 丢唤醒**（自研 UDT shutdown 永挂）：`Notified` future 逐 poll 重建、drop 即
   注销——`notify_waiters` 触发时队列已空。改 FIN_ACK 走 mpsc 通道（waker 挂 Receiver 常驻）。
2. **watch 无接收者静默丢值**（RST 误读为干净 EOF）：`err_tx.send` 在 `err_rx` 被丢弃时不存值，
   `error()` 恒 None——「结果未知 ≠ 成功」红线被绕过。`err_rx` 随状态机持有。
3. **current-thread runtime 自旋饥饿**：`recv_from/recv` 有积压即同步 Ready，demux/泵/驱动互饿
   （表现为 loopback ~55KB/s 与偶发重传超限）——所有包处理循环逐包 `yield_now()`。
4. **std Mutex 临时守卫重入死锁**（本轮诊断打印自伤）：同语句两个 `.lock()` 临时 guard = 死锁。

**判别**：`tests/e2e_udt.rs` 真 socket 四测（单文件 SHA-256 一致 / 配对门三态 / 0x09 加密路径 /
握手版本门 fail-closed）+ 引擎对偶注入四测（无损双向 FIN/EOF / 25% 丢包恢复 / RST 传播 /
重复 DATA 不重复投递）+ 发现帧新旧兼容 + devices 迁移幂等；全量回归绿。

## 自研流更名 RUDP 交付记录（2026-11-12）

**决策**（用户拍板）：拆分批给自研可靠 UDP 流顶用「UDT」之名——UDT4 是既有协议专名，
会误导互通预期且实现并非 UDT4。更名 **RUDP**（Reliable UDP，业界通用描述性缩写；
RFC 908/1151 的 RUDP 已历史化，本实现线格式以 WIRE-PROTOCOL.md §7 为权威、与任何
外部协议不做包级互通——§4.3 口径不变）。

- **范围**：Transport/MonitorProto/GUI Proto 变体、模块文件（git mv 保史）、函数与类型名、
  常量 `UDT_*`→`RUDP_*`、错误串、CLI `--proto rudp`、GUI 前端全量、发现帧字段名
  `rudp_port`（线值零变化）、配置键 `*RUDP`（未发布无存量，直接改名）；
- **迁移链改向**：devices 残余 `"udt"`→`"rudp"`；queue 头升 v3 并按头分档
  （无头 udt→quic 拆分前语义；v2/v3 头 udt→rudp）——`migrate_queue_text` 分档 + 幂等测试；
- **判别**：e2e_rudp 4 测（真 socket 全链路）+ 引擎单测 + 迁移判别 + 全量 225/0 绿；
  线格式与更名前零差异（WIRE-PROTOCOL §7 命名沿革注记）。
## 真 UDT4 槽位交付记录（2026-11-13，TECH-STACK §7.30）

**决策**：兑现 §7.29 让出的「UDT」名义——新增第 5 传输槽位 **UDT**，原生 Rust 逐字节
复刻 vendored libudt 4.x（C# 2.14 内嵌的同款协议），并在其上实现 **C# 方言应用层**。
全仓库唯一承诺外部互通的传输（§4.3 口径修订：UDT 槽位专通 C# 2.14，其余槽位不变）。
范围 = 用户拍板的「完整集 + 双向发现兼容」。

**范围**：

- 传输层 `protocol/udt.rs` + `transfer/udt.rs`：16B 包头（头/控制载荷大端、数据载荷
  1456B）、两段式 cookie 握手（响应 ISN 回显客户端 ISN——libudt 安全校验语义）、
  ACK（cum/rtt/rttvar/buf 6 词载荷 + 轻量 ACK）/NAK（区间编码）/ACK2/EXP/keepalive/
  SHUTDOWN、流窗 + 慢启动近似、服务端单 socket 按 dst socket id 多路复用、
  1002 拒绝门（版本/IP 过滤/连接表满）、30s 空闲 + EXP 断连。
- 应用层 `transfer/cswire.rs`：0x09 ECDH（CNG blob/PBKDF2-HMAC-SHA1/SHA256(X) 材料/
  seq 绑定 HMAC 段）/0x05/0x08 deflate/0x0A 前奏栈（8s 响应窗 + 认证前拒收 0x08/0x0A）
  + 0x00/0x01/0x02 组会话/0x03 断点（服务端权威 offset + 增量哈希）/0x04 目录同步
  （0x11 + 每文件跳过清单）/0x06/0x0B 覆盖查询；**裸流 1B ACK**（装饰器之外）；
  C# 净化语义（SafeName/SanitizeRelativePath/name_1.ext）+ v2 确认门/重复策略/
  进度/统计复用。
- 集成：`Transport::Udt` 全链（sender/folder/resume 顶层拦截转 cswire、monitor、
  CLI `--proto udt`、GUI 第 5 接收卡 + 发送选项 + 端口跟随 + 设置行 + dist 前端）、
  配置键 `server_port_udt`/`save_dir_udt`、发现帧 bit4+udt_port + **C# 双向兼容**、
  devices.json v2 格式迁移、queue v4 头按头分档迁移。

**迁移**：v1 裸数组 devices.json 的存量 "udt"（= 更名前 RUDP）首载一次性改写
"rudp" 并升级 v2 格式；v2 格式 "udt" = 真 UDT4 永不改写。queue v2/v3 头 "udt" →
"rudp"、v4 起 "udt" = 真 UDT4（判别测试锁定两侧语义）。

**实机钉死的偏差**（推断 vs .NET 实机——互通互锁的关键产出）：

1. CNG ECCPUBLICBLOB magic = **"ECK1" 大端 FourCC**（"ECC5" 系 ECDSA 族前缀误推；
   `to_le_bytes` 反转成 "1KCE" 被 CNG 拒收 → 对端哑材料 → confirm 失配）。
2. ECDH 材料 = **SHA256(共享点 X 大端 32B)**（DeriveKeyMaterial 默认 Hash/SHA256 KDF）。
3. PBKDF2-HMAC-SHA1（Rfc2898DeriveBytes）与 AES-256-CTR（计数器全 16B 大端递增、
   跨段持续）按 .NET 实机向量固化单测。
4. Windows ICMP 毒化（对已关端口发包 → recv 报 10054）：泵按瞬态继续 + send 重试，
   否则服务端整体退出（resume e2e 排障实录）。
5. C# 0x03 尾哈希 = **增量哈希**（本次连接字节），全文件哈希走可选 verifyFlag 字段。

**判别测试**（移除对应实现必须转红）：

- `protocol::udt` 6 项：seq 回绕/包编解码/握手编解码/NAK 区间（含伪造巨型区间
  内存炸弹防护）/非法包 fail-closed。
- `transfer::udt` 引擎 6 项：无损双向 + SHUTDOWN EOF、25% 确定性丢包 NAK 重传恢复、
  提前 drop 的 EOF 语义、重复 DATA 去重 + 乱序重排、超前 ACK 断连、窗口限流。
- `transfer::cswire` 6 项 KAT：PBKDF2-HMAC-SHA1（RFC 6070 + .NET Rfc2898DeriveBytes
  双源向量）、AES-256-CTR 密钥流（.NET AesCtrTransform 实机向量）、CNG blob 往返 +
  魔数、0x09 密钥调度对称（含跨段计数器持续）、C# 净化语义、区间合并。
- `tests/e2e_udt.rs` 7 项（真实 UDP socket）：单文件 SHA-256 回环、配对三态
  （无码/错码拒 + 对码 0x09 加密成功）、文本/目录、**C# 方言测试客户端**单文件/
  0x02 组会话并发分块组装/0x03 断点续传（服务端权威续点）、版本门 1002。
- CLI 跨进程 `--proto udt` recv×send 真实子进程；发现 C# 双向兼容判别 2 项；
  devices v2 格式迁移判别（v1 "udt" 改写 + v2 "udt" 保真）；queue v4 分档判别。

**实机对打**（C# 2.14.0.0 exe CLI，2026-11-13，全部 SHA-256 逐字节一致）：v2→C#
明文单文件（700KB）/0x09 加密单文件/目录 0x01（相对路径 2 文件）；C#→v2 明文单文件
（含 0x08 压缩协商，47 MB/s）/0x09 加密单文件；重命名策略（interop_1.bin）。

**测试基线**：225 → **254**（+29 = 引擎 6 + codec 6 + KAT 6 + e2e 7 + CLI 1 +
发现/devices/queue 判别 4，其中 §7.29 批零新增），`cargo test --workspace` 全绿。

**文件清单**：新增 `crates/trft-core/src/protocol/udt.rs`、`src/transfer/udt.rs`、
`src/transfer/cswire.rs`、`tests/e2e_udt.rs`；修改 `protocol/mod.rs`、`transfer/mod.rs`、
`transfer/{sender,folder,resume}.rs`、`monitor.rs`、`config.rs`、`discovery.rs`、
`devices.rs`、`Cargo.toml`（sha1）、`trft-cli/src/main.rs`、`trft-gui/src/{state,commands}.rs`、
`trft-gui/dist/{app.js,index.html}`、docs 四册。

---

## 独立审查修复批（2026-11-16，轮 UI-5：P0 + 6×P1）

外部独立审查（6 个并行审查上下文 + 逐条复核）发现 1×P0 + 6×P1，本批全部修复并配
「去修复必红」判别测试；基线 272 → 280 项全绿（rustc 0 告警，连跑 3 次无 flake）。

1. **P0 0x04 同步更新失败删除既有文件**：旧 Err 分支先删 save_path 再发布一个从未
   创建的 temp（净效果：用户上一版文件凭空消失、新档未落）。修复：新增
   cs_publish_replace（同目录 rename 原子覆盖），失败路径不触碰 save_path；
   receive_payload 增加 PartGuard 清理内层半成品。判别：
   cs_sync_failure_preserves_existing_file_and_success_replaces（e2e_udt）。
2. **P1 0x03 已完整零校验**：体收满但尾哈希前断连时 received == total 且会话保留，
   下一连接直接回 st=2。修复：CsResumeState.verified + 磁盘长度硬校验；未验证会话
   删除残件并回 st=0/offset 0 整组重来；已验证会话保留以支持 C#「已完整」重问（不重复
   记账）。判别：cs_resume_body_without_tail_hash_is_not_reported_complete。
3. **P1 0x02 组装器缺失仍回成功**：并发参数不符/TTL 清扫摘除后块被静默跳过、本连接
   哈希只覆盖自己收到的字节仍回 ACK 0x01。修复：取不到 tracker 即 Err（整组重发）。
   说明：仅 TTL/完成后可达，属防御性收口，无独立判别 e2e（已在审查报告登记）。
4. **P1 0x09 预认证 KDF 放大 + 中断握手不计数**：server_wrap 在证明字节前算 PBKDF2，
   且 IO 错误不计锁定 → 单主机发 1 字节即断可打满 CPU。修复：先读满 32B 证明再算 KDF；
   pairing_phase_err 把配对阶段的 Io/Proto 折算 AuthRejected（业务帧后错误不受影响）。
   判别：interrupted_encrypted_handshake_counts_toward_lockout（e2e_recv_options）。
5. **P1 UDT 轻量 ACK 无超前校验**：seq_off 可返回 ≈0x3FFFFF00（10 亿次 pop_front），
   并把 last_ack 推到未来（重传/窗口永久错乱）。修复：轻量分支复用完整 ACK 的
   cum <= next_seq+1 校验（越界断连）+ off 上界兜底。判别：
   lite_ack_oversized_breaks_connection_without_spin（引擎单测）。
6. **P1 Web ?t= 令牌只覆盖首个请求**：页内链接/表单下一次请求无 Cookie 无令牌 → 303。
   修复：auth_mw 令牌通过即签发会话（issue_session 与登录共用）、attach_session_cookies
   统一 HttpOnly+SameSite=Strict。判别：token_query_issues_session_for_subsequent_navigation。
7. **P1 is_upload_part_name 字节切片 panic**：非 ASCII 名（.up 后第 8 字节落在字符中）
   使共享启动/清理 panic。修复：is_char_boundary(8) 前置守卫。判别：
   upload_part_name_rejects_multibyte_without_panic（server 单测）。

**判别纪律执行**：上述 1/2/4/5/6/7 六项逐项做「去修复必红」实测（临时回退后对应测试
转红并记录断言）；3 为防御性收口（见上）。

**文档同步**：WIRE-PROTOCOL §2.1（旧服务端回退默认 fail-closed，删除已被轮 2 PoC 推翻的
「回退只可能发生在旧服务端上」）、§3（serverOffset = 磁盘事实，删除 max(declared, 实际)）、
§10.2（0x03 st=2 的验证前置条件、0x04 原子替换语义）。

**修复过程中自查发现并一并修掉的两处**（均配回归测试）：
   - 已验证会话保留后，同 sid 换 total 不得删除**已交付文件**（只删未验证半成品）——
     回归：cs_resume_verified_file_survives_param_change；
   - 完成即释放声明量（declared_held 幂等收尾），否则已验证会话在 TTL 窗口内持续
     占用 64 GiB 封顶额度，大批量同步会被误拒——回归：resume_declaration_release_is_idempotent。

**同批复核未修（登记后续批）**：0x02 跨 peer 会话逐出 DoS、0x01/0x04 最终判决 30s 窗口、
0x02/0x03 发布前缺 fsync、sanitize_name 的 .. 子串误拒、配置 .bak 空文件自愈、摘要缓存 TTL
单位、stats 今日时区/重写字节口径、scrub 停止口径、monitor 失败无退避、Web 多区间/空文件
416、更新器相对重定向丢端口等（完整清单见审查报告 P2 表）。

---

## P2 收口批（2026-11-16，轮 UI-5 续）

按审查报告 P2 清单先收 8 项（4 个单元可判别 + 2 个超时口径 + 2 个资源上限）；
基线 280 → **286 项全绿**（rustc 0 告警；clippy 维持 64 条既有风格项，无新增）。

1. **配置 `.bak` 自愈两处**（config.rs）：主文件与 `.bak` 共用 parse_text（空/纯空白
   一律按损坏——此前 `.bak` 空文本被 serde(default) 吃成默认配置，静默关掉配对码/IP
   过滤/确认）；保存时只有旧主文件「可解析且合法」才轮换 `.bak`（此前会把截断主文件
   写成备份，摧毁唯一好备份）。判别：empty_bak_is_not_silently_defaulted、
   save_keeps_good_bak_when_main_is_broken。
2. **摘要缓存 TTL 单位**（hashcache.rs）：mtime 是纳秒、TTL 是秒，旧实现直接相减
   （饱和为 0）→ 条目永不过期，hash_cache_days 成死配置。换算后按文档语义过期；
   判别：ttl_expiry_misses（改用生产同款纳秒输入，去修复必红）。
3. **统计「今日」边界时区**（stats.rs）：midnight().assume_utc() 丢掉本地偏移（UTC+8
   下今日从本地 08:00 起算）。改 assume_offset(now.offset()) + 抽出 today_start_for 可测；
   判别：today_start_uses_local_offset。
4. **文件名 `..` 子串误拒**（protocol/frame.rs）：裸文件名内 `..` 不构成穿越，旧实现
   一票否决导致 a..b.txt / v1..2.log 既发不出也收不了（与 sanitize_rel 口径不一致）。
   判别：accepts_double_dot_inside_name（精确段 `..`/分隔符仍拒绝）。
5. **0x01/0x04 最终判决窗口**（folder.rs / resume.rs）：从 30s 普通窗口改 300s 长窗——
   接收端回执前可能对最后一个文件做整文件重哈希，30s 会误报「对端拒绝」而其实已成功。
6. **RUDP 非环回 mss 钳制**（transfer/rudp.rs）：远端 60000B 提案钳到 1400，读侧待读
   缓冲按块计（2048 块）时单连接内存上限从 ≈123MB 降到 ≈2.8MB；判别：
   peer_mss_clamped_for_non_loopback。
7. **UDT 对端流窗钳制**（transfer/udt.rs）：ACK 通告的 flow_window 钳到 25600（libudt
   默认 flight flag）——否则恶意对端报 i32::MAX 可让发送侧把整个待发文件驻留内存；
   判别：ack_flow_window_is_clamped。
8. **复查修正**：hashcache 的 tamper_detected_via_cache 原先用秒级 mtime（生产不产生），
   TTL 修好后会误判过期——改用纳秒并补「命中必须返回原始摘要」断言。

**判别纪律**：1/2/3/4/6/7 六项逐项做「去修复必红」实测（临时回退 → 对应测试转红）；
5 为超时口径对称性修复（无独立判别 e2e，靠既有 0x01/0x04 e2e 回归覆盖）。

**仍登记后续批**：0x02 跨 peer 会话逐出、0x02/0x03 发布前 fsync、scrub 停止口径、
monitor 失败退避、Web 多区间/空文件 416、更新器相对重定向端口、0x04 目录复用符号链接
包含性校验等（见审查报告 P2 表）。

---

## 交互/网络面收口（2026-11-16，轮 UI-5 续 2）

再收 5 项（4 个可判别 + 1 个耐久性）：基线 286 → **291 项全绿**（rustc 0 告警；
clippy 维持 64 条既有风格项）。

1. **scrub 停止不得报「校验完成」**（scrub.rs + GUI）：`VerifyReport` 增 `stopped`；
   停止时不再补发 `(total,total)`（改回实际进度）——旧行为让进度条走满、结果面板
   mismatches 为空，与「完整扫描且全一致」无法区分；前端按 `stopped` 显示「已中止」
   （新增 L10N 键，zh/en 对称，门禁 bad=0）。判别：
   stop_midway_marks_partial_and_does_not_report_complete（由进度回调触发中途停止）。
2. **Web Range 语义**（trft-server/lib.rs）：空文件无 Range 一律 416 → 改 200 +
   Content-Length: 0（显式 Range 才 416）；多区间/未知单位 Range 从 416 改按 RFC 忽略
   → 200 全量（aria2/播放器/多线程下载器不再失败）。判别：
   empty_file_downloads_as_200_without_range、multi_range_and_unknown_unit_fall_back_to_200。
3. **发布前 fsync**（resume.rs / chunked.rs / cswire.rs）：v2 0x03、0x02 组装、C# 方言
   0x03 三条路径此前不落盘——哈希从页缓存算出，掉电后最终名可能是短文件/零尾而服务端
   已报成功。现与 0x00/0x01/0x04 同纪律（回执前 sync_all）。无独立判别测试（耐久性
   只能在真实掉电场景验证），由既有 0x02/0x03 e2e 回归覆盖。
4. **monitor 发送失败退避**（monitor.rs）：新增 retry_delay（1s→2s→…→上限 10 分钟）
   与每文件下次尝试时刻——旧实现失败即回队尾，每轮（默认 1s）对已死对端重连，永久
   产生连接风暴；失败事件带「第 N 次失败，Ns 后重试」。判别：
   retry_delay_backs_off_exponentially_and_caps。
5. **更新器相对重定向保留端口**（update.rs）：抽出 resolve_redirect，用 host_header_of
   （含端口）而非裸主机——非默认端口的更新源（https://host:8443）相对重定向此前掉到
   443/80 打空。判别：relative_redirect_keeps_port。

**判别纪律**：1/2/4/5 四项均做「去修复必红」实测；3 为耐久性加固（无判别 e2e）。

**仍登记后续批**：0x02 跨 peer 会话逐出、0x04 目录复用符号链接包含性、cswire 会话表
条数上限、0x08 解压放大比、Web 下载并发闸的 body 生命周期、GUI http_start/stop 竞态等。

---

## 落盘包含性 + 共享信息保持（2026-11-16，轮 UI-5 续 3）

再收 2 项：基线 291 → **292 项全绿**（rustc 0 告警；clippy 维持 64 条既有风格项；
L10N 门禁 zh=en=205、bad=0）。

1. **0x04 落盘包含性**（cswire.rs）：0x04 会复用既有会话目录（<folder>.<guid8>），
   而 save_dir 内预置的 junction/符号链接会把对端可控的相对路径写到保存目录之外
   （Windows 上 junction 不需要管理员权限；0x00/0x01/0x02/0x03 用随机半成品名或
   原子建目录，天然不吃这条路径）。新增 ensure_contained：canonicalize 最近存在
   祖先必须落在 canonical(save_dir) 前缀内；根目录与每个文件的父目录建前/建后各验一次。
   判别：cs_sync_rejects_junction_escape（Windows：把会话目录换成 mklink /J 指向树外，
   第二轮同步必须被拒且树外无文件）。
2. **共享信息不得被通用状态事件清空**（GUI）：`sync-state` 是「任意子系统状态变了」的
   通用信号，前端旧实现无条件 `httpInfo = null`——任一接收器/监控退出都会把仍在运行的
   共享显示成「未运行」，链接/二维码再也拿不回来（token 只在后端句柄）。修复：
   HttpHandle 增 token/dir；新增 http_info 命令；前端仅在 httpRunning=false 时清空，
   页面重载/重启后也从句柄恢复链接。前端行为无自动化测试（无 JS 测试基建），
   以 node --check + L10N 门禁 + 真机冒烟为准。

**判别纪律**：第 1 项做「去修复必红」实测（禁用包含性检查后测试转红）；第 2 项为 UI 状态
修复，登记为需真机冒烟验证。

**仍登记后续批**：0x02 跨 peer 会话逐出、cswire 会话/tracker 表条数上限、0x08 解压放大
比守卫（需全局解压预算，非单连接比值）、Web 下载并发闸的 body 生命周期（permit 绑 body）、
GUI http_start/stop 竞态占位、更新安装后进程不重启。

---

## 0x02 会话跨 peer 隔离（2026-11-16，轮 UI-5 续 4）

再收 1 项：基线 292 → **293 项全绿**（rustc 0 告警；clippy 维持 64 条既有风格项）。

**0x02 分块会话逐出按来源分桶**（chunked.rs）：旧策略全局最旧逐出——任意主机开 65
个组（每帧一个，`total=1` 即可）就能把他人正在传的半成品挤出表并删文件，受害连接
随后 0x0C 得 0x00、整组失败。修复：会话记录来源 IP；单来源上限 8 组，超限只逐出
**本来源**最旧且不在组装中的组；全局表（64）满则拒绝新组（fail-closed），绝不跨 peer
逐出。判别：session_eviction_is_per_peer_and_never_cross_peer（受害会话必须存活 +
全局满新来源被拒；已做去修复必红实测）。

**仍登记**：cswire 会话/tracker 表条数上限、0x08 解压放大比（需全局预算）、Web 下载
并发闸的 body 生命周期、GUI http_start/stop 竞态、更新安装后进程不重启。

---

## cswire 跨连接表条数上限（2026-11-16，轮 UI-5 续 5）

再收 1 项：基线 293 → **294 项全绿**（rustc 0 告警；clippy 维持 64 条既有风格项）。

**tracker/会话表条数上限**（cswire.rs）：`declared_total` 只封字节不封条数——每帧
一个 tracker（或每个 0x03 一个会话）即可无限建条目，每条持半成品句柄/会话名，仅靠
15 分钟 TTL 回收。新增 `CS_MAX_TRACKERS=64`、`CS_MAX_RESUME_SESSIONS=256`，超出按
`touched` 最旧逐出；resume 只摘会话/释放声明量、**不删文件**（可能是已验证交付）。
被逐连接随后得到显式错误（组装器缺失 → 整组重发），不会假成功。判别：
session_tables_are_capped（已做去修复必红实测）。

**仍登记**：0x08 解压放大比（需全局预算）、Web 下载并发闸的 body 生命周期、
GUI http_start/stop 竞态、更新安装后进程不重启。

---

## GUI 共享启停竞态（2026-11-16，轮 UI-5 续 6）

再收 1 项：基线 294 → **295 项全绿**（rustc 0 告警；clippy 维持 64 条既有风格项）。

**http_start/stop 竞态**（commands.rs + state.rs）：旧实现 check→bind→insert 有窗口——
两个并发 http_start 可都通过 `is_some()` 检查，后者覆盖前者（旧服务泄漏且 stop 只能
停一个）；bind 窗口内的 stop 也看不到占位（报「未运行」而服务仍起来）。修复：
`HttpHandle` 增 `gen: Arc<()>`；启动**先占位再 bind**（检查与插入同一临界区），bind
失败按 gen 收回占位；收尾凭 `Arc::ptr_eq` 判定占位仍是本次启动——被 stop 取走则返回
「共享在启动过程中被停止」，不得复活。判别：
http_start_placeholder_blocks_double_start_and_detects_stop（并发第二次启动被拒 + stop
后旧代收尾不得覆盖新代；两处均做去修复必红实测）。

**仍登记**：0x08 解压放大比（需全局预算）、Web 下载并发闸的 body 生命周期、
更新安装后进程不重启。

---

## Web 下载并发名额绑 body（2026-11-16，轮 UI-5 续 7）

再收 1 项：基线 295 → **296 项全绿**（rustc 0 告警；clippy 维持 64 条既有风格项）。

**permit 生命周期**（trft-server/lib.rs）：并发闸的 permit 原本随中间件返回即释放——
下载响应体是流式的，慢速客户端（每块隔几秒）可在 body 未读完时重新占名额，32 连接
上限被绕过（每个慢下载 = 一个长连接 + 空闲并发额度）。修复：中间件把 permit 放进请求
扩展（`PermitSlot`），下载处理器取出并包进 `PermitReader`（`AsyncRead` 包装，持有
`OwnedSemaphorePermit`），206/200 流式分支用它构造 `ReaderStream`——名额随 body 销毁
才归还；非流式路由请求结束时随扩展释放（行为不变）。判别：
permit_reader_holds_permit_until_dropped（已做去修复必红实测）。

**仍登记**：0x08 解压放大比（需全局预算）、更新安装后进程不重启。

---

## 真机 F4：GUI 校验聚合丢 stopped（2026-11-17，轮 UI-5 续 11）

CDP 驱动 GUI 冒烟（C9）发现：校验中途停止后仍提示「校验完成」，`scanned` 只有 1118/2002。
根因：`commands::verify_start` 的聚合体只累加计数（`scanned/hit/...`），**没有把各根的
`stopped` 合入**，前端 `r.stopped` 恒为 undefined —— 之前只改了 `scrub` 与前端，GUI 命令层
漏了。修复：`agg.stopped |= r.stopped;`，且停止后 `break 'outer` 不再进入下一个根。
真机复核：提示「校验已中止（仅扫描了部分文件）」、进度 1620/2002。

---

## 真机 F3：0x04 发布前数据落盘（2026-11-17，轮 UI-5 续 10）

B5（0x04 覆盖完成瞬间硬断电）暴露：接收端已回「同步完成」，重启后文件在最终名、
长度满 50 MB，但**内容与覆盖前后的版本都不符**（99.6% 字节不同）——F2 只修了改名
落盘，0x04 的临时文件**没有数据 fsync**（0x02/0x03 在轮 UI-5 续 2 已补）。

修复：`receive_payload` 写完后、`cs_publish_replace` 前对临时文件 `sync_all`（与
0x02/0x03 同纪律）。**真机复核**：二次断电后最终名存在、哈希与覆盖后的源一致、无残留。
基线 299 不变（无新增测试；由 B5 真机用例判别）。

---

## 真机 F2：发布改名必须落盘（2026-11-17，轮 UI-5 续 9）

B3（0x02 500 MiB 完成瞬间硬断电）暴露：**数据落盘了，改名没落盘**——重启后文件仍是
`b3.bin.<gid>.trft-part`（内容与源哈希完全一致、长度满），而发送端已收到「完成」。
根因：`publish_part` 用 `hard_link` + `remove_file`（0x04 用 `rename`），二者都不保证
目录项更新写入磁盘；`sync_all` 只覆盖文件数据，不覆盖父目录。

修复：新增 `publish` 模块——Windows 用 `MoveFileExW`，带 `MOVEFILE_WRITE_THROUGH`：
`move_noreplace`（不带 REPLACE_EXISTING，天然 fail-if-exists，替换「硬链接 + 删源」）与
`move_replace`（0x04 覆盖语义）。接入 `publish_part`（0x00/0x01/0x02/0x03）、UDP
`publish_part_sync`、C# 方言 `cs_publish_replace`、0x04 `publish_replace`。

判别：`publish::tests`（目标存在必失败/成功后源消失/覆盖生效）。
**真机复核**：同场景再断电一次，重启后 `recv\b3b.bin` 在**最终名**、524,288,000 B、
`36b7e118…b376` 与源一致，无 `.trft-part` 残留。基线 297 → **299 项全绿**，clippy 无新增。

---

## 真机 F1：0x02 发布后释放文件句柄（2026-11-17，轮 UI-5 续 8）

真机 A14 暴露、自动化测试覆盖不到的缺陷：**0x02 组装完成后会话仍持有最终文件句柄，
发布出来的文件被锁到会话 TTL（10 分钟）**——用户 10 分钟内打不开/改不了名/删不掉。
根因：`GroupSession.file` 是对半成品文件的 `File` 句柄，`publish_part` 用 `rename` 换成
最终名后句柄不变，Windows 上未共享的读者被挡。

修复：`file` 改 `Mutex<Option<File>>`；`finish` 成功后在 file→state 同序锁下置 `None`
释放；`receive` 的幂等分支（`assembling`/已覆盖）先于取句柄，迟到块仍按幂等忽略，
异常回收才回「分块组装器已被回收（请整组重发）」。

判别：`finish_releases_published_file_handle`（发布后会话句柄必须为 None；去修复必红）。
**真机复核**：重新部署后 0x02 传 8 MiB，接收进程存活期间读取成功且哈希与源一致
（修复前同一读取报 `being used by another process`）。基线 296 → **297 项全绿**，clippy 无新增。

**真机验证**：清单见 [QA-CHECKLIST.md](QA-CHECKLIST.md)——A 段 C# 2.14 互通（含本轮
改动对应的 A4/A7/A8/A9/A10/A12/A14）、B 段 NTFS 掉电 fsync（0x00–0x04 各 3 次）、
C 段 GUI 冒烟（共享保活/空文件与多区间 Range/校验中止/监控退避/统计零点）。

## 对齐批三交付记录（2026-11-13，TECH-STACK §7.31）

**范围**：C# 版（D:\zcode\TrFileTransfer）剩余功能缺口收官——§7.27 G3 登记、IPv6 双栈、
发送目标记忆、AutoUpdateCheck、监控参数快照；登记「不做」项维持（同步会话对话框、
Mica、错误码架构 shim）。UDT 互通（§7.30）后续补实机验证见下节。

- **A 接收行全路径**：判别 e2e 3 项（TCP 直接/跳过行 + UDT C# 方言行断言
  detail=规范文案、path=最终落盘全路径；退回文件名口径必红）；
- **B IPv6 双栈**：TCP/UDP/QUIC 三判别（通配 [::] 监听 + 127.0.0.1 对端），
  去 `only_v6(false)` 实证必红（Windows v6only 默认）；
- **C/D 配置**：config 单测（缺省 + round-trip）+ 前端回填/落盘；
- **E 监控快照**：src_port 接线 + 前端快照传参；
- **测试面**：a1c7b76 的 4 条告警清除，全量回归 0 告警。

## UDT 互通补全 + 实机排障修复（2026-11-13/14，TECH-STACK §7.31）

**实机验证轮**（C# 2.14.0.0，TECH-STACK §7.30 后续）抓到三个互通缺陷并当场修：

1. **P1 加密路径压缩协商失效**：服务端 0x18/0x1A 应答裸写绕过加密装饰器——C# 客户端
   经加密流读应答，段格式等不到合法段，干等 8s 响应窗后回退明文（传输成功但压缩静默
   失效）。改走 write_all；判别 e2e 加密+压缩全栈回环（裸写版 8.75s 超时红，修复绿）。
2. **P1 摘要缓存键 mtime 秒级粒度**：同秒同长改写 → 0x04 同步拿旧哈希误判「服务端
   已有」→ 增量备份漏改（静默丢数据方向；v2 帧 0x04 同病，非 UDT 新增）。全缓存键位
   改纳秒粒度（mtime_of/0x04 清单 ×2/scrub/0x01 回填/UDP session_id）；判别 e2e
   `cs_dialect_sync_incremental_roundtrip` 首轮即红（秒粒度）→ 纳秒绿。
3. **P2 本地摘要缓存当内容外发**：C# 方言 0x01/0x04 客户端 walk 未跳过
   `.trft-hash-cache.txt`（v2 帧有过滤）——补 is_cache_artifact 过滤。

**新功能**：UDT 槽位 0x04 差量同步客户端（此前 sync --proto udt 显式 Unsupported）——
C# SendFolderResumableAsync keepState 同构（能力位/全哈希清单/0x11 长窗判决/跳过清单/
增量哈希/带外 ACK），会话 GUID 与 C# DeriveSyncSession 同式互认；CLI/GUI sync UDT 分支
接线；判别 e2e 全量→改文件→二轮只补差异。

**实机对打**（全部 SHA-256 一致）：C#→v2 文件夹（压缩协商）/加密文件夹（P1 修复后
压缩即时协商）/GUI 并发 4 = 0x02 组会话（UIA 驱动，24 MiB）/v2→C# 文本 + 压缩单文件/
v2→C# 同步两轮（全量 → status=2 零传输）。发现互见维持字节级判别单测，GUI 级登记
可选后续项。

## 真机互通测试轮：UDT 吞吐塌陷修复（2026-11-14，TECH-STACK §7.32）

**发现**（真机 80MB 插桩实测）：C#→v2 单连接 UDT 仅 1.0MB/s（752 pkt/s），而
v2↔v2 112MB/s、C#↔C# 62.9MB/s；v2 接收侧零丢包零 NAK、流窗恒满、ACK 健康。
瓶颈 = libudt 默认 CC 退出慢启动后 `cwnd = RcvRate/1e6×(RTT+RC)+16`——`RcvRate`
读 ACK word4，v2 恒发 16B ACK（缺 word4/5）→ cwnd 恒钉 16 包。

**修复**：接收端实现 libudt `CPktTimeWindow(16,16)` 同款（到达间隔窗 + seq&0xF
探测对 + 中位数滤波），ACK 按 SYN 节流分档 24B/16B（逐字对齐 vendored core.cpp
checkTimers ACK 分支）；`m_ullLastAckTime` 单字段语义同步。

**实测**：C#→v2 80MB 0.6s（130.6MB/s，128 倍，超 C#↔C# 同口径）；真机矩阵
15/15 SHA-256 全对（双向明文/加密/压缩/80MB/文件夹/文本/同步三轮/负例×2/GUI
并发4=0x02）。登记：v2 发送端对 C# ~10MB/s（CC 近似 + 逐包调度，与 §7.28
优化项同批）。测试床 `.zcode/scratch-interop/`（gitignored，非自动化套件）。

## 性能优化批交付记录（2026-11-14，TECH-STACK §7.33）

**基线实测**（80MB 环回）暴露两级问题：RUDP 600s 跑不完（<0.13MB/s）；UDT v2→C#
10MB/s。根因三个：

1. **P0 RUDP 常态路径不发 ACK**（协议缺陷）：发送端窗口灌满后只能等 RTO 重传
   命中 Dup 才释放窗口，每轮 ≥400ms 且重传采样把 RTO 推到 3s。修复：驱动批量
   排空 + 批末合并 ACK；判别 4MB+3s 上界（旧行为 ≥5.2s 红）。
2. **P1 FIN_ACK 只发一次**：首个被丢后 shutdown 等 5s 兜底。修复：幂等重发；
   判别定向丢首个 FIN_ACK 红。
3. **P1 UDT lite-ACK 语义错位**：在途计数模型照搬减量模型的 `-= off` → 窗口
   棘轮到 0，发送端饿死在 ≤100/s 的完整 ACK 之间。修复：lite ACK 不动窗口；
   出包泵批量化。10 → 167.5 MB/s。

**同批**：§7.28 批量收发/ACK 合批/读聚合（RUDP+UDT 全泵）；e2e 测试 socket 收
缓冲镜像生产 4MB。

**实测**：RUDP <0.13 → **126.1 MB/s**；UDT v2→C# 10 → **167.5 MB/s**；环回
TCP 199 / QUIC 179 / UDT 161；真机矩阵 14/14 + GUI 0x02 复验全 SHA-256 一致；
264 测试全绿 0 告警（判别 2 项均实测去修复必红）。


---

## UI 高级感升级 + 审查迭代批（2026-11-16，第 9-13 轮：界面美化 → 代码审查 → 安全审查 × 5 闭环）

| 轮 | 视角 | P0 | P1 | P2 | P3 | 状态 |
|---|---|---|---|---|---|---|
| 9 | 前端 + GUI crate 代码/安全 | — | 1 | 10 | 20+ | ✅ P1/P2 全修，P3 择要 |
| 10 | core 传输层 + 密码学/协议安全 | — | 1 | 3 | 2 | ✅ 全修/登记（P1=UDT 槽位码哈希上线，协议固有→§5.2 登记 + GUI 告警） |
| 11 | CLI/支撑模块 + 更新链/路径穿越安全 | — | 1 | 1 | 8 | ✅ 全修（P1=cs_safe_name ADS 冒号） |
| 12 | 改动集回归审查 + 威胁模型复扫 | — | 1 | 4 | 5 | ✅ 全修（P1=resume 覆盖路径声明量泄漏） |
| 13 | 终扫（clippy + 修复验证） | — | — | — | — | ✅ deny 级清零；验证 12 项安全修复在位 |

**界面**（同批交付）：GUI 设计系统重写——渐变 accent/分层阴影/图标页签/玻璃拟态/进度条动效/控件基线统一/共享页两栏/暗色日志沉底/响应式与无障碍。VLM 截图评审从 ~6 分收敛 8-8.5 分；预览 harness `.zcode/ui-preview`（stub + 截图 + DOM 断言）。

**关键修复**（完整清单见 TECH-STACK §7.44）：
- **轮 9**：前端 activeTransfers 双扣（语言锁被提前解除）、暂停/继续/取消三处理器裸奔、群发/按钮乱序终态；GUI monitor_stop abort 兜底不存在（JoinHandle 脱管）、窗口隐藏停共享漏刷防睡眠、队列把用户暂停当失败重试。
- **轮 10**：cswire 0x03 单飞锁 guard 即 drop；RUDP 慢路径 1 许可发整批（背压架空）；UDT data_tx 无界（慢读者无界内存）；cswire 残件命名/TTL/磁盘预检/首块窗四防线对齐。
- **轮 11**：cs_safe_name 冒号 → NTFS ADS/MotW 抹除（实测复现）；cs_publish 发布竞态；monitor watcher 半死通道热自旋 + swap(0,1) 震荡饿死；CLI sync 缺 --pin。
- **轮 12（改动集自审）**：resume 会话覆盖泄漏声明量（远程持久 DoS）；declare/create 顺序；tracker 最终名残件；cs_publish 拷贝回退无 error-guard；0x04 会话内重发替换语义被 cs_publish 破坏（e2e_udt 拦截）。
- **轮 13**：clippy never_loop deny ×2（UDT 泵死循环结构）；触及文件风格告警清零；12 项安全修复 grep 验证在位。

**判别纪律**：本批新增修复未全部配备「去修复必红」判别测试（e2e_udt 的 0x04 重发用例实际拦截了发布语义回归）；cswire 声明量记账、monitor 交错队列、UDT 队列计数的专项判别列为后续测试债，登记在案。

**残余风险登记**：UDT 互通槽位配对认证（PRODUCT-SPEC §5.2 新增）；UTC 日志时间戳、RUDP 接收热路径拷贝、scrub 文件符号链接、PBKDF2 50k 维持——取舍理由见 TECH-STACK §7.44「登记接受」。

---

## 真机冒烟补录（2026-11-16，R13 后收口）

**方式**：`cargo build -p trft-gui` 后以 `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port` 启动真机 exe，CDP 直连 WebView2 实测（非 stub harness）。

**抓获（P1，静态截图无法发现）**：dist/app.js zh 字典第 69 行在死键清理轮被写坏为 `cf_un`（键名截断+值丢失的非法简写属性）→ 运行时 `ReferenceError` 使 app.js 顶层初始化中断，**全部事件监听器未挂载，UI 整体无响应**；`node --check` 语法合法，e2e/stub 截图均不覆盖此路径。同轮 en 侧死键 `known` 漏删。

**修复**：`cf_unknown: "仅未知设备（已知放行）"` 复原 + en 死键删除。

**判别检查**：新增 `.zcode/check_l10n.js`（zh/en 字典损坏简写键、data-i18n/t() 引用缺键、两侧键不对称三类校验，bad=0 为过；本 bug 在该脚本下必红）。

**复测全绿**：页面异常 0、控制台错误 0、6/6 标签切换 PASS、IPC 三命令（get_app_state/list_addresses/stats_summary）真实回数、设置页 19 项回填、qr-address 下拉 JS 填充=4（初始化完整证据）、错误 toast 0；亮/暗双主题截图归档 `.zcode/ui-preview/shots/real-smoke2-*`。VLM 亮色误判为深色一事再次印证：程序化验证优先于 VLM 臆测。

## 附加复审（2026-11-17，TCP 互通改造后）

**范围/方法**：4 个 crate（约 3 万行）——`cargo clippy --workspace --all-targets` 全量；600 个 `pub` 项引用扫描（剔除定义自身后为 0 引用者判死）；网络面解析器（cswire / v2 帧 / UDP/RUDP/UDT）、Web 管理面、更新链、Tauri 配置与前端渲染逐点复核。

**发现与修复**

| 级别 | 位置 | 问题 | 处置 |
|---|---|---|---|
| P2 | `cswire::cs_server_ecdh` | 客户端证明（c2s-confirm）校验失败时误调 `gate.success()`——锁定计数被清零，记账方向与「配对码错误」相反 | 改 `gate.fail()` |
| P2 | `cswire::handle_folder_resume` | 清单 `Vec::with_capacity(file_count)`（上限 1,000,000 ≈ 56MB/连接）× 64 并发 ≈ 3.5GB 预分配 DoS | 容量提示封顶 1024，逐项增长 |
| P2 | `trft-gui::next_free_port` | `port + 1` 在 port=65535 时 debug 构建溢出 panic（端口探测属用户可触发路径） | `saturating_add(1)` |
| P3 | 六处 | 死代码：`ACK_WORDS_FULL/EXT`、`CS_FLAG_TCP`、`describe_error`、`spawn_restarted`、`SessionKeys::client_view/server_view` | 删除；600 个 pub 项扫描已无 0 引用者 |
| P3 | `cswire` 等 | 重复的「对端关闭形态」判定（两处）、0x05 状态分支同块、`format!` 字面量、测试未用 import/冗余重绑定 | 提取 `peer_closed()`；化简；清理 |

**复核为无问题（抽样）**：cswire 线上长度全部前置校验（名称 4096 / 文本 1MB / 传输 1PiB / 区间 8192 / tracker 64 / 声明 64GiB）；AES-256-CTR + HMAC-SHA256 段绑定 seq、先验 MAC 后解密、16B 截断标签；解压 `take(MAX+1)` 炸弹防线；更新链 ed25519 verify_strict + https 强制 + 换入前/暂存后双重重校验 + 回滚；Web 登录锁定（10 次/10 分钟）、会话 HttpOnly+SameSite=Strict、CSRF 双提交（哈希后 ct_eq）、列表 `html_escape`/`url_escape`、上传字段数/大小/空闲超时；三套路径净化器（v2 严格 / C# 宽容 / Web 反斜杠归一）对 `..`、绝对路径、ADS、保留名、格式字符判定一致；`Command::new` 全部 argv 传参（无 shell 拼接）；Tauri CSP 严格、前端渲染走 `textContent`（唯一 `innerHTML` 是本地生成的二维码 SVG）。

**登记不改（风险已声明）**：① 0x09 收到 status=2（对端无配对码）时明文降级，仅 stderr 提示——release GUI 不可见（C# 语义，改动即破互通）；② Web 共享目录内的符号链接/junction 会被跟随（读/删可越出共享根，属运维配置面）；③ 0x03 直接写最终名（本机预置符号链接可被跟随，需对保存目录有写权限）；④ 配对码 KDF 为 C# 兼容的 PBKDF2-SHA1/50k，6 位码可离线爆破（GUI 已告警，建议 12 位或 QUIC/RUDP）。

**验证**：`cargo check --workspace --all-targets` 0 警告；clippy 余留均为风格类（参数个数/初始化写法，非本轮引入）；`cargo test --workspace --no-fail-fast` **302 项全绿**；CI 三平台矩阵复跑。

