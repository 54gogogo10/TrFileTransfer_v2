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
