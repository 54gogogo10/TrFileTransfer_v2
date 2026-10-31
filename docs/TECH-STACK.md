# TrFileTransfer v2 技术栈决策

| 项 | 内容 |
|------|------|
| 文档性质 | 技术选型权威记录（行为与要求的权威描述见 [PRODUCT-SPEC.md](PRODUCT-SPEC.md)，字节级协议见 [WIRE-PROTOCOL.md](WIRE-PROTOCOL.md)） |
| 决策基线 | 2026-10 用户拍板：**Rust 核心 + Tauri 2 桌面壳 + axum Web 面**；Win7 支持延后至后期独立分支 |
| 维护约定 | **随里程碑同步更新**——任何选型变化都必须落到本文对应条目（与 PRODUCT-SPEC.md 同纪律） |

---

## 1. 决策总览

本实现**从功能出发重新选型**，不继承原 WPF/C# 技术栈。规格书推导出的五条硬约束：

| 规格约束 | 推导出的技术要求 |
|---|---|
| 单文件免安装、无服务无驱动（§1.3） | 三平台自包含单二进制，≤ 数十 MB |
| 自定义二进制线协议 + 三种传输（§3.1/§4） | 精细 socket 控制，无 GC 抖动的吞吐稳定性 |
| 跨平台桌面 GUI + 托盘 + 主题 + 双语（§3.7） | WebView 系 GUI 框架，平台集成为插件点 |
| 内嵌加固 HTTP 服务器 + 手机浏览器（§3.4） | 内嵌 HTTP 服务，移动端零原生 App |
| 内存封顶设计点（§6.2） | 可静态钉住内存边界的语言 |

**结论：Rust 主栈**（备选 Go + Wails 记录在案，见 §8）。已拍板的两个决策点：

1. **Win7 支持延后**——主分支走 Tauri 2 / WebView2，不背 Win7 包袱；Win7 需求明确后开独立分支处理（预案见 §5）。
2. **可靠 UDP 流槽位选 QUIC（quinn）** 而非 SRT——无 FFI 负担、生态活跃；配对码体系走应用层（自签证书 + 指纹钉扎）。

## 2. 分层选型

| 层 | 选型 | 版本 | 状态 |
|---|---|---|---|
| 核心语言 | Rust（edition 2021，workspace 多 crate） | ≥1.85 | ✅ 已落地 |
| 异步运行时 | tokio | 1.x | ✅ 已落地 |
| 密码学 | RustCrypto：`p256`(ECDH) / `aes`+`ctr` / `hmac` / `pbkdf2` / `subtle` | 0.13/0.8/0.12/0.12/2 | ✅ 已落地 |
| 摘要 | `sha2`（SHA-256 流式） | 0.10 | ✅ 已落地 |
| 前向纠错 | `reed-solomon-erasure`（Galois 8） | 6 | ✅ 已落地（收发全链路） |
| 摘要缓存 | `trft-core::hashcache`（FNV-1a 行校验 + TTL + 追加日志 + 8MB 重写收敛 + 两代分代淘汰） | — | ✅ 已落地 |
| 压缩 | `flate2`（miniz_oxide 纯 Rust 后端，`Compression::fast()`） | 1 | ✅ 已落地（0x08 分段装饰器 + 采样） |
| 更新签名 | `ed25519-dalek`（verify_strict；清单签名 + 内嵌公钥） | 3 | ✅ 已落地 |
| 更新通道 | `tokio-rustls`（ring 后端）+ `webpki-roots`（自带 Mozilla 根集，零系统依赖） | 0.26/1.0 | ✅ 已落地（极简 HTTP/1.1 客户端，https 强制） |
| CLI | `clap` 4（derive） | 4 | ✅ 已落地 |
| 配置 | `serde` + `toml`，原子换入自愈 | 1/0.8 | ✅ 已落地 |
| Web 面 | `axum`（鉴权 / Range 206/416 / multipart 流式上传 / CSRF / 加固头，默认回环绑定） | 0.8 | ✅ 已落地（`trft-server` lib + bin 拆分，tower oneshot 测试） |
| 桌面 GUI | **Tauri 2**（系统 WebView + 轻前端；无 Node 构建——vanilla JS 经 `withGlobalTauri` 直调命令） | 2 | ✅ 已落地（M4'） |
| QR 编码 | `qrcode`（仅编码核，default-features=false 零依赖；SVG 由 GUI 自拼） | 0.14 | ✅ 已落地（M4'） |
| 网卡枚举 | `if-addrs`（共享二维码地址下拉） | 0.13 | ✅ 已落地（M4'） |
| Windows 集成 | `winreg`（WebView2 检测 / HKCU Run 自启）+ `windows-sys`（缺失运行时 MessageBox 引导） | 0.55/0.59 | ✅ 已落地（M4'） |
| 可靠 UDP 流 | **quinn**（QUIC，自签；`--pin` 指纹钉扎可选） | 0.11 | ✅ 已落地 |
| 本地日期 | `time`（local-offset；归档日期段/统计今日桶/旧格式时间列） | 0.3 | ✅ 已落地（M5'） |
| 目录事件加速 | `notify`（仅提前触发扫描，不承载判定；初始化失败退化纯轮询） | 7 | ✅ 已落地（M5'） |
| 设备存储 | `serde_json`（devices.json；M5' 随设备层下沉 core） | 1 | ✅ 已落地 |

## 3. 传输槽位映射

规格 §3.1 的三种传输 → 本实现的对应关系：

| 规格协议 | 本实现 | 线协议帧 | 状态 |
|---|---|---|---|
| TCP（通用） | tokio `TcpStream` + 0x09 加密装饰器（双向确认）+ 0x08 压缩装饰器（认证后协商） | 0x00 单文件 / 0x01 文件夹 / 0x02 分块 / 0x03/0x04 续传 / 0x05 配对 / 0x06 文本 / 0x08/0x09 加密压缩 / 0x0A–0x0C 能力覆盖收尾 / 0x10/0x11/0x1A 应答 | ✅ 已实现（0x07/0x17 旧版加密不实现——无旧版互通承诺） |
| UDT（可靠 UDP 流） | **QUIC**（quinn，替代槽位；`--pin` 钉扎可选） | 与 TCP 同帧 + 1 字节版本握手 | ✅ 已实现（含全部新帧） |
| 单向 UDP + RS-FEC | tokio `UdpSocket` + `reed-solomon-erasure` | 20 字节公共头 + 0x01/0x02/0x03/0x04 | ✅ 收发引擎全链路已实现 |

## 4. 线协议处置

- 产品级帧类型语义**沿用规格书 §4.1 编号**；字节级布局已抽取为 **[WIRE-PROTOCOL.md](WIRE-PROTOCOL.md)**（M3' 完成，与 `trft-core::protocol` 由判别测试互锁；多字节整数一律小端）。
- 与原 C# 版**不做互通承诺**（独立实现，不背旧协议兼容包袱）；旧对端兼容以能力协商（0x0A/0x1A）+ 显式降级路径实现。

## 5. 平台矩阵与 Win7 预案

| 目标 | 形态 | 里程碑 |
|---|---|---|
| Windows 10/11 x64 | Tauri GUI（WebView2）+ CLI，单 exe | M4' ✅（GUI 已落地）/ CLI M2' |
| Linux x64 / musl | CLI/daemon（musl 静态单二进制）+ AppImage GUI | M2' / GUI 待发布阶段 |
| macOS x64 + aarch64 | CLI + GUI universal binary | CLI 待发布阶段（本机无交叉工具链） |
| 手机 | 浏览器（Web 共享/管理面）+ 二维码 | M3' ✅ + 二维码 M4' ✅（trft-server + GUI 扫码页） |

**Win7 分支预案**（用户决策：主分支先行，后期独立分支）：
- GUI 从 Tauri 换 **egui**（纯 Rust 自绘，无 WebView2 依赖），托盘用 `tray-icon` crate；
- 核心库与 CLI 不受影响（MSRV 需回检）；
- 验收矩阵单列（Win7 SP1 + WebView 缺失环境）。

## 6. 里程碑映射（对应规格 §9.3）

| 里程碑 | 范围 | 验收标准 |
|---|---|---|
| **M1'** ✅ | 核心库（协议帧/加密/FEC/限速/配置自愈）+ CLI 四动词 + Web 骨架 | `cargo test` 全绿 + CLI 实机演练 |
| **M2'** ✅ | QUIC 槽位、单向 UDP 收发引擎、0x01 文件夹、0x09 加密装饰器、摘要缓存 + verify 比对、8 轮代码/安全审查 | 75 项测试全绿 + 假成功防护钉测试 + 审查日志闭环 |
| **M3'** ✅ | 0x02/0x03/0x04 续传与分块、0x08 压缩、Web 管理面（鉴权/Range/上传/CSRF）、ed25519 自更新、缓存 8MB 重写收敛、WIRE-PROTOCOL.md 抽取、限速接线判别 + 互通矩阵 e2e 化 | **121 项测试全绿（0 告警）+ CLI/server 实机演练**；多平台发布矩阵延后至发布阶段（本机无交叉工具链，见 §7.8）；进度事件对齐 §7.5 归 M4' |
| **M4'** ✅ | Tauri 2 桌面 GUI（托盘/主题三态/双语/拖放/进度卡片/共享二维码/校验/设置/检查更新/开机自启）+ **进度事件**（`trft-core::progress`，100ms 节流在 core，规格 §3.1；UDP 收发/0x00/0x01/0x02/0x03/0x04 全链路接线）+ scrub 校验引擎抽取（GUI/CLI 共用）+ WebView2 检测引导 | **128 项测试全绿（0 告警）**；进度判别测试（暂停时钟单测 + TCP/UDP e2e）+ GUI 实机启动/WebView2 冒烟 |
| **M5'** ✅ | 接收链路补齐（设备层下沉 core + `ConfirmReceive` + `PerDeviceFolder` + `AutoArchive`）+ 统计与历史（`trft-core::stats` + GUI 历史页签）+ 监控模式（`trft-core::monitor`，口径见 §7.10） | **156 项测试全绿（0 告警）**；确认三态/fail-closed/分目录落点/归档叠加/0x04 缓存键一致性/UDP 目录解析/监控未就绪不发出等判别测试 + CLI 实机收发（stats 记账验证）+ GUI 实机启动/WebView2 冒烟 |
| **M6'** ✅ | 独立审查轮 ×8（代码/安全交替，M2' 纪律：发现当场修 + 全量回归 + 判别纪律）+ **QUIC 0x0D 证书指纹通道绑定加固**（§7.11，双向确认） | **165 项测试全绿（0 告警）**；8 轮约 70 项发现闭环（1×P0 实测复现：0x03 偏移权威）+ 偏离登记；双臂中继/盲接受假服务端/缓存投毒/偏移放大/UDP kill-switch 五个关键判别均实证「去修复必红」；CLI/GUI 实机冒烟；REVIEW-LOG M6' 记录 |

## 7. 已知风险与偏离声明

1. ~~**WebView2 缺失的老系统**（Win10 LTSC 等）：首次启动需检测并引导安装运行时——记入 M4'~~ ✅ M4' 落地：注册表三处检测（HKLM/HKCU/WOW6432Node）+ 原生 MessageBox 引导官方 Bootstrapper 下载。
2. **reed-solomon-erasure 为纯 Rust 参考实现**：FEC 吞吐基准 ⬜ 发布阶段，不达标再换 C 绑定实现。
3. **quinn 0.11 → 后续大版本**：锁版本升级。
4. **CLI 参数面有意偏离规格 §3.6**：`--proto <tcp|udt|udp>` 取代 `[--tcp|--udt|--udp]` 开关；新增 `--text`、`--pin`、`--noencrypt`；`--nocompress` 已随 0x08 落地（send/sync）；新增 `--chunks 1-8`（0x02 并行分块）与 `update` 动词。差量同步 0x04 已落地（稳定会话 ID + 位图差分）。
5. ~~**进度事件机制**（规格 §3.1 节流 100ms）⬜ M4'~~ ✅ M4' 落地：`trft-core::progress`（惰性节流、终态必达、Outcome Drop 即失败）；0x00/0x01/0x02/0x03/0x04/UDP 双侧全接线；UI 只消费事件（§1.4 分层纪律）。
6. **QUIC 无 --pin 不防主动中间人**（自签模型 + 0x05 不绑定通道）——帮助文案已明示；通道绑定证明 ⬜ 后续加固项。
7. **与原 C# 版不做互通承诺**——规格 §4.3 互通矩阵对本实现不适用；自互通矩阵以 e2e 落地（`tests/e2e_interop.rs`）。
8. **M3' 新增偏离**（均已在 WIRE-PROTOCOL.md 记载）：
   - 0x04 清单上限 100,000（0x01 仍为 1,000,000）——位图协商内存有界；
   - 0x03 整文件哈希必带且服务端对 verifyFlag=0/1 均整文件重读比对——完整性优先（强于规格的「可选」）；
   - 0x02 限速语义 = **每连接一桶**（N 路并行聚合上限 = N × SpeedLimit，与「按面板限速」的独立客户端口径一致）；
   - 同步（0x04）对不支持的对端**显式报错**，不做静默语义降级（0x01 降级会破坏增量备份语义）；
   - 库层 `SendOptions::default` 压缩关（保守，保旧对端直连字节兼容），CLI/GUI 默认开；
   - 0x02 组装成功后会话保留为完成态（迟到 0x0C 判 0x01、0x0B 回满覆盖）——重试收敛于成功，杜绝二次发布。
9. **M4' 新增偏离/范围声明**（2026-10-31 对齐需求后更新）：
   - **已对齐规格**（M4' 交付 + 对齐补批）：托盘常驻（关闭=隐藏+保存配置、最小化=隐藏、仅托盘退出真退出）、主题三态实时换肤、双语运行时切换（传输中锁定）、拖放（多文件入队/单文件填充）、进度事件（100ms 节流 + 速度/ETA）、文件夹模式子选项（0x04 差量同步默认 / 0x01 整夹）、接收端多地址绑定（§3.3）、运行中冻结该协议页端口/目录/绑定下拉、端口全部占用时「换下一可用端口」提议、接收选项（重复文件 rename/skip、摘要缓存有效期、接收限速、UDP 参数）、HTTP 共享目录三选一 + 二维码 + `QrAddress` 记忆、文件库校验（§3.5 聚合+停止+进度）、发送队列（串行执行 + `queue.txt` 持久化 500 项 + 完成后动作：无/关机/休眠/命令，执行前确认）、**暂停/继续**（§3.2 取消型暂停：暂停即断，继续按 0x03/0x04 服务端会话与 0x04 位图差分续传；0x02 分块暂停后继续为新组全量）、**群发**（手输多目标并行、逐目标进度卡、汇总 {ok}/{total}；设备复选待设备记忆层）、**`SyncVerifyContent` strict**（`RecvOptions.strict_verify`：0x03 skip 与 0x04 位图全部绕过缓存必发，发送侧不携带缓存哈希，CLI/GUI 双侧生效——判别 e2e：非 strict 二次同步总量 0、strict 全量重传）、文本互传 + **历史落盘 200 条**、`PairingLength` 生成按钮、`NotifySound` 独立开关、**设备发现与记忆**（`trft-core::discovery`：UDP 广播 0xD1→0xD2，仅 IPv4，字节级见 WIRE-PROTOCOL.md §6；应答服务随 TCP/UDT 监听器启停、flags 实时；`devices.json` 记忆 10 条按 IP 去重，发送成功/发现应答双源合并；设备卡支持使用/加入群发/删除/清空）、**IP 过滤**（规格 §3.3 匹配规则全实现：精确/`192.168.1.*` 通配/CIDR v4+v6/跨族不匹配/坏条目 fail-closed；TCP/UDT 连接先行判定（不耗并发闸）+ UDP 逐包静默丢弃——判别 e2e：deny 拒/allow 未命中拒/allow 命中过），防火墙放行提示（首启一次）、防睡眠（传输/接收器/共享运行期 `SetThreadExecutionState` 派生钳制，abort 无泄漏）、完成通知（气泡+提示音）、输入校验红框（空值中性）、自动升级（检查/安装 + 启动 3 秒静默检查 + 「跳过此版本」）、开机自启（HKCU Run）、WebView2 检测引导；
   - **仍缺口 → M5' 已对齐排期**（2026-10-31 第二轮对齐需求，决策口径见第 10 条）：接收前确认 `ConfirmReceive`、按设备分目录 `PerDeviceFolder`（需先把设备记忆从 GUI 下沉 core——传输帧不携带设备名，名字仅来自 discovery 0xD1/0xD2）、按日期归档 `AutoArchive`、统计与历史（stats.log/聚合/CSV）、监控模式（拷贝完成检测+队列让位）；Win11 Mica 继续延后（用户拍板）；
   - 接收器「停止」= 任务 abort（连接中断即断；半成品由既有孤儿清扫兜底，与进程被杀同口径）；
   - GUI 行为与 CLI 严格同层（复用 trft-core 同一批入口，§3.6 纪律）。
10. **M5' 对齐决策**（2026-10-31 第二轮对齐需求，用户拍板；✅ 已随 M5' 交付）：
   - **批次**：一个批次全做（A 接收链路三件套 → B 统计历史 → C 监控模式）；Win11 Mica 继续延后；
   - **监控可靠性口径（用户要求「绝对可靠」）**：周期全量扫描为**唯一事实来源**（不丢事件），目录事件侦听（notify 类）仅作**提前扫描触发器**——事件不承载任何判定；事件层初始化失败自动退化为纯轮询，功能零损失；拷贝完成判定仍为规格 §3.2 双重门（独占打开 + 500ms 大小稳定窗）；
   - **归档叠加顺序**：`AutoArchive` 与 `PerDeviceFolder` 同开 → `<保存目录>/<设备>/<日期>/`（设备优先，按设备清理时连日期一起带走）；
   - **统计记录点**：core 完成/失败路径接线 → GUI 与 CLI 同享 stats.log（不加开关）；聚合/CSV 导出 API 在 core（可测），GUI 只做展示；
   - **CLI 范围**：`ConfirmReceive` 与监控模式为 GUI 功能（规格 §3.6 recv 无确认参数、无 monitor 动词）；core 确认钩子为 `Option`，无人值守路径不注入（语义等同 off），GUI 在 `confirm_receive != off` 时必须注入 responder；
   - **实现注意**：0x03/0x04 会话与 0x02 分块表绑定落盘目录——目录解析在会话建立时固定并随会话保存（PathBuf），续传用会话内记录，不重解析（防设备改名孤儿化旧会话）。
11. **M6' 对齐决策**（2026-10-31 第三轮对齐需求，用户拍板）：
   - **批次**：独立审查轮 ×8 全量（对齐 M2' 力度；代码/安全交替、每轮独立上下文审查代理、发现当场修 + 全量回归 + 判别纪律），范围 = M3'–M5' 累积代码（接收路径新选项、Web 管理面、自更新、monitor、设备/IP 过滤、stats、CLI/GUI 命令层；前端 JS 不设专门轮）+ 轮 7 GUI 命令层专项 + 轮 8 全量回扫；
   - **QUIC 通道绑定加固**（兑现 §7.6 登记项）：QUIC 槽位的 0x05 配对证明混入「客户端所见服务器证书指纹」（`quinn::Connection::peer_identity` 提取，双侧校验同源）——双臂中继两腿证书必然不同 → 证明必败；透明字节级中继不构成 MITM（TLS 完整性保护）；
   - **兼容口径**：新版服务端对 QUIC + 配对启用**强制**绑定证明（明文 0x05 拒绝）；新客户端先发绑定帧、遇旧服务端拒绝回退明文 0x05 并记警告（旧服务端 = 旧版软件固有弱点，如实降级）；
   - **范围外（如实登记）**：明文 TCP 0x05（`--noencrypt`）无通道材料可绑定（无 TLS/DH），双臂中继不可防——既有残余风险不变，靠「0x09 默认开」缓解；`--pin` 用户不受此影响（钉扎即绑定）。
12. **M6' 审查新增口径**（轮 2/6 修复落定）：
   - **设备来源分级**（`DeviceSource::Discovery/Transfer/User`，devices.json 新字段，旧文件反序列化为 Discovery——保守方向）：**ConfirmReceive=unknown 的「已知设备」只信任 Transfer/User**——0xD2 发现应答无认证，不得作为绕过用户确认的依据；来源只升不降；PerDeviceFolder 目录命名仍可用 Discovery 名（展示/命名与授权分离）；
   - **`?t=` 令牌 = HMAC(每安装随机密钥, code‖域) 截 16B**（config `token_secret` 首启生成，64 hex）：令牌泄漏只作废令牌（换密钥），不可离线反推低熵配对码；token_for/check_token 统一 32 hex（修复前 64/32 错位——扫码直连整链失效且判别测试绕过 token_for 掩盖失配）；
   - **PairingGate 按 IPv6 /64 聚合**：SLAAC/隐私扩展下按 /128 计数可无限绕过锁定；
   - **0x03 偏移权威 = 服务端磁盘事实**（规格 §3.1 原文「max(声明, 实际)」废弃为偏离——已实测 1MiB 输入绕过磁盘预检写满整盘）；收尾加半成品长度 == 声明硬校验；
   - **0x03 冲突改名后的摘要缓存键跟最终路径**（投毒红线）；**0x00 接收也免费填充缓存**（补齐规格 §3.1 四路径）；
   - **登记接受（不修）**：stats 仅记成功完成；UDP 发送侧统计为「已发出」口径；限量模式对拒绝路径不计数；明文 0x05 无 S→C 证明（残余风险，0x09/0x0D 已覆盖默认路径）；同步 flush 攻击仅在轮询间隔逐包场景且已有内核队列兜底；CLI recv 绑定 0.0.0.0 / 无接收限速注入等能力面差异；前端文案/日志中文残留（EN 模式）；GUI 日志 200 条 vs 规格 500（在案缺口）；路径红框/更新 URL 校验未实现（§7.9 未声明）；文件日志/crash.log 未实现（§7.9 未声明）。
13. **第二轮全量审查新增口径**（2026-11-01，8 轮制·轮 2 威胁模型）：
   - **QUIC 旧服务端降级改 fail-closed**（推翻 §7.11「回退只可能发生在旧服务端上」前提——实测 MITM 对 0x0D 回裸 0x00 即可伪装旧服务端把客户端逼进无 S→C 证明的明文 0x05 腿：盲接受 + 窃取 + 假成功，PoC 实证）：默认拒绝降级，CLI `--allow-legacy-pair`（send/sync）或 `--pin` 显式放行；GUI 无放行开关（一律 fail-closed）；判别 e2e：伪装旧服务端强制降级默认必败；
   - **authenticate_bound 非 AuthRejected 错误改为一律上抛**（旧 if-let 形状吞错后以未认证状态继续——正确性缺陷；实证两个利用变体在本栈均不可达：沉默型被 QUIC 传输层 ~30s idle 超时先杀连接，流重置型载荷写不达对端，登记为纵深防御修复而非可达漏洞）；
   - **PairingGate 的 IPv4-mapped IPv6（`::ffff:a.b.c.d`）归一到内嵌 IPv4 计数**：双栈监听上全部 IPv4 来源与 ::1 原先折叠进同一桶 `::`，任一攻击者可连带锁定全部 IPv4 用户（判别单测）；
   - **接收器并发闸获取加 30s 上限**（与 Web 面同纪律；满闸下合法连接不再无限静默等待）；**Web 请求体空闲 60s 超时**（头读超时只覆盖头阶段，慢滴 body 可占闸）；
   - **非硬链接卷发布回退改 create_new + 拷贝**（Windows rename 静默替换 → 并发同名 TOCTOU 覆盖窗口；与 UDP/Web 同口径，代价是崩溃窗口内可能残留最终名半成品——错误路径仍有清理兜底）；
   - **登记接受（不修）**：0x08 解压内存仅单段 64MB 上限、无跨连接聚合计账（64 并发 × ~60KB 压缩流 ≈ 4GB 瞬时，纯可用性、瞬时性；单段上限为规格 §6.1 声明值）；接收器慢滴连接占用（每读窗口内滴 1 字节可长持许可——闸获取超时已缓解排队侧，占用侧需空闲预算机制，量大未做）。
14. **第二轮全量审查·轮 4（输入校验/DoS）新增口径**（2026-11-01）：
   - **Web serve 必须配 Timer**（轮 2 修复自身缺陷，debug/release 双实证）：hyper 在每次读请求头时无条件武装 `header_read_timeout`，无 Timer 时 `Time::Empty` 直接 **panic**——明文 HTTP/1 全量请求被 RST、slowloris 守卫归零，而进程内 oneshot 测试不经真实 TCP 掩盖了整链失效。已补真实 TCP e2e（GET 成功 + 半开头 15s 掐断，去 Timer 必红）；
   - **去掉 `server-auto`**（h2c prior-knowledge 绕过 h1 专属 header_read_timeout 且无 idle 上限，静默 h2 连接永生）；目标客户端（手机浏览器）明文只走 HTTP/1，改 `hyper::server::conn::http1` 直连；
   - **0x02 块载荷改流式读**（固定 CHUNK 缓冲逐片落盘）：此前 `read_n_long` 按声明预分配整段——40B 帧头即可钉住 8MB × 64 闸至 300s（与 0x00/0x03 同纪律收敛）；
   - **更新器 chunked 块长行 8KB 上限**（恶意更新源无 CRLF 流不再无界缓冲）；**0x0B 应答读 60s 总预算**（恶意服务端逐字段拖延不再把单任务拖至数天）；**UDP MSGSIZE 跨平台错误码**（此前仅 Windows 10040，Linux/macOS/BSD 的 EMSGSIZE 仍会杀死接收器）；
   - **Web 后缀 Range `bytes=-N` 且 N≥size 回 200 全量**（RFC 9110 §14.1.2；此前误 416）；**更新 URL 裸 IPv6 字面量**（`https://[::1]/m`）可解析（默认端口）；
   - **登记接受（不修）**：GUI invoke 信任边界（`http_start(dir)`/`stats_export_csv(path)`/`monitor_start(watch_dir)` 接受前端任意路径、`devices_record` 可标 User 来源）——前端为本产品自带代码（无注入链，渲染均 textContent），本地攻击者模型出界；后续若开放第三方前端再收紧。
15. **第二轮全量审查·轮 5（资源泄漏/性能）新增口径**（2026-11-01）：
   - **摘要缓存 degraded 模式条目数硬封顶**（`DEGRADED_MAP_CAP` = 200,000，满则清空重建，摊还 O(1)）——轮 5 PoC 实证：degraded（目录不可写→纯内存）下唯一收敛路径（8MB 日志重写触发的两代淘汰）不可达且 `degraded` 永不恢复，200 万条 +260MB 零收敛；判别测试 `degraded_mode_map_is_bounded`（去 clear 必红）。注：分代淘汰在 degraded 下不可用（gen 恒不前进），故取计数封顶而非代数淘汰；
   - **Web 上传半成品 `.up*.part` 并入孤儿清扫**（`cleanup_upload_orphans`，7 天口径与 core 一致；server main 与 GUI `http_start` 启动时执行——Drop 守卫不覆盖进程被杀，此前不在任何清扫器覆盖内、落在用户共享目录永久残留）；
   - **文本历史单条截断 2KB**（协议允许 1MB 文本——不截断时稳态历史 ~200MB 且每条全量重写，写放大 200:1；前端展示只取 120 字符）；
   - **常驻接收器 JoinSet 随 accept 收割**（`try_join_next` 排空——完成条目驻留 ~190B/连接，此前仅 accept 出错分支 join）；
   - **前端**：`taskByProgress` 终态摘除（只增不减 ~100B/任务）、`refreshStats` 终态 1s 防抖（群发/队列 500 项完成风暴下每任务两次全量读盘 → 合并一次）、队列 push 钳 500（与后端 `queue_save` 上限对齐，超限此前静默丢持久化）；
   - **登记接受（不修）**：UDP `events` 通道逐包直发无节流——生产两调用点（CLI/GUI）均传 `None`，节流真身在 `opts.progress` Reporter 侧；公开 API 的可达性地雷，后续接线者须自行节流（udp.rs 注释已有自警）。§6.2 各内存封顶设计点复核结论：UDP 位集/FEC 超块/进度节流/容量防线全部成立，摘要缓存 degraded 路径已补（本条第 1 项）。
16. **第二轮全量审查·轮 6（规格符合性抽查）新增口径**（2026-11-01）：
   - **配置自愈补齐两个损坏场景**（规格 §3.8 原文「主文件存在但不可读/解析为空时回退 .bak」——此前仅 toml 语法错误路径回退，截断成空文件/占用不可读恰好静默丢配置）：不可读/空主文件均回退 `.bak`，「缺失=用户重置」语义不变；判别测试 `empty_main_falls_back_to_bak`；
   - **HTTP 共享随窗口隐藏而停止**（规格 §3.4「随主窗口关闭停止」——此前共享与窗口生命周期解绑，隐藏后共享目录持续对外可访问）；接收器/监控不受影响（托盘常驻语义）；
   - **发送队列补齐 QueueRetries**（规格 §3.2/§12.1：0–5 默认 1；config `queue_retries`）与**逐项参数快照**（入队时快照面板参数并随 queue.txt 持久化，行格式扩为 9 字段，旧 2 字段行兼容回读）；
   - **文件夹 0x01 失败自动转 0x04 差量续传**（规格 §3.2 AutoRetry 句末——`send_folder_auto`：0x01 逐文件回填本地摘要缓存 → 失败（非用法/认证/不支持类）以稳定会话 ID 转 0x04，已完整发出的文件被服务端核对跳过；判别 e2e `folder_send_falls_back_to_resume_after_failure`——前置代理掐断第 1 条连接模拟中断）；
   - **分块默认 4 路对齐规格 §3.1**（GUI 此前默认 2）；**防火墙提示按所启协议生成**（QUIC/单向 UDP → protocol=UDP；此前恒 TCP，首个启动为 UDT/UDP 接收器时命令无效）；**WIRE-PROTOCOL §3.4 修正**（已组装会话的 0x0B 应答为 `0x01`+满覆盖——与 PRODUCT-SPEC §4.1/§7.8 一致，文档漂移）；compress.rs 模块头注释同步 9B 段头；
   - **登记接受（不修）**：CLI `update --restart` 判用法错误（CLI 进程重启后无动词，语义不成立）；「同步会话」对话框（枚举+两步确认重置）未实现（磁盘即状态模型下语义弱化，WIRE §3.7 已注明 sessionId 为保留字段）；数据文件布局与 §8.1 C# 清单的差异（每目录 `.trft-hash-cache.txt` vs 全局 `hash-cache-*.txt`、`text-history.txt` vs `.log`、`config.toml` vs `.ini` 且不做旧 C# 配置迁移——与「不互通承诺」一致，stats.log 保留旧行兼容）；GUI 发送面板缺 SrcPort 输入（CLI `--srcport` 可用，GUI 面板后续按需补）；TCP 收发缓冲 4MB（§6.2）未显式设置——OS 默认在环回/LAN 表现充分，性能旋钮待实测有据再调。
17. **第二轮全量审查·轮 7（GUI/CLI 命令层 + 前端 JS）新增口径**（2026-11-01）：
   - **P1 暂停/继续链路自毁回归**（轮 7 历史「取消补发终态事件」与暂停清理互相打架——终态事件先于 invoke 返回到达，前端无条件清 reqByTask/pausedTasks/taskByProgress：继续按钮失忆抛 TypeError、onProgress 暂停守卫恒死代码）：`send_cancel` 增 `paused` 标记，前端暂停**先置位再 invoke** + 事件处理器对 paused 任务保留映射（继续/暂停守卫恢复可用）；
   - **队列 UDP 项被静默改走 TCP**（kind 映射与直发路径不一致 + UDP 三参数不入快照）：队列构造对齐 `proto=udp → "udpfile"`，passes/fecParity/nofec 入快照与 queue.txt（12 字段行，旧格式兼容）；
   - **0x02 回退 0x03 的进度卡无按钮**（第二 progressId 不在 task-start 事件里）：回退分支补发 `trft://task-start`；
   - **窗口隐藏停共享后前端假「运行中」**（死二维码）：新增 `trft://sync-state` 事件（停共享/接收器自摘/监控自摘统一发），前端重拉 `get_app_state` 复位共享页/圆点/按钮；
   - **监控槽位写入竞态**（run_monitor 立即失败的清理与 start 的写入交错 → 死句柄槽）：MonitorTask 代际令牌（占位先行 + ptr_eq 判代覆盖/清理）；
   - **校验可并发重入**（双击 → 双扫描互踩）：tasks 表在跑即拒绝；**主题/语言切换即时持久化**（与 qr-address 一致，重启不丢）；**GUI UDP 约束守卫**（folder/text + udp → L10N 提示，此前晦涩 IO 错）；**CLI 参数组合显式报错**（--passes/--fec-parity/--nofec 非 UDP、--srcport UDP、--chunks 非 --file）；CLI update 死代码删除；队列逐项校验（NaN port 不再让整批反序列化失败）+ persistQueue 失败可见；主动取消的 toast 文案与失败区分（取消仅 warn 日志）；
   - **登记接受（不修）**：接收确认弹窗并发（单 overlay——并发确认时前序靠后端 31s 看门狗 fail-closed 拒绝，无用户可感知错误，仅 UI 上后到覆盖先到；排队/徽标属打磨项）。

## 8. 记录在案的否决项

| 选项 | 理由 |
|---|---|
| Go + Wails | 交叉编译省事、出活快，但内存封顶只能靠纪律、GUI 生态弱一档；无 Rust 储备时的备选 |
| Electron / Node | 80MB+ 违背单文件轻量定位；裸 UDP/Buffer 处理吃力 |
| JVM 系（Compose Multiplatform） | 「单文件免安装、双击即用」过不去 |
| Flutter Desktop | 原生 socket 能力不足，核心被迫走 FFI，架构不干净 |
| Qt / C++ | 功能全覆盖但内存安全与测试体系工程成本最高 |
| reqwest（更新器 HTTP 客户端） | 全家桶依赖树违背单二进制轻量定位；极简 HTTP/1.1 + rustls 约 200 行即可覆盖清单/安装包拉取 |
