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

规格 §3.1 的四种传输（UDT/QUIC 槽位拆分，2026-11-10——原「UDT」槽位恢复 UDT 语义，QUIC 独立成模式）→ 本实现的对应关系：

| 规格协议 | 本实现 | 线协议帧 | 状态 |
|---|---|---|---|
| TCP（通用） | tokio `TcpStream` + 0x09 加密装饰器（双向确认）+ 0x08 压缩装饰器（认证后协商） | 0x00 单文件 / 0x01 文件夹 / 0x02 分块 / 0x03/0x04 续传 / 0x05 配对 / 0x06 文本 / 0x08/0x09 加密压缩 / 0x0A–0x0C 能力覆盖收尾 / 0x10/0x11/0x1A 应答 | ✅ 已实现（0x07/0x17 旧版加密不实现——无旧版互通承诺） |
| UDT（可靠 UDP 流） | **UDT**（原生 Rust 自研：ARQ + SACK + 固定窗口 256×1200B，`transfer::udt`；**与 UDT4 不做包级互通**——§4.3 口径不变；线格式 WIRE-PROTOCOL.md §7） | 与 TCP 同帧（0x05/0x09/0x0A/0x08 全继承 TCP 路径） | ✅ 已实现（含丢包注入单测与真 socket e2e） |
| QUIC（拆分新增槽位） | **QUIC**（quinn，TLS 1.3 + 自签证书 + 0x0D 通道绑定；`--pin` 钉扎可选） | 与 TCP 同帧 + 1 字节版本握手 | ✅ 已实现（含全部新帧） |
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
2. ~~**reed-solomon-erasure 为纯 Rust 参考实现**：FEC 吞吐基准 ⬜ 发布阶段，不达标再换 C 绑定实现~~ ✅ 已基准化（`tests/fec_bench.rs`，`--ignored` 手动跑）：4+2×1400B 组 **编码 1160 MB/s / 重建 891 MB/s**（release，20k 组 112MB 数据）——1 Gbps 链路需求（125 MB/s）的 ~9× 余量，纯 Rust 实现保留，C 绑定评估关闭。
3. **quinn 0.11 → 后续大版本**：锁版本升级。
4. **CLI 参数面有意偏离规格 §3.6**：`--proto <tcp|udt|udp>` 取代 `[--tcp|--udt|--udp]` 开关；新增 `--text`、`--pin`、`--noencrypt`；`--nocompress` 已随 0x08 落地（send/sync）；新增 `--chunks 1-8`（0x02 并行分块）与 `update` 动词。差量同步 0x04 已落地（稳定会话 ID + 位图差分）。
5. ~~**进度事件机制**（规格 §3.1 节流 100ms）⬜ M4'~~ ✅ M4' 落地：`trft-core::progress`（惰性节流、终态必达、Outcome Drop 即失败）；0x00/0x01/0x02/0x03/0x04/UDP 双侧全接线；UI 只消费事件（§1.4 分层纪律）。
6. ~~**QUIC 无 --pin 不防主动中间人**（自签模型 + 0x05 不绑定通道）~~ ✅ 已由 M6' 兑现（§7.11/§7.13）：0x0D 通道绑定证明——配对证明混入客户端所见证书指纹，QUIC+配对强制绑定、明文 0x05 fail-closed（CLI `--allow-legacy-pair`/`--pin` 显式放行）；残余仅明文 TCP `--noencrypt` 路径（无通道材料可绑定，既有登记）。
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
18. **第二轮全量审查·轮 8（判别力抽查 + 全量回扫）收尾口径**（2026-11-01）：
   - **判别力 12/12 强**（6 项实测「去修复必红」+ 6 项静态确认，无恒真/恒假/被兜底）；回扫 180 绿、构建 0 告警（含全部测试目标）、无调试残留；
   - 收尾修复：测试面 2 条编译警告（r6 引入，全 workspace 唯二告警破口）；`is_upload_part_name` 收紧为自产名严格同形（`.up`+8hex+单段 ext+`.part`，附判别单测——宽松 contains(".up") 理论误伤用户文件）；EMSGSIZE 注释平台值更正（FreeBSD/Solaris）；
   - 轮 1/轮 3 的完整发现清单与判别记录补入 REVIEW-LOG（此前仅在 commit message，文档欠账）；
   - **队列重试不区分错误类**（AuthRejected 等不可重试错误也重试至 QueueRetries 次——规格未限定错误类，仅浪费尝试，登记接受）。
19. **GUI 对齐批**（2026-11-01，第四轮对齐需求；规格缺口补齐 + 在案打磨项闭环 + 视觉精致化）：
   - **已对齐规格**：GUI 日志上限 200→500（§3.7）；**发送面板 SrcPort 输入**（§3.1/§12.1，CLI `--srcport` 同源；UDP 隐藏；`SendRequest.srcPort` + `sync_start` 接线 + 队列快照第 13 字段跨重启持久化，旧行兼容回读）；**输入校验全面化**（§3.7：表驱动 `FIELD_CHECKS` 覆盖端口/分块 1-8/轮数 1-5/校验片 1-8/限速/缓存天数/配对码 4-12 位数字/IP/群发目标逐行/路径非法字符 `< > : " | ? *`（剥盘符）/更新 URL http(s)——非法红框 + 淡红底 + `title` ToolTip，空值中性，语言切换后 ToolTip 随刷）；**EN 模式中文残留清理**（§3.7 双语纪律：`send_cancel` 终态事件补机器字段 `reason`，前端由比较 `"已取消"` 字符串改判 `reason==="cancelled"`；按设备明细 `" 文件"` 后缀改 L10N）；
   - **QueueItem camelCase 缺失修复**（本轮顺带发现）：`queue_save` 的 `Vec<QueueItem>` 无 `#[serde(rename_all="camelCase")]`——前端持久化发 `fecParity` 键、结构体期望 `fec_parity`，serde 对缺失 Option 静默给 None，**队列 UDP 三参数（passes/fecParity/nofec）跨重启持久化实际在丢**（轮 7 F2 只修了执行路径 `SendRequest`，持久化路径漏网）；补改名对齐，附队列快照 srcPort 同口径；
   - **在案打磨项闭环**：统一确认模态 `confirmDialog`（Promise，danger 变体）替换 `window.confirm` ×2（队列完成后动作 §3.2 / 统计全部清除）；接收确认弹窗排队（`confirmQueue` 依次呈现 + 标题徽标 (i/N)——并发确认不再后到覆盖先到，fail-closed 时限仍由后端 31s 看门狗兜底）；更新提示单 toast 双动作（安装+跳过合并）；
   - **视觉精致化**（token 体系不动、布局不变）：交互过渡 120ms（btn/seg/tab/输入框）、token 化细滚动条、`:focus-visible` 焦点环、`.btn.danger` 危险操作警示色、进度卡状态色条（running/done/failed 左缘）、invalid 淡红底、toast/modal 进场动画、`prefers-reduced-motion` 全量守卫；`data-i18n-ph` 占位符双语支持；
   - **文字截断/遮挡专项排查**（对齐批收尾）：① SrcPort 占位文案在 w80 输入框内截断（zh「源端口（可选）」/en「Source port (optional)」）——缩短为「源端口」/「Src port」；② **动态空状态 L10N 残留**（预存在）：5 处 JS 动态创建的空状态 li（队列/设备/文本历史/按设备明细/传输历史）未挂 `data-i18n`，语言切换后 applyLang 刷不到（实测英文界面残留中文「暂无记录」）——统一挂 `li.dataset.i18n` 随 applyLang 刷新；其余 6 页签 × 中英 × 1080/880 宽、长文件名进度卡（含按钮组）、长防火墙 toast、绑定地址下拉浮层逐项目检无截断/遮挡；
   - **「生成配对码」移正**（用户反馈轮）：此前生成勾选误置于**发送面板**——发送侧应填对端配对码，随机生成填入必然认证失败（对端未配对时亦无意义）；移至**设置页配对码旁**（本机接收侧，规格 §3.3 口径）并补齐 `PairingLength` 位数输入（config 键此前有键无 UI，4–12 红框校验 + 保存接线 + 无效回落默认生成）；生成源 `Math.random()` → **CSPRNG**（`crypto.getRandomValues` + 拒绝采样消模偏差）——配对码是认证凭据，可预测随机属弱点；发送/监控面板配对码占位改「对端配对码」/"Receiver's code" 明示方向；
20. **离线便携版**（2026-11-01，GUI 对齐批延伸）：
   - **机制**：GUI exe 旁存在 `WebView2Runtime\`（含 `msedgewebview2.exe` 判别标记）即视为微软 Fixed Version 固定版运行时——`main()` 最前 `use_portable_webview2()` 设 `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER`（外部已显式指定时不覆盖）并**跳过 Evergreen 检测**（离线机器无 Evergreen，不得引导下载）；主版本单 exe 不变（Evergreen 自动跟进微软安全补丁），便携版不自动更新——安全更新代价由离线场景补偿；
   - **构建**：`build.bat`（CRLF+GBK——cmd 三坑：LF 破坏括号块解析、UTF-8 中文乱码、括号块内 echo 的 `)` 提前闭块）产出三件套 + `.sha256` 边车 + `TrFileTransfer-GUI-<版>-portable.zip`（`build\WebView2FixedRuntime\` 就绪才打包，否则跳过并提示）；`build\fetch-webview2-fixed.ps1` 获取运行时：`-CabPath` 官方固定版 cab（许可最干净，第三方再分发走此路）或无参快照本机 Evergreen（布局同构，自用/内网足够）——edgeupdates API 已不再提供 WebView2 Fixed Version 条目；
   - **判别验证的坑（登记）**：WebView2 **进程池复用**——同 user-data-dir + 同版本时新建 WebView 直连已有浏览器池，executable folder 不参与 →「启动后看 msedgewebview2.exe 子进程路径」的判别测试必须**先杀净进程池冷启动**，否则假阴性（实测两次误报「便携未生效」均为此因）；冷启动判别通过（子进程路径落在便携目录）。
21. **测试细化 + 集成测试补强**（2026-11-01，181 → 197 项）：
   - **trft-gui 零测试清零**：crate 拆 lib + bin（Tauri 2 推荐结构，bin 仅入口）；`queue.txt` 序列化/解析抽纯函数（`queue_items_to_text`/`parse_queue_text`）并以 6 项互锁测试钉住——13 字段全量 round-trip、**serde 键对齐回归**（前端 persistQueue 确切 JSON 形状 ↔ QueueItem，钉死本批修的「camelCase 缺失 → 队列 UDP 参数跨重启静默丢失」事故类）、2/9/12 字段旧格式兼容、写侧 `|` 污染防御、解析层 500 钳制；SendRequest serde 契约 3 项（srcPort/passes/fecParity 落位 + 缺字段缺省 + display_name 三态）；便携版探测抽纯函数 `detect_portable_runtime` 3 单测（标记在/不在/外部指定优先）；
   - **B2 测出真实缺陷并修复**：新增 CLI 跨进程集成测试（`tests/cli_transfer.rs`：子进程 recv --count 1 ↔ send 全链路）暴露 **`trft send` 主线程栈溢出**——Windows 主线程默认栈 1MB，debug 构建异步发送调用链（0x03 → 加密/压缩装饰器 → 帧循环）栈帧膨胀必崩（100B 小文件即崩、与大小无关），release 1MiB 压线失败（exit=1）——CLI 此前仅有退出码测试（错误路径不触达深调用链）、实机演练均为 release 大文件路径，故潜伏至今。修复：CLI 入口挪 16MB 大栈线程（rustc 同款做法），四组合（debug/release × 100B/1MiB）全过；
   - **0x02 分块专项 e2e**（`tests/e2e_chunked.rs` ×3）：8 MiB 4 连接多分块边界（大于套件原 3 MiB 上限）、分块 × 配对 × 压缩全栈、对旧对端 Unsupported 后回退 0x03/0x00 **完整送达**（interop 测「会回退」，此处测「回退链路终点」）；
   - **flaky 治理**：`monitor.rs` `copy_complete_rejects_growing_file` 真时钟竞态（旧版单写点 100ms 处，首次采样被调度延迟跨过写点 → 两次采样同大小 → 误判稳定假红，全量跑实测复发过）改双写点确定性构造——写点间隔 200ms < 稳定窗 300ms，任意相隔一窗的采样必跨写点；
   - **环境事件（非项目缺陷，登记防误读）**：测试期间 C 盘 100% 满（TEMP 内历史审查 PoC 残留 ~2GB 已清理）引发 os error 1455 页面文件不足 / 瞬时 E0463 rlib 假性丢失 / 磁盘预检拒绝传输——同批症状（尤其 1455）先查磁盘水位再怀疑代码；
   - **范围外维持**：UDP 真丢包 e2e（环回无丢包，引擎级 11 项单元覆盖）、>100MB 大文件（套件时长）、前端 JS 测试（无 Node 工具链，契约由 serde 键对齐测试在 Rust 侧钉住）。
   - **验证**：181 项测试全绿（0 告警）；实机启动 + mock `__TAURI__` 浏览器测试床交互冒烟（红框/ToolTip/双语/双主题/确认模态/排队徽标/进度卡三态/语言锁全部过）；
   - **登记接受（不修）**：同步会话对话框维持登记不做（磁盘即状态模型下语义弱化，用户拍板）；core 错误串中文 Display 在 EN 模式直接展示（文案集中 L10N 纪律仅约束前端，core 错误国际化属独立批次）。
22. **第九轮审查修复（2026-11-01，197 → 203 项，全绿）**：
   - **P1 队列成败判定**：`run_single_send` 以「任务从 tasks 表消失」当成功，而 `settle_send` 成败都摘表 → QueueRetries 重试恒不触发、失败恒计入「N 完成」、全失败仍执行关机/休眠/自定义命令。修复：`send_start` 拆 `spawn_send`（返回 `oneshot` 结果通道），`settle_send` 统一成型 `Result<(),String>` 并回传；队列改为等真实结果（24h 兜底、通道断开按失败）；
   - **P2 监控相对目录**：`copy_complete(&dir.join(&check_path))` 对 `scan_dir` 已含前缀的路径二次 join → 相对监控目录恒判不就绪，改为直接使用 `check_path`；
   - **P2 0x02 越界溢出**：`offset + plen` 在错误信息里二次求值，`offset=u64::MAX` 时 debug 溢出 panic（`--count` 串行分支会掀掉接收器）→ 改 `checked_add`，新增判别测试（修复前以 panic 失败）；
   - **P2 CSV 公式注入**：统计导出对 `= + - @ \t \r` 开头的字段前置单引号（`path` 为对端可控文件名），新增判别测试；
   - **P3 批次**：clippy `min_max`（deny-by-default）致 `--all-targets` 编译失败 → `1.min(buf.len())`；Cookie 解析遇无 `=` 段不再整体放弃（坏段跳过）+ 测试；`ip_match` 归一 IPv4-mapped（与 `gate_key` 同口径）+ 测试；`scrub::collect` 改 `file_type()` 不跟随链接 + 深度上限 32（junction 环栈溢出）；更新器 IPv6 的 Host 头/相对重定向补方括号 + 测试；CLI 更新成功后不再宣称「旧文件备份」仍在；`write_atomic` 去掉第二份 .bak 复制（注释与实现对齐）；discovery 恒真断言收紧为真判别。

23. **构建 + GUI 实机全面测试**（2026-11-01，203 → 205 项）：
   - **方法**：release 构建后以隔离 `APPDATA` 启动真实 GUI，用 UI Automation（Enumerate/Invoke/ValuePattern，不依赖鼠标焦点）驱动界面，配合 CLI 子进程与 HTTP 客户端做端到端判定，逐步截图留证；
   - **P0 更新检查栈溢出（实机抓到，release-only）**：配置了 `UpdateUrl` 的用户**启动 3 秒后静默检查必崩**（APPCRASH 0xC00000FD，`thread 'main' has overflowed its stack`），手动点「检查更新」同样崩；debug 构建存活（`respond_async_serialized` 在 debug 走 `Box::pin`，release 深内联）→ 判定为默认 1MB 线程栈被 update 异步链（rustls 客户端配置 + 超时包装 + 连接 future）耗尽，与轮 9 修复的 CLI 主线程栈溢出同源。修复：`build.rs` 加 `/STACK:16777216`（PE 默认栈被无线程大小参数创建的线程继承）；实测配置 `UpdateUrl` 启动 12s + 手动检查均存活；
   - **P1 `--count` × 0x02 并行分块互斥**：接收端把首条连接的中途判决 `INCOMPLETE`(0x02) 也计入 `--count`，`recv --count 1` 在收到第一个分片后即退出 → 发送端被 RST、落盘只剩 `.trft-part`（CLI 与 GUI 均实测复现）。修复：仅 `0x01`（已组装）计入；新增 e2e 判别测试 `chunked_with_count_one_receives_full_file`；
   - **P2 Web 根目录上传后 404**：`/up/` 成功回 303 `/view/{path}`，根源时得到 `/view/`——axum 的 `{*path}` 通配要求至少一段，不匹配任何路由 → 浏览器落在 404 白页（下载/删除的取消链接同病）。修复：`view_url()` 统一（空路径回 `/`），覆盖上传跳转、删除跳转、取消链接、父目录链接；新增 web 测试 `root_upload_redirects_to_root_listing`；
   - **P3 语言切换后动态列表不刷新**：统计「按设备」行在 EN 下残留中文「5 文件」（动态文本不在 `data-i18n` 覆盖内）。修复：`setLang` 重渲染 stats/devices；
   - **实测通过项**：启动/渲染、六页签、收发全链路（GUI 收 CLI 发 5MiB+777 逐字节一致；GUI 发 CLI 收）、中文文本发送、队列 2 项串行发送、并行分块 0x02、监控目录自动发送+归档、HTTP 共享（列目录/下载/Range 206/上传/穿越拦截 400）、配对码（无码拒绝+有码成功）、校验（3 文件：一致 1/无记录 2；篡改后 1 不一致并点名）、设置持久化、中英与深浅主题；
   - **未覆盖（登记）**：并行群发、文本历史列表、CSV 导出（原生保存对话框）、QUIC/UDP 接收器、托盘菜单与系统通知。

24. **用户可见文案去协议化**（2026-11-01，205 → 206 项）：
   - **原则**：线协议帧码（`0xNN`）、设计文档章节号、内部产物名一律不进用户可见输出——GUI 日志/传输历史、CLI 输出与 `--help`、系统通知、CSV 导出；
   - **统计明细**：`0x00`/`0x01 文件夹`/`0x02 分块×N`/`0x03 续传`/`0x04 同步`/`0x06 文本` → 「直接发送/整夹发送/分块传输×N/续传传输/文件夹同步/文本消息」；旧 stats.log 在**读取时**按 `normalize_detail` 归一（幂等、不篡改未知文案、不改写用户文件，随下一次重写自然收敛）；
   - **错误文案**：所有 `proto/Unsupported/Rejected` 去掉帧码、`fail-closed`、`会话/逐出/半成品` 等内部术语（「对端数据无法识别（协议版本可能不兼容）」「分块传输已中断」「续传协商失败」…）；
   - **CLI 帮助**：`--chunks/--noencrypt/--nocompress/--allow-legacy-pair/--count/--pin/update` 的说明去掉 `0x0N` 与「规格 §x」，改为功能描述；
   - **日志噪声**：防火墙提示日志由「netsh: <原始命令>」改为中文说明（命令仍留在可复制的 toast）；UDP 接收日志不再打印会话 ID（只报文件名）；
   - **验证**：core 115 项单测（新增 `legacy_protocol_labels_are_normalized_on_load`）；GUI 实机历史/日志逐行确认无 `0x`；`trft send --help`/`update --help` 无帧码。
25. **与原 C# 版功能对齐**（2026-11-08，206 → 209 项）：
   - **对齐方法**：逐节对比 E:\zcode\TrFileTransfer（原版）规格与实现 vs 本仓库——两份 PRODUCT-SPEC 95% 逐字同源，功能面差距极小；缺口矩阵经用户拍板分三批（A1/A2–A5/B），C 批（同步会话对话框、Mica）维持登记不做；
   - **A1 文件日志 + crash.log**（规格 §3.7 硬缺口闭环）：`trft-gui/src/logging.rs`——`logs/yyyy-MM-dd.log` 按天追加（civil 日历换算零依赖）、启动清理 >30 天、`crash.log` 记 panic + `Backtrace::force_capture` + 原生友好弹窗（挂默认钩子前）；全部后端日志出口（state/commands/main 共 11 处）统一收敛到 `emit_log` 双写辅助（UI 事件 + 文件各一份，文件侧无第二套来源）；传输终态在 `settle_send` 落盘（任务成败最需跨重启留痕）；写失败静默（文件日志不可用不得影响功能）；
   - **A2–A5 GUI 小 UX**（对齐原版交互）：A2 协议↔端口跟随（切协议时端口框自动填对应接收页端口——原版 v2.14，防 UDP 发错端口的零反馈黑洞）；A3 批量入队（多选文件对话框，补拖放之外的批量入口，快照纪律 + 500 钳制同口径）；A4 帮助对话框（标题栏「?」→ 双语可滚动说明，正文存 L10N `help_body`）；A5 进度卡设备名徽标（task-start 后按 IP 命中已知设备补「→ 设备名」，对齐原版 v2.15 DeviceDisplay.NameFor——**接收侧因 core 进度事件不携带 peer 登记**为后续项，本轮不扩 core API）；
   - **B PRODUCT-SPEC 文档对齐**（清除重写版规格中的 C# 遗留自相矛盾）：头部基线声明（承自 C# v2.14 规格 + Rust 实现基线指向 TECH-STACK）；§7.2 CS1985 → Rust 等价纪律；§8.1 数据文件布局改写为 Rust 实际（config.toml/每目录哈希缓存/devices.json/logs+crash）；§8.2 运行时改 Win10/11 + Rust + WebView2 双形态；§9 平台策略重写（「Rust/Go 重写暂不采纳」条目标注已由本仓库实施，消除否决自己的悖论）；§10 质量规格改 206 项 Rust 测试 + tauri.conf 版本单源 + CI 缺席如实登记；§4.3 C# ≤2.11 互通矩阵 → 不做互通承诺 + 自互通 e2e；§6.1 补 0x04 清单 100,000 偏离注；§7.1 完成确认集合统一（补 0x03）；§12.1 标注 C# 键名参考 + config.rs 权威；AGENTS.md 断链 → TECH-STACK 承接其职能；
   - **验证**：cargo test -p trft-gui 15 项全绿（logging 3 项新增：ISO 日期文件名/30 天清理仅删 .log/非日志文件不动）；mock 浏览器测试床实测 A2（8081/8082 跟随）/A3（双文件入队）/A4（双语帮助开合）/A5（已知设备徽标 + 未知 IP 负例）；全量回归 209/0、0 告警；
   - **提交前自审修复**：crash.log 与日常日志**分锁**——panic 若正发生在 `log_line` 持锁期间，钩子内 `write_crash_log` 再抢同一把非重入 Mutex 会死锁（崩溃路径反而卡死）；改独立 `CRASH_LOCK` + `try_lock`，争用（双线程同时 panic）时无锁直写——append 交错风险可接受，宁留痕不丢失。
26. **五项收尾批**（2026-11-08，209 → 210 项）：
   - **A5 接收侧设备名徽标**（补齐对齐批登记的后续项）：`ProgressEvent` 增 `peer: Option<String>` + `Reporter::set_peer`（首值锁定——分块多连接共享 Reporter 时迟到连接不得改写归属）；接收侧 6 个 register 站点全接线（0x00/0x03/0x04/0x01/0x02/UDP），GUI 发送侧 3 个 register 补目标 IP；前端徽标改 **ev.peer 单源**（发送/接收同一逻辑，命中已知设备显示记忆名、未知回落 IP），task-start 依赖 reqByTask 的旧路径删除；判别：progress 单测（首值锁定 + set_peer 不产生事件）+ e2e_tcp 进度测试断言 `peer == 127.0.0.1` 全事件成立；
   - **CI 接入**（§10.2 登记的缺席项闭环）：`.github/workflows/ci.yml`——Windows 全量测试 + release 编译门；Linux/macOS 逻辑层三 crate（trft-gui 依赖 WebView2/Tauri 系统栈，跨平台 GUI 仍为发布阶段项）；CLI `--version` 冒烟；
   - **FEC 吞吐基准**（§7.2 发布阶段项闭环）：`tests/fec_bench.rs`（`--ignored` 手动跑）——4+2×1400B 组 **编码 1160 MB/s / 重建 891 MB/s**（release，20k 组 112MB）：1 Gbps 链路需求 125 MB/s 的 ~9× 余量，纯 Rust 保留、C 绑定评估关闭；
   - **core 错误串国际化（shim 批次）**：前端 `te()` 子串模式映射（20 条高频 core 错误 → 英文），只挂在 toast/log 两个显示咽喉点，zh 透传、未命中回落原文；**登记**：错误码架构（ErrorKind → 前端模板）为后续独立批次，shim 覆盖不了参数化长尾（如「需要 ≥ N 字节」中的数字随原文保留）；
   - **验证**：全量 210/0、0 告警；mock 测试床实测接收卡徽标（ev.peer → 设备名）与 EN 错误 shim。
27. **对齐批二**（2026-11-09，对齐扫尾：210 项维持）：
   - **G1 传输历史「资源管理器定位」**（对齐原版 HistoryDialog）：新增 `open_locate` 命令（Windows `explorer /select,`；非 Windows 回落打开父目录）；历史行补 📂 按钮（旧 6 字段行无路径不提供）；⚠️ 实现坑登记——插入新 `#[tauri::command]` 时把既有 `open_path` 的属性行拆到了新函数上方，tauri 宏双展开报 E0428 重名（属性必须紧跟其函数）；
   - **G2 目录类生效提示**（规格 §3.3「下次服务器启动生效（有提示）」）：保存设置时若任一接收器运行中，追加 warn toast 提示目录类选项下次启动生效；
   - **G3 最近接收定位——登记不做**：Rust 最近接收仅存文件名（无完整路径），定位需扩 core 事件载荷（可选后续项）；原版 RecentFiles 存全路径；
   - **验证**：mock 实测定位调用路径透传 + 双 toast；全量 210/0。
28. **UDT/QUIC 槽位拆分**（2026-11-10，用户拍板：原「UDT」恢复 UDT 语义、QUIC 独立成第四模式）：
   - **UDT 原生实现**（`transfer::udt` + `protocol/udt.rs`，~900 行）：UDP 之上可靠有序双向字节流——HS/HS_ACK 握手（conn_id 随机 + nonce 回显防 off-path）、DATA/ACK+SACK（立即逐包确认、乱序重排上限 1024 包）、FIN/FIN_ACK 收尾、RST 附原因；RTO 按 RFC 6298 简化 EWMA（200ms–3s），单包重传 >12 断连；固定窗口 256×1200B（无拥塞控制——局域网工具定位，**与 UDT4 语义差异登记**）；30s 空闲超时（对齐原版 UDT_RCVTIMEO/UDT_SNDTIMEO）；服务端单 socket 按 conn_id 多路分解 + IP 过滤先于握手 + 连接表 256；帧层复用 `handle_conn`（TCP 入口）——0x05/0x09/0x0A/0x08 与 TCP 同路径（**不得复用 QUIC 入口**——其跳过 0x09，机密性语义不同）；
   - **拆分改名**：UI/CLI 全线 `UDT (QUIC)` → `QUIC` 独立模式 + 新增 `UDT` 模式（CLI `--proto tcp|quic|udt|udp`；`--pin` 归 QUIC）；`Transport::Udt` 新变体接入 `connect_stack`/`send_file`/`send_text`/`send_folder_auto`/`MonitorProto`；GUI 接收页四卡、设置页四目录、协议↔端口跟随映射；
   - **发现帧 0xD2 向后兼容扩展**：flags bit1 语义正名（= QUIC，旧版把它显示为 UDT 恰与其实现一致），新增 bit3 + 尾部可选 `udt_port` 字段——旧解码器读新帧把 quic_port 当 udt_port 显示，语义恰好一致；新解码器对旧短帧回 `udt_port=None`；
   - **存量迁移**：devices.json / queue.txt 里 proto `"udt"`（拆分前=QUIC 槽位）首载一次性改写 `"quic"` 并落盘（devices 走 `DeviceStore::load`；queue 以 `#trft-queue-v2` 版本头判别，迁移幂等）；此后 `"udt"` 即真 UDT；
   - **配置新键**：`server_port_udt` / `save_dir_udt`（默认 8080 / AppData 下 `udt` 子目录，随「各传输同默认端口、UDP 族同端口需错开」既有约定）；
   - **实现坑登记（本轮排障实录）**：(1) tokio `Notify::notified()` future 逐 poll 重建、**drop 即从等待队列注销**——`notify_waiters` 丢唤醒致 shutdown 永挂，FIN_ACK 改走 mpsc 通道（waker 挂 Receiver 上常驻存活）；(2) `watch::Sender::send` 在**无接收者时静默失败且不存值**——`error()` 所在对象必须持有 `err_rx`，否则 RST/超时被误读为干净 EOF（「结果未知 ≠ 成功」红线）；(3) current-thread runtime 上 `recv_from/recv` 有积压即同步 Ready——demux/泵/驱动循环**必须逐包 `yield_now()`**，否则互相饿死（loopback 上表现为 ~55KB/s 限速与偶发重传超限）；(4) std::sync::Mutex 不可重入——同语句两个临时 guard 同锁 = 死锁；
   - **性能登记**：loopback 实测 ~85KB/s（1MB 真传输）——每数据包跨 ~8 次任务调度 + Windows socket 事件唤醒（每包 ms 级）为主因；**优化项登记**（后续批次）：ACK 合批、批量收发（一次事件多包收集）、应用写聚合；真实高 RTT 链路上限由窗口给出（256×1200B/RTT，50ms ≈ 6MB/s）；
   - **测试**：`tests/e2e_udt.rs`（真 socket：单文件 SHA-256 一致、配对门三态、0x09 加密路径、握手版本门 fail-closed）+ 引擎单测（对偶注入：无损双向+FIN/EOF、25% 丢包重传恢复、RST 传播、重复 DATA 不重复投递）+ 发现帧新旧兼容 + devices 迁移幂等判别；全量回归绿。

## 8. 记录在案的否决项

| 选项 | 理由 |
|---|---|
| Go + Wails | 交叉编译省事、出活快，但内存封顶只能靠纪律、GUI 生态弱一档；无 Rust 储备时的备选 |
| Electron / Node | 80MB+ 违背单文件轻量定位；裸 UDP/Buffer 处理吃力 |
| JVM 系（Compose Multiplatform） | 「单文件免安装、双击即用」过不去 |
| Flutter Desktop | 原生 socket 能力不足，核心被迫走 FFI，架构不干净 |
| Qt / C++ | 功能全覆盖但内存安全与测试体系工程成本最高 |
| reqwest（更新器 HTTP 客户端） | 全家桶依赖树违背单二进制轻量定位；极简 HTTP/1.1 + rustls 约 200 行即可覆盖清单/安装包拉取 |
