# TrFileTransfer

**面向局域网的点对点文件传输工具**：单文件免安装、全程 SHA-256 完整性校验，覆盖「日常互传 → 增量备份 → 弱网 / 无回传链路 → 无头自动化」全谱系场景。

> **English** — LAN peer-to-peer file transfer in a single executable: no install, end-to-end SHA-256 verification, five transports (TCP / QUIC / RUDP / UDT, with **TCP and UDT interoperating with the original C# edition** / one-way UDP + Reed-Solomon FEC), GUI + CLI + web share. This README is primarily in Chinese; see [Docs](#文档) for design documents.

---

## 特性

- **五种传输协议**，同一套校验与续传能力：
  - **TCP** —— 通用、防火墙友好；应用层与原 C# 版 TCP 逐字节互通（2026-11-17 改造：明文/压缩/0x09 加密/目录/同步，SHA-256 逐字节一致；TECH-STACK §7.56）；
  - **QUIC**（quinn）—— 传输层 TLS 1.3 加密 + 可选证书指纹钉扎（`--pin`）；
  - **RUDP** —— 原生 Rust 实现的自研可靠 UDP 流（ARQ + SACK 重传），高丢包 Wi-Fi 更稳；线协议与 TCP 完全一致，0x09 加密可选（曾名 UDT——因与 UDT4 协议重名更名，不做包级互通）；
  - **UDT** —— 原生 Rust 复刻 libudt 4.x + C# 方言应用层，**与原 C# 版 2.14 直接互传**（实机双向验证：明文/0x09 加密/目录/压缩，SHA-256 逐字节一致；TECH-STACK §7.30）；
  - **单向 UDP + Reed-Solomon 前向纠错** —— 只有单向可达的链路也能传（多轮重发 + 分组交织纠错，无回传握手）；START 携带全文件 SHA-256，**收齐即校验发布**（不依赖 END，END 全丢也不会停在半成品），收尾哈希在独立线程执行、不占收包（TECH-STACK §7.59）。
- **完整性优先**：每个文件计算 SHA-256 并在接收端重算比对；半成品先落临时文件、校验通过后原子改名；「结果未知绝不报成功」。
- **断点续传与增量同步**：单文件 / 文件夹续传；`sync` 差量同步只传差异，本地删除的文件服务端保留（增量备份语义）；GUI 与 CLI 会话互相接力。
- **并行分块**：单文件 1–8 路并发连接（默认 4），大文件在高速局域网更快。
- **可靠接收侧**：接收前确认（未知设备弹窗 / 30 秒无应答视为拒绝）、IP 过滤（精确 / 通配 / CIDR）、按设备分目录、按日期归档、磁盘空间预检。
- **自动化**：监控目录（文件就绪自动发出，拷贝完成检测）、发送队列 + 完成后动作（关机 / 休眠 / 执行命令）、群发多目标并行。
- **HTTP 共享 + 二维码**：手机浏览器直接浏览 / 上传 / 断点下载 / 删除，配对码或访问令牌鉴权。
- **文件库校验**：重算全部接收文件的 SHA-256 与缓存比对，核对是否被篡改 / 损坏。
- **桌面集成**：托盘常驻、深 / 浅 / 跟随系统主题、中英双语运行时切换、完成通知、开机自启、检查更新。

## 下载与运行

从 [Releases](../../releases) 下载（或自行构建，见 [从源码构建](#从源码构建)）：

| 文件 | 用途 |
|---|---|
| `TrFileTransfer-GUI-0.3.0.exe` | 桌面图形界面（单文件） |
| `TrFileTransfer-GUI-0.3.0-portable.zip` | 离线便携版（GUI + 内置 WebView2 运行时，解压即用） |
| `TrFileTransfer-0.3.0.exe` | 命令行工具（无界面环境 / 脚本） |
| `TrFileTransfer-server-0.3.0.exe` | Web 管理面 |

**系统要求**：Windows 10/11 x64。GUI 依赖 WebView2 运行时（多数 Win10/11 已内置；缺失时程序会引导安装，便携版无需联网）。CLI / server 无此依赖。

> 边界说明：产品定位就是局域网（含 VPN 虚拟局域网），**不做**公网直连 / NAT 穿透；单向 UDP 模式协议上无法认证加密，仅适用于可信链路。

## 快速上手

### 图形界面

1. 两台电脑都运行 `TrFileTransfer-GUI-0.3.0.exe`；
2. 接收方在「接收」页启动监听（TCP / QUIC / RUDP / UDT / UDP 五协议可同时运行，各卡片独立端口与目录；绑定地址支持 IPv4 / IPv6 网卡与「全部 IPv6」双栈通配），首次启动按提示放行防火墙；
3. 发送方在「发送」页拖入文件 / 文件夹，填对方 IP 与端口，点「发送」；
4. 对方若启用了配对码，发送时填入相同配对码即可（可在设置页生成 4–12 位强配对码）；
5. 「共享」页一键开启 HTTP 共享，手机扫码即可浏览 / 上传 / 下载。

### 命令行

```bat
:: 发送文件（断点续传 + 加密，失败自动重试）
trft send --ip 192.168.1.20 --port 8080 --file big.zip

:: 发送整个文件夹（差量同步：重复执行只传差异）
trft sync --folder D:\work --ip 192.168.1.20 --port 8080

:: 无头接收（可挂计划任务 / 开机自启）
trft recv --port 8080 --out D:\recv

:: 单向 UDP 接收 / 发送（FEC 校验片 2）
trft recv --proto udp --out D:\inbox
trft send --ip 192.168.1.20 --port 8080 --file fw.bin --proto udp --fec-parity 2

:: 并行分块（1-8 路，弱网链路选 RUDP / 加密链路选 QUIC）
trft send --ip 192.168.1.20 --port 8080 --file big.zip --proto rudp --chunks 4

:: 文件库完整性校验（发现不一致退出码 1，适合挂脚本）
trft verify --dir D:\recv
```

常用参数：`--proto tcp|quic|rudp|udt|udp`、`--code <配对码>`、`--limit <KB/s>`、`--srcport <源端口>`、`--noencrypt`、`--nocompress`。完整参数见 `trft send --help`。

## 默认端口

| 服务 | 默认端口 | 说明 |
|---|---|---|
| TCP / QUIC / RUDP / UDT / 单向 UDP 接收 | 各 8080 | 可独立配置、同时运行（QUIC/RUDP/UDT 与单向 UDP 同承载于 UDP，同端口需错开） |
| HTTP 共享 | 8090 | 手机浏览器访问 |
| 设备发现 | 45000/udp | 仅 IPv4 广播 |

配置与数据位于 `%APPDATA%\TrFileTransfer\`（`config.toml`、统计、历史、摘要缓存等），随程序自动管理。

## 从源码构建

依赖：Rust ≥ 1.85（Windows x64）。

```bat
git clone https://github.com/54gogogo10/TrFileTransfer_v2.git
cd TrFileTransfer_v2
cargo build --release --workspace   :: 产物在 target\release\
cargo test --workspace              :: 全量自动化测试

build.bat                           :: 一键发布：release\ 三件套 + sha256 边车
                                    :: build\WebView2FixedRuntime\ 就绪时额外打出离线便携版
                                    :: （运行 build\fetch-webview2-fixed.ps1 获取运行时）
```

## 安全模型

- 传输加密：TCP / UDT（C# 方言）在设置配对码时走 0x09 ECDH 会话密钥（P-256 + PBKDF2，无码不加密，与 C# 2.14 行为一致）；RUDP 的 0x09 为可选；QUIC 由 TLS 1.3 承担（配对启用时强制 0x0D 通道绑定，防双臂中间人）；配对码用于双向认证（恒时比较 + 错误次数按 IP 锁定）。
- 建议：配对码使用 8 位以上（6 位存在离线爆破空间，加长即可消除）。
- 明确不做：公网直连 / NAT 穿透 / 中继；单向 UDP 模式的认证与加密（协议上不可行，仅限可信链路使用）。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/PRODUCT-SPEC.md](docs/PRODUCT-SPEC.md) | 产品规格（行为与要求的权威描述） |
| [docs/TECH-STACK.md](docs/TECH-STACK.md) | 技术选型与里程碑记录 |
| [docs/WIRE-PROTOCOL.md](docs/WIRE-PROTOCOL.md) | 线协议字节级布局（互通实现参考） |
| [docs/QA-CHECKLIST.md](docs/QA-CHECKLIST.md) | 真机验证清单（C# 2.14 TCP/UDT 互通 / NTFS 掉电 fsync / GUI 冒烟 / 单向 UDP 专项） |
| [docs/QA-RESULTS-2026-11-17.md](docs/QA-RESULTS-2026-11-17.md) | 真机验证结果与修复记录（C# 互通矩阵 / VM 双向 / GUI） |
| [docs/REVIEW-LOG.md](docs/REVIEW-LOG.md) | 代码与安全审查日志（逐轮发现、修复与判别测试） |

## 路线图

- Linux / macOS CLI（逻辑层已零 UI 依赖，跨平台无头版规划中）
- Web 管理面增强（任务发起 / 进度 / 取消）
