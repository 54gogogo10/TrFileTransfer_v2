/* TrFileTransfer GUI 前端（无构建 vanilla JS，经 withGlobalTauri 注入的 API 调 Rust 命令）。
   文案纪律（规格 §3.7）：禁止内联三元拼文案——全部经 L10N 字典 t() 取值；传输中锁定语言切换。 */

const T = window.__TAURI__;
const invoke = T.core.invoke;
const listen = T.event.listen;

/* ============ L10N ============ */
const L10N = {
  zh: {
    tab_send: "发送", tab_recv: "接收", tab_share: "共享", tab_verify: "校验", tab_settings: "设置",
    bind_addr: "绑定地址", wildcard_v4: "全部 IPv4 (0.0.0.0)", wildcard_v6: "全部 IPv6 (::)", no_addr_selected: "请至少勾选一个绑定地址", partial_bind: "部分地址绑定失败", dd_placeholder: "选择监听地址…",
    duplicate: "重复文件", dup_rename: "改名保留（file_1）", dup_skip: "跳过相同内容", cache_days: "摘要缓存/同步续点有效期（天，0=永久）",
    share_dir: "共享目录", after_done: "完成后", ad_none: "无动作", ad_shutdown: "关机（60s 可取消）", ad_sleep: "休眠", ad_command: "执行命令",
    confirm_shutdown: "队列完成后将关闭系统（60 秒后执行，shutdown /a 可取消）。确认执行队列？",
    confirm_sleep: "队列完成后系统将进入休眠。确认执行队列？",
    confirm_command: "队列完成后将执行命令：", confirm_tail: "。确认执行队列？",
    firewall_msg: "首次启动接收器：如其他设备无法连接，请用管理员命令放行防火墙：",
    skip_version: "跳过此版本", update_found_toast: "发现新版本",
    pause: "暂停",
    devices: "设备", discover: "发现设备", devices_clear: "清空记忆", use: "使用", to_group: "加入群发",
    ip_filter: "IP 过滤", if_off: "关闭", if_allow: "白名单（allow）", if_deny: "黑名单（deny）",
    discovering: "发现中…", online: "在线",
    group_targets: "群发目标（每行 ip:port）", group_send: "并行群发", group_summary: "群发完成",
    group_bad_target: "非法目标（跳过）", paused: "已暂停", resume: "继续", cancel_task: "取消",
    resume_unavailable: "该任务不支持在此继续（队列项请重新执行队列）",
    text_history: "文本历史（200 条）", th_empty: "暂无记录", gen_code: "生成配对码", pairing_len: "配对码位数",
    code_ph_send: "对端配对码", code_ph_local: "4-12 位数字",
    help_title: "使用说明", help_close: "关闭",
    text_title: "收到文本", text_from: "来自", text_copy_ok: "已复制",
    text_history_label: "历史记录", text_truncated: "（原文超过 64KB，这里只保留前 64KB）", text_view_full: "点击查看全文",
    help_body: "发送：类型选文件/文件夹/文本/监控/队列，填对方 IP 与端口，点「发送」；「分块数」可多连接加速大文件。\n接收：在「接收」页启动监听（TCP/QUIC/RUDP/UDP 可同时运行，各自独立端口与目录）。首次启动按提示放行防火墙。\n配对码：接收方在「设置」页设置或生成配对码；发送方填入相同配对码即可。建议 8 位以上。\n共享：「共享」页开启 HTTP 共享，手机扫码即可浏览/上传/下载。\n同步：文件夹发送默认差量同步——重复发送只传差异，适合日常备份。「排除扩展名」对整夹/同步/队列里的文件夹项生效。\n校验：「校验」页重算全部接收文件的 SHA-256，核对是否被改动；支持定时与周期性自动校验。\n监控：类型选「监控」，设置目录与目标，文件就绪即自动发出；可填排除扩展名（如 .tmp,.log）。\n队列：类型选「队列」，添加文件/文件夹后发送；可设完成后动作（关机/休眠/命令）。\n拖放：文件直接拖入窗口——单文件填路径，多文件入队列。",
    notify_sound: "提示音", sync_strict: "同步逐字节核对（绕过摘要缓存，双侧生效）",
    kind: "类型", kind_file: "文件", kind_folder: "文件夹", kind_text: "文本", kind_monitor: "监控", kind_queue: "队列",
    queue_add_files: "添加文件…", queue_add_folder: "添加文件夹…", queue_hint: "文件与文件夹可混合入队，按顺序逐项发送",
    queue_group_send: "群发队列",
    send_exclude: "排除扩展名",
    path: "路径", text: "文本", browse: "浏览…", target: "目标", pairing: "配对码",
    limit: "KB/s", compress: "压缩", encrypt: "加密",
    passes: "重发轮数 1-5", fec_parity: "FEC 校验片 1-8", nofec: "关闭 FEC",
    send: "发送", send_chunked: "并行分块发送",
    drop_hint: "可直接拖入文件/文件夹", queue: "发送队列", queue_clear: "清空",
    queue_empty: "队列为空", progress: "传输进度",
    port: "端口", save_dir: "保存目录", start: "启动", stop: "停止", open_dir: "打开目录",
    recent: "最近接收", none: "暂无记录",
    share_start: "开启共享", share_stop: "停止共享", address: "网卡地址", share_url: "链接", copy: "复制",
    qr_hint: "手机浏览器扫码即可浏览 / 上传 / 下载共享目录。",
    verify_desc: "聚合扫描全部已配置保存目录，重算 SHA-256 与摘要缓存比对。",
    verify_start: "开始校验", verify_stop: "停止",
    verify_once: "定时校验", verify_periodic: "周期性校验", verify_every: "每",
    verify_minute: "分钟", verify_hour: "小时", verify_day: "天",
    verify_next: "下次自动校验：{time}", verify_next_none: "未设置自动校验",
    verify_once_missing: "请选择定时校验的时间", verify_period_invalid: "请输入有效的周期（至少 1 分钟）",
    verify_scheduled_start: "已启动定时校验",
    verify_schedule_failed: "自动校验启动失败",
    verify_busy: "校验正在进行，稍后重试",
    v_scanned: "已扫描", v_hit: "一致", v_fresh: "无记录", v_bad: "不一致", v_unread: "无法读取",
    settings_general: "通用", notify: "完成通知", autostart: "开机自启",
    folder_mode: "发送方式", mode_sync: "差量同步（二次只传差异）", mode_plain: "整夹发送（全量）",
    sync_hint: "按 (源路径, 目标地址) 派生稳定会话 ID，与 CLI sync 互相接力",
    settings_limits: "限速与 UDP", send_limit_lbl: "发送限速 KB/s", recv_limit_lbl: "接收限速 KB/s",
    udp_passes_lbl: "UDP 重发轮数", fec: "FEC 前向纠错", udp_parity_lbl: "校验片",
    settings_update: "更新", update_url: "清单 URL", check_update: "检查更新", auto_update_check: "自动检查更新（启动时静默，发现新版本提示）", save: "保存设置",
    logs: "日志", clear: "清空",
    st_running: "传输中", st_done: "完成", st_failed: "失败",
    up_to_date: "已是最新版本", new_version: "发现新版本", update_fail: "检查失败",
    saved: "设置已保存", save_fail: "保存失败", copied: "已复制", copy_fail: "复制失败", http_off: "共享未运行",
    verify_done: "校验完成", verify_stopped: "校验已中止（仅扫描了部分文件）", send_fail: "发送失败", lang_locked: "传输进行中，语言切换已锁定",
    queue_sent: "队列已全部执行", queue_full: "队列已达 500 项上限",
    udp_file_only: "单向 UDP 仅支持单文件（无握手通道）",
    udt_code_warn: "TCP/UDT 走 C# 方言的配对认证以未加盐哈希上线（C# 2.14 互锁约束）：嗅探可离线爆破配对码。该场景建议 12 位配对码，或改用 QUIC/RUDP 槽位",
    tab_stats: "历史",
    stats_summary: "统计概览", refresh: "刷新", export_csv: "导出 CSV", stats_clear: "全部清除",
    st_today: "今日次数", st_today_bytes: "今日流量", st_week_bytes: "7 天流量", st_total: "累计次数", st_total_bytes: "累计流量",
    by_device: "按设备明细", stats_history: "传输历史", dir_all: "全部", dir_s: "发送", dir_r: "接收",
    stats_clear_confirm: "确定清除全部传输统计？（不可恢复）",
    locate: "在资源管理器中定位", dir_apply_hint: "目录类选项将在对应接收器下次启动时生效",
    monitor: "监控模式", monitor_start: "启动监控", monitor_stop: "停止监控", monitor_dir: "监控目录",
    monitor_exclude: "排除扩展名",
    monitor_hint: "目录内文件就绪即自动发出（独占打开 + 稳定窗双判定）；成功后移入「已发送文件/」。排除的扩展名（如 .tmp, .log）不入队。",
    mon_queued: "入队", mon_not_ready: "未就绪（等待）", mon_dropped: "已消失（丢弃）", mon_sending: "发送中", mon_sent: "已发送", mon_failed: "失败",
    confirm_receive: "接收前确认", cf_off: "关闭（不确认）", cf_unknown: "仅未知设备（已知放行）", cf_all: "一律确认（30 秒无应答视为拒绝）",
    per_device: "按设备分目录", auto_archive: "按日期归档",
    recv_dir_hint: "分目录/归档作用于新接收会话；叠加顺序 = 保存目录/设备/日期。",
    confirm_title: "接收确认", confirm_allow: "允许接收", confirm_deny: "拒绝",
    install_now: "立即安装", installing: "安装中…", install_done: "已安装，即将重启", install_fail: "安装失败",
    confirm_msg: "设备 {d}（{p}）请求向本机发送文件。是否允许？",
    confirm_expired: "确认已过期",
    srcport_ph: "源端口",
    chunks_lbl: "分块数", chunks_ph: "4",
    files_unit: "文件",
    cancelled: "已取消",
    confirm_yn: "请确认", confirm_ok: "确认", confirm_cancel: "取消",
    invalid_ip: "IP 格式不正确",
    invalid_port: "端口须为 1-65535 的整数",
    invalid_num: "须为非负整数",
    invalid_range: "须为 {min}-{max} 的整数",
    invalid_path: "路径含非法字符 < > : \" | ? *",
    invalid_url: "URL 须以 http:// 或 https:// 开头",
    invalid_code: "配对码须为 4-12 位数字",
    invalid_group: "存在非法目标行（应为 ip:port）",
  },
  en: {
    tab_send: "Send", tab_recv: "Receive", tab_share: "Share", tab_verify: "Verify", tab_settings: "Settings",
    bind_addr: "Bind addresses", wildcard_v4: "All IPv4 (0.0.0.0)", wildcard_v6: "All IPv6 (::)", no_addr_selected: "Select at least one bind address", partial_bind: "Some addresses failed to bind", dd_placeholder: "Select bind addresses…",
    duplicate: "Duplicates", dup_rename: "Rename (file_1)", dup_skip: "Skip identical", cache_days: "Hash / sync-resume TTL (days; 0 = forever)",
    share_dir: "Shared dir", after_done: "After done", ad_none: "None", ad_shutdown: "Shutdown (60s)", ad_sleep: "Sleep", ad_command: "Run command",
    confirm_shutdown: "The system will shut down after the queue finishes (60s, cancellable via shutdown /a). Run the queue?",
    confirm_sleep: "The system will sleep after the queue finishes. Run the queue?",
    confirm_command: "This command will run after the queue finishes: ", confirm_tail: ". Run the queue?",
    firewall_msg: "Receiver started: if other devices cannot connect, allow the firewall with (admin):",
    skip_version: "Skip this version", update_found_toast: "New version",
    pause: "Pause",
    devices: "Devices", discover: "Discover", devices_clear: "Clear memory", use: "Use", to_group: "To group",
    ip_filter: "IP filter", if_off: "Off", if_allow: "Allow list", if_deny: "Deny list",
    discovering: "Discovering…", online: "online",
    group_targets: "Group targets (ip:port per line)", group_send: "Send to all", group_summary: "Group send finished",
    group_bad_target: "Invalid target (skipped)", paused: "Paused", resume: "Resume", cancel_task: "Cancel",
    resume_unavailable: "This task cannot be resumed here (queue items: re-run the queue)",
    text_history: "Text history (200)", th_empty: "No records", gen_code: "Gen pairing code", pairing_len: "Code length",
    code_ph_send: "Receiver's code", code_ph_local: "4-12 digits",
    help_title: "Help", help_close: "Close",
    text_title: "Text received", text_from: "from", text_copy_ok: "Copied",
    text_history_label: "History", text_truncated: "(original exceeds 64 KB; only the first 64 KB is kept)", text_view_full: "Click to view full text",
    help_body: "Send: pick a type (file/folder/text/monitor/queue), fill the target IP and port, click Send. \"Chunks\" speeds up large files with parallel connections.\nReceive: start listeners on the Receive tab (TCP/QUIC/RUDP/UDP can run at once, each with its own port and folder). Allow the firewall on first start.\nPairing code: the receiver sets or generates it in Settings; the sender enters the same code. 8+ digits recommended.\nShare: enable HTTP sharing on the Share tab, then scan the QR with a phone to browse/upload/download.\nSync: folder sends are delta-sync by default - only differences are re-sent, ideal for backups. Skip-extensions applies to folder sends, sync and folder items in the queue.\nVerify: the Verify tab re-hashes received files to detect tampering; supports scheduled and recurring checks.\nMonitor: pick the Monitor type, set the folder and target; ready files are sent automatically (list extensions to skip, e.g. .tmp,.log).\nQueue: pick the Queue type, add files/folders, then send; set an after-done action (shutdown/sleep/command).\nDrag & drop: drop files onto the window - single file fills the path, multiple files go to the queue.",
    notify_sound: "Sound", sync_strict: "Sync byte-verify (bypass digest cache, both sides)",
    kind: "Type", kind_file: "File", kind_folder: "Folder", kind_text: "Text", kind_monitor: "Monitor", kind_queue: "Queue",
    queue_add_files: "Add files…", queue_add_folder: "Add folder…", queue_hint: "Files and folders can be mixed; sent one by one in order",
    queue_group_send: "Group queue",
    send_exclude: "Skip extensions",
    path: "Path", text: "Text", browse: "Browse…", target: "Target", pairing: "Pairing",
    limit: "KB/s", compress: "Compress", encrypt: "Encrypt",
    passes: "Passes 1-5", fec_parity: "FEC parity 1-8", nofec: "Disable FEC",
    send: "Send", send_chunked: "Parallel chunks",
    drop_hint: "Drag & drop files/folders here", queue: "Send queue", queue_clear: "Clear",
    queue_empty: "Queue is empty", progress: "Transfers",
    port: "Port", save_dir: "Save dir", start: "Start", stop: "Stop", open_dir: "Open dir",
    recent: "Recent received", none: "No records",
    share_start: "Start sharing", share_stop: "Stop sharing", address: "NIC address", share_url: "URL", copy: "Copy",
    qr_hint: "Scan with a mobile browser to browse / upload / download the shared folder.",
    verify_desc: "Scan all configured save dirs, re-hash SHA-256 and compare with the digest cache.",
    verify_start: "Start verify", verify_stop: "Stop",
    verify_once: "Scheduled verify", verify_periodic: "Recurring verify", verify_every: "Every",
    verify_minute: "minute(s)", verify_hour: "hour(s)", verify_day: "day(s)",
    verify_next: "Next auto-verify: {time}", verify_next_none: "No auto-verify scheduled",
    verify_once_missing: "Pick a date and time for the scheduled verify", verify_period_invalid: "Enter a valid interval (at least 1 minute)",
    verify_scheduled_start: "Scheduled verify started",
    verify_schedule_failed: "Failed to start scheduled verify",
    verify_busy: "Verify is already running; will retry",
    v_scanned: "Scanned", v_hit: "Matched", v_fresh: "No record", v_bad: "Mismatch", v_unread: "Unreadable",
    settings_general: "General", notify: "Notifications", autostart: "Launch on startup",
    folder_mode: "Send mode", mode_sync: "Delta sync (changes only)", mode_plain: "Full folder send",
    sync_hint: "Stable session ID from (source path, target) — interoperates with CLI sync",
    settings_limits: "Limits & UDP", send_limit_lbl: "Send limit KB/s", recv_limit_lbl: "Recv limit KB/s",
    udp_passes_lbl: "UDP passes", fec: "FEC", udp_parity_lbl: "Parity",
    settings_update: "Update", update_url: "Manifest URL", check_update: "Check update", auto_update_check: "Check for updates automatically (silent at startup)", save: "Save settings",
    logs: "Logs", clear: "Clear",
    st_running: "Running", st_done: "Done", st_failed: "Failed",
    up_to_date: "Up to date", new_version: "New version", update_fail: "Check failed",
    saved: "Settings saved", save_fail: "Save failed", copied: "Copied", copy_fail: "Copy failed", http_off: "Sharing not running",
    verify_done: "Verify finished", verify_stopped: "Verify stopped (partial scan)", send_fail: "Send failed", lang_locked: "Language locked during transfers",
    queue_sent: "Queue finished", queue_full: "Queue reached the 500-item limit",
    udp_file_only: "One-way UDP supports single files only (no handshake channel)",
    udt_code_warn: "TCP/UDT (C# dialect) send an unsalted pairing-code hash on the wire (C# 2.14 interop constraint): sniffing enables offline brute force. Use a 12-digit code here, or switch to QUIC/RUDP.",
    tab_stats: "History",
    stats_summary: "Overview", refresh: "Refresh", export_csv: "Export CSV", stats_clear: "Clear all",
    st_today: "Today", st_today_bytes: "Today bytes", st_week_bytes: "7-day bytes", st_total: "Total count", st_total_bytes: "Total bytes",
    by_device: "Per device", stats_history: "Transfer history", dir_all: "All", dir_s: "Sent", dir_r: "Received",
    stats_clear_confirm: "Clear all transfer statistics? (irreversible)",
    locate: "Locate in Explorer", dir_apply_hint: "Directory options take effect when the receiver next starts",
    monitor: "Monitor", monitor_start: "Start monitor", monitor_stop: "Stop monitor", monitor_dir: "Watch dir",
    monitor_exclude: "Skip extensions",
    monitor_hint: "Ready files in the folder are sent automatically (exclusive open + stable window); on success they move to the Sent folder. Skipped extensions (e.g. .tmp, .log) are ignored.",
    mon_queued: "queued", mon_not_ready: "not ready (waiting)", mon_dropped: "vanished (dropped)", mon_sending: "sending", mon_sent: "sent", mon_failed: "failed",
    confirm_receive: "Confirm before receive", cf_off: "Off (no confirm)", cf_unknown: "Unknown devices only", cf_all: "Always (30s silence = deny)",
    per_device: "Per-device folder", auto_archive: "Date archive",
    recv_dir_hint: "Applies to new receive sessions; order = save dir / device / date.",
    confirm_title: "Incoming transfer", confirm_allow: "Allow", confirm_deny: "Deny",
    install_now: "Install now", installing: "Installing…", install_done: "Installed, restarting", install_fail: "Install failed",
    confirm_msg: "Device {d} ({p}) wants to send files to this machine. Allow?",
    confirm_expired: "Confirmation expired",
    srcport_ph: "Src port",
    chunks_lbl: "Chunks", chunks_ph: "4",
    files_unit: "files",
    cancelled: "Cancelled",
    confirm_yn: "Please confirm", confirm_ok: "Confirm", confirm_cancel: "Cancel",
    invalid_ip: "Invalid IP address",
    invalid_port: "Port must be an integer 1-65535",
    invalid_num: "Must be a non-negative integer",
    invalid_range: "Must be an integer {min}-{max}",
    invalid_path: "Path contains illegal characters < > : \" | ? *",
    invalid_url: "URL must start with http:// or https://",
    invalid_code: "Pairing code must be 4-12 digits",
    invalid_group: "Invalid target line (expected ip:port)",
  },
};

let lang = "zh";
const t = (k) => L10N[lang][k] !== undefined ? L10N[lang][k] : k;

/* ============ 后端错误串英译 shim（TECH-STACK §26 登记）============
   core 错误是中文 Display（错误码架构为后续独立批次）——EN 界面下按子串模式
   改写展示文案，未命中回落原文。只在 toast/log 出口应用（全 UI 显示的单咽喉点），
   zh 界面原样透传；模式为中文子串 → 对英文原文天然 no-op，无双改写风险。 */
const ERR_EN = [
  [/磁盘可用空间不足/, "Not enough free disk space on the receiver"],
  [/对端拒绝[:：]\s*/, "Rejected by peer: "],
  [/配对码错误|配对码不匹配/, "Wrong pairing code"],
  [/尝试过多|已锁定|已计错锁定/, "Too many failed attempts - temporarily locked"],
  [/对端不支持[:：]?\s*/, "Not supported by peer: "],
  [/路径不是目录/, "Path is not a directory"],
  [/文件不存在|找不到指定的|系统找不到/, "File or path not found"],
  [/连接被拒绝/, "Connection refused"],
  [/远程主机强迫关闭|中止了一个已建立的连接/, "Connection reset by peer"],
  [/连接超时|请求超时/, "Connection timed out"],
  [/无法识别|协议版本/, "Unrecognized peer data (protocol version mismatch?)"],
  [/已中断|被掐断/, "Transfer interrupted"],
  [/续传协商失败/, "Resume negotiation failed"],
  [/越界|分块.*不符/, "Chunk framing error"],
  [/单向 UDP/, "One-way UDP: "],
  [/指纹钉扎/, "Certificate pinning: "],
  [/加密|降级/, "Encryption negotiation failed"],
  [/占用/, "File is locked or in use"],
  [/非法文件名|非法路径|非法文件/, "Illegal file name or path"],
  [/拒绝[:：]\s*/, "Denied: "],
];
function te(s) {
  if (lang !== "en" || typeof s !== "string") return s;
  let out = s;
  for (const [re, rep] of ERR_EN) out = out.replace(re, rep);
  return out;
}

/* ============ 状态 ============ */
let appState = null;            // get_app_state 返回
const tasks = new Map();        // progressId -> { el, bar, meta, state }
const taskByProgress = new Map(); // progressId -> 任务 ID（task-start 事件绑定）
const reqByTask = new Map();      // 任务 ID -> { req, kind }（继续 = 原参数重发）
const pausedTasks = new Set();    // 已暂停任务 ID
const taskTerminalSeen = new Map(); // 任务 ID -> { ok }（UI-1 P2-4：终态事件先于
// invoke 返回时兜底群发/补挂判定；条目生命周期 = 会话内任务数，量级可忽略）
const groupPending = new Map();   // 群发批次：taskId -> true；全部终态后汇总
let groupTotal = 0;
let groupOk = 0;
let groupFail = 0;
let activeTransfers = 0;        // 运行态计数（语言锁定）
let sendKind = "file";
const queueItems = [];          // 拖放/手动加入的队列
let httpInfo = null;            // { port, token, dir }
let knownDevices = [];          // 已知设备缓存（进度卡设备名徽标，A5）
let udtCodeWarned = false;      // UDT+配对码风险告警（安全轮 P1-1，每会话一次）

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function fmtBytes(n) {
  // UI-1 P3-9：NaN 与非正数显式归零（!n 会把 NaN 一并当 0 掩盖上游缺陷）。
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return v.toFixed(v >= 100 || i === 0 ? 0 : 1) + " " + units[i];
}

/* ============ 文案应用 ============ */
function applyLang() {
  document.documentElement.lang = lang === "zh" ? "zh-CN" : "en-US";
  $$("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  // 占位符同走 L10N（data-i18n-ph）——与文案纪律一致。
  $$("[data-i18n-ph]").forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  $("#lang-zh").classList.toggle("active", lang === "zh");
  $("#lang-en").classList.toggle("active", lang === "en");
  localStorage.setItem("trft-lang", lang);
  // 定时校验状态是动态文案（含时间），语言切换后单独刷新。
  if (typeof renderVerifyNext === "function") renderVerifyNext();
}

/* ============ 主题 ============ */
const media = window.matchMedia("(prefers-color-scheme: dark)");
function applyTheme() {
  let cfgTheme = appState ? appState.config.theme : localStorage.getItem("trft-theme") || "system";
  // UI-1 P2-6：非法/缺失值白名单归一——null 主题曾让 $("#theme-null") 命中
  // 空节点直接 TypeError，且 applyTheme 在 init 主链路上会打断全部后续接线。
  if (!["light", "system", "dark"].includes(cfgTheme)) cfgTheme = "system";
  const dark = cfgTheme === "dark" || (cfgTheme === "system" && media.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  $$("#theme-seg .seg-btn").forEach((b) => b.classList.remove("active"));
  const btn = $("#theme-" + cfgTheme);
  if (btn) btn.classList.add("active");
}
media.addEventListener("change", () => applyTheme());

/* ============ Toast / 日志 ============ */
// actions: [{ text, fn }]（兼容旧签名 toast(msg, cls, actionText, onAction)——B3：一个 toast 可挂多个动作）。
function toast(msg, cls, actionText, onAction, extraActions) {
  const layer = $("#toast-layer");
  const el = document.createElement("div");
  el.className = "toast " + (cls || "");
  const span = document.createElement("span");
  span.className = "tmsg";
  span.textContent = te(msg);
  el.appendChild(span);
  const actions = [];
  if (actionText) actions.push({ text: actionText, fn: onAction });
  if (extraActions) actions.push(...extraActions);
  if (actions.length) {
    const wrap = document.createElement("span");
    wrap.className = "tbtns";
    for (const a of actions) {
      const btn = document.createElement("button");
      btn.className = "tbtn";
      btn.textContent = a.text;
      btn.addEventListener("click", () => { a.fn(); el.remove(); });
      wrap.appendChild(btn);
    }
    el.appendChild(wrap);
  }
  layer.appendChild(el);
  // UI-1 P3-19：toast 数量上限（坏目标批量/日志风暴时防无界堆叠）。
  while (layer.children.length > 5) layer.firstChild.remove();
  setTimeout(() => el.remove(), 8000);
}

function beep() {
  // notify_sound 口径对齐 fillSettings（!== false 默认开）——旧配置无此字段
  // 时 UI-1 P3-12：此前按 undefined 静音，勾选显示开、实际无声。
  if (!appState || !appState.config.notify_enabled || appState.config.notify_sound === false) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.connect(g);
    g.connect(ctx.destination);
    o.frequency.value = 880;
    g.gain.value = 0.08;
    o.start();
    o.stop(ctx.currentTime + 0.18);
    setTimeout(() => ctx.close(), 400);
  } catch (e) { /* 音频设备不可用时静默 */ }
}

function log(level, msg) {
  const list = $("#log-list");
  const empty = list.querySelector(".empty");
  if (empty) empty.remove();
  const li = document.createElement("li");
  li.className = level || "";
  li.textContent = new Date().toLocaleTimeString() + "  " + te(msg);
  list.prepend(li);
  while (list.children.length > 500) list.lastChild.remove(); // 规格 §3.7：UI 日志上限 500 条
}

/* ============ 页签 ============ */
$$("#tabs .tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    $$("#tabs .tab").forEach((x) => x.classList.remove("active"));
    tab.classList.add("active");
    $$(".pane").forEach((p) => p.classList.remove("active"));
    $("#pane-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "stats") refreshStats();
  });
});

/* ============ 发送 ============ */
function updateKindRows() {
  const isFile = sendKind === "file";
  const isFolder = sendKind === "folder";
  const isText = sendKind === "text";
  const isMonitor = sendKind === "monitor";
  const isQueue = sendKind === "queue";
  const isUdp = $("#send-proto").value === "udp";

  // 监控与队列都是「类型」的一项：各自展示一块配置区，普通发送字段互斥隐藏。
  // 监控运行中即使切到其他类型也保留卡片（状态/记录可见）。
  const monitorRunning = $("#dot-monitor").classList.contains("on");
  $("#monitor-card").classList.toggle("hidden", isQueue || !(isMonitor || monitorRunning));
  $("#queue-card").classList.toggle("hidden", !isQueue);

  $("#path-row").classList.toggle("hidden", isText || isMonitor || isQueue);
  $("#text-row").classList.toggle("hidden", !isText);
  // 规格 §3.1 文件夹模式子选项：0x04 差量同步（默认）与 0x01 整夹发送。
  $("#folder-opts").classList.toggle("hidden", !(isFolder && !isUdp) || isMonitor || isQueue);
  // 排除扩展名只对文件夹/同步发送有意义（单文件与文本不产生清单）。
  $("#folder-exclude-row").classList.toggle("hidden", !(isFolder && !isUdp) || isMonitor || isQueue);
  // 0x02 并行分块与 UDP 单发都只对单文件有意义（规格 §3.6）。
  $("#btn-send-chunked").classList.toggle("hidden", !(isFile && !isUdp) || isMonitor || isQueue);
  $("#udp-opts").classList.toggle("hidden", !(isFile && isUdp) || isMonitor || isQueue);
  // 源端口仅连接型协议可绑定（§3.1；UDP 无连接语义，与 CLI --srcport 约束同口径）。
  $("#send-srcport").classList.toggle("hidden", isUdp || isMonitor);
  // 队列逐项按文件/文件夹发送，不走并行分块；隐藏无意义的分块数。
  $("#send-chunks").classList.toggle("hidden", isQueue);
  $("#chunks-lbl").classList.toggle("hidden", isQueue);

  // 监控使用自己卡片里的目标/协议/配对码，隐藏普通发送的对应行与动作行；
  // 队列仍复用主发送卡的目标/配对码（入队时逐项快照）。
  [$("#send-ip"), $("#send-code")].forEach((el) => {
    const row = el && el.closest(".row");
    if (row) row.classList.toggle("hidden", isMonitor);
  });
  const sendRow = $("#btn-send") && $("#btn-send").closest(".row");
  if (sendRow) sendRow.classList.toggle("hidden", isMonitor || isQueue);
  // 群发行在队列页保留（群发队列），其它普通类型用「并行群发」；监控页不需要。
  const groupRow = $("#group-targets") && $("#group-targets").closest(".row");
  if (groupRow) groupRow.classList.toggle("hidden", isMonitor);
  $("#btn-group-send").classList.toggle("hidden", isQueue);
  $("#btn-queue-group-send").classList.toggle("hidden", !isQueue);
}
$$("#kind-seg .seg-btn").forEach((b) => {
  b.addEventListener("click", () => {
    $$("#kind-seg .seg-btn").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    sendKind = b.dataset.kind;
    updateKindRows();
  });
});
$("#send-proto").addEventListener("change", () => {
  // 对齐原版 v2.14「协议↔端口跟随」：切协议时端口框自动跟随对应接收页端口
  // （否则 UDP 发到 TCP 端口是零反馈黑洞）。
  const key = { tcp: "server_port_tcp", quic: "server_port_quic", rudp: "server_port_rudp", udt: "server_port_udt", udp: "server_port_udp" }[$("#send-proto").value];
  if (appState && appState.config[key]) $("#send-port").value = appState.config[key];
  updateKindRows();
});

$("#btn-browse").addEventListener("click", async () => {
  const file = await T.dialog.open({
    multiple: false,
    directory: sendKind === "folder",
    defaultPath: (appState && appState.config && appState.config.last_path) || undefined,
  });
  if (file) {
    $("#send-path").value = file;
    // 规格 §12.1 LastPath：记忆所选目录（下次开对话框落在这里）。
    if (appState && appState.config) {
      const i = Math.max(file.lastIndexOf("\\"), file.lastIndexOf("/"));
      appState.config.last_path = i > 0 ? file.slice(0, i) : null;
      invoke("save_config", { config: appState.config }).catch(() => { /* 忽略 */ });
    }
  }
});

const RE_V4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const RE_V6 = /^\[[0-9a-fA-F:]+\]$|^[0-9a-fA-F:]+$/;

/* ============ 输入校验（规格 §3.7：端口 1-65535 仅数字、IP 字面量、配对码仅数字、
   路径非法字符、更新 URL 须 http(s)——非法红框 + ToolTip，空值中性） ============ */
// 数字仅接受纯数字（收紧 parseInt("80abc")===80 的旧口径）。
const numOk = (min, max) => (v) => {
  v = v.trim();
  if (v === "") return true;
  if (!/^\d+$/.test(v)) return false;
  const n = parseInt(v, 10);
  return n >= min && n <= max;
};
const ipOk = (v) => { v = v.trim(); return v === "" || RE_V4.test(v) || RE_V6.test(v); };
const codeOk = (v) => { v = v.trim(); return v === "" || /^[0-9]{4,12}$/.test(v); };
// Windows 非法字符集；剥离盘符前缀 `X:`（其中的冒号合法）。
const pathOk = (v) => {
  v = v.trim();
  return v === "" || !/[<>:"|?*]/.test(v.replace(/^[a-zA-Z]:/, ""));
};
const urlOk = (v) => { v = v.trim(); return v === "" || /^https?:\/\//i.test(v); };
// 群发目标：每行 ip:port（IPv6 方括号同 parseTarget 口径）；空框中性。
const groupTargetsOk = (v) => {
  const lines = v.split("\n").map((x) => x.trim()).filter(Boolean);
  if (!lines.length) return true;
  return lines.every((ln) => {
    const m = parseTarget(ln);
    return !!m && !!m.ip && m.port >= 1 && m.port <= 65535;
  });
};

// 校验表：sel 可命中多个元素；args 供 {min}/{max} 占位文案。
const FIELD_CHECKS = [
  { sel: "#send-ip", ok: ipOk, tip: "invalid_ip" },
  { sel: "#send-port", ok: numOk(1, 65535), tip: "invalid_port" },
  { sel: "#send-srcport", ok: numOk(1, 65535), tip: "invalid_port" },
  { sel: "#send-chunks", ok: numOk(1, 8), tip: "invalid_range", args: [1, 8] },
  { sel: "#send-code", ok: codeOk, tip: "invalid_code" },
  { sel: "#send-limit", ok: numOk(0, 10000000), tip: "invalid_num" },
  { sel: "#send-passes", ok: numOk(1, 5), tip: "invalid_range", args: [1, 5] },
  { sel: "#send-parity", ok: numOk(1, 8), tip: "invalid_range", args: [1, 8] },
  { sel: "#send-path", ok: pathOk, tip: "invalid_path" },
  { sel: "#group-targets", ok: groupTargetsOk, tip: "invalid_group" },
  { sel: "#monitor-ip", ok: ipOk, tip: "invalid_ip" },
  { sel: "#monitor-port", ok: numOk(1, 65535), tip: "invalid_port" },
  { sel: "#monitor-code", ok: codeOk, tip: "invalid_code" },
  { sel: "#monitor-dir", ok: pathOk, tip: "invalid_path" },
  { sel: "#http-port", ok: numOk(1, 65535), tip: "invalid_port" },
  { sel: "#cfg-code", ok: codeOk, tip: "invalid_code" },
  { sel: "#cfg-pairing-len", ok: numOk(4, 12), tip: "invalid_range", args: [4, 12] },
  { sel: "#cfg-cache-days", ok: numOk(0, 36500), tip: "invalid_num" },
  { sel: "#cfg-limit", ok: numOk(0, 10000000), tip: "invalid_num" },
  { sel: "#cfg-recv-limit", ok: numOk(0, 10000000), tip: "invalid_num" },
  { sel: "#cfg-passes", ok: numOk(1, 5), tip: "invalid_range", args: [1, 5] },
  { sel: "#cfg-parity", ok: numOk(1, 8), tip: "invalid_range", args: [1, 8] },
  { sel: "#cfg-update-url", ok: urlOk, tip: "invalid_url" },
  { sel: ".cfg-dir", ok: pathOk, tip: "invalid_path" },
  { sel: ".recv-dir", ok: pathOk, tip: "invalid_path" },
  { sel: ".recv-port", ok: numOk(1, 65535), tip: "invalid_port" },
];

function checkField(el, chk) {
  const good = chk.ok(el.value);
  el.classList.toggle("invalid", !good);
  // ToolTip：非法时给出具体原因；合法/空清除。
  el.title = good ? "" : t(chk.tip).replace("{min}", chk.args ? chk.args[0] : "").replace("{max}", chk.args ? chk.args[1] : "");
}

let revalidateFields = null; // 语言切换后重跑（ToolTip 文案随语言刷新）
function wireValidation() {
  const runs = [];
  for (const chk of FIELD_CHECKS) {
    for (const el of $$(chk.sel)) {
      const run = () => checkField(el, chk);
      el.addEventListener("input", run);
      runs.push(run);
    }
  }
  revalidateFields = () => runs.forEach((run) => run());
  revalidateFields();
}

/* 排除扩展名输入：逗号/分号/空白分隔都接受；后端再做一次归一化（去点/小写/去重）。 */
function parseExts(str) {
  return String(str || "")
    .split(/[,;\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function sendRequest(kindOverride) {
  const proto = $("#send-proto").value;
  const kind = kindOverride || sendKind;
  const srcPort = parseInt($("#send-srcport").value, 10);
  const isText = kind === "text";
  const req = {
    kind: proto === "udp" ? "udpfile" : kind,
    // 只提交当前选中类型的内容：文本页不带文件路径，文件/文件夹页不带文本，
    // 避免切换类型后把上一页残留的字段一起发给后端。
    path: isText ? null : ($("#send-path").value.trim() || null),
    text: isText ? ($("#send-text").value || null) : null,
    ip: $("#send-ip").value.trim(),
    port: parseInt($("#send-port").value, 10),
    proto,
    code: $("#send-code").value.trim() || null,
    limit: parseInt($("#send-limit").value, 10) || null,
    chunks: null,
    srcPort: $("#send-srcport").classList.contains("hidden") || !srcPort ? null : srcPort,
    nocompress: !$("#send-compress").checked,
    noencrypt: !$("#send-encrypt").checked,
    passes: parseInt($("#send-passes").value, 10) || null,
    fecParity: parseInt($("#send-parity").value, 10) || null,
    nofec: $("#send-nofec").checked,
    pin: null,
    // 文件夹/同步发送的排除扩展名。**始终带上**：拖放的目录按 "file" 入队后由后端
    // 自动路由成整夹发送（前端拿不到 is_dir），此处按 kind 过滤会静默丢掉排除项；
    // 纯单文件/文本发送时该字段被后端忽略（只有文件夹 walker 读它）。
    excludeExts: parseExts($("#send-exclude").value),
  };
  // 安全轮 P1-1 缓解：TCP/UDT（C# 方言）+ 配对码 = 未加盐码哈希上线（C# 互锁
  // 协议固有约束，线格式不可改）——按会话一次告警，指引加长配对码或换槽位。
  if ((req.proto === "udt" || req.proto === "tcp") && req.code && !udtCodeWarned) {
    udtCodeWarned = true;
    toast(t("udt_code_warn"), "warn");
    log("warn", t("udt_code_warn"));
  }
  const errs = [];
  // 提交门与红框同口径（仅数字）：红框标非法的字段不再被 parseInt 静默放行。
  // UI-1 P3-10：必填项空值也不再放行——空 IP/端口曾把 NaN 一路送到 invoke
  // 反序列化，用户只看到晦涩错误（红框空值中性是输入期策略，提交期必填）。
  const raw = (sel) => $(sel).value.trim();
  if (raw("#send-ip") === "" || !ipOk(raw("#send-ip"))) errs.push(t("target"));
  if (raw("#send-port") === "" || !numOk(1, 65535)(raw("#send-port"))) errs.push(t("port"));
  if (raw("#send-srcport") !== "" && !numOk(1, 65535)(raw("#send-srcport"))) errs.push(t("port"));
  const code = req.code;
  if (code && !(/^[0-9]{4,12}$/.test(code))) errs.push(t("pairing"));
  if (raw("#send-limit") !== "" && !numOk(0, 10000000)(raw("#send-limit"))) errs.push(t("limit"));
  if (raw("#send-passes") !== "" && !numOk(1, 5)(raw("#send-passes"))) errs.push(t("passes"));
  if (raw("#send-parity") !== "" && !numOk(1, 8)(raw("#send-parity"))) errs.push(t("fec_parity"));
  if (kind !== "text" && !req.path) errs.push(t("path"));
  if (kind === "text" && !req.text) errs.push(t("text"));
  // 轮 7 F8：GUI 补 CLI 同款 UDP 约束（此前给的是晦涩 IO 错误）。
  if (req.proto === "udp" && (kind === "folder" || kind === "text")) errs.push(t("udp_file_only"));
  return { req, errs };
}

/* 发送面板目标记忆（规格 §12.1 ClientIP/ClientPort/ClientProtocol——对齐原版
   跨重启恢复；原版存于关窗，本实现随发送动作落盘更稳——TECH-STACK §7.31）。 */
function persistSendMemory() {
  if (!appState || !appState.config) return;
  appState.config.client_ip = $("#send-ip").value.trim() || null;
  const port = parseInt($("#send-port").value, 10);
  appState.config.client_port = port >= 1 && port <= 65535 ? port : null;
  appState.config.client_proto = $("#send-proto").value;
  appState.config.folder_exclude_exts = parseExts($("#send-exclude").value);
  invoke("save_config", { config: appState.config }).catch(() => { /* 记忆失败不打扰 */ });
}

async function doSend(chunked) {
  const { req, errs } = sendRequest();
  if (errs.length) { toast(errs.join(", "), "err"); return; }
  persistSendMemory();
  try {
    if (chunked) {
      // 提交门：红框已标非法时分块数不再 clamp 静默放行（红框与实际行为一致）。
      const cv = $("#send-chunks").value.trim();
      if (cv !== "" && !numOk(1, 8)(cv)) {
        toast(t("invalid_range").replace("{min}", 1).replace("{max}", 8), "err");
        return;
      }
      req.chunks = Math.min(8, Math.max(1, parseInt(cv, 10) || 4));
      await startTask({ kind: "chunked", req });
    } else if (sendKind === "folder" && $("#folder-mode").value === "sync" && req.proto !== "udp") {
      // 0x04 差量同步：稳定会话 ID，二次只传差异（规格 §3.1/§3.2）。
      await startTask({ kind: "sync", req });
    } else {
      await startTask({ kind: "send", req });
    }
  } catch (e) {
    toast(String(e), "err");
  }
}
$("#btn-send").addEventListener("click", () => doSend(false));
$("#btn-send-chunked").addEventListener("click", () => doSend(true));

/* ============ 队列 ============ */
function renderQueue() {
  const list = $("#queue-list");
  list.textContent = "";
  if (!queueItems.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.dataset.i18n = "queue_empty"; // 挂 data-i18n：语言切换由 applyLang 统一刷新
    li.textContent = t("queue_empty");
    list.appendChild(li);
    return;
  }
  queueItems.forEach((item, i) => {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.className = "grow";
    name.textContent = item.kind === "folder" ? "[D] " + item.path : item.path;
    const x = document.createElement("button");
    x.className = "x";
    x.textContent = "✕";
    x.addEventListener("click", () => { queueItems.splice(i, 1); renderQueue(); });
    li.appendChild(name);
    li.appendChild(x);
    list.appendChild(li);
  });
}
function persistQueue() {
  const items = queueItems.map((q) => q.snap
    ? { kind: q.kind, path: q.path, ip: q.snap.ip, port: q.snap.port, proto: q.snap.proto,
        code: q.snap.code, limit: q.snap.limit, nocompress: q.snap.nocompress, noencrypt: q.snap.noencrypt,
        passes: q.snap.passes, fecParity: q.snap.fecParity, nofec: q.snap.nofec,
        srcPort: q.snap.srcPort || null, excludeExts: q.snap.excludeExts || [] }
    : { kind: q.kind, path: q.path });
  invoke("queue_save", { items }).catch((e) => toast(t("send_fail") + ": " + e, "err"));
}
function queueSnapshot() {
  const sp = parseInt($("#send-srcport").value, 10);
  return {
    ip: $("#send-ip").value.trim(),
    port: parseInt($("#send-port").value, 10),
    proto: $("#send-proto").value,
    code: $("#send-code").value.trim() || null,
    limit: parseInt($("#send-limit").value, 10) || null,
    nocompress: !$("#send-compress").checked,
    noencrypt: !$("#send-encrypt").checked,
    passes: parseInt($("#send-passes").value, 10) || null,
    fecParity: parseInt($("#send-parity").value, 10) || null,
    nofec: $("#send-nofec").checked,
    srcPort: sp >= 1 && sp <= 65535 ? sp : null,
    excludeExts: parseExts($("#send-exclude").value),
  };
}
// 入队即快照面板参数（规格 §3.2「逐项快照面板参数」——入队后改面板
// 不得 retroactively 改变已入队项的行为）。文件与文件夹共用同一条入队路径。
function queueAddPaths(paths, kind) {
  if (!paths) return;
  if (typeof paths === "string") paths = [paths];
  if (!paths.length) return;
  const snap = queueSnapshot();
  const k = kind === "folder" ? "folder" : "file";
  for (const p of paths) {
    if (queueItems.length >= 500) { toast(t("queue_full"), "err"); break; }
    queueItems.push({ kind: k, path: p, snap });
  }
  renderQueue();
  persistQueue();
}
$("#btn-queue-add-files").addEventListener("click", async () => {
  try {
    const files = await T.dialog.open({
      multiple: true,
      directory: false,
      defaultPath: (appState && appState.config && appState.config.last_path) || undefined,
    });
    queueAddPaths(files, "file");
  } catch (e) { toast(String(e), "err"); }
});
$("#btn-queue-add-folder").addEventListener("click", async () => {
  try {
    const dirs = await T.dialog.open({ multiple: true, directory: true });
    queueAddPaths(dirs, "folder");
  } catch (e) { toast(String(e), "err"); }
});
$("#btn-queue-clear").addEventListener("click", () => { queueItems.length = 0; renderQueue(); persistQueue(); });
function queueReqFor(item, sp, target) {
  const kind0 = item.kind === "folder" ? "folder" : "file";
  return {
    kind: sp.proto === "udp" ? "udpfile" : kind0,
    path: item.path, text: null,
    ip: target.ip, port: target.port,
    proto: sp.proto === "udp" ? "udp" : sp.proto,
    code: sp.code, limit: sp.limit,
    chunks: null, nocompress: sp.nocompress, noencrypt: sp.noencrypt,
    passes: sp.passes, fecParity: sp.fecParity, nofec: !!sp.nofec, pin: null,
    srcPort: sp.srcPort || null,
    excludeExts: sp.excludeExts || [],
  };
}

function queueGroupTargets() {
  const lines = $("#group-targets").value.split(String.fromCharCode(10)).map((x) => x.trim()).filter(Boolean);
  if (!lines.length) return null;
  const seen = new Set();
  const out = [];
  for (const tg of lines) {
    const m = parseTarget(tg);
    if (!m || !m.ip || !(m.port >= 1 && m.port <= 65535)) {
      toast(t("group_bad_target") + ": " + tg, "err");
      return null;
    }
    const key = m.ip + ":" + m.port;
    if (!seen.has(key)) { seen.add(key); out.push(m); }
  }
  return out.length ? out : null;
}

async function runQueueSend(btn, group) {
  if (!queueItems.length || btn.disabled) return;
  const targets = group ? queueGroupTargets() : null;
  if (group && !targets) return;
  btn.disabled = true;
  // 逐项按入队快照构造（旧条目无快照时回落当前面板值）；群发时每项再展开到每个目标。
  const cur = queueSnapshot();
  let bad = 0;
  const reqs = [];
  for (const item of queueItems) {
    const sp = item.snap || cur;
    if (!sp.ip || !(sp.port >= 1 && sp.port <= 65535)) { bad += 1; continue; }
    if (targets) {
      for (const t of targets) reqs.push(queueReqFor(item, sp, t));
    } else {
      reqs.push(queueReqFor(item, sp, sp));
    }
  }
  if (bad) toast(t("group_bad_target") + " ×" + bad, "err");
  if (!reqs.length) { btn.disabled = false; return; }
  // 完成后动作执行前确认（规格 §3.2：执行前弹确认；关机/休眠按危险操作呈现）。
  const ad = $("#after-done").value;
  if (ad !== "none") {
    let msg;
    if (ad === "shutdown") msg = t("confirm_shutdown");
    else if (ad === "sleep") msg = t("confirm_sleep");
    else msg = t("confirm_command") + $("#after-command").value + t("confirm_tail");
    if (!(await confirmDialog(msg, { danger: ad === "shutdown" || ad === "sleep" }))) { btn.disabled = false; return; }
  }
  try {
    await invoke("send_queue", {
      items: reqs,
      afterDone: ad === "none" ? null : ad,
      afterCommand: ad === "command" ? $("#after-command").value : null,
    });
    // 启动成功才清队列（轮 7 P3：invoke 失败即丢整个队列）。
    queueItems.length = 0;
    renderQueue();
    persistQueue();
    toast(t("queue_sent"), "ok");
  } catch (e) { toast(String(e), "err"); }
  btn.disabled = false;
}
$("#btn-queue-run").addEventListener("click", () => runQueueSend($("#btn-queue-run"), false));
$("#btn-queue-group-send").addEventListener("click", () => runQueueSend($("#btn-queue-group-send"), true));
/* 群发（规格 §3.2）：并行对每目标起独立客户端，逐目标进度卡 + 汇总 {ok}/{total} */
function parseTarget(s2) {
  s2 = s2.trim();
  if (s2.startsWith("[")) {
    const i = s2.indexOf("]");
    if (i < 0) return null;
    const ip = s2.slice(1, i);
    const rest = s2.slice(i + 1);
    if (!rest.startsWith(":")) return null;
    return { ip, port: parseInt(rest.slice(1), 10) };
  }
  const i = s2.lastIndexOf(":");
  if (i <= 0) return null;
  return { ip: s2.slice(0, i), port: parseInt(s2.slice(i + 1), 10) };
}

$("#btn-group-send").addEventListener("click", async () => {
  const btn = $("#btn-group-send");
  if (btn.disabled) return; // UI-1 P3-3：发起期间禁用（防两批计数器交错）
  const lines = $("#group-targets").value.split(String.fromCharCode(10)).map((x) => x.trim()).filter(Boolean);
  const targets = [...new Set(lines)];
  if (!targets.length) return;
  const base = sendRequest();
  if (base.errs.length) { toast(base.errs.join(", "), "err"); return; }
  btn.disabled = true;
  groupLaunching = true;
  let launched = 0;
  groupTotal = 0; groupOk = 0; groupFail = 0;
  groupPending.clear(); // 轮 7 P2：残留 id 会让本批及之后所有汇总失效
  for (const tg of targets) {
    const m = parseTarget(tg);
    if (!m || !m.ip || !(m.port >= 1 && m.port <= 65535)) { toast(t("group_bad_target") + ": " + tg, "err"); continue; }
    const req = JSON.parse(JSON.stringify(base.req));
    req.ip = m.ip;
    req.port = m.port;
    try {
      const id = await startTask({ kind: "send", req });
      groupPending.set(id, true);
      groupTotal += 1;
      launched += 1;
      // UI-1 P2-4：瞬时任务终态可能先于 invoke 返回——注册后凭 taskTerminalSeen
      // 补收敛，否则该槽位永悬挂、汇总永不出现。
      const term = taskTerminalSeen.get(id);
      if (term) groupSettle(id, term.ok, term.paused);
    } catch (e) { toast(String(e), "err"); }
  }
  groupLaunching = false;
  if (!launched) groupTotal = 0;
  groupMaybeSummary(); // launching 门控期间被压下的汇总在此补判（UI-4 P3-3）
  btn.disabled = false;
});

$("#after-done").addEventListener("change", () => {
  $("#after-command").classList.toggle("hidden", $("#after-done").value !== "command");
});

/* ============ 设备（发现 + 记忆，规格 §3.3） ============ */
let onlineIps = new Set();

function renderDevices(devices) {
  const list = $("#devices-list");
  list.textContent = "";
  if (!devices.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.dataset.i18n = "none";
    li.textContent = t("none");
    list.appendChild(li);
    return;
  }
  devices.forEach((d) => {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = d.name + "  ";
    const ipTag = document.createElement("span");
    ipTag.className = "mono";
    ipTag.style.fontSize = "12px";
    ipTag.textContent = d.ip + ":" + d.port;
    li.appendChild(name);
    li.appendChild(ipTag);
    const proto = document.createElement("span");
    proto.className = "tag";
    proto.textContent = d.proto.toUpperCase();
    li.appendChild(proto);
    if (onlineIps.has(d.ip)) {
      const on = document.createElement("span");
      on.className = "tag online";
      on.textContent = t("online");
      li.appendChild(on);
    }
    if (d.needs_pairing) {
      const pair = document.createElement("span");
      pair.className = "tag pair";
      pair.textContent = t("pairing");
      li.appendChild(pair);
    }
    const use = document.createElement("button");
    use.className = "btn small";
    use.textContent = t("use");
    use.addEventListener("click", () => {
      $("#send-ip").value = d.ip;
      $("#send-port").value = d.port;
      // 流式协议记忆名直填（"tcp"/"quic"/"udt" 与发送下拉值一致）；udp 单发无此语义。
      if (["tcp", "quic", "rudp", "udt"].includes(d.proto)) $("#send-proto").value = d.proto;
    });
    const toGroup = document.createElement("button");
    toGroup.className = "btn small";
    toGroup.textContent = t("to_group");
    toGroup.addEventListener("click", () => {
      $("#group-targets").value = ($("#group-targets").value.trim() + String.fromCharCode(10) + d.ip + ":" + d.port).trim();
    });
    const del = document.createElement("button");
    del.className = "x";
    del.textContent = "✕";
    del.addEventListener("click", async () => {
      try { await invoke("devices_remove", { ip: d.ip }); await reloadDevices(); } catch (e) { toast(String(e), "err"); }
    });
    li.appendChild(use);
    li.appendChild(toGroup);
    li.appendChild(del);
    list.appendChild(li);
  });
}

async function reloadDevices() {
  try {
    const devices = await invoke("devices_load");
    knownDevices = devices || [];
    renderDevices(devices);
  } catch (e) { /* 忽略 */ }
}

$("#btn-discover").addEventListener("click", async () => {
  const btn = $("#btn-discover");
  btn.disabled = true;
  btn.textContent = t("discovering");
  try {
    const found = await invoke("discover_devices");
    onlineIps = new Set(found.map((d) => d.ip));
    await reloadDevices();
    toast(t("devices") + ": " + found.length, "ok");
  } catch (e) { toast(String(e), "err"); }
  btn.disabled = false;
  btn.textContent = t("discover");
});

$("#btn-devices-clear").addEventListener("click", async () => {
  try {
    await invoke("devices_clear");
    onlineIps = new Set();
    await reloadDevices();
  } catch (e) { toast(String(e), "err"); }
});

/* ============ 进度卡片 ============ */
function fmtEta(sec) {
  if (!isFinite(sec) || sec <= 0) return "";
  if (sec >= 3600) {
    // 规格 §6.2：超过 1 小时以 h:mm:ss 显示。
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = Math.floor(sec % 60);
    return h + ":" + String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
  }
  const m = Math.floor(sec / 60);
  const s = Math.floor(sec % 60);
  return m > 0 ? m + "m" + String(s).padStart(2, "0") + "s" : s + "s";
}

function ensureCard(ev) {
  let card = tasks.get(ev.id);
  if (!card) {
    const el = document.createElement("div");
    el.className = "pcard";
    const head = document.createElement("div");
    head.className = "phead";
    const name = document.createElement("span");
    name.className = "pname";
    name.textContent = (ev.kind === "send" ? "↑ " : "↓ ") + ev.name;
    const state = document.createElement("span");
    state.className = "pstate running";
    state.textContent = t("st_running");
    const meta = document.createElement("span");
    meta.className = "pmeta";
    head.appendChild(name);
    head.appendChild(state);
    head.appendChild(meta);
    const bar = document.createElement("progress");
    bar.max = 1;
    bar.value = 0;
    el.appendChild(head);
    el.appendChild(bar);
    $("#progress-list").prepend(el);
    // counted：activeTransfers 的 +1/-1 配对标志（UI-1 P1-1——建卡只加一次，
    // 暂停终态/取消/完成等多条扣减路径凭它去重，防语言锁被提前解除）。
    card = { el, name, state, meta, bar, kind: ev.kind, base: ev.name, lastT: performance.now(), lastDone: 0, speed: 0, counted: true };
    tasks.set(ev.id, card);
    activeTransfers += 1;
    updateLangLock();
    attachCardButtons(ev.id, card);
  }
  return card;
}

/* 计数扣减唯一入口：只对未扣过的卡扣一次（P1-1 修复） */
function releaseCard(card) {
  if (!card.counted) return;
  card.counted = false;
  activeTransfers = Math.max(0, activeTransfers - 1);
  updateLangLock();
}

/* 暂停/继续/取消（规格 §3.2：取消型暂停——暂停即断，继续按 0x03/0x04 服务端会话续传） */
function attachCardButtons(progressId, card) {
  if (card.kind !== "send") return;
  const taskId = taskByProgress.get(progressId);
  // UI-1 P2-5：不再以 reqByTask.has 为前置（task-start 事件可能先于 invoke 返回，
  // 否则按钮永不出现）；已终态的任务不再挂按钮。resume 点击时再实时取 entry。
  if (!taskId || taskTerminalSeen.has(taskId)) return;
  const head = card.el.querySelector(".phead");
  let btns = head.querySelector(".pbtns");
  if (btns) return;
  btns = document.createElement("span");
  btns.className = "pbtns";
  const mk = (txt, fn) => {
    const b = document.createElement("button");
    b.className = "btn small";
    b.textContent = txt;
    b.addEventListener("click", fn);
    return b;
  };
  const pauseBtn = mk(pausedTasks.has(taskId) ? t("resume") : t("pause"), async () => {
    if (!pausedTasks.has(taskId)) {
      // 轮 7 F1：先置位再 invoke——send_cancel 的终态事件可能先于 invoke
      // 返回到达，置位晚了会被事件处理器当取消清理干净（暂停自毁回归）。
      pausedTasks.add(taskId);
      card.state.textContent = t("paused");
      card.state.className = "pstate failed";
      pauseBtn.textContent = t("resume");
      // UI-1 P2-3：invoke 失败回滚「已暂停」假象（传输实际仍在跑）。
      try {
        await invoke("send_cancel", { id: taskId, paused: true });
      } catch (e) {
        pausedTasks.delete(taskId);
        card.state.textContent = t("st_running");
        card.state.className = "pstate running";
        pauseBtn.textContent = t("pause");
        toast(String(e), "err");
      }
    } else {
      const entry = reqByTask.get(taskId);
      // UI-4 P3-4：队列子任务卡片（Rust 侧发起，无 reqByTask 条目）——
      // 「继续」此前静默无效；明确提示改用队列重跑。
      if (!entry) { toast(t("resume_unavailable"), "warn"); return; }
      // UI-1 P2-1：先起任务成功再拆旧卡——起不动时暂停卡保留，续传入口不丢。
      try {
        pausedTasks.delete(taskId);
        await startTask(entry);
      } catch (e) {
        pausedTasks.add(taskId);
        toast(String(e), "err");
        return;
      }
      btns.remove();
      card.el.remove();
      tasks.delete(progressId);
    }
  });
  const cancelBtn = mk(t("cancel_task"), async () => {
    // UI-1 P2-2：取消失败也要走本地清理（否则残留 pausedTasks 会误吞后续终态）。
    try {
      await invoke("send_cancel", { id: taskId });
    } catch (e) { toast(String(e), "err"); }
    cancelledProgress.add(progressId);
    setTimeout(() => cancelledProgress.delete(progressId), 10000);
    reqByTask.delete(taskId);
    pausedTasks.delete(taskId);
    taskByProgress.delete(progressId);
    card.el.remove();
    tasks.delete(progressId);
    releaseCard(card);
  });
  btns.appendChild(pauseBtn);
  btns.appendChild(cancelBtn);
  head.appendChild(btns);
}



/* 统一发起：记录 req 供继续使用 */
async function startTask(entry) {
  const { kind, req } = entry;
  let id;
  if (kind === "sync") {
    id = await invoke("sync_start", {
      folder: req.path, ip: req.ip, port: req.port, proto: req.proto,
      code: req.code, limit: req.limit, nocompress: req.nocompress,
      srcPort: req.srcPort || null,
      excludeExts: req.excludeExts || [],
    });
  } else if (kind === "chunked") {
    id = await invoke("send_chunked_start", { req });
  } else {
    id = await invoke("send_start", { req });
  }
  reqByTask.set(id, entry);
  // UI-1 P2-5：invoke 返回时 task-start 事件可能已到（按钮已挂好）；若卡片
  // 已存在且按钮未挂（乱序窗口错过 attachCardButtons），此处补挂一次。
  for (const [pid, tid] of taskByProgress) {
    if (tid === id) {
      const card = tasks.get(pid);
      if (card) attachCardButtons(pid, card);
    }
  }
  return id;
}

let cancelledProgress = new Set(); // 取消任务的进度 ID（迟到的终态事件直接忽略）
function onProgress(ev) {
  if (cancelledProgress.has(ev.id) && !tasks.has(ev.id)) {
    return; // 轮 7 P3：取消后迟到的终态事件不得重建幽灵卡
  }
  const card = ensureCard(ev);
  // 对端徽标（对齐原版 v2.15 DeviceDisplay.NameFor，A5 收发全量）：core 事件
  // 携带 peer（发送=目标 IP，接收=来源 IP）——命中已知设备显示记忆名，未知回落 IP。
  if (ev.peer) {
    const dev = knownDevices.find((d) => d.ip === ev.peer);
    const label = dev && dev.name ? dev.name : ev.peer;
    const want = (ev.kind === "send" ? "↑ " : "↓ ") + card.base + " → " + label;
    if (card.name.textContent !== want) card.name.textContent = want;
  }
  const frac = ev.total > 0 ? Math.min(1, ev.done / ev.total) : 0;
  card.bar.value = frac;
  // 速度（指数滑动）+ ETA（客户端按事件增量估算，core 只报字节）。
  const now = performance.now();
  const dt = (now - card.lastT) / 1000;
  if (dt > 0.05 && ev.done >= card.lastDone) {
    const inst = (ev.done - card.lastDone) / dt;
    card.speed = card.speed ? card.speed * 0.7 + inst * 0.3 : inst;
    card.lastT = now;
    card.lastDone = ev.done;
  }
  let meta = fmtBytes(ev.done) + (ev.total > 0 ? " / " + fmtBytes(ev.total) : "");
  if (card.speed > 0) meta += "  " + fmtBytes(card.speed) + "/s";
  if (ev.total > 0 && card.speed > 0 && ev.state === "running") meta += "  ETA " + fmtEta((ev.total - ev.done) / card.speed);
  card.meta.textContent = meta;
  if (ev.state !== "running") {
    // 暂停语义（轮 7 P2）：暂停 = abort → Outcome Drop 发 failed——
    // 该「失败」不得覆盖「已暂停」/清卡（否则继续按钮 6 秒后不可达）。
    const pausedOwner = taskByProgress.get(ev.id);
    if (ev.state === "failed" && pausedOwner && pausedTasks.has(pausedOwner)) {
      releaseCard(card); // UI-1 P1-1：计数扣减经 counted 标志去重
      return;
    }
    card.state.textContent = ev.state === "done" ? t("st_done") : t("st_failed");
    card.state.className = "pstate " + ev.state;
    card.el.classList.toggle("done", ev.state === "done");
    card.el.classList.toggle("failed", ev.state !== "done");
    if (ev.state === "done") beep();
    if (ev.kind === "recv" && ev.state === "done") addRecent(ev.name, ev.total);
    releaseCard(card); // UI-1 P1-1：计数扣减经 counted 标志去重
    setTimeout(() => { card.el.remove(); tasks.delete(ev.id); }, 6000);
  }
}

function updateLangLock() {
  const lock = activeTransfers > 0;
  $("#lang-zh").disabled = lock;
  $("#lang-en").disabled = lock;
}

/* ============ 接收 ============ */
function renderReceivers() {
  const running = new Map(appState.receivers.map((r) => [r.proto, r]));
  $$(".recv-card").forEach((card) => {
    const proto = card.dataset.proto;
    const r = running.get(proto);
    $("#dot-" + proto).classList.toggle("on", !!r);
    card.querySelector(".recv-port").value = r ? r.port : card.querySelector(".recv-port").value;
    card.querySelector(".recv-start").disabled = !!r;
    card.querySelector(".recv-stop").disabled = !r;
    // 运行中冻结该页的端口/目录/绑定下拉；其他协议页随时可改（规格 §3.3）。
    card.querySelector(".recv-port").disabled = !!r;
    card.querySelector(".recv-dir").disabled = !!r;
    card.querySelector(".recv-browse").disabled = !!r;
    card.querySelector(".dd-toggle").disabled = !!r;
    let hint = card.querySelector(".bound-hint");
    if (!hint) {
      hint = document.createElement("span");
      hint.className = "bound-hint";
      card.querySelector(".card-title").appendChild(hint);
    }
    hint.textContent = r ? r.bound.join("  ") : "";
  });
}

/* 绑定地址下拉多选（规格 §3.3）：族通配默认勾选 + 各网卡 IPv4。
   收起态显示已选摘要，点开浮层勾选；点组件外关闭。
   注：Windows 允许通配+具体网卡同端口共存（更具体的绑定优先接收）；
   Linux 上冲突则由逐地址失败上报呈现，不做 UI 互斥。 */
function ddLabelFor(sel) {
  if (!sel.length) return t("dd_placeholder");
  const named = sel.map((v) =>
    v === "0.0.0.0" ? t("wildcard_v4") : v === "::" ? t("wildcard_v6") : v
  );
  return named.length <= 2 ? named.join(", ") : named[0] + " +" + (named.length - 1);
}

function renderAddrDropdowns() {
  $$(".dd[data-addr-proto]").forEach((dd) => {
    const panel = dd.querySelector(".dd-panel");
    const label = dd.querySelector(".dd-label");
    // 重渲染（语言切换/地址刷新）时保留已选。
    const prev = new Set([...panel.querySelectorAll("input:checked")].map((x) => x.value));
    panel.textContent = "";
    // 绑定候选（对齐原版）：双族通配 + 全部 IPv4/可用 IPv6 网卡地址（bindAddresses）；
    // addresses 仅 IPv4——二维码面向手机浏览器，不混入 v6。
    const items = [
      ["0.0.0.0", t("wildcard_v4")],
      ["::", t("wildcard_v6")],
    ].concat((appState.bindAddresses || appState.addresses || []).map((a) => [a, a]));
    items.forEach(([val, text]) => {
      const lb = document.createElement("label");
      lb.className = "chk";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = val;
      // 用户已交互过（dirty）就以旧选中集为准——允许「全不勾」跨重渲染存续；
      // 否则首渲染默认通配 v4（原逻辑：prev 为空即重置 0.0.0.0，取消全部后
      // 语言切换会静默回勾，违背用户意图）。
      cb.checked = dd.dataset.dirty ? prev.has(val) : (prev.size ? prev.has(val) : val === "0.0.0.0");
      cb.addEventListener("change", () => {
        dd.dataset.dirty = "1";
        label.textContent = ddLabelFor([...panel.querySelectorAll("input:checked")].map((x) => x.value));
      });
      lb.appendChild(cb);
      lb.appendChild(document.createTextNode(" " + text));
      panel.appendChild(lb);
    });
    label.textContent = ddLabelFor([...panel.querySelectorAll("input:checked")].map((x) => x.value));

    if (!dd.dataset.toggleWired) {
      dd.dataset.toggleWired = "1";
      dd.querySelector(".dd-toggle").addEventListener("click", (e) => {
        e.stopPropagation();
        const p = dd.querySelector(".dd-panel");
        const opening = p.classList.contains("hidden");
        $$(".dd-panel").forEach((x) => x.classList.add("hidden"));
        if (opening) p.classList.remove("hidden");
      });
    }
  });
}

document.addEventListener("click", () => {
  $$(".dd-panel").forEach((x) => x.classList.add("hidden"));
});

function checkedAddrs(proto) {
  const dd = document.querySelector('.dd[data-addr-proto="' + proto + '"]');
  return [...dd.querySelectorAll(".dd-panel input:checked")].map((x) => x.value);
}

$$(".recv-card").forEach((card) => {
  const proto = card.dataset.proto;
  card.querySelector(".recv-start").addEventListener("click", async () => {
    const addrs = checkedAddrs(proto);
    if (!addrs.length) { toast(t("no_addr_selected"), "err"); return; }
    // UI-1 P3-3：await 期间防连点（双 invoke 双监听）。
    const btn = card.querySelector(".recv-start");
    if (btn.disabled) return;
    btn.disabled = true;
    try {
      const res = await invoke("recv_start", {
        proto,
        port: parseInt(card.querySelector(".recv-port").value, 10),
        saveDir: card.querySelector(".recv-dir").value.trim() || null,
        addrs,
      });
      appState.receivers.push({ proto, port: res.port, bound: res.bound });
      (res.failed || []).forEach((f) => toast(t("partial_bind") + ": " + f.addr + " — " + f.error, "err"));
      renderReceivers();
    } catch (e) {
      toast(String(e), "err");
      renderReceivers(); // 失败复位按钮
    }
  });
  card.querySelector(".recv-stop").addEventListener("click", async () => {
    try {
      await invoke("recv_stop", { proto });
      appState.receivers = appState.receivers.filter((r) => r.proto !== proto);
      renderReceivers();
    } catch (e) { toast(String(e), "err"); }
  });
  card.querySelector(".recv-open").addEventListener("click", () => {
    const dir = card.querySelector(".recv-dir").value.trim();
    if (dir) invoke("open_path", { path: dir });
  });
  card.querySelector(".recv-browse").addEventListener("click", async () => {
    const d = await T.dialog.open({ multiple: false, directory: true });
    if (d) {
      const recv = card.querySelector(".recv-dir");
      recv.value = d;
      // 程序赋值不触发 input——手动派发，让设置页/内存配置同步。
      recv.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });
});

function renderTextHistory(items) {
  const list = $("#text-history");
  list.textContent = "";
  if (!items.length) {
    const li = document.createElement("li");
    li.className = "empty";
    li.dataset.i18n = "th_empty";
    li.textContent = t("th_empty");
    list.appendChild(li);
    return;
  }
  items.forEach((it) => {
    const li = document.createElement("li");
    const time = document.createElement("span");
    time.className = "pmeta";
    const d = new Date(Number(it.time) * 1000);
    time.textContent = d.toLocaleTimeString();
    const txt = document.createElement("span");
    txt.className = "grow";
    txt.textContent = it.text.length > 120 ? it.text.slice(0, 120) + "…" : it.text;
    li.appendChild(time);
    li.appendChild(txt);
    // 点一条看全文（轮 10）：复用接收弹窗，带历史时间与截断标记。
    li.title = t("text_view_full");
    li.addEventListener("click", () => {
      showTextModal(it.text, "", {
        at: d.toLocaleTimeString(),
        history: true,
        truncated: !!it.truncated,
      });
    });
    list.appendChild(li);
  });
}

function addRecent(name, size) {
  const list = $("#recent-list");
  const empty = list.querySelector(".empty");
  if (empty) empty.remove();
  const li = document.createElement("li");
  const n = document.createElement("span");
  n.className = "grow";
  n.textContent = name;
  const s = document.createElement("span");
  s.className = "pmeta";
  s.textContent = fmtBytes(size) + "  " + new Date().toLocaleTimeString();
  li.appendChild(n);
  li.appendChild(s);
  list.prepend(li);
  while (list.children.length > 100) list.lastChild.remove();
}

/* ============ 共享 + 二维码 ============ */
function renderAddressOptions() {
  const sel = $("#qr-address");
  sel.textContent = "";
  (appState.addresses || []).forEach((a) => {
    const opt = document.createElement("option");
    opt.value = a;
    opt.textContent = a;
    sel.appendChild(opt);
  });
}

function currentShareUrl() {
  if (!httpInfo) return "";
  const addr = $("#qr-address").value || "127.0.0.1";
  const base = "http://" + addr + ":" + httpInfo.port + "/";
  return httpInfo.token ? base + "?t=" + httpInfo.token : base;
}

async function refreshQr() {
  const url = currentShareUrl();
  $("#share-url").value = url;
  const box = $("#qr-box");
  if (!url) {
    box.textContent = "";
    const hint = document.createElement("div");
    hint.className = "qr-empty";
    hint.textContent = t("http_off");
    box.appendChild(hint);
    return;
  }
  try {
    const svg = await invoke("qr_svg", { text: url });
    box.innerHTML = svg;
  } catch (e) {
    box.textContent = String(e);
  }
}

$("#qr-address").addEventListener("change", async () => {
  // 规格 §12.1 QrAddress：选择记忆。
  appState.config.qr_address = $("#qr-address").value;
  try { await invoke("save_config", { config: appState.config }); } catch (e) { /* 下次仍可选 */ }
  refreshQr();
});
$("#btn-copy-url").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#share-url").value);
    toast(t("copied"), "ok");
  } catch (e) { toast(t("copy_fail") + ": " + e, "err"); }
});

$("#btn-http-start").addEventListener("click", async () => {
  try {
    const port = parseInt($("#http-port").value, 10);
    const dir = appState.config[$("#share-dir-sel").value];
    httpInfo = await invoke("http_start", { port, dir });
    $("#share-dir-line").textContent = httpInfo.dir;
    appState.httpRunning = true;
    refreshQr();
  } catch (e) { toast(String(e), "err"); }
});
$("#btn-http-stop").addEventListener("click", async () => {
  try {
    await invoke("http_stop");
    httpInfo = null;
    appState.httpRunning = false;
    refreshQr();
  } catch (e) { toast(String(e), "err"); }
});

/* ============ 校验 ============ */
$("#btn-verify-start").addEventListener("click", async () => {
  try {
    await invoke("verify_start");
  } catch (e) { toast(String(e), "err"); }
});
$("#btn-verify-stop").addEventListener("click", () => invoke("verify_stop"));

/* ============ 校验定时 / 周期 ============ */
// 调度是 GUI 侧的轻量定时器（不依赖后端）：配置随 localStorage 持久化，
// 应用运行（含隐藏到托盘）期间按到期时间触发 verify_start；应用退出后
// 下次启动会补跑已到期的定时项。
const VERIFY_ONCE_KEY = "trft-verify-once-at";
const VERIFY_PERIOD_KEY = "trft-verify-period-min";
const VERIFY_LAST_KEY = "trft-verify-last-run";
let verifyScheduleTimer = null;
let verifyScheduleWired = false;

function readVerifySchedule() {
  const num = (k) => {
    const v = parseInt(localStorage.getItem(k) || "0", 10);
    return isFinite(v) && v > 0 ? v : 0;
  };
  return { once: num(VERIFY_ONCE_KEY), period: num(VERIFY_PERIOD_KEY), last: num(VERIFY_LAST_KEY) };
}
function writeVerifySchedule(s) {
  const put = (k, v) => { if (v > 0) localStorage.setItem(k, String(v)); else localStorage.removeItem(k); };
  put(VERIFY_ONCE_KEY, s.once || 0);
  put(VERIFY_PERIOD_KEY, s.period || 0);
  put(VERIFY_LAST_KEY, s.last || 0);
}
function verifyPad2(n) { return String(n).padStart(2, "0"); }
function toLocalInput(ms) {
  const d = new Date(ms);
  return d.getFullYear() + "-" + verifyPad2(d.getMonth() + 1) + "-" + verifyPad2(d.getDate())
    + "T" + verifyPad2(d.getHours()) + ":" + verifyPad2(d.getMinutes());
}
function formatVerifyTime(ms) { return new Date(ms).toLocaleString(); }
function nextVerifyDue(now) {
  now = now || Date.now();
  const s = readVerifySchedule();
  let due = 0;
  if (s.once > 0) due = s.once;
  if (s.period > 0) {
    // 首次周期从当前时刻起算；之后以最近一次自动运行为锚点。
    let p = s.last > 0 ? s.last + s.period * 60000 : now + s.period * 60000;
    if (p <= now) p = now + 1000; // 错过的周期只补跑一次，不连续追补
    due = due > 0 ? Math.min(due, p) : p;
  }
  return due;
}
function renderVerifyNext() {
  const el = $("#verify-next");
  if (!el) return;
  const due = nextVerifyDue();
  el.textContent = due > 0 ? t("verify_next").replace("{time}", formatVerifyTime(due)) : t("verify_next_none");
}
function syncVerifyScheduleUi(loadInputs) {
  const s = readVerifySchedule();
  const onceChk = $("#verify-once-enable"), onceAt = $("#verify-once-at");
  const pChk = $("#verify-period-enable"), pVal = $("#verify-period-value"), pUnit = $("#verify-period-unit");
  if (!onceChk || !onceAt || !pChk || !pVal || !pUnit) return;
  onceChk.checked = s.once > 0;
  if (!s.once) onceAt.value = "";
  if (loadInputs) {
    if (s.once > 0) onceAt.value = toLocalInput(s.once);
    pChk.checked = s.period > 0;
    if (s.period > 0) {
      if (s.period % 1440 === 0) { pVal.value = s.period / 1440; pUnit.value = "day"; }
      else if (s.period % 60 === 0) { pVal.value = s.period / 60; pUnit.value = "hour"; }
      else { pVal.value = s.period; pUnit.value = "minute"; }
    } else {
      pVal.value = 1;
      pUnit.value = "hour";
    }
  }
  if (!s.period) pChk.checked = false;
  renderVerifyNext();
}
async function runScheduledVerify() {
  const s = readVerifySchedule();
  const now = Date.now();
  const onceDue = s.once > 0 && s.once <= now;
  const periodDue = s.period > 0 && s.last > 0 && s.last + s.period * 60000 <= now;
  // 只有周期项确实到期（或首次启用）才重置周期锚点；一次性的运行不应推迟
  // 尚未到期的周期校验。
  const resetPeriod = periodDue || (s.period > 0 && s.last === 0);
  if (!onceDue && !periodDue) return "none";
  try {
    await invoke("verify_start");
    const cur = readVerifySchedule();
    if (onceDue) cur.once = 0;
    if (resetPeriod) cur.last = now;
    writeVerifySchedule(cur);
    renderVerifyNext();
    toast(t("verify_scheduled_start"), "ok");
    return "started";
  } catch (e) {
    const msg = String(e);
    if (msg.indexOf("进行中") >= 0 || msg.toLowerCase().indexOf("running") >= 0) {
      toast(t("verify_busy"), "warn");
      return "busy"; // 保留到期项，60s 后重试
    }
    const cur = readVerifySchedule();
    if (onceDue) cur.once = 0;
    if (resetPeriod) cur.last = now; // 周期项失败后等下一个周期，避免紧循环
    writeVerifySchedule(cur);
    renderVerifyNext();
    toast(t("verify_schedule_failed") + ": " + msg, "err");
    return "failed";
  }
}
function scheduleVerifyTimer() {
  if (verifyScheduleTimer) { clearTimeout(verifyScheduleTimer); verifyScheduleTimer = null; }
  renderVerifyNext();
  const due = nextVerifyDue();
  if (!due) return;
  const delay = Math.max(0, Math.min(due - Date.now(), 2147483647));
  verifyScheduleTimer = setTimeout(async () => {
    verifyScheduleTimer = null;
    const result = await runScheduledVerify();
    if (result === "busy") {
      verifyScheduleTimer = setTimeout(scheduleVerifyTimer, 60000);
      return;
    }
    syncVerifyScheduleUi(false);
    scheduleVerifyTimer();
  }, delay);
}
function saveVerifyOnce() {
  const chk = $("#verify-once-enable");
  const at = $("#verify-once-at");
  const s = readVerifySchedule();
  if (!chk.checked) {
    s.once = 0;
    writeVerifySchedule(s);
    renderVerifyNext();
    scheduleVerifyTimer();
    return;
  }
  let ms = at.value ? new Date(at.value).getTime() : 0;
  if (!ms || isNaN(ms)) {
    // 勾选但未选时间：默认一小时后，避免“勾了却静默不生效”。
    ms = Date.now() + 3600000;
    at.value = toLocalInput(ms);
  }
  s.once = ms;
  writeVerifySchedule(s);
  renderVerifyNext();
  scheduleVerifyTimer();
}
function saveVerifyPeriod() {
  const chk = $("#verify-period-enable");
  const s = readVerifySchedule();
  if (!chk.checked) {
    s.period = 0;
    s.last = 0;
    writeVerifySchedule(s);
    renderVerifyNext();
    scheduleVerifyTimer();
    return;
  }
  const v = parseInt($("#verify-period-value").value, 10);
  const unit = $("#verify-period-unit").value;
  const factor = unit === "day" ? 1440 : unit === "hour" ? 60 : 1;
  if (!v || v < 1) {
    toast(t("verify_period_invalid"), "err");
    chk.checked = false;
    s.period = 0;
    s.last = 0;
    writeVerifySchedule(s);
    renderVerifyNext();
    scheduleVerifyTimer();
    return;
  }
  let minutes = v * factor;
  if (minutes > 525600) minutes = 525600; // 上限一年
  s.period = minutes;
  s.last = 0; // 修改周期后重新计时
  writeVerifySchedule(s);
  renderVerifyNext();
  scheduleVerifyTimer();
}
function initVerifySchedule() {
  if (verifyScheduleWired) return;
  verifyScheduleWired = true;
  syncVerifyScheduleUi(true);
  $("#verify-once-enable").addEventListener("change", saveVerifyOnce);
  $("#verify-once-at").addEventListener("change", () => { if ($("#verify-once-enable").checked) saveVerifyOnce(); });
  $("#verify-period-enable").addEventListener("change", saveVerifyPeriod);
  $("#verify-period-value").addEventListener("change", () => { if ($("#verify-period-enable").checked) saveVerifyPeriod(); });
  $("#verify-period-unit").addEventListener("change", () => { if ($("#verify-period-enable").checked) saveVerifyPeriod(); });
  scheduleVerifyTimer();
}

/* ============ 设置 ============ */
function fillShareDirOptions() {
  const sel = $("#share-dir-sel");
  sel.textContent = "";
  [["save_dir_tcp", "TCP"], ["save_dir_quic", "QUIC"], ["save_dir_rudp", "RUDP"], ["save_dir_udt", "UDT"], ["save_dir_udp", "UDP"]].forEach(([k, label]) => {
    const opt = document.createElement("option");
    opt.value = k;
    opt.textContent = label + " — " + (appState.config[k] || "");
    sel.appendChild(opt);
  });
}

const SAVE_DIR_KEYS = {
  tcp: "save_dir_tcp", quic: "save_dir_quic", rudp: "save_dir_rudp", udt: "save_dir_udt", udp: "save_dir_udp",
};

function fillSettings() {
  const c = appState.config;
  $("#cfg-code").value = c.pairing_code || "";
  $("#cfg-pairing-len").value = c.pairing_length || 6;
  $("#cfg-notify").checked = !!c.notify_enabled;
  $$(".cfg-dir").forEach((inp) => { inp.value = c[inp.dataset.key] || ""; });
  $("#cfg-sync-strict").checked = !!c.sync_verify_content;
  $("#cfg-filter-mode").value = (c.ip_filter_mode || "Off").toLowerCase();
  $("#cfg-filter-list").value = (c.ip_filter_list || []).join(String.fromCharCode(10));
  $("#cfg-notify-sound").checked = c.notify_sound !== false;
  $("#cfg-duplicate").value = c.duplicate_files === "Skip" ? "skip" : "rename";
  $("#cfg-cache-days").value = c.hash_cache_days;
  $("#monitor-exclude").value = (c.monitor_exclude_exts || []).join(", ");
  $("#send-exclude").value = (c.folder_exclude_exts || []).join(", ");
  $("#cfg-confirm").value = (c.confirm_receive || "Off").toLowerCase();
  $("#cfg-per-device").checked = !!c.per_device_folder;
  $("#cfg-archive").checked = !!c.auto_archive;
  $("#cfg-limit").value = c.speed_limit || 0;
  $("#cfg-recv-limit").value = c.recv_speed_limit || 0;
  $("#cfg-passes").value = c.udp_passes;
  $("#cfg-fec").checked = !!c.udp_fec;
  $("#cfg-parity").value = c.udp_fec_parity;
  $("#cfg-update-url").value = c.update_url || "";
  $("#cfg-auto-update").checked = c.auto_update_check !== false;
  $("#http-port").value = c.http_port;
  $("#version-line").textContent = "v" + appState.version;
  $$(".recv-card").forEach((card) => {
    const key = SAVE_DIR_KEYS[card.dataset.proto];
    card.querySelector(".recv-dir").value = c[key] || "";
    card.querySelector(".recv-port").value = {
      tcp: c.server_port_tcp, quic: c.server_port_quic, rudp: c.server_port_rudp, udt: c.server_port_udt, udp: c.server_port_udp,
    }[card.dataset.proto];
  });
}

/* 接收卡片与设置页共用同一组 save_dir_*：一处编辑，另一处立即跟随；
   启动接收器时 commands.rs 会把卡片值写回配置（持久化默认目录）。 */
$$(".recv-card").forEach((card) => {
  const key = SAVE_DIR_KEYS[card.dataset.proto];
  const input = card.querySelector(".recv-dir");
  if (!key || !input) return;
  input.addEventListener("input", () => {
    if (appState && appState.config) appState.config[key] = input.value.trim();
    const cfg = document.querySelector('.cfg-dir[data-key="' + key + '"]');
    if (cfg) cfg.value = input.value;
  });
});
$$(".cfg-dir").forEach((input) => {
  input.addEventListener("input", () => {
    if (appState && appState.config) appState.config[input.dataset.key] = input.value.trim();
    const proto = (input.dataset.key || "").replace("save_dir_", "");
    const card = document.querySelector('.recv-card[data-proto="' + proto + '"]');
    if (card) {
      const recv = card.querySelector(".recv-dir");
      if (recv) recv.value = input.value;
    }
  });
});

async function saveSettings() {
  // 提交门：红框字段不再放行（与发送面板同口径）。
  // UI-1 P2-7：此前只拦配对码位数——update_url/cache_days/parity 等红框
  // 字段被 parseInt||默认 静默改写或直接入库，红框与实际落库值不一致。
  const bad = $$("#pane-settings input.invalid, #pane-settings textarea.invalid, #http-port.invalid");
  if (bad.length) {
    toast((bad[0].title || t("save_fail")), "err");
    return;
  }
  const c = JSON.parse(JSON.stringify(appState.config));
  const code = $("#cfg-code").value.trim();
  c.pairing_code = code || null;
  c.pairing_length = parseInt($("#cfg-pairing-len").value, 10) || 6;
  c.notify_enabled = $("#cfg-notify").checked;
  c.notify_sound = $("#cfg-notify-sound").checked;
  c.sync_verify_content = $("#cfg-sync-strict").checked;
  c.ip_filter_mode = $("#cfg-filter-mode").value === "allow" ? "Allow" : $("#cfg-filter-mode").value === "deny" ? "Deny" : "Off";
  c.ip_filter_list = $("#cfg-filter-list").value.split(String.fromCharCode(10)).map((x) => x.trim()).filter(Boolean);
  c.duplicate_files = $("#cfg-duplicate").value === "skip" ? "Skip" : "Rename";
  c.hash_cache_days = parseInt($("#cfg-cache-days").value, 10) || 0;
  const cfv = $("#cfg-confirm").value;
  c.confirm_receive = cfv === "unknown" ? "Unknown" : cfv === "all" ? "All" : "Off";
  c.per_device_folder = $("#cfg-per-device").checked;
  c.auto_archive = $("#cfg-archive").checked;
  $$(".cfg-dir").forEach((inp) => { c[inp.dataset.key] = inp.value.trim(); });
  c.speed_limit = parseInt($("#cfg-limit").value, 10) || 0;
  c.recv_speed_limit = parseInt($("#cfg-recv-limit").value, 10) || 0;
  c.udp_passes = parseInt($("#cfg-passes").value, 10) || 2;
  c.udp_fec = $("#cfg-fec").checked;
  c.udp_fec_parity = parseInt($("#cfg-parity").value, 10) || 2;
  c.update_url = $("#cfg-update-url").value.trim() || null;
  c.auto_update_check = $("#cfg-auto-update").checked;
  c.http_port = parseInt($("#http-port").value, 10) || 8090;
  c.language = lang;
  c.theme = localStorage.getItem("trft-theme") || "system";
  try {
    await invoke("save_config", { config: c });
    appState.config = c;
    toast(t("saved"), "ok");
    // 规格 §3.3「目录类选项下次服务器启动生效（有提示）」：接收器运行中才提示。
    if (appState.receivers && appState.receivers.length) toast(t("dir_apply_hint"), "warn");
  } catch (e) {
    toast(t("save_fail") + ": " + e, "err");
  }
}
$("#btn-save-cfg").addEventListener("click", saveSettings);

/* 生成配对码（设置页 = 本机接收侧，规格 §3.3 PairingLength 4-12）。
   用户反馈轮移正：此前「生成」误置于发送面板——发送侧应填对端配对码，
   随机生成填入必然认证失败。CSPRNG（crypto.getRandomValues + 拒绝采样消模偏差）
   ——配对码是认证凭据，Math.random 可预测属弱点。 */
$("#btn-gen-code").addEventListener("click", () => {
  const lenRaw = $("#cfg-pairing-len").value.trim();
  const parsed = parseInt(lenRaw, 10);
  // 位数无效（空/越界红框）回落 config 默认——不得把空串写进配对码框。
  const len = parsed >= 4 && parsed <= 12 ? parsed : (appState.config.pairing_length || 6);
  const buf = new Uint8Array(1);
  let code = "";
  for (let i = 0; i < len; i += 1) {
    let b = 250;
    while (b >= 250) { crypto.getRandomValues(buf); b = buf[0]; } // 拒绝 250-255，0-9 均匀
    code += b % 10;
  }
  $("#cfg-code").value = code;
});

$$(".cfg-dir-browse").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const d = await T.dialog.open({ multiple: false, directory: true });
    if (d) {
      const inp = document.querySelector('.cfg-dir[data-key="' + btn.dataset.key + '"]');
      inp.value = d;
      inp.dispatchEvent(new Event("input", { bubbles: true })); // 同步接收卡片
    }
  });
});

const autoChk = $("#cfg-autostart");
autoChk.addEventListener("change", async () => {
  try {
    await invoke("autostart_set", { enable: autoChk.checked });
  } catch (e) {
    autoChk.checked = !autoChk.checked;
    toast(String(e), "err");
  }
});

$("#btn-check-update").addEventListener("click", async () => {
  try {
    const r = await invoke("update_check");
    if (r.hasUpdate) {
      toast(t("new_version") + ": " + r.version, "ok", t("install_now"), async () => {
        toast(t("installing"), "ok");
        try {
          await invoke("update_install");
          toast(t("install_done"), "ok");
          setTimeout(() => window.location.reload(), 1500);
        } catch (e) { toast(t("install_fail") + ": " + e, "err"); }
      });
    } else toast(t("up_to_date") + " (" + r.current + ")", "ok");
  } catch (e) { toast(t("update_fail") + ": " + e, "err"); }
});

/* ============ 拖放（规格 §3.2：多文件逐项入队；单文件填充路径框） ============ */
function setupDragDrop() {
  T.webview.getCurrentWebview().onDragDropEvent((ev) => {
    const p = ev.payload;
    if (p.type === "enter" || p.type === "over") {
      document.body.classList.add("dragging");
    } else if (p.type === "leave") {
      document.body.classList.remove("dragging");
    } else if (p.type === "drop") {
      document.body.classList.remove("dragging");
      const paths = p.paths || [];
      // 队列是独立类型页：拖入多文件（或当前就在队列页）时统一进队列并切到队列页，
      // 不再从文件/文件夹/文本页静默入队。
      if (paths.length === 1 && sendKind !== "queue") {
        $("#send-path").value = paths[0];
        if (sendKind === "text") {
          $$("#kind-seg .seg-btn").forEach((x) => x.classList.toggle("active", x.dataset.kind === "file"));
          sendKind = "file";
          updateKindRows();
        }
      } else if (paths.length > 0) {
        if (sendKind !== "queue") {
          $$("#kind-seg .seg-btn").forEach((x) => x.classList.toggle("active", x.dataset.kind === "queue"));
          sendKind = "queue";
          updateKindRows();
        }
        const snap = queueSnapshot();
        for (const f of paths) {
          if (queueItems.length >= 500) { toast(t("queue_full"), "err"); break; }
          queueItems.push({ kind: "file", path: f, snap });
        }
        renderQueue();
        persistQueue();
      }
    }
  });
}

/* ============ 传输统计与历史（规格 §3.3，M5'） ============ */
let refreshStatsTimer = null;
function scheduleStatsRefresh() {
  if (refreshStatsTimer) return;
  refreshStatsTimer = setTimeout(() => { refreshStatsTimer = null; refreshStats(); }, 1000);
}
async function refreshStats() {
  try {
    const s = await invoke("stats_summary");
    $("#st-today-count").textContent = s.today ? s.today.count : 0;
    $("#st-today-bytes").textContent = fmtBytes(s.today ? s.today.bytes : 0);
    $("#st-week-bytes").textContent = fmtBytes(s.week ? s.week.bytes : 0);
    $("#st-total-count").textContent = s.total ? s.total.count : 0;
    $("#st-total-bytes").textContent = fmtBytes(s.total ? s.total.bytes : 0);
    const dl = $("#stats-devices");
    dl.textContent = "";
    if (!s.by_device || !s.by_device.length) {
      const li = document.createElement("li");
      li.className = "empty";
      li.dataset.i18n = "none";
      li.textContent = t("none");
      dl.appendChild(li);
    } else {
      s.by_device.forEach((d) => {
        const li = document.createElement("li");
        const name = document.createElement("span");
        name.className = "grow";
        name.textContent = d.peer;
        const meta = document.createElement("span");
        meta.className = "pmeta";
        meta.textContent = d.count + " ×  " + fmtBytes(d.bytes) + "  " + d.files + " " + t("files_unit");
        li.appendChild(name);
        li.appendChild(meta);
        dl.appendChild(li);
      });
    }
    await refreshStatsRecords();
  } catch (e) { /* 统计不可用静默 */ }
}

async function refreshStatsRecords() {
  const list = $("#stats-list");
  list.textContent = "";
  try {
    const rows = await invoke("stats_records", { direction: $("#stats-direction").value, limit: 300 });
    if (!rows.length) {
      const li = document.createElement("li");
      li.className = "empty";
      li.dataset.i18n = "none";
      li.textContent = t("none");
      list.appendChild(li);
      return;
    }
    rows.forEach((r) => {
      const li = document.createElement("li");
      const time = document.createElement("span");
      time.className = "pmeta";
      time.textContent = new Date(Number(r.time) * 1000).toLocaleString();
      const body = document.createElement("span");
      body.className = "grow";
      body.textContent = (r.dir === "S" ? "↑ " : "↓ ") + r.path + "  " + fmtBytes(r.bytes) + "  " + r.detail + "  → " + r.peer;
      li.appendChild(time);
      li.appendChild(body);
      // 对齐原版 HistoryDialog：资源管理器定位（旧 6 字段行无路径时不提供）。
      if (r.path) {
        const loc = document.createElement("button");
        loc.className = "x";
        loc.title = t("locate");
        loc.textContent = "📂";
        loc.addEventListener("click", () => invoke("open_locate", { path: r.path }).catch((e) => toast(String(e), "err")));
        li.appendChild(loc);
      }
      list.appendChild(li);
    });
  } catch (e) { /* 静默 */ }
}
$("#stats-direction").addEventListener("change", refreshStatsRecords);
$("#btn-stats-refresh").addEventListener("click", refreshStats);
$("#btn-stats-clear").addEventListener("click", async () => {
  if (!(await confirmDialog(t("stats_clear_confirm"), { danger: true }))) return;
  try { await invoke("stats_clear"); await refreshStats(); } catch (e) { toast(String(e), "err"); }
});
$("#btn-stats-export").addEventListener("click", async () => {
  try {
    const path = await T.dialog.save({
      defaultPath: "trft-stats-" + new Date().toISOString().slice(0, 10) + ".csv",
      filters: [{ name: "CSV", extensions: ["csv"] }],
    });
    if (!path) return;
    await invoke("stats_export_csv", { path });
    toast(t("copied") + ": " + path, "ok");
  } catch (e) { toast(String(e), "err"); }
});

/* ============ 监控模式（规格 §3.2，M5'） ============ */
function monitorLine(kind, name) {
  const map = { queued: "mon_queued", "not-ready": "mon_not_ready", dropped: "mon_dropped", sending: "mon_sending", sent: "mon_sent", failed: "mon_failed" };
  const list = $("#monitor-list");
  const empty = list.querySelector(".empty");
  if (empty) empty.remove();
  const li = document.createElement("li");
  const k = document.createElement("span");
  k.className = "pmeta";
  // UI-1 P3-15a：挂 data-i18n——语言切换时 applyLang 统一刷新（否则残留旧语言）。
  if (map[kind]) k.dataset.i18n = map[kind];
  k.textContent = t(map[kind] || kind);
  const n = document.createElement("span");
  n.className = "grow";
  n.textContent = name;
  li.appendChild(k);
  li.appendChild(n);
  li.className = kind === "failed" ? "err" : kind === "sent" ? "ok" : "";
  list.prepend(li);
  while (list.children.length > 100) list.lastChild.remove();
}

$("#btn-monitor-browse").addEventListener("click", async () => {
  const d = await T.dialog.open({ multiple: false, directory: true });
  if (d) $("#monitor-dir").value = d;
});
$("#btn-monitor-start").addEventListener("click", async () => {
  const dir = $("#monitor-dir").value.trim();
  const ip = $("#monitor-ip").value.trim();
  const port = parseInt($("#monitor-port").value, 10);
  if (!dir) { toast(t("monitor_dir"), "err"); return; }
  if (!ip || !(port >= 1 && port <= 65535)) { toast(t("target") + "/" + t("port"), "err"); return; }
  // 排除扩展名：逗号/分号/空白分隔都接受，原样交给后端归一化（去点、小写、去重）。
  const excludeExts = $("#monitor-exclude").value
    .split(/[,;\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  try {
    await invoke("monitor_start", {
      req: {
        watchDir: dir, ip, port,
        proto: $("#monitor-proto").value,
        code: $("#monitor-code").value.trim() || null,
        // 启动时快照发送面板源端口/限速（对齐原版监控继承客户端面板参数）。
        srcPort: parseInt($("#send-srcport").value, 10) || null,
        limit: parseInt($("#send-limit").value, 10) || null,
        passes: null, fecParity: null, nofec: false,
        excludeExts,
      },
    });
    // 后端已把归一化后的列表落盘；本地副本同步，避免后续 save_config 用旧值覆盖。
    if (appState && appState.config) appState.config.monitor_exclude_exts = excludeExts;
    $("#dot-monitor").classList.add("on");
    $("#btn-monitor-start").disabled = true;
    $("#btn-monitor-stop").disabled = false;
    updateKindRows();
  } catch (e) { toast(String(e), "err"); }
});
$("#btn-monitor-stop").addEventListener("click", async () => {
  try {
    await invoke("monitor_stop");
  } catch (e) {
    toast(String(e), "err");
    return; // UI-1 P3-6：停止失败时 UI 不复位（与后端真实状态保持一致）
  }
  $("#dot-monitor").classList.remove("on");
  $("#btn-monitor-start").disabled = false;
  $("#btn-monitor-stop").disabled = true;
  updateKindRows();
});

/* ============ 通用确认模态（B1：替代 window.confirm——风格与接收确认弹窗统一） ============ */
function confirmDialog(msg, opts) {
  let ov = $("#yn-overlay");
  if (!ov) {
    ov = document.createElement("div");
    ov.id = "yn-overlay";
    ov.className = "hidden";
    const modal = document.createElement("div");
    modal.className = "modal";
    const title = document.createElement("div");
    title.className = "modal-title";
    title.id = "yn-title";
    const body = document.createElement("div");
    body.className = "modal-msg";
    body.id = "yn-msg";
    const btns = document.createElement("div");
    btns.className = "modal-btns";
    const no = document.createElement("button");
    no.className = "btn";
    no.id = "btn-yn-cancel";
    const yes = document.createElement("button");
    yes.className = "btn primary";
    yes.id = "btn-yn-ok";
    btns.appendChild(no);
    btns.appendChild(yes);
    modal.appendChild(title);
    modal.appendChild(body);
    modal.appendChild(btns);
    ov.appendChild(modal);
    document.body.appendChild(ov);
  }
  $("#yn-title").textContent = (opts && opts.title) || t("confirm_yn");
  $("#yn-msg").textContent = msg;
  const yes = $("#btn-yn-ok");
  const no = $("#btn-yn-cancel");
  yes.textContent = t("confirm_ok");
  yes.className = (opts && opts.danger) ? "btn danger" : "btn primary";
  no.textContent = t("confirm_cancel");
  ov.classList.remove("hidden");
  return new Promise((resolve) => {
    yes.onclick = () => { ov.classList.add("hidden"); resolve(true); };
    no.onclick = () => { ov.classList.add("hidden"); resolve(false); };
  });
}

/* ============ 接收前确认弹窗（规格 §3.3：无应答 = 拒绝，fail-closed） ============
   B2：并发确认排队呈现——单 overlay 逐个展示（标题徽标 i/N），后到不再覆盖先到；
   等待队列中的请求其 30s 时限由后端看门狗兜底（前端排队不延长 fail-closed 时限）。 */
let confirmTimer = null;
const confirmQueue = []; // { id, device, peer }
let confirmShowing = null;
function showConfirm(id, device, peer) {
  confirmQueue.push({ id, device, peer });
  if (confirmShowing) {
    // 已有弹窗在展示：即时更新标题徽标提示积压（i/N）——
    // pumpConfirm 对正展示中的弹窗不动作，徽标必须在这里刷新。
    $("#confirm-title").textContent = t("confirm_title") + " (" + (confirmQueue.length + 1) + ")";
    return;
  }
  pumpConfirm();
}
function pumpConfirm() {
  if (confirmShowing || !confirmQueue.length) return;
  confirmShowing = confirmQueue.shift();
  const { id, device, peer } = confirmShowing;
  const ov = $("#confirm-overlay");
  $("#confirm-msg").textContent = t("confirm_msg").replace("{d}", device).replace("{p}", peer);
  // 排队徽标：仅积压 >1 时呈现（i/N）。
  const total = confirmQueue.length + 1;
  $("#confirm-title").textContent = total > 1
    ? t("confirm_title") + " (" + total + ")"
    : t("confirm_title");
  ov.classList.remove("hidden");
  let left = 30;
  const cd = $("#confirm-count");
  cd.textContent = String(left) + "s";
  clearInterval(confirmTimer);
  confirmTimer = setInterval(() => {
    left -= 1;
    cd.textContent = String(left) + "s";
    if (left <= 0) {
      clearInterval(confirmTimer);
      // UI-1 P3-13：接线闲置字典 confirm_expired——超时拒绝不该无感静默。
      toast(t("confirm_expired"), "warn");
      log("warn", t("confirm_expired"));
      closeConfirm(id, false);
    }
  }, 1000);
  $("#btn-confirm-allow").onclick = () => { clearInterval(confirmTimer); closeConfirm(id, true); };
  $("#btn-confirm-deny").onclick = () => { clearInterval(confirmTimer); closeConfirm(id, false); };
}
async function closeConfirm(id, allow) {
  $("#confirm-overlay").classList.add("hidden");
  confirmShowing = null;
  try { await invoke("confirm_reply", { id, allow }); } catch (e) { /* 已超时/不存在 */ }
  pumpConfirm();
}

/* ============ 事件接线 ============ */
/* 群发槽位收敛（UI-1 P2-4 抽取）：终态事件与 invoke 返回乱序时由
   taskTerminalSeen 兜底补收敛；neutralized = 暂停（不计成败）。
   UI-4 P3-3：汇总判定加 launching 门控——launching 期间（多目标 invoke
   尚未全部返回）瞬时终态不得中途触发「1/1」式汇总并清零计数。 */
let groupLaunching = false;
function groupMaybeSummary() {
  if (groupLaunching || groupPending.size !== 0 || groupTotal === 0) return;
  const msg = t("group_summary") + " " + groupOk + " / " + groupTotal + (groupFail ? " (" + t("send_fail") + " " + groupFail + ")" : "");
  toast(msg, groupFail ? "err" : "ok");
  log(groupFail ? "warn" : "ok", msg);
  groupTotal = 0; groupOk = 0; groupFail = 0;
}
function groupSettle(id, ok, neutralized) {
  if (!groupPending.delete(id)) return;
  if (!neutralized) { if (ok) groupOk += 1; else groupFail += 1; }
  groupMaybeSummary();
}

async function wireEvents() {
  await listen("trft://progress", (ev) => onProgress(ev.payload));
  // 轮 7 F4/F7：后端异步状态变化（窗口隐藏停共享/接收器自摘/监控自摘）——
  // 前端重拉状态复位按钮/圆点/共享页（死二维码假「运行中」）。
  await listen("trft://sync-state", async () => {
    try {
      appState = await invoke("get_app_state");
      // 轮 UI-5 续 3 P2：sync-state 是「任意子系统状态变了」的通用信号——
      // 共享仍在运行时不得清空链接/二维码（token 只在后端句柄里，前端丢了
      // 就再也拿不回来；旧实现任何接收器/监控退出都会把运行中的共享显示成
      // 「未运行」）。
      if (appState.httpRunning) {
        const info = await invoke("http_info").catch(() => null);
        if (info) {
          httpInfo = info;
          $("#share-dir-line").textContent = info.dir;
        }
      } else {
        httpInfo = null;
        $("#share-dir-line").textContent = "";
      }
      refreshQr();
      renderReceivers();
      invoke("monitor_status").then((on) => {
        $("#dot-monitor").classList.toggle("on", !!on);
        $("#btn-monitor-start").disabled = !!on;
        $("#btn-monitor-stop").disabled = !on;
        updateKindRows();
      }).catch(() => {});
    } catch (e) { /* 状态重拉失败保旧值 */ }
  });
  await listen("trft://task-start", (ev) => {
    const p = ev.payload;
    taskByProgress.set(p.progressId, p.id);
    const card = tasks.get(p.progressId);
    if (card) attachCardButtons(p.progressId, card);
  });
  await listen("trft://task", (ev) => {
    const p = ev.payload;
    // 轮 7 F1：暂停的终态事件（paused 标记）不清 reqByTask/pausedTasks/
    // taskByProgress——「继续」按钮与 onProgress 暂停守卫都依赖它们。
    const isPaused = !!p.paused || pausedTasks.has(p.id);
    // UI-1 P2-4：先记录终态（invoke 返回晚于事件时，注册侧凭此收敛群发槽位）。
    taskTerminalSeen.set(p.id, { ok: !!p.ok, paused: isPaused });
    if (isPaused) {
      groupSettle(p.id, false, true); // 暂停 = 槽位收敛，不计成败
      return;
    }
    reqByTask.delete(p.id);
    pausedTasks.delete(p.id);
    groupSettle(p.id, !!p.ok);
    if (p.ok) { log("ok", "#" + p.id + " " + (p.summary || "OK")); if (p.summary) beep(); }
    else if (p.reason === "cancelled") {
      // 轮 7 F5：主动取消不是失败——warn 日志即可，不弹失败 toast。
      // 机器字段 reason 判别（后端 send_cancel 补发）；人读文案走 L10N。
      log("warn", "#" + p.id + " " + t("cancelled"));
    }
    else {
      log("err", "#" + p.id + " " + t("send_fail") + ": " + (p.error || ""));
      toast(t("send_fail") + ": " + (p.error || ""), "err");
    }
    for (const [k, v] of taskByProgress) { if (v === p.id) taskByProgress.delete(k); }
    scheduleStatsRefresh();
  });
  await listen("trft://text", (ev) => {
    // 轮 10：载荷为 { text, from }——弹窗显示全文与来源（旧版裸字符串仍兼容）。
    const p = ev.payload;
    const text = p && typeof p === "object" ? String(p.text ?? "") : String(p ?? "");
    const from = p && typeof p === "object" ? String(p.from ?? "") : "";
    beep();
    showTextModal(text, from);
    const list = $("#text-history");
    const empty = list.querySelector(".empty");
    if (empty) empty.remove();
    const li = document.createElement("li");
    const tm = document.createElement("span");
    tm.className = "pmeta";
    tm.textContent = new Date().toLocaleTimeString();
    const tx = document.createElement("span");
    tx.className = "grow";
    tx.textContent = text.length > 120 ? text.slice(0, 120) + "…" : text;
    li.appendChild(tm);
    li.appendChild(tx);
    li.title = t("text_view_full");
    li.addEventListener("click", () => showTextModal(text, from));
    list.prepend(li);
    while (list.children.length > 200) list.lastChild.remove();
  });
  await listen("trft://firewall-hint", (ev) => {
    const p = ev.payload;
    toast(t("firewall_msg") + " " + p.command, "warn", t("copy"), () => navigator.clipboard.writeText(p.command));
    // 日志只写「需要放行防火墙」，原始命令留在可复制的 toast 里（不把实现细节写进日志）。
    log("warn", t("firewall_msg"));
  });
  await listen("trft://log", (ev) => log(ev.payload.level, ev.payload.message));
  await listen("trft://confirm", (ev) => {
    const p = ev.payload;
    beep();
    showConfirm(p.id, p.device, p.peer);
    log("warn", t("confirm_title") + ": " + p.device + " (" + p.peer + ")");
  });
  await listen("trft://monitor", (ev) => {
    const p = ev.payload;
    // 外部标签枚举：{"Queued": {"name": ...}}。
    const tag = Object.keys(p)[0];
    const data = p[tag] || {};
    const kind = { Queued: "queued", NotReady: "not-ready", Dropped: "dropped", Sending: "sending", Sent: "sent", Failed: "failed" }[tag];
    if (kind) monitorLine(kind, data.name || "");
    if (kind === "sent") beep();
  });
  await listen("trft://verify", (ev) => {
    const { done, total } = ev.payload;
    $("#verify-bar").max = Math.max(1, total);
    $("#verify-bar").value = done;
    $("#verify-text").textContent = done + " / " + total;
  });
  await listen("trft://verify-result", (ev) => {
    const r = ev.payload;
    $("#v-scanned").textContent = r.scanned;
    $("#v-hit").textContent = r.hit;
    $("#v-fresh").textContent = r.fresh;
    $("#v-bad").textContent = r.mismatches.length;
    $("#v-unread").textContent = r.unreadable;
    const mm = $("#verify-mismatch");
    mm.textContent = "";
    r.mismatches.forEach((m) => {
      const li = document.createElement("li");
      li.textContent = m;
      mm.appendChild(li);
    });
    // 轮 UI-5 续 P2：中途停止不得显示「校验完成」（只扫了部分文件时
    // mismatches 为空与「完整扫描且全一致」无法区分）。
    if (r.stopped) {
      toast(t("verify_stopped"), "warn");
    } else {
      toast(t("verify_done"), r.mismatches.length ? "err" : "ok");
    }
  });
}

/* ============ 头部控件 ============ */
$("#lang-zh").addEventListener("click", () => setLang("zh"));
$("#lang-en").addEventListener("click", () => setLang("en"));
function setLang(v) {
  if (activeTransfers > 0) { toast(t("lang_locked"), "err"); return; }
  lang = v;
  applyLang();
  renderQueue();
  renderAddrDropdowns();
  // UI-1 P3-15b：暂停卡驻留期语言切换——状态词与按钮文案定点刷新
  //（暂停卡不在 data-i18n 覆盖范围，否则中英混排直到继续/取消）。
  tasks.forEach((card, pid) => {
    const tid = taskByProgress.get(pid);
    if (!tid || !pausedTasks.has(tid)) return;
    card.state.textContent = t("paused");
    const pauseBtn = card.el.querySelector(".pbtns button");
    if (pauseBtn) pauseBtn.textContent = t("resume");
  });
  // UI-1 P3-15c：在队确认弹窗即时重渲染（否则打开状态下语言不刷新）。
  if (confirmShowing) {
    $("#confirm-msg").textContent = t("confirm_msg").replace("{d}", confirmShowing.device).replace("{p}", confirmShowing.peer);
    const total = confirmQueue.length + 1;
    $("#confirm-title").textContent = t("confirm_title") + (total > 1 ? " (" + total + ")" : "");
    $("#btn-confirm-allow").textContent = t("confirm_allow");
    $("#btn-confirm-deny").textContent = t("confirm_deny");
  }
  // 动态渲染的列表不在 data-i18n 覆盖范围内：语言切换后必须重渲染，
  // 否则中英混排（实机测试：按设备行残留「5 文件」/ 统计历史仍是旧文案）。
  refreshStats();
  reloadDevices();
  if (revalidateFields) revalidateFields(); // ToolTip 文案随语言刷新
  // 轮 7 F11：即时持久化（与 qr-address 一致）——否则关窗保存的 cfg 不含
  // 本次改动，重启丢语言。
  if (appState) {
    appState.config.language = v;
    invoke("save_config", { config: appState.config }).catch(() => {});
  }
}
["light", "system", "dark"].forEach((mode) => {
  $("#theme-" + mode).addEventListener("click", () => {
    localStorage.setItem("trft-theme", mode);
    if (appState) {
      appState.config.theme = mode;
      // 轮 7 F11：即时持久化（同上）。
      invoke("save_config", { config: appState.config }).catch(() => {});
    }
    applyTheme();
  });
});

$("#btn-log-clear").addEventListener("click", () => {
  $("#log-list").textContent = "";
});

/* ============ 使用说明（对齐原版 HelpDialog：双语可滚动） ============ */
$("#btn-help").addEventListener("click", () => {
  // 打开时取词：语言切换后再次打开即随语言刷新。
  $("#help-body").textContent = t("help_body");
  $("#help-overlay").classList.remove("hidden");
});
$("#btn-help-close").addEventListener("click", () => $("#help-overlay").classList.add("hidden"));

/* ============ 收到文本弹窗（轮 10：对端 0x06 文本到达即弹窗显示全文） ============ */
// 多条连续到达时按「时间 · 来源」分段累积；关闭即清空。
const textModal = { parts: [] };

function showTextModal(text, from, opts = {}) {
  const at = opts.at || new Date().toLocaleTimeString();
  // 历史条目可能带截断标记（>64KB 只保留前段）——在正文末尾如实说明。
  const body = opts.truncated ? text + "\n\n" + t("text_truncated") : text;
  textModal.parts.push({ text: body, from, at });
  const multi = textModal.parts.length > 1;
  const pre = $("#text-body");
  pre.textContent = textModal.parts
    .map((p) => {
      if (!multi) return p.text;
      const head = "—— " + p.at + (p.from ? " · " + t("text_from") + " " + p.from : "") + " ——";
      return head + "\n" + p.text;
    })
    .join("\n\n");
  $("#text-meta").textContent = from
    ? t("text_from") + " " + from + " · " + at
    : (opts.history ? t("text_history_label") + " · " : "") + at;
  $("#text-title").textContent = multi ? t("text_title") + "（" + textModal.parts.length + "）" : t("text_title");
  $("#text-overlay").classList.remove("hidden");
  pre.scrollTop = pre.scrollHeight;
}

function closeTextModal() {
  $("#text-overlay").classList.add("hidden");
  textModal.parts = [];
  $("#text-body").textContent = "";
  $("#text-meta").textContent = "";
}

$("#btn-text-close").addEventListener("click", closeTextModal);
$("#btn-text-copy").addEventListener("click", () => {
  const text = $("#text-body").textContent;
  if (!text) return;
  navigator.clipboard
    .writeText(text)
    .then(() => toast(t("text_copy_ok"), "ok"))
    .catch(() => {});
});
$("#text-overlay").addEventListener("click", (e) => {
  if (e.target.id === "text-overlay") closeTextModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !$("#text-overlay").classList.contains("hidden")) closeTextModal();
});

/* ============ 启动 ============ */
(async function init() {
  lang = localStorage.getItem("trft-lang") || "zh";
  appState = await invoke("get_app_state");
  // 页面重载/重启后共享可能仍在运行：从后端句柄恢复链接（token 不在状态快照里）。
  if (appState.httpRunning) {
    httpInfo = await invoke("http_info").catch(() => null);
    if (httpInfo) $("#share-dir-line").textContent = httpInfo.dir;
  }
  lang = appState.config.language || lang;
  // UI-4 F8：语言白名单归一（theme 同款）——非法值会让 t() 抛 TypeError
  // 打断整个 init 接线。
  if (!["zh", "en"].includes(lang)) lang = "zh";
  applyLang();
  applyTheme();
  fillSettings();
  // 发送面板目标记忆（§12.1 ClientIP/Port/Protocol）：先填协议再填端口，
  // 记忆值优先于「协议↔端口跟随」（程序赋值不触发 change，无跟随覆盖）。
  if (appState.config.client_proto && $("#send-proto").querySelector(`option[value="${appState.config.client_proto}"]`)) {
    $("#send-proto").value = appState.config.client_proto;
  }
  if (appState.config.client_ip) $("#send-ip").value = appState.config.client_ip;
  if (appState.config.client_port) $("#send-port").value = appState.config.client_port;
  fillShareDirOptions();
  renderAddrDropdowns();
  renderReceivers();
  renderAddressOptions();
  invoke("text_history_load").then((items) => renderTextHistory(items)).catch(() => {});
  reloadDevices();
  $("#btn-th-clear").addEventListener("click", async () => {
    try {
      await invoke("text_history_clear");
      renderTextHistory([]);
    } catch (e) { toast(String(e), "err"); }
  });
  invoke("queue_load").then((items) => {
    items.forEach((it) => {
      const hasSnap = it.ip !== undefined || it.port !== undefined || it.proto !== undefined;
      queueItems.push(hasSnap
        ? { kind: it.kind, path: it.path, snap: {
            ip: it.ip || "", port: it.port || 0, proto: it.proto || "tcp",
            code: it.code || null, limit: it.limit || null,
            nocompress: !!it.nocompress, noencrypt: !!it.noencrypt,
            passes: it.passes || null, fecParity: it.fecParity || null, nofec: !!it.nofec,
            srcPort: it.srcPort || null } }
        : { kind: it.kind, path: it.path });
    });
    renderQueue();
  }).catch(() => {});
  refreshStats();
  invoke("monitor_status").then((on) => {
    $("#dot-monitor").classList.toggle("on", !!on);
    $("#btn-monitor-start").disabled = !!on;
    $("#btn-monitor-stop").disabled = !on;
    updateKindRows();
  }).catch(() => {});
  if (appState.config.qr_address) $("#qr-address").value = appState.config.qr_address;
  refreshQr();
  invoke("autostart_get").then((on) => { autoChk.checked = on; }).catch(() => {});
  await wireEvents();
  setupDragDrop();
  updateKindRows();
  wireValidation();
  initVerifySchedule();
  // 规格 §3.7 自动升级：启动 3 秒后台静默检查（配置了 UpdateUrl 才查），「跳过此版本」记忆。
  setTimeout(async () => {
    if (!appState.config.update_url) return;
    if (appState.config.auto_update_check === false) return; // 规格 §12.1 AutoUpdateCheck
    try {
      const r = await invoke("update_check");
      if (r.hasUpdate && r.version !== appState.config.skip_version) {
        // 轮 7 P2：此前只有「跳过」没有「安装」；B3：双动作合并进同一 toast
        // （此前两个独立 toast 叠叠覆盖，界面噪声大）。
        toast(t("update_found_toast") + ": " + r.version, "ok", t("install_now"), async () => {
          toast(t("installing"), "ok");
          try {
            await invoke("update_install");
            toast(t("install_done"), "ok");
            setTimeout(() => window.location.reload(), 1500);
          } catch (e) { toast(t("install_fail") + ": " + e, "err"); }
        }, [{ text: t("skip_version"), fn: async () => {
          appState.config.skip_version = r.version;
          try { await invoke("save_config", { config: appState.config }); } catch (e) { /* 忽略 */ }
        } }]);
        log("ok", t("update_found_toast") + ": " + r.version + " — " + r.url);
      }
    } catch (e) { /* 静默检查失败不打扰 */ }
  }, 3000);
})();
