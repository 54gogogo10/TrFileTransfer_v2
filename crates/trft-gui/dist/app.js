/* TrFileTransfer GUI 前端（无构建 vanilla JS，经 withGlobalTauri 注入的 API 调 Rust 命令）。
   文案纪律（规格 §3.7）：禁止内联三元拼文案——全部经 L10N 字典 t() 取值；传输中锁定语言切换。 */

const T = window.__TAURI__;
const invoke = T.core.invoke;
const listen = T.event.listen;

/* ============ L10N ============ */
const L10N = {
  zh: {
    tab_send: "发送", tab_recv: "接收", tab_share: "共享", tab_verify: "校验", tab_settings: "设置",
    bind_addr: "绑定地址", wildcard_v4: "全部 IPv4 (0.0.0.0)", no_addr_selected: "请至少勾选一个绑定地址", partial_bind: "部分地址绑定失败", dd_placeholder: "选择监听地址…",
    duplicate: "重复文件", dup_rename: "改名保留（file_1）", dup_skip: "跳过相同内容", cache_days: "摘要缓存有效期（天）",
    share_dir: "共享目录", after_done: "完成后", ad_none: "无动作", ad_shutdown: "关机（60s 可取消）", ad_sleep: "休眠", ad_command: "执行命令",
    confirm_shutdown: "队列完成后将关闭系统（60 秒后执行，shutdown /a 可取消）。确认执行队列？",
    confirm_sleep: "队列完成后系统将进入休眠。确认执行队列？",
    confirm_command: "队列完成后将执行命令：", confirm_tail: "。确认执行队列？",
    firewall_msg: "首次启动接收器：如其他设备无法连接，请用管理员命令放行防火墙：",
    skip_version: "跳过此版本", update_found_toast: "发现新版本",
    pause: "暂停",
    devices: "设备", discover: "发现设备", devices_clear: "清空记忆", use: "使用", to_group: "加入群发",
    ip_filter: "IP 过滤", if_off: "关闭", if_allow: "白名单（allow）", if_deny: "黑名单（deny）",
    discovering: "发现中…", online: "在线", known: "已知",
    group_targets: "群发目标（每行 ip:port）", group_send: "并行群发", group_summary: "群发完成",
    group_bad_target: "非法目标（跳过）", paused: "已暂停", resume: "继续", cancel_task: "取消",
    text_history: "文本历史（200 条）", th_empty: "暂无记录", gen_code: "生成配对码", pairing_len: "配对码位数",
    code_ph_send: "对端配对码", code_ph_local: "4-12 位数字",
    notify_sound: "提示音", sync_strict: "同步逐字节核对（绕过摘要缓存，双侧生效）",
    kind: "类型", kind_file: "文件", kind_folder: "文件夹", kind_text: "文本",
    path: "路径", text: "文本", browse: "浏览…", target: "目标", pairing: "配对码",
    limit: "KB/s", compress: "压缩", encrypt: "加密",
    passes: "重发轮数 1-5", fec_parity: "FEC 校验片 1-8", nofec: "关闭 FEC",
    send: "发送", send_chunked: "并行分块发送", queue_add: "加入队列",
    drop_hint: "可直接拖入文件/文件夹", queue: "发送队列", queue_run: "串行发送", queue_clear: "清空",
    queue_empty: "队列为空", progress: "传输进度",
    port: "端口", save_dir: "保存目录", start: "启动", stop: "停止", open_dir: "打开目录",
    recent: "最近接收", none: "暂无记录",
    share_start: "开启共享", share_stop: "停止共享", address: "网卡地址", share_url: "链接", copy: "复制",
    qr_hint: "手机浏览器扫码即可浏览 / 上传 / 下载共享目录。",
    verify_desc: "聚合扫描全部已配置保存目录，重算 SHA-256 与摘要缓存比对。",
    verify_start: "开始校验", verify_stop: "停止",
    v_scanned: "已扫描", v_hit: "一致", v_fresh: "无记录", v_bad: "不一致", v_unread: "无法读取",
    settings_general: "通用", notify: "完成通知", autostart: "开机自启",
    folder_mode: "发送方式", mode_sync: "差量同步（二次只传差异）", mode_plain: "整夹发送（全量）",
    sync_hint: "按 (源路径, 目标地址) 派生稳定会话 ID，与 CLI sync 互相接力",
    settings_limits: "限速与 UDP", send_limit_lbl: "发送限速 KB/s", recv_limit_lbl: "接收限速 KB/s",
    udp_passes_lbl: "UDP 重发轮数", fec: "FEC 前向纠错", udp_parity_lbl: "校验片",
    settings_update: "更新", update_url: "清单 URL", check_update: "检查更新", save: "保存设置",
    logs: "日志", clear: "清空",
    st_running: "传输中", st_done: "完成", st_failed: "失败", st_unknown: "未知",
    up_to_date: "已是最新版本", new_version: "发现新版本", update_fail: "检查失败",
    saved: "设置已保存", save_fail: "保存失败", copied: "已复制", copy_fail: "复制失败",
    started: "已启动", stopped: "已停止", http_on: "共享已开启", http_off: "共享未运行",
    verify_done: "校验完成", send_fail: "发送失败", lang_locked: "传输进行中，语言切换已锁定",
    queue_sent: "队列已全部执行", queue_full: "队列已达 500 项上限",
    udp_file_only: "单向 UDP 仅支持单文件（无握手通道）",
    tab_stats: "历史",
    stats_summary: "统计概览", refresh: "刷新", export_csv: "导出 CSV", stats_clear: "全部清除",
    st_today: "今日次数", st_today_bytes: "今日流量", st_week_bytes: "7 天流量", st_total: "累计次数", st_total_bytes: "累计流量",
    by_device: "按设备明细", stats_history: "传输历史", dir_all: "全部", dir_s: "发送", dir_r: "接收",
    stats_clear_confirm: "确定清除全部传输统计？（不可恢复）",
    monitor: "监控模式", monitor_start: "启动监控", monitor_stop: "停止监控", monitor_dir: "监控目录",
    monitor_hint: "目录内文件就绪即自动发出（独占打开 + 稳定窗双判定）；成功后移入「已发送文件/」。",
    mon_queued: "入队", mon_not_ready: "未就绪（等待）", mon_dropped: "已消失（丢弃）", mon_sending: "发送中", mon_sent: "已发送", mon_failed: "失败",
    monitor_running: "监控运行中",
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
    bind_addr: "Bind addresses", wildcard_v4: "All IPv4 (0.0.0.0)", no_addr_selected: "Select at least one bind address", partial_bind: "Some addresses failed to bind", dd_placeholder: "Select bind addresses…",
    duplicate: "Duplicates", dup_rename: "Rename (file_1)", dup_skip: "Skip identical", cache_days: "Hash cache TTL (days)",
    share_dir: "Shared dir", after_done: "After done", ad_none: "None", ad_shutdown: "Shutdown (60s)", ad_sleep: "Sleep", ad_command: "Run command",
    confirm_shutdown: "The system will shut down after the queue finishes (60s, cancellable via shutdown /a). Run the queue?",
    confirm_sleep: "The system will sleep after the queue finishes. Run the queue?",
    confirm_command: "This command will run after the queue finishes: ", confirm_tail: ". Run the queue?",
    firewall_msg: "Receiver started: if other devices cannot connect, allow the firewall with (admin):",
    skip_version: "Skip this version", update_found_toast: "New version",
    pause: "Pause",
    devices: "Devices", discover: "Discover", devices_clear: "Clear memory", use: "Use", to_group: "To group",
    ip_filter: "IP filter", if_off: "Off", if_allow: "Allow list", if_deny: "Deny list",
    discovering: "Discovering…", online: "online", known: "known",
    group_targets: "Group targets (ip:port per line)", group_send: "Send to all", group_summary: "Group send finished",
    group_bad_target: "Invalid target (skipped)", paused: "Paused", resume: "Resume", cancel_task: "Cancel",
    text_history: "Text history (200)", th_empty: "No records", gen_code: "Gen pairing code", pairing_len: "Code length",
    code_ph_send: "Receiver's code", code_ph_local: "4-12 digits",
    notify_sound: "Sound", sync_strict: "Sync byte-verify (bypass digest cache, both sides)",
    kind: "Type", kind_file: "File", kind_folder: "Folder", kind_text: "Text",
    path: "Path", text: "Text", browse: "Browse…", target: "Target", pairing: "Pairing",
    limit: "KB/s", compress: "Compress", encrypt: "Encrypt",
    passes: "Passes 1-5", fec_parity: "FEC parity 1-8", nofec: "Disable FEC",
    send: "Send", send_chunked: "Parallel chunks", queue_add: "Add to queue",
    drop_hint: "Drag & drop files/folders here", queue: "Send queue", queue_run: "Run serially", queue_clear: "Clear",
    queue_empty: "Queue is empty", progress: "Transfers",
    port: "Port", save_dir: "Save dir", start: "Start", stop: "Stop", open_dir: "Open dir",
    recent: "Recent received", none: "No records",
    share_start: "Start sharing", share_stop: "Stop sharing", address: "NIC address", share_url: "URL", copy: "Copy",
    qr_hint: "Scan with a mobile browser to browse / upload / download the shared folder.",
    verify_desc: "Scan all configured save dirs, re-hash SHA-256 and compare with the digest cache.",
    verify_start: "Start verify", verify_stop: "Stop",
    v_scanned: "Scanned", v_hit: "Matched", v_fresh: "No record", v_bad: "Mismatch", v_unread: "Unreadable",
    settings_general: "General", notify: "Notifications", autostart: "Launch on startup",
    folder_mode: "Send mode", mode_sync: "Delta sync (changes only)", mode_plain: "Full folder send",
    sync_hint: "Stable session ID from (source path, target) — interoperates with CLI sync",
    settings_limits: "Limits & UDP", send_limit_lbl: "Send limit KB/s", recv_limit_lbl: "Recv limit KB/s",
    udp_passes_lbl: "UDP passes", fec: "FEC", udp_parity_lbl: "Parity",
    settings_update: "Update", update_url: "Manifest URL", check_update: "Check update", save: "Save settings",
    logs: "Logs", clear: "Clear",
    st_running: "Running", st_done: "Done", st_failed: "Failed", st_unknown: "Unknown",
    up_to_date: "Up to date", new_version: "New version", update_fail: "Check failed",
    saved: "Settings saved", save_fail: "Save failed", copied: "Copied", copy_fail: "Copy failed",
    started: "started", stopped: "stopped", http_on: "Sharing started", http_off: "Sharing not running",
    verify_done: "Verify finished", send_fail: "Send failed", lang_locked: "Language locked during transfers",
    queue_sent: "Queue finished", queue_full: "Queue reached the 500-item limit",
    udp_file_only: "One-way UDP supports single files only (no handshake channel)",
    tab_stats: "History",
    stats_summary: "Overview", refresh: "Refresh", export_csv: "Export CSV", stats_clear: "Clear all",
    st_today: "Today", st_today_bytes: "Today bytes", st_week_bytes: "7-day bytes", st_total: "Total count", st_total_bytes: "Total bytes",
    by_device: "Per device", stats_history: "Transfer history", dir_all: "All", dir_s: "Sent", dir_r: "Received",
    stats_clear_confirm: "Clear all transfer statistics? (irreversible)",
    monitor: "Monitor", monitor_start: "Start monitor", monitor_stop: "Stop monitor", monitor_dir: "Watch dir",
    monitor_hint: "Ready files are sent automatically (exclusive open + stable window); moved to \"Sent files\" on success.",
    mon_queued: "queued", mon_not_ready: "not ready (waiting)", mon_dropped: "vanished (dropped)", mon_sending: "sending", mon_sent: "sent", mon_failed: "failed",
    monitor_running: "Monitor running",
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

/* ============ 状态 ============ */
let appState = null;            // get_app_state 返回
const tasks = new Map();        // progressId -> { el, bar, meta, state }
const taskByProgress = new Map(); // progressId -> 任务 ID（task-start 事件绑定）
const reqByTask = new Map();      // 任务 ID -> { req, kind }（继续 = 原参数重发）
const pausedTasks = new Set();    // 已暂停任务 ID
const groupPending = new Map();   // 群发批次：taskId -> true；全部终态后汇总
let groupTotal = 0;
let groupOk = 0;
let groupFail = 0;
let activeTransfers = 0;        // 运行态计数（语言锁定）
let sendKind = "file";
const queueItems = [];          // 拖放/手动加入的队列
let httpInfo = null;            // { port, token, dir }

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function fmtBytes(n) {
  if (!n) return "0 B";
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
}

/* ============ 主题 ============ */
const media = window.matchMedia("(prefers-color-scheme: dark)");
function applyTheme() {
  const cfgTheme = appState ? appState.config.theme : localStorage.getItem("trft-theme") || "system";
  const dark = cfgTheme === "dark" || (cfgTheme === "system" && media.matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  $$("#theme-seg .seg-btn").forEach((b) => b.classList.remove("active"));
  $("#theme-" + cfgTheme).classList.add("active");
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
  span.textContent = msg;
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
  setTimeout(() => el.remove(), 8000);
}

function beep() {
  if (!appState || !appState.config.notify_enabled || !appState.config.notify_sound) return;
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
  li.textContent = new Date().toLocaleTimeString() + "  " + msg;
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
  const isUdp = $("#send-proto").value === "udp";
  $("#path-row").classList.toggle("hidden", sendKind === "text");
  $("#text-row").classList.toggle("hidden", sendKind !== "text");
  // 规格 §3.1 文件夹模式子选项：0x04 差量同步（默认）与 0x01 整夹发送。
  $("#folder-opts").classList.toggle("hidden", !(isFolder && !isUdp));
  // 0x02 并行分块与 UDP 单发都只对单文件有意义（规格 §3.6）。
  $("#btn-send-chunked").classList.toggle("hidden", !(isFile && !isUdp));
  $("#udp-opts").classList.toggle("hidden", !(isFile && isUdp));
  // 源端口仅连接型协议可绑定（§3.1；UDP 无连接语义，与 CLI --srcport 约束同口径）。
  $("#send-srcport").classList.toggle("hidden", isUdp);
}
$$("#kind-seg .seg-btn").forEach((b) => {
  b.addEventListener("click", () => {
    $$("#kind-seg .seg-btn").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    sendKind = b.dataset.kind;
    updateKindRows();
  });
});
$("#send-proto").addEventListener("change", () => updateKindRows());

$("#btn-browse").addEventListener("click", async () => {
  const file = await T.dialog.open({ multiple: false, directory: sendKind === "folder" });
  if (file) $("#send-path").value = file;
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

function sendRequest(kindOverride) {
  const proto = $("#send-proto").value;
  const kind = kindOverride || sendKind;
  const srcPort = parseInt($("#send-srcport").value, 10);
  const req = {
    kind: proto === "udp" ? "udpfile" : kind,
    path: $("#send-path").value.trim() || null,
    text: $("#send-text").value || null,
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
  };
  const errs = [];
  // 提交门与红框同口径（仅数字）：红框标非法的字段不再被 parseInt 静默放行。
  const raw = (sel) => $(sel).value.trim();
  if (!ipOk(raw("#send-ip"))) errs.push(t("target"));
  if (!numOk(1, 65535)(raw("#send-port"))) errs.push(t("port"));
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

async function doSend(chunked) {
  const { req, errs } = sendRequest();
  if (errs.length) { toast(errs.join(", "), "err"); return; }
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
        srcPort: q.snap.srcPort || null }
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
  };
}
$("#btn-queue-add").addEventListener("click", () => {
  const p = $("#send-path").value.trim();
  if (!p) return;
  if (queueItems.length >= 500) { toast(t("queue_full"), "err"); return; }
  // 轮 6 P2-4：入队即快照面板参数（规格 §3.2「逐项快照面板参数」——
  // 入队后改面板不得 retroactively 改变已入队项的行为）。
  queueItems.push({ kind: sendKind, path: p, snap: queueSnapshot() });
  renderQueue();
  persistQueue();
});
$("#btn-queue-clear").addEventListener("click", () => { queueItems.length = 0; renderQueue(); persistQueue(); });
$("#btn-queue-run").addEventListener("click", async () => {
  if (!queueItems.length) return;
  // 轮 6 P2-4：逐项按入队快照构造（旧条目无快照时回落当前面板值）。
  // 轮 7 F2：kind 映射与直发路径一致（proto=udp → "udpfile"）——此前队列
  // 里的 UDP 项被静默改走 TCP/0x03；UDP 专属参数（passes/fecParity/nofec）
  // 一并入快照（此前恒丢）。
  const cur = queueSnapshot();
  // 轮 7 F13：逐项校验（NaN port 快照此前让整个 invoke 反序列化失败、整批不执行）。
  const bad = queueItems.filter((item) => {
    const sp = item.snap || cur;
    return !sp.ip || !(sp.port >= 1 && sp.port <= 65535);
  });
  if (bad.length) {
    toast(t("group_bad_target") + " ×" + bad.length, "err");
  }
  const reqs = queueItems.filter((item) => {
    const sp = item.snap || cur;
    return !!sp.ip && sp.port >= 1 && sp.port <= 65535;
  }).map((item) => {
    const sp = item.snap || cur;
    const kind0 = item.kind === "folder" ? "folder" : "file";
    return {
      kind: sp.proto === "udp" ? "udpfile" : kind0,
      path: item.path, text: null,
      ip: sp.ip, port: sp.port,
      proto: sp.proto === "udp" ? "udp" : sp.proto,
      code: sp.code, limit: sp.limit,
      chunks: null, nocompress: sp.nocompress, noencrypt: sp.noencrypt,
      passes: sp.passes, fecParity: sp.fecParity, nofec: !!sp.nofec, pin: null,
      srcPort: sp.srcPort || null,
    };
  });
  // 完成后动作执行前确认（规格 §3.2：执行前弹确认；关机/休眠按危险操作呈现）。
  const ad = $("#after-done").value;
  if (ad !== "none") {
    let msg;
    if (ad === "shutdown") msg = t("confirm_shutdown");
    else if (ad === "sleep") msg = t("confirm_sleep");
    else msg = t("confirm_command") + $("#after-command").value + t("confirm_tail");
    if (!(await confirmDialog(msg, { danger: ad === "shutdown" || ad === "sleep" }))) return;
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
});
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
  const lines = $("#group-targets").value.split(String.fromCharCode(10)).map((x) => x.trim()).filter(Boolean);
  const targets = [...new Set(lines)];
  if (!targets.length) return;
  const base = sendRequest();
  if (base.errs.length) { toast(base.errs.join(", "), "err"); return; }
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
    } catch (e) { toast(String(e), "err"); }
  }
  if (!launched) groupTotal = 0;
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
      if (d.proto === "udt" || d.proto === "tcp") $("#send-proto").value = d.proto;
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
    card = { el, name, state, meta, bar, kind: ev.kind, lastT: performance.now(), lastDone: 0, speed: 0 };
    tasks.set(ev.id, card);
    activeTransfers += 1;
    updateLangLock();
    attachCardButtons(ev.id, card);
  }
  return card;
}

/* 暂停/继续/取消（规格 §3.2：取消型暂停——暂停即断，继续按 0x03/0x04 服务端会话续传） */
function attachCardButtons(progressId, card) {
  if (card.kind !== "send") return;
  const taskId = taskByProgress.get(progressId);
  if (!taskId || reqByTask.has(taskId) === false) return;
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
      await invoke("send_cancel", { id: taskId, paused: true });
    } else {
      const entry = reqByTask.get(taskId);
      pausedTasks.delete(taskId);
      btns.remove();
      card.el.remove();
      tasks.delete(progressId);
      await startTask(entry);
    }
  });
  const cancelBtn = mk(t("cancel_task"), async () => {
    await invoke("send_cancel", { id: taskId });
    cancelledProgress.add(progressId);
    setTimeout(() => cancelledProgress.delete(progressId), 10000);
    reqByTask.delete(taskId);
    pausedTasks.delete(taskId);
    card.el.remove();
    tasks.delete(progressId);
    activeTransfers = Math.max(0, activeTransfers - 1);
    updateLangLock();
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
    });
  } else if (kind === "chunked") {
    id = await invoke("send_chunked_start", { req });
  } else {
    id = await invoke("send_start", { req });
  }
  reqByTask.set(id, entry);
  return id;
}

let cancelledProgress = new Set(); // 取消任务的进度 ID（迟到的终态事件直接忽略）
function onProgress(ev) {
  if (cancelledProgress.has(ev.id) && !tasks.has(ev.id)) {
    return; // 轮 7 P3：取消后迟到的终态事件不得重建幽灵卡
  }
  const card = ensureCard(ev);
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
      activeTransfers = Math.max(0, activeTransfers - 1);
      updateLangLock();
      return;
    }
    card.state.textContent = ev.state === "done" ? t("st_done") : t("st_failed");
    card.state.className = "pstate " + ev.state;
    card.el.classList.toggle("done", ev.state === "done");
    card.el.classList.toggle("failed", ev.state !== "done");
    if (ev.state === "done") beep();
    if (ev.kind === "recv" && ev.state === "done") addRecent(ev.name, ev.total);
    activeTransfers = Math.max(0, activeTransfers - 1);
    updateLangLock();
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
  const named = sel.map((v) => (v === "0.0.0.0" ? t("wildcard_v4") : v));
  return named.length <= 2 ? named.join(", ") : named[0] + " +" + (named.length - 1);
}

function renderAddrDropdowns() {
  $$(".dd[data-addr-proto]").forEach((dd) => {
    const panel = dd.querySelector(".dd-panel");
    const label = dd.querySelector(".dd-label");
    // 重渲染（语言切换/地址刷新）时保留已选。
    const prev = new Set([...panel.querySelectorAll("input:checked")].map((x) => x.value));
    panel.textContent = "";
    const items = [["0.0.0.0", t("wildcard_v4")]].concat((appState.addresses || []).map((a) => [a, a]));
    items.forEach(([val, text]) => {
      const lb = document.createElement("label");
      lb.className = "chk";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = val;
      cb.checked = prev.size ? prev.has(val) : val === "0.0.0.0";
      cb.addEventListener("change", () => {
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
    } catch (e) { toast(String(e), "err"); }
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
    if (d) card.querySelector(".recv-dir").value = d;
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
    li.addEventListener("click", () => { navigator.clipboard.writeText(it.text); toast(t("copied"), "ok"); });
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

/* ============ 设置 ============ */
function fillShareDirOptions() {
  const sel = $("#share-dir-sel");
  sel.textContent = "";
  [["save_dir_tcp", "TCP"], ["save_dir_quic", "UDT"], ["save_dir_udp", "UDP"]].forEach(([k, label]) => {
    const opt = document.createElement("option");
    opt.value = k;
    opt.textContent = label + " — " + (appState.config[k] || "");
    sel.appendChild(opt);
  });
}

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
  $("#cfg-confirm").value = (c.confirm_receive || "Off").toLowerCase();
  $("#cfg-per-device").checked = !!c.per_device_folder;
  $("#cfg-archive").checked = !!c.auto_archive;
  $("#cfg-limit").value = c.speed_limit || 0;
  $("#cfg-recv-limit").value = c.recv_speed_limit || 0;
  $("#cfg-passes").value = c.udp_passes;
  $("#cfg-fec").checked = !!c.udp_fec;
  $("#cfg-parity").value = c.udp_fec_parity;
  $("#cfg-update-url").value = c.update_url || "";
  $("#http-port").value = c.http_port;
  $("#version-line").textContent = "v" + appState.version;
  $$(".recv-card").forEach((card) => {
    const key = { tcp: "save_dir_tcp", udt: "save_dir_quic", udp: "save_dir_udp" }[card.dataset.proto];
    card.querySelector(".recv-dir").value = c[key] || "";
    card.querySelector(".recv-port").value = {
      tcp: c.server_port_tcp, udt: c.server_port_quic, udp: c.server_port_udp,
    }[card.dataset.proto];
  });
}

async function saveSettings() {
  // 提交门：红框字段不再放行（与发送面板同口径）。
  if ($("#cfg-pairing-len").classList.contains("invalid")) {
    toast(t("invalid_range").replace("{min}", 4).replace("{max}", 12), "err");
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
  c.http_port = parseInt($("#http-port").value, 10) || 8090;
  c.language = lang;
  c.theme = localStorage.getItem("trft-theme") || "system";
  try {
    await invoke("save_config", { config: c });
    appState.config = c;
    toast(t("saved"), "ok");
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
    if (d) document.querySelector('.cfg-dir[data-key="' + btn.dataset.key + '"]').value = d;
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
  let depth = 0;
  T.webview.getCurrentWebview().onDragDropEvent((ev) => {
    const p = ev.payload;
    if (p.type === "enter" || p.type === "over") {
      document.body.classList.add("dragging");
    } else if (p.type === "leave") {
      document.body.classList.remove("dragging");
    } else if (p.type === "drop") {
      document.body.classList.remove("dragging");
      const paths = p.paths || [];
      if (paths.length === 1) {
        $("#send-path").value = paths[0];
        if (sendKind === "text") {
          $$("#kind-seg .seg-btn").forEach((x) => x.classList.toggle("active", x.dataset.kind === "file"));
          sendKind = "file";
          updateKindRows();
        }
      } else if (paths.length > 1) {
        const snap = queueSnapshot();
        for (const f of paths) {
          if (queueItems.length >= 500) { toast(t("queue_full"), "err"); break; }
          queueItems.push({ kind: "file", path: f, snap });
        }
        renderQueue();
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
  try {
    await invoke("monitor_start", {
      req: {
        watchDir: dir, ip, port,
        proto: $("#monitor-proto").value,
        code: $("#monitor-code").value.trim() || null,
        limit: null, passes: null, fecParity: null, nofec: false,
      },
    });
    $("#dot-monitor").classList.add("on");
    $("#btn-monitor-start").disabled = true;
    $("#btn-monitor-stop").disabled = false;
  } catch (e) { toast(String(e), "err"); }
});
$("#btn-monitor-stop").addEventListener("click", async () => {
  try {
    await invoke("monitor_stop");
  } catch (e) { toast(String(e), "err"); }
  $("#dot-monitor").classList.remove("on");
  $("#btn-monitor-start").disabled = false;
  $("#btn-monitor-stop").disabled = true;
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
async function wireEvents() {
  await listen("trft://progress", (ev) => onProgress(ev.payload));
  // 轮 7 F4/F7：后端异步状态变化（窗口隐藏停共享/接收器自摘/监控自摘）——
  // 前端重拉状态复位按钮/圆点/共享页（死二维码假「运行中」）。
  await listen("trft://sync-state", async () => {
    try {
      appState = await invoke("get_app_state");
      httpInfo = null;
      $("#share-dir-line").textContent = "";
      refreshQr();
      renderReceivers();
      invoke("monitor_status").then((on) => {
        $("#dot-monitor").classList.toggle("on", !!on);
        $("#btn-monitor-start").disabled = !!on;
        $("#btn-monitor-stop").disabled = !on;
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
    if (isPaused) {
      if (groupPending.delete(p.id)) {
        // 群发槽位收敛（不计失败）——否则汇总永不出现。
        if (groupPending.size === 0 && groupTotal > 0) {
          const msg = t("group_summary") + " " + groupOk + " / " + groupTotal + (groupFail ? " (" + t("send_fail") + " " + groupFail + ")" : "");
          toast(msg, groupFail ? "err" : "ok");
          log(groupFail ? "warn" : "ok", msg);
          groupTotal = 0; groupOk = 0; groupFail = 0;
        }
      }
      return;
    }
    reqByTask.delete(p.id);
    pausedTasks.delete(p.id);
    if (groupPending.delete(p.id)) {
      if (p.ok) groupOk += 1; else groupFail += 1;
      if (groupPending.size === 0 && groupTotal > 0) {
        const msg = t("group_summary") + " " + groupOk + " / " + groupTotal + (groupFail ? " (" + t("send_fail") + " " + groupFail + ")" : "");
        toast(msg, groupFail ? "err" : "ok");
        log(groupFail ? "warn" : "ok", msg);
        groupTotal = 0; groupOk = 0; groupFail = 0;
      }
    }
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
    const text = ev.payload;
    beep();
    toast(text, "", t("copy"), () => navigator.clipboard.writeText(text));
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
    li.addEventListener("click", () => { navigator.clipboard.writeText(text); toast(t("copied"), "ok"); });
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
    toast(t("verify_done"), r.mismatches.length ? "err" : "ok");
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

/* ============ 启动 ============ */
(async function init() {
  lang = localStorage.getItem("trft-lang") || "zh";
  appState = await invoke("get_app_state");
  lang = appState.config.language || lang;
  applyLang();
  applyTheme();
  fillSettings();
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
  }).catch(() => {});
  if (appState.config.qr_address) $("#qr-address").value = appState.config.qr_address;
  refreshQr();
  invoke("autostart_get").then((on) => { autoChk.checked = on; }).catch(() => {});
  await wireEvents();
  setupDragDrop();
  updateKindRows();
  wireValidation();
  // 规格 §3.7 自动升级：启动 3 秒后台静默检查（配置了 UpdateUrl 才查），「跳过此版本」记忆。
  setTimeout(async () => {
    if (!appState.config.update_url) return;
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
