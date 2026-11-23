# 全项目代码审查（2026-11-23，第 9 轮）

| 项 | 内容 |
|---|---|
| 范围 | `crates/` 全部 67 个 `.rs`（33,385 行）：接口层、传输引擎、文件路径、基础设施、应用层 |
| 方式 | 5 个独立子审查（cswire / 传输引擎 / 文件路径 / 基础设施 / 应用层）+ 主审逐条复核 |
| 静态检查 | `cargo clippy --workspace --all-targets`：0 error、50 warning（全部为 clamp/多余 return/同型 cast 类风格项） |
| 回归基线 | `cargo test --workspace` 317 passed（审查期间未改代码） |
| 结论 | 子审查原始 47 条，去重合并后 **6×P1、20×P2、18×P3**；无 P0（无内存不安全、无远程代码执行、无已验证的静默数据损坏在默认配置下可被单包触发） |
| 状态 | **同日全部修复**（6×P1、20×P2、18×P3），修复记录与判别测试见 §八 |

## 一、P1（建议立即修复）

### P1-1 RUDP 接收器单包即死：10054 / 跨平台 EMSGSIZE 直接 `return Err`
- 位置：`crates/trft-core/src/transfer/rudp.rs:1472-1481`
- 证据：
```rust
Err(e) => {
    if e.raw_os_error() == Some(10040) { continue; }
    return Err(Error::Io(e));
}
```
  同仓 `udp.rs:1430-1437` 处理 10040/90/40/97，`udt.rs:1620-1632` 处理 10040+10054；只有 RUDP 服务端两者都缺。
- 影响：① Windows 上向已关端口发 ACK/FIN_ACK 后收到 ICMP port-unreachable，下一次 `recv_from` 返回 WSAECONNRESET(10054) → 整个 `serve_rudp_on` 退出，GUI 接收器停摆；② Linux/macOS 上任意主机发一个 >1536B 的垃圾 UDP 包（EMSGSIZE）即可杀死接收器。
- 修复：错误分支统一 `matches!(code, Some(10040)|Some(90)|Some(40)|Some(97)|Some(10054)) => continue`，抽公共 `is_transient_udp_err`。
- 复核：主审已读码确认。

### P1-2 UDT 握手 `flight_flag` 未钳制 → 发送侧流窗无界，可被对端打爆内存
- 位置：`crates/trft-core/src/transfer/udt.rs:1419`、`:1779`；对照 ACK 路径 `:519`
- 证据：
```rust
build_conn(my_id, peer_id, addr, isn, isn, peer_flight.max(2), None, None);   // 无上界
s.flow_window = (words[3] as i32).clamp(2, pw::UDT_FLIGHT_FLAG);             // ACK 路径有
```
  `window() = min(flow_window, cwnd)`，`flow_window` 来自对端任意 i32。
- 影响：恶意/异常对端在 HS_RESP（或 C# 客户端 HS_REQ）里给 `flight_flag = i32::MAX`，发送侧把应用连续写入的全部数据压入 `pkts`（已编码线包），文件多大驻留多大（上限 1PiB 声明），直接 OOM。
- 修复：`build_conn`/`SendState::new` 入口统一 `.clamp(2, pw::UDT_FLIGHT_FLAG)`；补握手路径判别测试（现有 `ack_flow_window_is_clamped` 只覆盖 ACK）。
- 复核：主审已读码确认。

### P1-3 0x03「已完整」只核磁盘长度、不比对客户端整文件哈希 → 同尺寸改内容被判成功
- 位置：`crates/trft-core/src/transfer/cswire.rs:2458-2472`
- 证据：
```rust
Some((etotal, _, true, _, path)) if etotal == total as u64 => {
    let ok = std::fs::metadata(&path).map(|m| m.len() == total as u64).unwrap_or(false);
    ... Session::Done(path)
}
```
  客户端 `0x03` 帧携带的 `full_hash` 在 Done 分支从未使用；会话 verified 后保留 30 分钟，sid 由 (path,size,目标) 确定性派生、不含内容。
- 影响：发送成功后的 30 分钟内，把源文件改成同尺寸不同内容再发 → 服务端回 status 2、零传输，客户端记成功，接收端保留旧内容（静默数据陈旧）。`WIRE-PROTOCOL.md §10.2` 与 C# 参考实现均要求与哈希比对。
- 修复：`CsResumeState` 增 `verified_hash`，Done 分支在 `full_hash` 存在时比对；不等则作废会话按新传并保留旧文件。补判别测试。
- 复核：主审已读码确认。

### P1-4 0x04 增量复核把「读失败」当「内容不符」，直接删既有文件
- 位置：`crates/trft-core/src/transfer/cswire.rs:2956-2959`（同类 `sync_hash_of` `:1409`）
- 证据：
```rust
let actual = crate::hash::sha256_file(&save_path).unwrap_or_default();
if !ct_eq(&actual, &e.hash) {
    let _ = std::fs::remove_file(&save_path);
    return Ok((false, 0, files));
}
```
  同文件 0x03 路径（2648-2650）明确写着「读失败 = 报错并保留文件——绝不把读不到当内容不符去删档」。
- 影响：0x04 二轮同步时 AV 扫描/共享冲突导致读取失败 → 零哈希 → 判不符 → 删除用户既有文件；`sync_hash_of` 还会把零哈希写进内存缓存与落盘 journal，`known_complete` 随后据键命中判「已知完整」。
- 修复：`actual` 用 `sha256_file(&save_path)?`（失败即报错保留）；`sync_hash_of` 读失败返回 None 且不落盘。
- 复核：主审已读码确认。

### P1-5 分块接收的空闲逐出会删掉「组装中」半成品 → 整组数据丢失
- 位置：`crates/trft-core/src/transfer/chunked.rs:178-185`（对照单来源配额逐出 `:212-216`）
- 证据：`map.retain(...)` 只按 `last_seen` 判新鲜，`!fresh` 即 `drop_group(s)`（删 `.part`）；而配额逐出明确排除 `assembling`（`try_lock().map(|g| g.assembling)`）。
- 影响：约 100GB 级 0x02 在慢盘上 `sync_all + sha256_file` 可超 `SESSION_TTL`(600s)，期间任何其他连接的新 0x02 帧触发 `ensure` → 删 part → 组装失败，整组已传数据丢失。
- 修复：TTL 分支同样跳过 `assembling`；或组装期间续期 `last_seen`。
- 复核：主审已读码确认。

### P1-6 Web 上传无 fsync、无写透发布 → 掉电后最终名文件可能空/截断
- 位置：`crates/trft-server/src/lib.rs:929`（`drop(out)`）、`:944`（`hard_link` 发布）
- 证据：
```rust
drop(out);                                   // 无 flush/sync_all
match tokio::fs::hard_link(&part, &cand).await { Ok(()) => { ... } }
```
  退化拷贝分支（975）有 `dst.sync_all()`，正常 NTFS 路径没有；core 已于 F2/F3 全面改用 `MoveFileExW(WRITE_THROUGH)`。
- 影响：上传 1 个文件 → 303「已接收」→ 数秒内硬断电：文件名在、内容可能不完整（与 B3 同型数据丢失）。
- 修复：`out.flush().await` + `out.sync_all().await` 后再发布；发布复用 `trft_core::publish::move_noreplace`。
- 复核：主审已读码确认。
## 二、P2（按修复成本排序）

| # | 结论 | 位置 | 影响 | 修复 | 复核 |
|---|---|---|---|---|---|
| P2-1 | C# 方言 0x00/0x01/0x02 发布仍用 `hard_link + remove_file`（无写透） | cswire.rs:191-195 | 掉电后「数据在、名字丢」，7 天后孤儿清扫删残件 | 改 `publish::move_noreplace`，保留冲突重名 | 主审 ✓ |
| P2-2 | 0x02 完成、0x04 追加分支发布前无 `sync_all` | cswire.rs:2303-2334、2944-2960 | 完成回执后硬断电 → 最终名尾部为零 | 发布前 `sync_all` | 主审 ✓ |
| P2-3 | 0x03 会话不绑定文件名（`CsResumeState.name` 存而不用） | cswire.rs:2427-2472 | 同 NAT 下同名同尺寸文件共享会话：回「已完整」或从他处偏移续写 | existing 元组加 name 比对，Done 分支同时比 hash | 主审 ✓ |
| P2-4 | 0x04 清单整表驻留 + `manifest_total` 无检查累加 | cswire.rs:2745-2757 | 1 条连接可占 ~4GiB；约 0.7MB 输入即可让 u64 回绕，架空总长校验 | 清单累计字节预算 + checked 加法 | 主审 ✓ |
| P2-5 | 缓存族文件名接收侧不拒绝；journal 的 `.bak` 漏出排除名单 | hashcache.rs:236-256、config.rs:258 | 对端可把伪造 `.trft-hash-cache-server.txt` 落进保存目录（投毒续点）；重写后 8MB `.bak` 会被当用户内容外发 | 落盘名统一拒绝缓存族 + 补 `SERVER_CACHE_BAK` 判定 | 主审 ✓（本次新增 journal 的副作用） |
| P2-6 | `stats.log` 重写只按 5000 行截断、不按字节 | stats.rs:108-126 | 长行场景重写后仍 >2MB → 每条统计全量读+写（含 `.bak`）永续放大 | 按字节从尾累计；重写后仍超则减半 | 主审 ✓ |
| P2-7 | 单向 UDP 会话表全局最旧逐出并删 `.part` | udp.rs:764-777 | 任意主机 64 个 START 即可逐出他人进行中会话并删半成品 | 按来源分桶（同 chunked 口径），不跨 peer 删 | 主审 ✓ |
| P2-8 | 单向 UDP 异步收尾未置投递抑制；每个收尾 job 起一个 OS 线程且无上限 | udp.rs:1101-1114、1484-1504 | 第 2 轮 START 可能与收尾线程并发写同一 `.part`；空文件 START 可高频刷线程 | 入队前 `mark_suppressed`；固定 worker 池 | 子审查（代码位置已核对） |
| P2-9 | QUIC 建流后读版本字节无超时，保活连接可长期持有并发许可 | quic.rs:383-390 | 64 条零数据连接可占死 64 个许可 | `read_u8` 套 30s 超时 | 主审 ✓ |
| P2-10 | RUDP/UDT 在取并发闸前建连接状态与缓冲 | rudp.rs:1360-1386、udt.rs:1773-1810 | 连接表 256 远大于 64 许可，等闸期间缓冲可被打满（RUDP ≈1.2GB、UDT ≈9GB 峰值） | 许可前移到建状态之前，或加未读字节预算 | 子审查 |
| P2-11 | UDT 周期 NAK 用全部 loss 表一次编码，可远超单包上限 | udt.rs:889-899 | 重丢包时 NAK 被丢/触发硬错误计数，恢复通道失效 | 按载荷上限分批发 NAK | 子审查 |
| P2-12 | UDT `poll_write` 先查窗后注册通知，存在丢失唤醒 | udt.rs:1110-1130 | 窗口打满瞬间的 ACK 通知丢失 → 写侧挂到空闲超时 | 先注册 `notified` 再查窗；或 `notify_one` 存 permit | 子审查（与注释自述顺序相反，已核对注释） |
| P2-13 | `/login` 豁免并发闸且请求体无空闲超时 | trft-server/lib.rs:216-217、374-378 | 未认证可慢滴 body 无限占用连接与 fd | 给 body 提取套 `BODY_IDLE_TIMEOUT` | 子审查（代码位置已核对） |
| P2-14 | `token_secret` 定长切片无校验，短值 panic 且发生在持配置锁时 | commands.rs:1418-1429 | 配置被手工改短 → 启动共享 panic，配置锁中毒后全命令连锁 panic | `Config::validate` 校验 64 hex；解析失败重生成 | 主审 ✓ |
| P2-15 | `recv_start`/`http_start` 忽略保存目录创建失败 | commands.rs:1015、1410 | 无效路径仍报启动成功并把坏路径持久化，来传文件全在落盘阶段失败 | 失败回滚占位并返回明确错误 | 主审 ✓ |
| P2-16 | Web serve 遇单次 accept 错误整体退出，GUI 槽位仍显示运行中 | trft-server/lib.rs:1237-1238、commands.rs:1460-1466 | 瞬态错误（Windows RST/EMFILE）后共享实际停止，UI 不同步 | accept 错误分类 continue；GUI 收尾清槽+发事件 | 主审 ✓（服务端）；GUI 侧子审查 |
| P2-17 | v2 0x04 / 0x01(Skip) 落盘路径缺 `ensure_contained` | resume.rs:409-510、folder.rs:304 | 保存目录内预置 junction 可把对端相对路径写出目录（cswire 侧有该防线） | 提取公共助手，建目录前后各校验一次 | 主审 ✓（`resume.rs` 全文无该调用） |
| P2-18 | 0x04 无会话串行化：并发同步同时回成功，缓存回填可投毒 | resume.rs:506-511 | 后发布者覆盖前者且双方都回 OK；摘要按对方 (size,mtime) 键回填 | 按 (root,rel) 串行化；发布后按 present 复核再回填 | 子审查 |
| P2-19 | 0x03 在 `offset == size` 时跳过 `sync_all` 直接发布 | resume.rs:343-397 | part 已满但未落盘时校验通过并发布，掉电后截断 | `sync_all` 移出 `if offset < size` | 子审查 |
| P2-20 | 连接任务 panic 无隔离：JoinSet 静默吞掉，接收器任务 panic 时 UI 状态不同步 | cswire.rs:1870-1885（`while set.try_join_next().is_some() {}`）、commands.rs:1134-1137 | 一次 panic 若发生在持锁期间会毒化 `CsServerState` 的互斥量，后续连接全部 `.expect` panic，接收器「假运行」 | JoinSet 结果打印；接收任务加 `catch_unwind` 或监督重启 | 主审 ✓ |

## 三、P3（可选修复 / 观察项）

| # | 结论 | 位置 | 说明 |
|---|---|---|---|
| P3-1 | 更新器相对重定向直接拼到 authority | update.rs:263-273 | `Location: file.exe` → `https://hostfile.exe`；`.evil.com/x` 可把连接引向第三方主机（清单有 ed25519 验签，不能投毒，但属误连） |
| P3-2 | `sanitize_name` 的 Cf 黑名单缺 U+2066–2069/U+061C 等 | protocol/frame.rs:63-74 | bidi isolate 同样可视觉反转扩展名；建议按 Unicode 类别拒全部 Cf |
| P3-3 | 发现应答 1 字节探测 → ≥5 字节应答、无速率限制 | discovery.rs:289-318 | 可被伪造源反射放大；建议每源令牌桶 |
| P3-4 | monitor 非 Windows 用追加写打开判就绪 | monitor.rs:383-388 | 只读文件永不发送（Windows 分支无此问题） |
| P3-5 | 设备记忆 `last_seen` 秒级 + 稳定排序截断 | devices.rs:69-92 | 同秒新增的第 11 台会被当场丢弃 |
| P3-6 | 配对失败双重计数（握手层一次 + `conn_settle` 一次） | cswire.rs:987/996 + receiver.rs:574 | 实际 5 次错码即锁 10 分钟（文档/QA 为 10 次） |
| P3-7 | 0x04 续点扫描的整文件 SHA-256 在 async 任务内同步执行 | cswire.rs:1409 及调用点 | 64 并发冷文件哈希可占住 tokio worker；v2 路径均走 `spawn_blocking` |
| P3-8 | 0x0B 查询持全局表锁 await 会话锁 | chunked.rs:415 | 慢盘写停顿可阻塞所有新组 `ensure` |
| P3-9 | 0x03 会话锁跨 5 分钟网络读持有 | resume.rs:289-290 | 同名连接可占满并发许可等锁 |
| P3-10 | 0x01 中途失败后已发布文件留在新根目录，无回滚 | folder.rs:375 | 重试生成 `root_1`，半套目录残留 |
| P3-11 | `collect_files` 遍历完才判文件数上限 | folder.rs:64 | 百万文件目录可先吃满内存 |
| P3-12 | 孤儿半成品清扫深度封顶 6 | receiver.rs:466 | 深层 `.trft-part` 崩溃残件永不清扫 |
| P3-13 | 已完成组的重复 0x0C 每次计一次成功 | receiver.rs:967 | 可把 `--count` 限额接收器提前打满 |
| P3-14 | `send_cancel` 的 `user_cancelled` 记账不回收 | commands.rs:603-616 | 直发/取消路径永久留 ID（无界小泄漏） |
| P3-15 | `trft-server` 的 `--bind` 非法直接 panic | trft-server/main.rs:50-70 | 应为用法错误 exit 2 |
| P3-16 | CLI 组合校验漏网：`sync --pin` 对非 QUIC 静默无效、`recv --proto udp --noencrypt` 被吞、`--port 0` 未拒 | cli/main.rs:576-579、463-486、55-58 | 参数被静默忽略，与 send 分支口径不一致 |
| P3-17 | Web 上传半成品名在原名上加 13+ 字节 | trft-server/lib.rs:877-885 | 250 字符名在 Windows 必超 255 → 500 |
| P3-18 | 服务端 journal 每文件一次 `File::flush`（Windows 即 `FlushFileBuffers`） | hashcache.rs、cswire.rs:1419/1427 | 大目录 0x04 同步每文件多一次 fsync，元数据开销翻倍（本次新增 journal 的副作用） |
## 四、复核为无问题的重点区域

- **帧解析边界**：0x00/0x01/0x02/0x03/0x04/0x06 的长度前缀均先校验再转 `usize`（名 4096、文本 1MB、`total ≤ 1PiB`、`offset + chunk ≤ total`、`fileCount ≤ 1M`、加密段 ≤256KB、压缩段 ≤64MB、区间 ≤8192），未见负长度/越界/切片 panic。
- **路径净化**：`sanitize_name` / `sanitize_rel` 逐段拒绝 `..`、空段、`/`、`\`、冒号、控制与 Cf 字符、尾点/尾空格、Windows 保留名；`resolve_under`（Web）额外拒绝绝对路径与盘符前缀；`resolve_save_dir` 对设备名做净化、IPv6 冒号替换。
- **加密与压缩**：AES-256-CTR + 截断 HMAC 先验后解、tag 绑定 seq/iv、`ct_eq` 恒时比较；ECDH(P-256)+HKDF 分 c2s/s2c；IV/私钥/握手随机全部 `OsRng`；解压 `Take(limit+1)` 硬上限 + 增量缓冲。
- **发布原子性**：v2 / UDP / 0x03 / 0x04 均走 `publish.rs` 的 `MoveFileExW(WRITE_THROUGH)`，fail-if-exists 由原子操作兜底，拷贝回退失败会清候选。
- **并发与资源上限**：trackers 64 / resume 256 / group_peers 4096 / sync_hashes 200k / declared_total 64GiB / RUDP·UDT 连接表 256 / 分块单来源配额；`std::sync::Mutex` 临界区内无 `.await`。
- **Web 安全**：`ct_eq` 校验令牌、会话 `HttpOnly + SameSite=Strict`、删除 CSRF 双提交、模板 `html_escape`/`url_escape`、CSP/XFO/nosniff 齐全、上传 4GB 整请求 / 2GB 单文件 / 1000 字段上限。
- **更新器**：清单 `verify_strict`（内嵌 ed25519 公钥）、https 强制（明文仅回环）、逐跳重定向重新解析、下载流式 SHA-256 + 换入前后双校验。

## 五、已登记/已接受（本次不重复计为缺陷）

- Web 共享目录内的符号链接/junction 会被跟随（`REVIEW-LOG` 与 `TECH-STACK §7` 已登记为「本地攻击者出模型」，不改）。
- 摘要缓存行只做 FNV-1a 行校验、非 MAC（同上，属本机 tamper 面）。
- 无配对码时任何 LAN 主机可发起传输（产品默认值，配对码为可选加固）。

## 六、建议修复顺序

1. **P1-1 / P1-2**（一行级钳制与错误分类，风险收益最高，配两条判别测试）。
2. **P1-3 / P1-4**（0x03 完成判定与 0x04 删除路径，涉及数据正确性；改完补 e2e：同尺寸改内容重发、读失败保留）。
3. **P1-5 / P1-6**（分块逐出与 Web 上传落盘；均为条件触发但后果是数据丢失）。
4. **P2 批次 A（耐久性）**：P2-1、P2-2、P2-5、P2-6、P2-19 —— 统一到 `publish` + `sync_all` 纪律。
5. **P2 批次 B（远程 DoS）**：P2-4、P2-7、P2-8、P2-9、P2-10、P2-13、P2-20。
6. **P2 批次 C（正确性）**：P2-3、P2-17、P2-18、P2-11、P2-12、P2-14、P2-15、P2-16。
7. **P3** 按模块顺手收敛（多数是 1–5 行改动 + 注释更新）。

## 七、方法说明

- 5 个子审查各自独立上下文，按「数据丢失 → 对端输入导致的 panic/越界/无界分配 → 并发 → 路径安全 → 认证授权 → 资源上限」六维逐文件通读，要求每条给出代码原文与触发场景。
- 主审对全部 P1 与 P2-1…P2-7、P2-9、P2-14…P2-17、P2-20 逐条回读源码复核；未亲自复核的条目已在上表「复核」列标注「子审查」。
- 静态检查与测试基线未改动代码，保证结论对应提交 `b540977`（`main` HEAD）。

## 八、修复记录（2026-11-23，同日完成）

全量回归：`cargo test --workspace` **361 passed / 0 failed**（审查基线 317，新增 44 条判别/回归测试）；
`cargo clippy --workspace --all-targets` 0 error（53 warning，均为风格项）。

### P1（6/6）

| 条目 | 修复 | 判别测试 |
|---|---|---|
| P1-1 | 抽 `transfer::udp::is_transient_udp_err`（10040/90/40/97 + 10054），RUDP/UDT/UDP 三处共用 | `udp.rs::transient_udp_errors_are_classified` |
| P1-2 | `SendState::new` 统一 `clamp(2, UDT_FLIGHT_FLAG)`，握手两路传原值 | `udt.rs::handshake_flow_window_is_clamped` |
| P1-3 | `CsResumeState.verified_hash`；Done 分支比对客户端整文件哈希，不符则作废按新传（保留旧档） | `e2e_interop.rs::resume_done_must_match_hash_not_only_size` |
| P1-4 | 0x04 复核改用 `spawn_blocking + ??`（读失败报错保留文件）；`sync_hash_of` 改 `Option` 且失败不写缓存/journal | 现有 0x04 e2e + 新增 resume 用例 |
| P1-5 | chunked TTL 逐出跳过 `assembling`（try_lock 失败视同组装中） | `chunked.rs::ttl_eviction_skips_assembling_group` |
| P1-6 | Web 上传 `flush + sync_all` 后发布，发布改 `publish::move_noreplace` | `web.rs::upload_long_filename_uses_short_part_name`（走新发布路径） |

### P2（20/20）

| 条目 | 修复 |
|---|---|
| P2-1 | `cs_publish` 改 `publish::move_noreplace`（WRITE_THROUGH），保留冲突重名与拷贝回退 |
| P2-2 | 0x02 完成与 0x04 追加发布前 `sync_all` |
| P2-3 | 0x03 会话表比对文件名（`CsResumeState.name` 不再存而不用） |
| P2-4 | 清单路径累计 ≤16MiB + `manifest_total` checked 加法 |
| P2-5 | `is_cache_artifact` 按前缀覆盖 journal 的 `.bak`；接收落盘名（v2 `sanitize_name`/`sanitize_rel`、C# `cs_safe_name`/`cs_sanitize_rel`）拒绝缓存族与半成品名 |
| P2-6 | `stats.log` 重写按字节从尾累计 + 5s 节流 + 减半重试 |
| P2-7 | UDP 会话按来源分桶（每源 8），全局满拒绝新来源 |
| P2-8 | 异步收尾入队前 `mark_suppressed`；收尾改 `spawn_blocking`，空文件同步快速路径 |
| P2-9 | QUIC 建流后首字节读 30s 超时 |
| P2-10 | RUDP/UDT 在建连接状态前 `try_acquire` 并发许可，许可由连接任务持有（内层传 1 许可副本） |
| P2-11 | UDT 周期 NAK 按单包上限分批（364 字/包） |
| P2-12 | UDT `poll_write` 改「先注册通知 → 二次查窗 → Pending」 |
| P2-13 | `/login` body 读取套超时（`TimedBody` 提取器，408） |
| P2-14 | `parse_hex32` 校验 64 hex；锁外解析，非法/缺失即重生成并保存 |
| P2-15 | `prepare_save_dir`：创建失败/非目录 → 回滚占位并报错，成功后才写回配置 |
| P2-16 | serve 循环分类瞬态 accept 错误并退避重试 |
| P2-17 | `ensure_contained` 提升到 receiver，v2 0x01/0x04 的 base 与每个 parent 前后各校验 |
| P2-18 | 0x04 按根名会话锁（30s 等待上限）；发布后按发布前 mtime 复核再回填缓存 |
| P2-19 | 0x03 打开句柄与 `sync_all` 移出 `if offset < size` |
| P2-20 | 连接任务 JoinSet 结果打印 panic；GUI 接收器改监督外壳（panic 时 emit 并走收尾） |

### P3（18/18）

| 条目 | 修复 |
|---|---|
| P3-1 | 更新器按 RFC 3986 解析相对重定向 + 拒绝跨 host |
| P3-2 | `has_format_char` 改为完整 Cf 码位表（含 U+2066–2069、U+061C、Tag 字符） |
| P3-3 | 发现应答加每源 5 次/秒 + 全局 200 次/秒令牌桶 |
| P3-4 | monitor 非 Windows 就绪探测改只读打开 |
| P3-5 | 设备 `last_seen` 改毫秒；截断先剔除最旧再 push |
| P3-6 | 删除握手层 `gate.fail`，失败只由 `conn_settle` 记一次（阈值恢复 10 次） |
| P3-7 | 0x04 续点/跳过与 0x04 复核的整文件哈希全部移入 `spawn_blocking` |
| P3-8 | `ranges_of` 先 clone Arc 释放会话表锁再取状态锁 |
| P3-9 | 0x03 会话锁加 30s 获取超时 |
| P3-10 | 0x01 Rename 模式新根加 `NewRootGuard`，失败回滚整根（Skip 不动） |
| P3-11 | `collect_files` 在 walk 内达上限即报错 |
| P3-12 | 孤儿清扫改显式栈 + 深度 64（receiver 与 resume 两处） |
| P3-13 | 0x0C 按 gid 只计一次成功（`counted` 原子标志） |
| P3-14 | 队列子任务用 `QueueChildGuard` 记账，直发不再残留 |
| P3-15 | `trft-server` 非法 `--bind` → exit 2，运行错误 → exit 1 |
| P3-16 | CLI：`sync --pin` 守卫、UDP 拒绝 `--noencrypt`、端口 range(1..=65535) |
| P3-17 | 上传半成品名改固定短名 `.up{8hex}.part` |
| P3-18 | journal 追加改 64 行攒批 flush（Drop 兜底、重写/保存前清空计数）；崩溃最多丢最近 63 条，只多算一次哈希 |
