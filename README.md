# GoPass 🚀

A high-performance, Zero-Copy transparent proxy for Windows, tailored for extreme resource optimization and granular process-level bypass control.  
一款为 Windows 打造的高性能、零拷贝（Zero-Copy）透明代理终端，专为极限压榨硬件资源以及进程级管控而生。

---

## 🌟 Key Features / 核心特性

- **True Transparent Proxy (真正的透明代理)**  
  Uses `WinDivert` to operate at the network layer. No need to configure system proxies. Instantly intercepts traffic from applications that do not naturally support proxy settings.  
  使用 `WinDivert` 运行在操作系统的网卡底层，**无需设置系统代理**，可直接强行接管一切不懂也没有代理设置选项的软件。

- **Zero-Copy & `sync.Pool` (零损耗转发)**  
  Achieves a flat-line memory footprint and minimal CPU overhead by utilizing native kernel-level `io.Copy` and recycling memory buffer pools. Safe to run silently on low-end devices.  
  原生内核级 `io.Copy` 对拷与内存池（`sync.Pool`）加持，彻底解放 Go 语言 GC，实现零损耗、零波动的极限压榨性能，甚至能在极度受限的设备上静默运行。

- **Intelligent SNI Sniffing (智能 SNI 域名防污染)**  
  Extracts real domain names from the `TLS ClientHello` packet to prevent IP blocking and DNS pollution (e.g., YouTube/Google playback errors).  
  穿透取 SNI 真实域名，将完整的请求直接喂给远端代理隧道，完美解决局域网内建 DNS 解析被污染或伪造等问题。

- **Real-Time Web UI (实时可视化面板)**  
  Built-in local dashboard at `http://127.0.0.1:8080`. Monitor massive active connections, one-click add bypass rules, and manage settings via a sleek interface.  
  极度炫酷丝滑的本地 Web 控制台，支持查看海量活动连接、追踪直连/代理流向、一键拉黑/放行直连进程。

- **Hot-Reloadable SOCKS5 & HTTP (动态上游与热重载)**  
  Supports routing to SOCKS5 or HTTP upstream proxies. UI settings changes (Protocol/IP/Port) are injected to the background engine instantly—zero downtime or restarts required.  
  原生支持 SOCKS5 与 HTTP CONNECT 协议作为上游，前端大屏随心切换。点击保存**瞬间后台热重载**，不再需要修改 JSON 忍痛重启断网。

---

## 📥 Installation & Usage / 安装与使用

1. **Download / 下载**  
   Compile from source using `go build` or download the ultra-slim release executable `gopass_1.6.3.exe`.  
   根据源码自行编译，或直接下载极限瘦身的成品执行文件 `gopass_1.6.3.exe`。

2. **Run as Administrator / 提权运行**  
   ⚠️ GoPass **MUST** be run as Administrator because the `WinDivert` driver requires high-level system permissions.  
   ⚠️ **必须以管理员身份运行**，这是 `WinDivert` 驱动劫持网卡的硬性需求。

3. **Open Dashboard / 打开控制面板**  
   Visit `http://127.0.0.1:8080` in your favorite modern browser.  
   保持黑框后台常驻，在现代浏览器中大方打开 `http://127.0.0.1:8080` 进入极简看板。

4. **Configure Upstream / 配置节点**  
   Head to the **Settings** tab and enter your local/remote upstream proxy (e.g., `127.0.0.1:1080` -> SOCKS5). Click save.  
   在 **Settings** 面板中填写你真实的远端或本地中转代理地址（如 `127.0.0.1:1080` 选 SOCKS5）。

5. **Whitelist Processes / 进程白名单**  
   By default, GoPass operates in `Whitelist` mode. Go to the `Dashboard` and click **Add to Rules** for applications you wish to route through the proxy.  
   默认处于 `Whitelist（白名单）` 劫持模式。在仪表盘看见目标软件后，轻轻一点 **Add to Rules**，流量即刻起飞。

## 📝 Release Notes / 更新日志 (v1.6.2)

- **🛡️ 调度控制中心专项审计与加固 (Route Controller Hardening)**：
  - **Health / Failure 判定语义严密化**：严格区分明确成功、明确失败与指标缺失；缺失握手字段绝不盲目制造成功状态；`FailureCount` 与 `SuccessCount` 严格互斥自增与清零。
  - **真实物理时间劣变跟踪**：彻底废弃基于探测周期的累加方案，改用高精度 `degradedSince` 物理时间戳跟踪连续劣变时长，达到 20 秒稳定退化才流转状态，完全消除视频播放与大文件下载防误切隐患。
  - **Active / Standby 严格一致性**：保证全系统在任何时刻存在且仅存在唯一一个 `ACTIVE` 节点；`FAILED` 与 `RECOVERING` 节点严禁进入 `Standby` 备用池。
  - **候选防抖与稳定时间重置**：防抖计时统一收归控制器状态机管理，候选退化或被反超立即清空观察时间，彻底杜绝历史残留时间导致的误切。
  - **紧急故障转移 (Emergency Failover)**：当当前活跃节点彻底故障（连续失败达到阈值）时，立即启动紧急晋升流程，无视常规切线冷却期，确保高可用不陷于死等。
  - **严格恢复阶梯 (Recovery Threshold)**：`FAILED` 节点探测成功仅先进入 `RECOVERING`，必须连续成功达到门槛次数才恢复至 `READY`，杜绝诈尸节点颠覆生产。
  - **并发安全与零宕机热切验证**：完善所有并发读写锁粒度与只读原子快照，消灭多协程竞态风险；经由本地 RFC1928 Mock SOCKS5 测试验证，上游切换期间老长连接绝不断流、新连接秒级走新节点。
  - **Web 端与系统全栈版本同步**：Web UI 与后端启动内核统一升级至 `v1.6.2`。

---

## 📝 Release Notes / 更新日志 (v1.6.1)

- **🎯 动态线路控制中心深度加固与指标增强**：
  - **SingleSpeed 与 FinalScore 透出**：API 返回结构与外部指标上报补充单次测速 (`SingleSpeed`) 与最终综合评分 (`FinalScore`)，让看板和外部监控对调度决策依据一目了然。
  - **初始平滑切线守卫优化**：完善 `AutoEnabled` 首次启动或初始上游为空时的防抖逻辑，允许首选就绪节点瞬间无缝挂载，无需等待冷启动保护期，进一步提升初次调度体验。
  - **状态机与探针微调**：优化高频探测与健康恢复评估边界条件，确保高丢包及网络抖动环境下节点降级与回切行为更稳健。

---

## 📝 Release Notes / 更新日志 (v1.6.0)

- **🔀 核心重磅升级：Windows 全局透明代理 + 动态线路调度中心 (Dynamic Route Controller)**：
  - 将 GoPass 从“固定上游代理”升级为**全局透明代理与动态调度控制中心**。
  - **9 状态线路状态机 (State Machine)**：严密管理 `UNKNOWN`, `TESTING`, `READY`, `ACTIVE`, `DEGRADED`, `FAILING`, `FAILED`, `RECOVERING`, `STANDBY`，严禁非法跳跃（如禁止直接 ACTIVE -> FAILED 悬崖跳跃），状态流转具备严格守卫条件。
  - **多维度综合评分 (Scorer)**：拒绝“低 Ping = 最佳”，综合加权速度（含最低速度保证）、稳定性指数、丢包率、Jitter、RTT 延迟、握手状态与时段系数；分 Normal Mode 与 Peak Mode 两套自适应权重。
  - **历史多窗口平滑计分 (Historical Smoothing)**：融合 `InstantScore`（40%）、`ShortTermScore`（40%，5~15分钟 EWMA 平滑）与 `LongTermScore`（20%，数小时平滑），杜绝单次瞬时虚高测速颠覆长期稳定节点。
  - **自适应高峰期策略 (Peak Hour Strategy)**：支持 `auto` / `scheduled` / `always` / `never`，维护 24 小时每时段聚合指标（平均/最低速度、RTT、丢包、Jitter、失败率），随时间自动感知高峰期并倾斜稳定与低丢包权重。
  - **温备用池 (Warm Standby)**：维护 1 个 `ACTIVE` 节点与前 3 个高分 `STANDBY` 热备节点；实施分级轻量心跳探测（Active 5s 高频、Standby 30s 低频、Failed 120s 恢复探测，并发控制池），控制 CPU 与网络开销。
  - **防抖动机制 (Anti-Flapping)**：具备 `SwitchThreshold` 门槛分差、`SwitchCooldown` 冷却时间、`MinimumStableTime` 稳定观察期、`FailureThreshold` 连续失败门槛与 `RecoveryThreshold` 恢复门槛，彻底防止 A<->B 频繁来回震荡。
  - **零中断平滑热切 (Zero Downtime Hot Upstream Switching)**：利用 GoPass 现有 `UpdateUpstream()` 与原子替换机制；切换节点时，**已有长连接（如 YouTube 4K、大文件下载、SSH 等）继续由旧节点套接字转发，绝不断流！新连接瞬间接入新节点！**
  - **视频/长连接防误切保护**：短时间（如 3 秒）测速波动不切，仅在持续劣变（>20秒且丢包/抖动抬升）才进入 DEGRADED，全面保护影音流媒体体验。
  - **CFST 数据无缝接入**：GoPass 自身零依赖、不复制代码、不侵入 GOWAY 与 CFST；通过标准 RESTful 接口 `POST /api/routes/report` 接收外部 CFST 或测试工具的质量指标 JSON，支持单条或批量。
  - **RESTful API 矩阵**：提供 `/api/routes`, `/api/routes/current`, `/api/routes/standby`, `/api/routes/metrics`, `/api/routes/switch`, `/api/routes/enable`, `/api/routes/disable`, `/api/routes/report`。
  - **异步周期持久化**：内存高速运行，每 5 分钟异步批量持久化时段统计与线路数据至 `routes_history.json`，零磁盘 I/O 阻塞。

---

## 📝 Release Notes / 更新日志 (v1.5.2)

- **⚡ Web UI 加载提速**：移除头部 Google Fonts 渲染阻塞外链（国内直连被墙会卡 12s+，走代理也要 ~1s），字体改用系统栈（Segoe UI / Microsoft YaHei），UI 现在 100% 本地加载、毫秒级打开。
- **🛡️ WebSocket 广播写超时**：为广播写入增加 5s deadline，防止单个挂死的 UI 标签页阻塞整个广播循环导致所有面板停更。

---

## 📝 Release Notes / 更新日志 (v1.5.1)

- **♻️ 配置一键复位**：Settings 新增「Danger Zone」复位按钮（`POST /api/config/reset`），将全部配置（上游代理 / 模式 / 白名单 / split 分流 / 性能 / DNS 中继）复位为出厂默认值并**热生效**，同时写回 `config.json`。
- **🔄 规则文件下载进度条**：`Update Rule Files` 按钮新增实时进度条（按文件显示 `done/total`，来自 Content-Length），`GET /api/split/update-rules` 轮询进度快照；带并发保护（更新中重复触发返回提示）。
- **🧪 新增单元测试**：`TestUpdateTracker`（下载进度状态机）、`TestResetConfigSavesDefaults`（复位配置落盘）。

---

## 📝 Release Notes / 更新日志 (v1.5.0)

- **🌏 新增「绝对分流」Split Routing（中国站直连 / 国外站强制代理）**：
  - 基于真实目标的地理分流：SNI 域名（geosite:cn）优先，其次目标 IP（geoip:cn）；中国站强制直连，国外站强制走上游代理。
  - 支持 `geo` / `process` / `both` 三种模式与可配置优先级（`geo_priority`），与原有进程白名单无缝共存、热重载。
  - **🛡️ 零中国痕迹**：真实 IP 绝不泄漏（代理失败不直连回退）、DNS 中继杜绝系统/DoH/DoT 泄漏（国外域名经上游代理走 DoT 解析）、国外 UDP（QUIC/STUN/TURN）一律丢弃、IPv6 默认全屏蔽。
  - **📦 规则内置**：geosite:cn（6,417 条域名）与 geoip:cn（8,070 个 IPv4 网段）经 `//go:embed` 直接编译进二进制，开箱即用；磁盘规则文件存在时优先加载（支持在线更新 / 自定义），删除磁盘文件即恢复内置版本。
  - 规则文件在线更新（Web UI 一键 / `auto_update_hours` 定时），支持 v2ray geosite/geoip `.dat`、纯文本列表、MaxMind GeoLite2 CSV。
  - Web UI `Settings → Split Routing` 面板：开关、模式、优先级、IPv6/UDP 策略、DNS 中继、自定义直连/代理列表、规则更新与加载统计。

---

## 📝 Release Notes / 更新日志 (v1.4.9)

- **🧩 完美解决 Cloudflare Turnstile "卡住？故障" 循环**：
  - 深度扩充 `netstat.go` 进程探测能力，全量补齐 Windows UDP 端口映射表 (`GetExtendedUdpTable`) 动态检索。
  - 解决先前因 UDP 端口 PID 未查到而导致的 QUIC 验证数据包走本地宽带 IP 泄露问题，精准拦截受控进程出站 UDP 443，使 Cloudflare 人机验证能够在 0.5 秒内秒过。
- **🛡️ Zero-Data-Loss TLS SNI 嗅探器**：
  - 无论 SNI 提取结果或分片与否，100% 完整保留并透传 TLS ClientHello 报文，彻底避免远端服务器因首包缺失而中断 SSL 握手。
- **⚡ 极致转发与吞吐提速**：
  - 解封 Windows 原生 TCP Window Auto-Tuning 动态窗口调优算法，大幅提升大文件下载与并发吞吐。
  - 单次内存缓冲区调整为 CPU L1/L2 Cache 友好的 32KB/64KB 组合。
  - 全局复用 Upstream Proxy Dialer，降低高并发建连延迟与 GC 锁开销。

---

## 🌏 Split Routing (绝对分流) — 中国站直连 / 国外站强制代理

GoPass 新增**基于目标地理位置的绝对分流**：中国大陆网站/IP 强制直连，中国以外网站/IP 强制走上游代理。分流决策基于**真实目标**（优先 TLS SNI 域名，其次目标 IP），而非客户端进程。

### 配置（config.json）

> 本项目配置为 JSON 格式；字段名与下列 YAML 完全一致，直接照抄到 `"split": {...}` 即可。

```yaml
split:
  enabled: true            # 总开关
  mode: "both"             # geo（纯地理）| process（纯进程白名单）| both（同时启用）
  geo_priority: true       # true=地理分流优先于进程白名单（绝对分流）；false=仅白名单进程参与分流
  cn_direct: true          # 中国站强制直连
  foreign_proxy: true      # 国外站强制走代理（零泄漏）
  block_ipv6: true         # 屏蔽全部出站 IPv6（防 IPv6 泄漏，推荐开启）
  rule_files:
    geosite: "geosite.dat" # geosite.dat / 文本域名列表 / GeoLite2 CSV
    geoip: "geoip.dat"     # geoip.dat / 文本 CIDR 列表
  custom_direct: []        # 自定义强制直连：域名 / full: / keyword: / regexp: / CIDR
  custom_proxy: []         # 自定义强制代理：同上
  # ---- 「零中国痕迹」附加配置 ----
  dns_relay_port: 5300     # 本地 DNS 中继端口（0=关闭 DNS 劫持，不推荐）
  system_dns: ""           # 中国域名解析 DNS（留空=应用原始 DNS 服务器）
  dot_server: "1.1.1.1:853"        # 国外域名 DoT 服务器（经上游代理出口）
  dot_sni: "cloudflare-dns.com"    # DoT TLS SNI
  block_foreign_udp: true  # 丢弃国外 UDP（QUIC/STUN/TURN 零泄漏）
  auto_update_hours: 0     # 规则文件自动更新间隔（小时），0=关闭
  update_urls:
    geosite: "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
    geoip: "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
```

> ⚠️ **向后兼容**：旧版 `config.json` 没有 `split` 块时，分流保持关闭，原有进程白名单行为完全不变。新生成的默认配置会开启 `both` 模式（绝对分流）。

### 分流优先级（自高到低）

1. **自定义规则** `custom_direct` / `custom_proxy`（先域名后 IP）
2. **进程优先级**（`both` + `geo_priority=false` 时）：非白名单进程直连旁路
3. **地理判定**：SNI 域名（geosite:cn）→ 未命中再目标 IP（geoip:cn）
4. **fail-safe**：无法判定的一律按国外处理（走代理），**绝不直连泄漏**

### 规则文件

- **📦 开箱即用**：geosite:cn（6,417 条域名规则）与 geoip:cn（5,070 个 IPv4 网段）已通过 `//go:embed` **直接编译进 GoPass 二进制**，无需下载任何文件即可启用分流。
- **磁盘覆盖（可选）**：磁盘上的 `geosite.dat` / `geoip.dat`（或自定义 `.txt/.list/.csv`）存在时优先加载磁盘文件；可用 `.tools\download.ps1` 或 Web UI `Settings → Split Routing → Update Rule Files` 一键在线更新到最新版。**删除磁盘文件即恢复内置版本。**
- **重新生成内置规则**：运行 `.tools\download.ps1` 获取最新 `.dat` 后，执行 `go test -tags genrules -run TestGenEmbeddedRules ./internal/engine/`，重新编译即可把最新规则固化进二进制。

### 🛡️ 「零中国痕迹」保障机制

| 泄漏途径 | 防护措施 |
|---|---|
| 客户端真实 IP | 国外流量必须经上游代理出口；**代理连接失败直接断开，绝不直连回退** |
| DNS 泄漏（系统/DoH/DoT） | DNS 中继劫持 UDP 53：中国域名走系统 DNS；**国外域名经上游代理走 DoT（1.1.1.1:853）解析**，全程不触碰中国境内解析器。应用的 DoH/DoT（TCP 853/443）按地理分流走代理 |
| WebRTC / STUN / TURN | 国外目标 UDP 一律丢弃（含 STUN 3478、TURN 3478/5349、QUIC 443），WebRTC 无法通过 UDP 探测到本地 IP |
| IPv6 泄漏 | `block_ipv6` 默认开启，出站 IPv6 全部静默丢弃 |
| QUIC / HTTP3 | 国外 UDP 443 丢弃，浏览器强制回退 TCP 经代理；中国站 QUIC 不受影响 |
| TLS ClientHello 指纹 | GoPass 是**透明 TCP 代理（无 MITM）**，ClientHello 由客户端应用原样透传，远端看到的即应用自身指纹；如需指纹伪装，请在上游代理（如 v2ray/xray + uTLS）层面实现 |

### Web UI

`Settings → Split Routing (绝对分流)`：一键开关、模式选择、优先级、IPv6/UDP 策略、DNS 中继、自定义直连/代理列表（一行一条）、规则文件在线更新，并实时显示 geosite:cn / geoip:cn 规则加载统计。

---

## 🔀 Dynamic Route Controller (动态线路调度中心)

GoPass v1.6.0 引入了**动态线路调度器**，使 GoPass 正式成为整个系统的调度控制中心。

### 架构流程

```
Windows 应用程序
      ↓
  WinDivert (网卡底层拦截)
      ↓
    GoPass (透明代理内核)
      ↓
Dynamic Route Controller (多维度打分 / 状态机 / 防抖)
      ↓
当前最优 GOWAY 节点 (SOCKS5 / HTTP)
      ↓
    GOWAY (外部高速隧道)
      ↓
   Internet
```

> ⚠️ **无侵入设计**：GOWAY 与 CFST 均为独立外部程序，GoPass 不依赖、不修改、不复制代码。GoPass 仅将 GOWAY 提供的本地/远端代理端口视为待调度线路，接收外部测速数据后调度最佳上游。

### 1. 线路状态机 (9 种状态流转)

每条线路具备明确的生命周期状态：
- `UNKNOWN`: 未初始化状态。
- `TESTING`: 正在进行连通性轻量校验。
- `READY`: 测量健康、就绪的候选线路。
- `ACTIVE`: 当前正在承担流量转发的最优活跃线路。
- `DEGRADED`: 出现持续劣变（对长连接有缓冲保护，防止 3 秒临时抖动误切）。
- `FAILING`: 劣变加剧，健康探测连续失败。
- `FAILED`: 连续失败达到 `failure_threshold`（默认 3 次），被判定为故障。
- `RECOVERING`: 故障线路在恢复探测中成功建连，开始观察复苏。
- `STANDBY`: 健康度与评分维持在前 N 名（默认 3 条）的温备用线路。

严禁非法跨状态跃迁（如禁止直接 `ACTIVE -> ACTIVE` 或直接跳崖 `ACTIVE -> FAILED`，故障必须经过降级确认）。

### 2. 线路评分与历史多窗口平滑

拒绝“Ping 最低 = 最佳”的片面策略，采用综合加权评分：
- **Normal Mode**: Speed 30%, Stability 25%, PacketLoss 15%, Jitter 15%, Latency 10%, Handshake 5%
- **Peak Mode**: Stability 30%, Speed 30%, PacketLoss 20%, Jitter 15%, Latency 5%
- **多窗口历史平滑**：
  $$\text{FinalScore} = \text{Instant} \times 0.4 + \text{ShortTerm} \times 0.4 + \text{LongTerm} \times 0.2$$
  融合瞬时测速、近期 5~15 分钟 EWMA 平滑与数小时长期表现，有效杜绝偶发虚高测速节点把长期稳定节点顶掉。

### 3. 高峰期时段自适应 (Peak Hour Strategy)

- 模式支持：`auto` | `scheduled` | `always` | `never`。
- 自动按小时（0 ~ 23）聚合并记录各线路的历史平均速度、最低速度、RTT、丢包率、Jitter 与失败率。
- 系统随时间持续学习，自动感知夜间高峰网络拥堵并切换至偏向稳定和低丢包的高峰计分策略。

### 4. 温备用池 (Warm Standby)

- 维护 1 条 `ACTIVE` 线路和前 3 条 `STANDBY` 备用线路。
- **分级低开销探测**：
  - `Active` 线路：高频检测（默认 5s），快速感知异常。
  - `Standby` 线路：低频检测（默认 30s），保证随时可顶上。
  - `Failed` 线路：超低频恢复检测（默认 120s）。
- 仅执行 SOCKS5 握手认证或 TCP 探活，单次仅传输数个字节，绝不高频全速压测，控制系统开销。

### 5. 防频繁抖动 (Anti-Flapping) 与平滑热切

- **防抖条件**：
  1. 新线路评分必须高于当前活跃线路评分至少 `switch_threshold`（默认 5.0 分）。
  2. 距离上次切换必须超过 `switch_cooldown`（默认 60s），除非当前线路已彻底故障。
  3. 候选新线路必须持续保持高分超过 `minimum_stable_time`（默认 30s）。
- **零中断平滑热切**：
  - 切换线路时，仅热更上游 Dialer 缓存；
  - **已有的长连接（如 YouTube 4K 播放、大文件下载等）继续由原有线路套接字转发，绝不杀掉旧连接，绝不断流！**
  - **新发起的网络请求立即使用新选出的最优线路建连。**

### 6. 配置示例 (`config.json` -> `automatic_route`)

```json
"automatic_route": {
  "enabled": true,
  "check_interval": 5,
  "standby_check_interval": 30,
  "recover_check_interval": 120,
  "switch_threshold": 5.0,
  "switch_cooldown": 60,
  "minimum_stable_time": 30,
  "failure_threshold": 3,
  "recovery_threshold": 3,
  "peak_mode": "auto",
  "peak_start_hour": 18,
  "peak_end_hour": 23,
  "history_window": 60,
  "standby_count": 3,
  "max_probe_concurrency": 4,
  "history_file": "routes_history.json",
  "history_save_interval": 300,
  "routes": [
    {
      "id": "goway-01",
      "name": "GOWAY 香港节点",
      "address": "127.0.0.1",
      "port": 9192,
      "protocol": "socks5",
      "type": "goway"
    },
    {
      "id": "goway-02",
      "name": "GOWAY 日本节点",
      "address": "127.0.0.1",
      "port": 9193,
      "protocol": "socks5",
      "type": "goway"
    }
  ]
}
```

### 7. RESTful API 列表

| 接口 | 方法 | 说明 |
|---|---|---|
| `/api/routes` | GET | 返回所有线路状态、当前评分与自动调度开关状态 |
| `/api/routes` | POST | 动态注册或修改线路配置 |
| `/api/routes` | DELETE | 删除指定线路（需提供 `id`） |
| `/api/routes/current` | GET | 返回当前活跃的线路详情与状态快照 |
| `/api/routes/standby` | GET | 返回当前处于就绪状态的温备用线路列表 |
| `/api/routes/metrics` | GET | 返回各线路当前的综合测量指标 |
| `/api/routes/switch` | POST | 手动切换到指定线路（`{"id": "goway-02"}`） |
| `/api/routes/enable` | POST | 开启自动线路调度 |
| `/api/routes/disable` | POST | 关闭自动线路调度（固定当前线路） |
| `/api/routes/report` | POST | 接收外部 CFST / 探测脚本上报的测速指标 JSON（支持单个或数组） |

### 8. 外部 CFST 数据上报示例

外部测试工具（如 CFST 独立进程或 Python 脚本）通过 HTTP POST 发送指标，格式如下：

```bash
curl -X POST http://127.0.0.1:8080/api/routes/report \
  -H "Content-Type: application/json" \
  -d '[
    {
      "id": "goway-01",
      "download_speed": 45000000,
      "min_speed": 35000000,
      "stability": 0.98,
      "packet_loss": 0.00,
      "jitter": 1.5,
      "rtt": 35.0,
      "handshake_success": true
    }
  ]'
```

---

## 🛠️ Performance Optimization / 轻量化设定

GoPass is aggressively optimized. To further relieve UI rendering limits and WebSocket packing pressure on your device, increase the **Refresh Interval** setting located in the Dashboard's **Settings** panel (default is `3s` to `5s`).

GoPass 自带极致的资源管理。如果你的软路由或挂机电脑真的“骨瘦如柴”，你可以在面板的 **Settings** 里把 **Dashboard Optimization (Refresh Interval)** 设定为 `5` 秒至 `30` 秒！从而切断后台所有额外计算，进入绝对的免打扰静默加速状态。

---

## 🤝 GoPass vs Browser Extensions / 用法建议

GoPass acts as an incredibly powerful "middleman" for non-configurable OS background applications (Terminal, WinUpdate, Games). 

However, for heavy **pure web-browsing** (e.g., watching 4K YouTube videos), modern browser extensions (like *ZeroOmega*) interacting directly with the Chromium native C++ network stack will theoretically always execute with slightly lower latency. 

**Pro Tip:** Use browser extensions for your daily driver browser to leverage absolute 0-RTT speeds, while utilizing GoPass to seamlessly catch and accelerate everything else on your operating system! 🚀

GoPass 是为那些**不懂代理、无法设置代理**的系统底层软件而生的透明兜底方案。对于纯血多媒体冲浪（例如主力浏览器），直接给浏览器本身加装诸如 `ZeroOmega` 等代理调度插件，永远能获得极致纯天然的纯粹极速体验（免去了网卡中转跳传的极微小损耗）。

**最佳姿势：** 浏览器内装扩展火力全开，其余万物交给 GoPass 暴力拖出火海！🚀
 
---

## 📝 Release Notes

### v1.6.3
- **SwitchTo 状态机合法性硬约束**：
  - 彻底修复非法状态（`FAILED`、`RECOVERING` 等）激活漏洞；在修改活跃线路（`c.activeRoute`）前，严格验证目标线路状态机流转合法性，TransitionTo 失败时绝对不修改当前活跃线路与旧线路状态。
  - 手动与自动切换对 `FAILED` / `RECOVERING` 线路返回清晰错误，杜绝状态越级。
- **Start 初始化锁粒度优化**：
  - 首选线路激活过程将 `onSwitch` 回调移出 `routesMu` 锁保护区，避免未来上游热更新扩展引发锁嵌套或死锁风险。
- **ACTIVE 线路唯一性全面加固**：
  - 动态注册（`RegisterRoute`）主动规避伪造状态，杜绝出现双 ACTIVE 线路。
  - 新增 `CheckActiveConsistency` 全局断言，覆盖正常切换、非法切换、紧急转移、动态注册、注销及初始化场景。
