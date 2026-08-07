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
   Compile from source using `go build` or download the ultra-slim release executable `gopass_1.5.0.exe`.  
   根据源码自行编译，或直接下载极限瘦身的成品执行文件 `gopass_1.5.0.exe`。

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
