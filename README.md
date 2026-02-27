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
   Compile from source using `go build` or download the ultra-slim release executable `gopass_1.1.6.exe`.  
   根据源码自行编译，或直接下载极限瘦身的成品执行文件 `gopass_1.1.6.exe`。

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
