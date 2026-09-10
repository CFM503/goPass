# GoPass 🚀

A lightweight Windows IPv4 TCP transparent proxy focused on reliable forwarding, low memory usage, and stable high-concurrency operation.

一款为 Windows 打造的轻量级 IPv4 TCP 透明代理终端，专注于稳定转发、低内存占用以及高并发连接生命周期管理。

## 🌟 Core Features / 核心特性

- **True Transparent Proxy / 真正的透明代理**  
  Uses WinDivert at the network layer so supported IPv4 TCP applications do not need system proxy settings.

- **Proxy-Only Forwarding / 纯代理转发**  
  GoPass does not perform GeoIP/GeoSite split routing, process whitelist routing, Fake-IP DNS relay, direct/foreign routing, or UDP/QUIC routing. It receives the original destination and forwards the TCP connection to the configured upstream proxy.

- **SOCKS5 & HTTP CONNECT Upstream / 上游代理**  
  Supports SOCKS5 and HTTP CONNECT upstream proxies with hot switching.

- **Low-Memory Relay / 低内存转发**  
  Relay buffers are limited to **32 KB–1 MB**. The default is **256 KB**. There is no 2 MB buffer option or 2 MB buffer pool.

- **Safe Connection Lifecycle / 安全连接生命周期**  
  Bidirectional forwarding is managed independently. An I/O failure closes both sides so blocked relay goroutines can exit instead of waiting indefinitely.

- **Local Web Dashboard / 本地控制面板**  
  `http://127.0.0.1:8080` shows active proxied connections, traffic rates, upstream settings, and relay buffer settings.

## 📥 Installation & Usage / 安装与使用

1. **Build / 编译**  
   Run `go build -ldflags="-s -w" -o gopass.exe ./cmd/gopass` on Windows.

2. **Run as Administrator / 管理员运行**  
   GoPass requires Administrator privileges because WinDivert requires elevated permissions.

3. **Configure Upstream / 配置上游**  
   Open `http://127.0.0.1:8080`, select SOCKS5 or HTTP CONNECT, then enter the upstream address and port. The default development setup uses `127.0.0.1:9192`.

4. **Configure Relay Buffer / 配置转发缓冲区**  
   Choose 32 KB, 64 KB, 128 KB, 256 KB, 512 KB, or 1 MB. Values above 1 MB are rejected and clamped by the runtime.

## ⚠️ Scope / 功能范围

GoPass v1.6.7 is intentionally a proxy-only core. Routing decisions belong to the upstream/client architecture; GoPass itself does not inspect SNI for routing and does not maintain split-routing rule databases.

This release focuses on IPv4 TCP transparent interception and forwarding. IPv6/UDP/QUIC are not handled by the core interceptor.

## 📝 Release Notes / 更新日志

### v1.6.7

- Removed split-routing and its rule database from the core.
- Removed process whitelist and process/network-state caches.
- Removed DNS relay, Fake-IP resolution, GeoIP/GeoSite routing, IPv6 blocking, and foreign UDP blocking.
- Removed the 2 MB buffer pool and the Bidirectional Wait parameter.
- Added a hard 1 MB runtime relay-buffer maximum.
- Default relay buffer is 256 KB.
- Reworked bidirectional relay shutdown to prevent I/O goroutine hangs.
- Simplified WinDivert to IPv4 TCP transparent interception.
- Simplified the dashboard to proxy-only operation.
