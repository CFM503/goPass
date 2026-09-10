# GoPass Changelog

## v1.6.7

- **核心转发重构**：GoPass 改为纯 TCP 透明转发核心，仅负责 WinDivert 劫持、Original Destination、上游 SOCKS5/HTTP CONNECT 与双向 relay。
- **彻底移除分流**：删除 GeoIP/GeoSite、进程白名单、Custom Direct/Proxy、CN/Foreign 路由、Split、Fake-IP DNS Relay、国外 UDP/QUIC 分流等全部相关代码与配置。
- **移除 2MB Buffer Pool 参数**：用户可配置的 relay buffer 安全范围调整为 **32KB–1MB**，最大值固定 1MB。
- **默认 Buffer**：调整为 256KB，避免高并发下无意义的内存放大。
- **Relay 生命周期重构**：移除旧的 Bidirectional Wait 参数，双向 relay 使用独立 goroutine + WaitGroup；异常 I/O 会主动关闭双方连接，避免连接长期卡死。
- **Payload 安全**：删除 TLS SNI peek/replay 路径，核心代理不再主动读取、缓存、重复发送应用层数据。
- **ConnTracker 重构**：仅承担透明代理连接交接，删除进程名等分流字段，并改进 Close 幂等性。
- **WinDivert 简化**：只拦截 IPv4 TCP，移除 UDP/53/443、IPv6、进程查询与分流规则路径。
- **API/UI 配置精简**：删除 split/rules API 以及 Socket Buffer、Bidirectional Wait 等无效性能参数。
- **版本号**：v1.6.7。

## v1.6.6

- **TProxy Buffer 默认值**：512 KB。
- **TProxy Buffer 安全范围**：32 KB–2 MB。
- **Web UI 预设**：32 KB、256 KB、512 KB（推荐）、1 MB、2 MB，并支持自定义输入。
- **自定义值校验**：前端与 API/运行时统一限制为 32 KB–2 MB，防止异常大值造成不必要的内存占用。
- **Socket Buffer**：固定为 `0`，继续使用 Windows TCP Auto-Tuning，不再向用户开放设置。
- **TCP 高级参数收敛**：TCP NoDelay、Bidirectional Wait、TCP Keep-Alive、Keep-Alive Period、TCP Linger 使用稳定默认值，普通 Web UI 不再允许随意修改。
- **保持 v1.6.5 核心能力**：保留 OrigDstIP 优先、Fake-IP 恢复、SNI fallback 与既有透明代理逻辑。
